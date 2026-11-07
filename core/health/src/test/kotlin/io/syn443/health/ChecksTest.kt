package io.syn443.health

import io.syn443.policy.Check
import org.junit.Assert.*
import org.junit.Test
import java.io.ByteArrayInputStream
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.*
import java.util.concurrent.atomic.AtomicLong

class ChecksTest {
    private val check = Check("internet", "https_204", "https://example.org/")
    private fun result(probe: Probe): Batch = ProbePool().use { CheckJob(it, probe).run(listOf(check)) }
    @Test fun completedSuccessAndFailureAreDistinctFromIncomplete() {
        assertEquals(listOf(true), result(Probe { _, _ -> true }).values())
        assertNull(result(Probe { _, _ -> false }).incompleteOutcome)
        assertEquals(listOf(false), result(Probe { _, _ -> false }).values())
        assertEquals(listOf(false), result(Probe { _, _ -> error("network") }).values())
        for (outcome in listOf(Outcome.CANCELLED, Outcome.DEADLINE, Outcome.UNAVAILABLE)) {
            val batch = Batch(listOf(Outcome.PASS, outcome)); assertFalse(batch.complete)
            assertEquals(outcome, batch.incompleteOutcome)
            assertThrows(IllegalStateException::class.java) { batch.values() }
        }
    }
    @Test fun positionalDiagnosticsKeepEachFailureSeparateFromLaterSuccessOrMismatch() {
        ProbePool().use { pool ->
            var index = 0
            val job = CheckJob(pool, Probe { _, scope ->
                when (index++) {
                    0 -> { scope.enter(Stage.RESOLVE); throw java.net.UnknownHostException("private-target") }
                    1 -> { scope.enter(Stage.RESPONSE); true }
                    else -> { scope.enter(Stage.RESPONSE); false }
                }
            })
            val batch = job.run(listOf(check, check, check))
            assertEquals(listOf(false, true, false), batch.values())
            assertEquals(listOf(
                CheckObservation(Outcome.FAIL, Failure.DNS, Stage.RESOLVE),
                CheckObservation(Outcome.PASS, null, Stage.RESPONSE),
                CheckObservation(Outcome.FAIL, null, Stage.RESPONSE)), batch.observations)
            assertFalse(batch.toString().contains("private-target"))
            assertFalse(batch.toString().contains(check.target))
            // Existing aggregate attribution still retains the last exception.
            assertEquals(Failure.DNS, job.failure)
            assertThrows(IllegalArgumentException::class.java) {
                Batch(listOf(Outcome.PASS), listOf(CheckObservation(Outcome.FAIL)))
            }
        }
    }
    @Test fun checksNeverStartedDoNotInheritAStageOrNetworkFailure() {
        ProbePool().use { pool ->
            val cancelled = CheckJob(pool, Probe { _, _ -> error("must_not_run") })
            cancelled.cancel()
            assertEquals(List(8) { CheckObservation(Outcome.CANCELLED) }, cancelled.run(List(8) { check }).observations)
            val clock = AtomicLong()
            val deadline = CheckJob(pool, Probe { _, scope -> scope.enter(Stage.RESPONSE); clock.set(300); true }, { clock.get() }, 100, 200)
            assertEquals(listOf(CheckObservation(Outcome.DEADLINE, null, Stage.RESPONSE), CheckObservation(Outcome.DEADLINE)),
                deadline.run(listOf(check, check)).observations)
        }
    }
    @Test fun cancellationBeforeStartDoesNotCallProbe() {
        ProbePool().use { pool ->
            val job = CheckJob(pool, Probe { _, _ -> error("must_not_run") }); job.cancel()
            assertEquals(listOf(Outcome.CANCELLED), job.run(listOf(check)).outcomes)
        }
    }
    @Test fun cancellationClosesSocketAndUnblocksCaller() {
        ProbePool().use { pool ->
            val attached = CountDownLatch(1); val release = CountDownLatch(1); val socket = Socket()
            val job = CheckJob(pool, Probe { _, scope -> scope.attach(socket); attached.countDown(); release.await(); true })
            val caller = Executors.newSingleThreadExecutor()
            try {
                val result = caller.submit<Batch> { job.run(listOf(check, check)) }
                assertTrue(attached.await(2, TimeUnit.SECONDS)); job.cancel()
                assertTrue(socket.isClosed)
                assertEquals(listOf(Outcome.CANCELLED, Outcome.CANCELLED), result.get(2, TimeUnit.SECONDS).outcomes)
            } finally { release.countDown(); caller.shutdownNow() }
        }
    }
    @Test fun attachmentAndCancellationRaceNeverLeavesSocketOpen() {
        val threads = Executors.newFixedThreadPool(2)
        try { repeat(100) {
            val scope = ProbeScope(); val socket = Socket(); val start = CountDownLatch(1)
            val a = threads.submit { start.await(); scope.attach(socket) }
            val b = threads.submit { start.await(); scope.cancel() }
            start.countDown(); a.get(2, TimeUnit.SECONDS); b.get(2, TimeUnit.SECONDS)
            assertTrue(socket.isClosed); assertThrows(IllegalStateException::class.java) { scope.requireActive() }
        } } finally { threads.shutdownNow() }
    }
    @Test fun alreadyCancelledScopeRejectsLaterSocket() {
        val scope = ProbeScope(); scope.cancel(); val socket = Socket(); scope.attach(socket)
        assertTrue(socket.isClosed)
    }
    @Test fun completeBatchAndSingleUseBounds() {
        ProbePool().use { pool ->
            val job = CheckJob(pool, Probe { _, _ -> true })
            assertEquals(List(8) { true }, job.run(List(8) { check }).values())
            assertThrows(IllegalStateException::class.java) { job.run(listOf(check)) }
            for (size in listOf(0, 9)) assertThrows(IllegalArgumentException::class.java) {
                CheckJob(pool, Probe { _, _ -> true }).run(List(size) { check })
            }
            assertThrows(IllegalArgumentException::class.java) { CheckJob(pool, Probe { _, _ -> true }, checkMillis = 3_001) }
            assertThrows(IllegalArgumentException::class.java) { CheckJob(pool, Probe { _, _ -> true }, batchMillis = 30_001) }
        }
    }
    @Test fun elapsedBatchDeadlineRejectsLateSuccessAndDoesNotRunRemainingChecks() {
        ProbePool().use { pool ->
            val clock = AtomicLong(0)
            val job = CheckJob(pool, Probe { _, _ -> clock.set(300); true }, { clock.get() }, 100, 200)
            assertEquals(listOf(Outcome.DEADLINE, Outcome.DEADLINE), job.run(listOf(check, check)).outcomes)
        }
    }
    @Test fun elapsedPerCheckDeadlineRejectsLateSuccess() {
        ProbePool().use { pool ->
            val clock = AtomicLong(0)
            val job = CheckJob(pool, Probe { _, _ -> clock.set(200); true }, { clock.get() }, 100, 1_000)
            assertEquals(Outcome.FAIL, job.run(listOf(check)).outcomes.single())
            assertEquals(Failure.TIMEOUT, job.failure)
        }
    }
    @Test fun timeoutFreezesEachStageAndLateResolverCannotAdvanceIt() {
        for (stage in Stage.entries.filter { it != Stage.QUEUED }) ProbePool().use { pool ->
            val release = CountDownLatch(1); val finished = CountDownLatch(1)
            lateinit var scope: ProbeScope
            val job = CheckJob(pool, Probe { _, current ->
                scope = current; current.enter(stage)
                while (release.count > 0) try { release.await() } catch (_: InterruptedException) { }
                try { current.enter(Stage.RESPONSE); true } finally { finished.countDown() }
            }, checkMillis = 100)
            try {
                assertEquals(Outcome.FAIL, job.run(listOf(check)).outcomes.single())
                assertEquals(Failure.TIMEOUT, job.failure); assertEquals(stage, job.failureStage)
                release.countDown(); assertTrue(finished.await(2, TimeUnit.SECONDS))
                assertEquals(stage, scope.stage); assertEquals(stage, job.failureStage)
            } finally { release.countDown() }
        }
    }
    @Test fun queuedTimeoutIsCapacityFailureWithoutNetworkAttribution() {
        ProbePool().use { pool ->
            val entered = CountDownLatch(2); val release = CountDownLatch(1)
            repeat(2) { pool.executor.submit { entered.countDown(); release.await() } }
            try {
                assertTrue(entered.await(2, TimeUnit.SECONDS))
                assertEquals(2L,pool.counters().getValue("active"));assertEquals(2L,pool.counters().getValue("workers"))
                val job = CheckJob(pool, Probe { _, _ -> error("queued probe must not execute") }, checkMillis = 100)
                assertEquals(CheckObservation(Outcome.UNAVAILABLE, Failure.WORKER_START_TIMEOUT), job.run(listOf(check)).observations.single())
                assertEquals(0L,pool.counters().getValue("queued"));assertEquals(0L,pool.counters().getValue("shutdown"))
                assertNull(job.failure); assertNull(job.failureStage)
                assertEquals(0, pool.executor.queue.size)
                val occupying = pool.executor.submit(Runnable { error("queue occupant must not execute") })
                try {
                    val rejected = CheckJob(pool, Probe { _, _ -> error("rejected probe must not execute") })
                    assertEquals(CheckObservation(Outcome.UNAVAILABLE, Failure.WORKER_REJECTED), rejected.run(listOf(check)).observations.single())
                    assertNull(rejected.failure);assertNull(rejected.failureStage)
                } finally {
                    occupying.cancel(false)
                    (occupying as? Runnable)?.let { pool.executor.remove(it) }
                }
            } finally { release.countDown() }
        }
    }
    @Test fun cancellingQueuedProbeRemovesItWithoutNetworkAttribution() {
        ProbePool().use { pool ->
            val entered = CountDownLatch(2); val release = CountDownLatch(1)
            val caller = Executors.newSingleThreadExecutor()
            repeat(2) { pool.executor.submit { entered.countDown(); release.await() } }
            try {
                assertTrue(entered.await(2, TimeUnit.SECONDS))
                val job = CheckJob(pool, Probe { _, _ -> error("cancelled probe must not execute") })
                val result = caller.submit<Batch> { job.run(listOf(check)) }
                val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2)
                while (pool.executor.queue.size != 1) { assertTrue(System.nanoTime() < deadline); Thread.yield() }
                job.cancel(); assertEquals(Outcome.CANCELLED, result.get(2, TimeUnit.SECONDS).outcomes.single())
                assertNull(job.failure); assertNull(job.failureStage); assertEquals(0, pool.executor.queue.size)
            } finally { release.countDown(); caller.shutdownNow() }
        }
    }
    @Test fun nonInterruptibleResolverCannotGrowWorkersOrPoisonUnexecutedChecks() {
        ProbePool().use { pool ->
            val release = CountDownLatch(1)
            val blocked = Probe { _, _ -> while (release.count > 0) { try { release.await() } catch (_: InterruptedException) { } }; true }
            try {
                repeat(2) { assertEquals(Outcome.FAIL, CheckJob(pool, blocked, checkMillis = 100).run(listOf(check)).outcomes.single()) }
                val batch = CheckJob(pool, blocked, checkMillis = 100).run(listOf(check))
                assertEquals(Outcome.UNAVAILABLE, batch.outcomes.single()); assertFalse(batch.complete)
                assertEquals(2, pool.executor.poolSize); assertEquals(0, pool.executor.queue.size)
            } finally { release.countDown() }
        }
    }
    private fun banner(text: String, expected: String = "SSH-2.0", delay: Long = 0): Outcome {
        val server = ServerSocket(0, 1, java.net.InetAddress.getLoopbackAddress())
        val serving = Executors.newSingleThreadExecutor { r -> Thread(r).apply { isDaemon = true } }
        val task = serving.submit { runCatching { server.accept().use { socket ->
            for (b in text.toByteArray()) { socket.getOutputStream().write(b.toInt()); if (delay > 0) Thread.sleep(delay) }
        } } }
        return try {
            ProbePool().use { pool -> CheckJob(pool, NetworkProbe(), checkMillis = 250).run(
                listOf(Check("ssh", "tcp_banner", server.inetAddress.hostAddress, server.localPort, expected))).outcomes.single() }
        } finally { server.close(); serving.shutdownNow(); task.get(2, TimeUnit.SECONDS) }
    }
    @Test fun tcpBannerMatchesAndEofOrMismatchFails() {
        assertEquals(Outcome.PASS, banner("SSH-2.0"))
        assertEquals(Outcome.FAIL, banner("SSH-"))
        assertEquals(Outcome.FAIL, banner("NOT-SSH"))
    }
    @Test fun slowTrickleCannotExtendPerCheckDeadline() { assertEquals(Outcome.FAIL, banner("SSH-2.0", delay = 100)) }
    @Test fun strictResponseStatusAndHeaders() {
        fun status(s: String) = status204(ByteArrayInputStream(s.toByteArray()))
        assertTrue(status("HTTP/1.1 204 No Content\r\nX-Test: ok\r\n\r\n"))
        assertTrue(status("HTTP/1.0 204\r\n\r\n"))
        assertFalse(status("HTTP/1.1 302 Found\r\nLocation: https://example.org/\r\n\r\n"))
        assertFalse(status("HTTP/1.1 2040 Invalid\r\n\r\n"))
        assertThrows(java.io.EOFException::class.java) { status("HTTP/1.1 204\r\n") }
        for (invalid in listOf("HTTP/1.1 204\n\n", "HTTP/1.1 204\r\nNoColon\r\n\r\n", "HTTP/1.1 204\r\nX: "+"a".repeat(16_384)+"\r\n\r\n")) {
            assertThrows(IllegalArgumentException::class.java) { status(invalid) }
        }
    }
    @Test fun onlyFixedFailureClassesLeaveTheWorker() {
        ProbePool().use { pool ->
            for ((error, expected) in listOf(
                java.net.UnknownHostException("sensitive-target") to Failure.DNS,
                javax.net.ssl.SSLException("sensitive-certificate") to Failure.TLS,
                java.io.EOFException() to Failure.EOF,
                java.net.SocketTimeoutException() to Failure.TIMEOUT,
                IllegalArgumentException("sensitive-input") to Failure.TRANSPORT)) {
                val job = CheckJob(pool, Probe { _, _ -> throw error })
                assertEquals(Outcome.FAIL, job.run(listOf(check)).outcomes.single()); assertEquals(expected, job.failure)
            }
        }
    }
}
