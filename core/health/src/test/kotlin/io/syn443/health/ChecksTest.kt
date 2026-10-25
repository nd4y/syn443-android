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
        assertEquals(listOf(false), result(Probe { _, _ -> false }).values())
        assertEquals(listOf(false), result(Probe { _, _ -> error("network") }).values())
        for (outcome in listOf(Outcome.CANCELLED, Outcome.DEADLINE, Outcome.UNAVAILABLE)) {
            val batch = Batch(listOf(Outcome.PASS, outcome)); assertFalse(batch.complete)
            assertThrows(IllegalStateException::class.java) { batch.values() }
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
