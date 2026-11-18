package io.syn443.android

import io.syn443.android.observability.JournalWriter
import io.syn443.android.observability.PendingJournalEvent
import io.syn443.observability.EventClock
import io.syn443.observability.EventCode
import io.syn443.observability.EventCorrelation
import io.syn443.observability.EventDetail
import io.syn443.observability.EventGenerations
import io.syn443.observability.EventPhase
import io.syn443.observability.StructuredEvent
import java.io.Closeable
import java.io.IOException
import java.util.Collections
import java.util.concurrent.AbstractExecutorService
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.Callable
import java.util.concurrent.CountDownLatch
import java.util.concurrent.FutureTask
import java.util.concurrent.ThreadFactory
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import org.junit.Assert.*
import org.junit.Test

/** Owned local workers and fake clocks only. No production owner/key/storage. */
class JournalWriterTest {
    private fun awaitIgnoringCancellation(latch: CountDownLatch) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
        while (latch.count > 0) {
            val left = deadline - System.nanoTime()
            check(left > 0) { "synthetic_gate_deadline" }
            try { check(latch.await(left, TimeUnit.NANOSECONDS)) { "synthetic_gate_deadline" } }
            catch (_: InterruptedException) { }
        }
    }
    private inner class OwnedExecutor(blockStart: Boolean = false) : AbstractExecutorService(), Closeable {
        val start = CountDownLatch(if (blockStart) 1 else 0)
        val submissions = AtomicInteger()
        val threads = AtomicInteger()
        private val tasks = Collections.synchronizedList(ArrayList<FutureTask<Unit>>())
        private val exits = Collections.synchronizedList(ArrayList<CountDownLatch>())
        private val delegate = ThreadPoolExecutor(1, 1, 0, TimeUnit.MILLISECONDS, ArrayBlockingQueue<Runnable>(2), ThreadFactory { task ->
            threads.incrementAndGet()
            Thread(task, "structured-journal-fixture")
        })
        override fun execute(command: Runnable) {
            submissions.incrementAndGet()
            val exit = CountDownLatch(1)
            val task = FutureTask(Callable { command.run(); Unit })
            tasks += task
            exits += exit
            delegate.execute {
                try { awaitIgnoringCancellation(start); task.run() } finally { exit.countDown() }
            }
        }
        fun cancelActual(index: Int) { assertTrue(tasks[index].cancel(true)) }
        fun cancelled(index: Int) = tasks[index].isCancelled
        fun hasActuallyExited(index: Int) = exits[index].count == 0L
        fun awaitExit(index: Int) { assertTrue(exits[index].await(10, TimeUnit.SECONDS)) }
        override fun shutdown() = delegate.shutdown()
        override fun shutdownNow(): MutableList<Runnable> = delegate.shutdownNow()
        override fun isShutdown() = delegate.isShutdown
        override fun isTerminated() = delegate.isTerminated
        override fun awaitTermination(timeout: Long, unit: TimeUnit) = delegate.awaitTermination(timeout, unit)
        override fun close() {
            start.countDown()
            delegate.shutdownNow()
            assertTrue(delegate.awaitTermination(10, TimeUnit.SECONDS))
        }
    }
    private fun pending(index: Int) = PendingJournalEvent(1_000L + index, index.toLong(), EventGenerations(1, 2),
        EventDetail.Lifecycle(EventPhase.RECOVERING, EventCode.RETRY_SCHEDULED))

    @Test fun blockedWriterBoundsQueueAndRetainsActualOwnershipUntilExit() {
        val producer = Thread.currentThread()
        OwnedExecutor(blockStart = true).use { executor ->
            val entered = CountDownLatch(1)
            val release = CountDownLatch(1)
            val elapsed = AtomicLong(1_000)
            val correlations = AtomicInteger()
            val clocks = AtomicInteger()
            val batches = Collections.synchronizedList(ArrayList<List<StructuredEvent>>())
            val callbacks = Collections.synchronizedList(ArrayList<Thread>())
            val writer = JournalWriter(executor,
                { callbacks += Thread.currentThread(); clocks.incrementAndGet(); EventClock(9, 10_000 + elapsed.get(), elapsed.get()) },
                { callbacks += Thread.currentThread(); correlations.incrementAndGet(); EventCorrelation.fromBytes(ByteArray(16) { 7 }) },
                { records ->
                    callbacks += Thread.currentThread()
                    batches += records.toList()
                    if (batches.size == 1) { entered.countDown(); awaitIgnoringCancellation(release) }
                }, elapsed::get, { elapsed.addAndGet(it) })
            try {
                assertTrue(writer.offer(pending(1)))
                assertEquals(0, correlations.get())
                assertEquals(0, clocks.get())
                assertTrue(batches.isEmpty())
                executor.start.countDown()
                assertTrue(entered.await(10, TimeUnit.SECONDS))
                for (index in 2..65) assertTrue(writer.offer(pending(index)))
                assertFalse(writer.offer(pending(66)))
                val blocked = writer.status()
                assertTrue(blocked.running)
                assertFalse(blocked.failed)
                assertEquals(64, blocked.queued)
                assertEquals(1L, blocked.dropped)
                executor.cancelActual(0)
                assertTrue(executor.cancelled(0))
                assertFalse(executor.hasActuallyExited(0))
                assertTrue(writer.status().running)
                assertEquals(1, executor.submissions.get())
                assertEquals(1, executor.threads.get())
                assertEquals(1, correlations.get())
            } finally { release.countDown(); executor.start.countDown() }
            executor.awaitExit(0)
            assertFalse(writer.status().running)
            assertFalse(writer.status().failed)
            assertEquals(0, writer.status().queued)
            assertEquals(listOf(1, 64), batches.map { it.size })
            assertTrue(writer.offer(pending(67)))
            executor.awaitExit(1)
            assertEquals(66L, batches.last().single().sequence)
            assertEquals(1, correlations.get())
            assertEquals(1, executor.threads.get())
            assertTrue(callbacks.all { it !== producer })
            assertEquals("JournalWriterStatus([redacted])", writer.status().toString())
        }
    }

    @Test fun writerFailureOrRejectedDispatchLatchesWithoutRetryOrProducerFailure() {
        OwnedExecutor().use { executor ->
            val entered = CountDownLatch(1)
            val release = CountDownLatch(1)
            val calls = AtomicInteger()
            val writer = JournalWriter(executor, { EventClock(1, 10_000, 1_000) },
                { EventCorrelation.fromBytes(ByteArray(16)) }, {
                    calls.incrementAndGet(); entered.countDown(); awaitIgnoringCancellation(release)
                    throw IOException("synthetic_append_failure")
                }, { 1_000 }, {})
            try {
                assertTrue(writer.offer(pending(1)))
                assertTrue(entered.await(10, TimeUnit.SECONDS))
                assertTrue(writer.offer(pending(2)))
                assertTrue(writer.offer(pending(3)))
            } finally { release.countDown() }
            executor.awaitExit(0)
            val failed = writer.status()
            assertTrue(failed.failed)
            assertFalse(failed.running)
            assertEquals(0, failed.queued)
            assertEquals(3L, failed.dropped)
            repeat(3) { assertFalse(writer.offer(pending(4))) }
            assertEquals(6L, writer.status().dropped)
            assertEquals(1, calls.get())
            assertEquals(1, executor.submissions.get())
        }
        OwnedExecutor().use { executor ->
            executor.shutdown()
            val callbacks = AtomicInteger()
            val writer = JournalWriter(executor,
                { callbacks.incrementAndGet(); EventClock(1, 10_000, 1_000) },
                { callbacks.incrementAndGet(); EventCorrelation.fromBytes(ByteArray(16)) },
                { callbacks.incrementAndGet() }, { 1_000 }, {})
            // Admission to RAM is not a promise that dispatch or persistence succeeded.
            assertTrue(writer.offer(pending(1)))
            assertTrue(writer.status().failed)
            assertFalse(writer.status().running)
            assertEquals(1L, writer.status().dropped)
            assertFalse(writer.offer(pending(2)))
            assertEquals(2L, writer.status().dropped)
            assertEquals(0, callbacks.get())
            assertEquals(0, executor.threads.get())
            assertEquals(1, executor.submissions.get())
        }
    }

    @Test fun batchingPreservesOriginalTimesCorrelationSequenceAndMinimumWriteSpacing() {
        val producer = Thread.currentThread()
        OwnedExecutor(blockStart = true).use { executor ->
            val firstEntered = CountDownLatch(1)
            val release = CountDownLatch(1)
            val elapsed = AtomicLong(1_000)
            val pauses = Collections.synchronizedList(ArrayList<Long>())
            val starts = Collections.synchronizedList(ArrayList<Long>())
            val batches = Collections.synchronizedList(ArrayList<List<StructuredEvent>>())
            val correlations = AtomicInteger()
            val callbackThreads = Collections.synchronizedList(ArrayList<Thread>())
            val originalCorrelation = ByteArray(16) { (it + 1).toByte() }
            val writer = JournalWriter(executor,
                { callbackThreads += Thread.currentThread(); EventClock(9, 10_000 + elapsed.get(), elapsed.get()) },
                { callbackThreads += Thread.currentThread(); correlations.incrementAndGet(); EventCorrelation.fromBytes(originalCorrelation) },
                { records ->
                    callbackThreads += Thread.currentThread()
                    starts += elapsed.get()
                    batches += records.toList()
                    if (batches.size == 1) { firstEntered.countDown(); awaitIgnoringCancellation(release) }
                }, elapsed::get, { delay -> pauses += delay; elapsed.addAndGet(delay) })
            try {
                for (index in 1..3) assertTrue(writer.offer(pending(index)))
                executor.start.countDown()
                assertTrue(firstEntered.await(10, TimeUnit.SECONDS))
                for (index in 4..5) assertTrue(writer.offer(pending(index)))
                // A lifecycle producer finishing a slower intent write may
                // enqueue its original timestamp after a newer engine event.
                assertTrue(writer.offer(pending(2)))
            } finally { release.countDown(); executor.start.countDown() }
            executor.awaitExit(0)
            assertEquals(listOf(3, 2), batches.map { it.size })
            assertEquals(1L, writer.status().dropped)
            assertEquals(listOf(1_000L, 1_500L), starts.toList())
            assertEquals(listOf(500L), pauses.toList())
            elapsed.addAndGet(700)
            assertTrue(writer.offer(pending(6)))
            executor.awaitExit(1)
            val all = batches.flatMap { it }
            assertEquals((1L..6L).toList(), all.map { it.sequence })
            assertEquals((1L..6L).toList(), all.map { it.clock.elapsedMs })
            assertEquals((1_001L..1_006L).toList(), all.map { it.clock.wallMs })
            assertTrue(all.all { it.clock.boot == 9 && it.generations == EventGenerations(1, 2) })
            all.forEach { assertArrayEquals(originalCorrelation, it.correlation.bytes()) }
            assertEquals(1, correlations.get())
            assertEquals(listOf(1_000L, 1_500L, 2_200L), starts.toList())
            assertEquals(listOf(500L), pauses.toList())
            assertTrue(starts.zipWithNext().all { (before, after) -> after - before >= 500 })
            assertTrue(callbackThreads.all { it !== producer })
            assertEquals(1, executor.threads.get())
            assertFalse(writer.status().failed)
            assertFalse(writer.status().running)
            assertEquals(1L, writer.status().dropped)
            assertEquals("PendingJournalEvent([redacted])", pending(1).toString())
        }
    }
}
