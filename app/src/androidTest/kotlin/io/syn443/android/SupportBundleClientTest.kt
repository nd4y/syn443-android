package io.syn443.android

import io.syn443.android.support.SupportBundleClient
import java.io.IOException
import java.io.OutputStream
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.junit.Assert.*
import org.junit.Test

/** Synthetic local callbacks only. No provider, SAF document, device or network. */
class SupportBundleClientTest {
    private fun awaitActualRelease(release: CountDownLatch) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(20)
        while (release.count > 0) {
            val remaining = deadline - System.nanoTime()
            check(remaining > 0) { "synthetic_write_deadline" }
            try {
                check(release.await(remaining, TimeUnit.NANOSECONDS)) { "synthetic_write_deadline" }
            } catch (_: InterruptedException) {
                // A synchronous document provider need not honour UI cancellation.
            }
        }
    }

    @Test fun blockedCancellationAndDocumentWriteFailureRetainExportOwnershipUntilActualExit() = runBlocking {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val actualExited = AtomicBoolean()
        val writeCalls = AtomicInteger()
        val competingCalls = AtomicInteger()
        val stream = object : OutputStream() {
            override fun write(value: Int) {
                writeCalls.incrementAndGet()
                entered.countDown()
                awaitActualRelease(release)
            }
        }
        val ui = launch(Dispatchers.Default) {
            SupportBundleClient.withExportLease {
                withContext(Dispatchers.IO) {
                    try { stream.use { it.write(0x53) } }
                    finally { actualExited.set(true) }
                }
            }
        }
        try {
            assertTrue(entered.await(10, TimeUnit.SECONDS))
            ui.cancel()
            assertTrue(ui.isCancelled)
            assertFalse(ui.isCompleted)
            assertFalse(actualExited.get())
            repeat(3) {
                var rejected = false
                try {
                    SupportBundleClient.withExportLease { competingCalls.incrementAndGet() }
                } catch (error: IllegalStateException) {
                    assertEquals("bundle_export_busy", error.message)
                    rejected = true
                }
                assertTrue(rejected)
            }
            assertEquals(0, competingCalls.get())
            assertEquals(1, writeCalls.get())
        } finally {
            release.countDown()
            withContext(NonCancellable) { withTimeout(10_000) { ui.join() } }
        }
        assertTrue(actualExited.get())
        assertTrue(ui.isCompleted)
        assertEquals("next_explicit_export", SupportBundleClient.withExportLease {
            withContext(Dispatchers.IO) { competingCalls.incrementAndGet(); "next_explicit_export" }
        })
        assertEquals(1, competingCalls.get())

        val failedWriteExited = AtomicBoolean()
        var observedFailure = false
        try {
            SupportBundleClient.withExportLease {
                withContext(Dispatchers.IO) {
                    try {
                        object : OutputStream() {
                            override fun write(value: Int) { throw IOException("synthetic_document_write_failure") }
                        }.use { it.write(0x53) }
                    } finally { failedWriteExited.set(true) }
                }
            }
        } catch (error: IOException) {
            assertEquals("synthetic_document_write_failure", error.message)
            observedFailure = true
        }
        assertTrue(observedFailure)
        assertTrue(failedWriteExited.get())
        assertEquals(7, SupportBundleClient.withExportLease { withContext(Dispatchers.IO) { 7 } })
    }
}
