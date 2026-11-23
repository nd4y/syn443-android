package io.syn443.android

import android.system.Os
import androidx.test.platform.app.InstrumentationRegistry
import io.syn443.android.observability.JournalCipherStore
import io.syn443.android.observability.JournalPublicationFence
import io.syn443.android.observability.JournalWriter
import io.syn443.android.observability.LocalDiagnosticJournal
import io.syn443.android.support.DiagnosticArchive
import io.syn443.android.support.SupportBundleSources
import io.syn443.observability.EventClock
import io.syn443.observability.EventCode
import io.syn443.observability.EventCorrelation
import io.syn443.observability.EventDetail
import io.syn443.observability.EventGenerations
import io.syn443.observability.EventPhase
import io.syn443.observability.JournalRetention
import io.syn443.observability.StructuredEvent
import java.io.File
import java.nio.file.Files
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import javax.crypto.spec.SecretKeySpec
import org.junit.Assert.*
import org.junit.Test

class JournalCipherStoreTest {
    private class Fixture(val base: File) {
        val dir = File(base, "journal")
        val fence = JournalPublicationFence()
        val now = AtomicReference(EventClock(7, 1_000L, 100L))
        val reads = AtomicInteger()
        val creates = AtomicInteger()
        private val syntheticKey = SecretKeySpec(ByteArray(32) { (it * 3 + 1).toByte() }, "AES")

        fun store(stage: (JournalCipherStore.Stage) -> Unit = {}) = JournalCipherStore(
            dir, { create ->
                if (create) creates.incrementAndGet() else reads.incrementAndGet()
                syntheticKey
            }, now::get, fence, stage,
        )

        fun event(sequence: Long = 1L) = StructuredEvent(sequence, now.get(),
            EventCorrelation.fromBytes(ByteArray(16) { it.toByte() }), EventGenerations(20, 30),
            EventDetail.Lifecycle(EventPhase.ONLINE, EventCode.REQUIRED_HTTPS_OK))

        fun disk() = dir.listFiles()?.associate { it.name to it.readBytes().toList() }.orEmpty()
    }

    private fun fixture(block: (Fixture) -> Unit) {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val base = Files.createTempDirectory(context.cacheDir.toPath(), "journal-test-").toFile()
        try { block(Fixture(base)) } finally { base.deleteRecursively() }
    }

    private fun denied(block: () -> Unit) {
        try { block() } catch (_: Exception) { return }
        fail("Expected journal operation to fail closed")
    }

    @Test fun passiveSnapshotIsEncryptedOnDiskReadOnlyAndWorksAcrossStoreRecreation() = fixture { f ->
        assertNull(f.store().snapshot().bytes)
        assertFalse(f.dir.exists())
        assertEquals(0, f.creates.get())
        assertEquals(0, f.reads.get())
        f.store().append(listOf(f.event()))
        val before = f.disk()
        val frame = before.values.single().toByteArray()
        assertTrue(frame.size <= JournalRetention.MAX_FRAME_BYTES)
        assertFalse(frame.toString(Charsets.ISO_8859_1).contains("required_https_ok"))
        val result = f.store().snapshot()
        assertFalse(result.partial)
        val json = org.json.JSONObject(checkNotNull(result.bytes).decodeToString())
        assertEquals("required_https_ok", json.getString("code"))
        assertEquals(100L, json.getLong("elapsed"))
        assertEquals(20L, json.getLong("intentGeneration"))
        assertEquals(before, f.disk())
        assertEquals(1, f.creates.get())
        assertEquals(1, f.reads.get())
    }

    @Test fun deniedLoginHistorySurvivesRecreationAndPreservesCurrentVpnState() = fixture { f ->
        val state = org.json.JSONObject().put("desiredOn", false).put("phase", "Off")
            .put("reason", "user_stopped").put("generation", 20L).put("networkEpoch", 30L)
        val unknown = org.json.JSONObject().put("desiredOn", true)
        assertNull(io.syn443.android.vpn.StateStore.appendLoginDenial(unknown))
        assertFalse(unknown.has("events"))
        val receipt = checkNotNull(io.syn443.android.vpn.StateStore.appendLoginDenial(state))
        assertEquals("user_stopped", state.getString("reason"))
        assertEquals("Off", state.getString("phase"))
        assertFalse(state.getBoolean("desiredOn"))
        assertEquals(1L, state.getLong("eventSequence"))
        assertEquals(1, state.getJSONArray("events").length())
        assertEquals("auth_access_denied", receipt.getString("code"))
        assertEquals(20L, receipt.getLong("intentGeneration"))
        assertEquals(30L, receipt.getLong("networkEpoch"))
        val detail = EventDetail.Lifecycle(checkNotNull(EventPhase.fromWire(receipt.getString("phase"))),
            EventCode.fromWire(receipt.getString("code")))
        f.store().append(listOf(f.event().copy(detail = detail, level = io.syn443.observability.EventLevel.WARN)))
        val before = f.disk()
        assertFalse(before.values.single().toByteArray().toString(Charsets.ISO_8859_1).contains("auth_access_denied"))
        val restored = org.json.JSONObject(checkNotNull(f.store().snapshot().bytes).decodeToString())
        assertEquals("auth_access_denied", restored.getString("code"))
        assertEquals("provisioning", restored.getString("channel"))
        assertEquals("Off", restored.getString("phase"))
        assertEquals(before, f.disk())
    }

    @Test fun expiredFloorSurvivesFailedReplacementAndRejectsRollbackAfterRecreation() = fixture { f ->
        f.store().append(listOf(f.event()))
        val before = f.disk()
        val deadline = JournalRetention.MAX_AGE_MS
        f.now.set(EventClock(7, 1_000L + deadline, 100L + deadline))
        val expired = f.store().snapshot()
        assertNull(expired.bytes)
        assertTrue(expired.partial)
        denied {
            f.store { if (it == JournalCipherStore.Stage.BEFORE_WRITE) error("synthetic_write_failure") }
                .append(listOf(f.event(2)))
        }
        assertEquals(before, f.disk())
        f.now.set(EventClock(7, 999, 100L + deadline))
        denied { f.store().snapshot() }
        denied { f.store().append(listOf(f.event(3))) }
        assertEquals(before, f.disk())
    }

    @Test fun passiveReadOverlappingNewCommittedFloorCannotPublishOldHistory() = fixture { f ->
        f.store().append(listOf(f.event()))
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val executor = Executors.newSingleThreadExecutor()
        try {
            val reader = f.store { stage ->
                if (stage == JournalCipherStore.Stage.BEFORE_READ) {
                    entered.countDown()
                    check(release.await(10, TimeUnit.SECONDS))
                }
            }
            val result = executor.submit<Boolean> { runCatching { reader.snapshot() }.isFailure }
            assertTrue(entered.await(10, TimeUnit.SECONDS))
            f.now.set(EventClock(7, 2_000, 200))
            f.store().append(listOf(f.event(2)))
            f.now.set(EventClock(7, 1_500, 210))
            release.countDown()
            assertTrue("Stale reader published with superseded floor", result.get(10, TimeUnit.SECONDS))
            denied { f.store().snapshot() }
            assertEquals(2, f.disk().size)
        } finally {
            release.countDown()
            executor.shutdownNow()
            assertTrue(executor.awaitTermination(10, TimeUnit.SECONDS))
        }
    }

    @Test fun renamedOrDamagedCiphertextAndForeignEntriesFailClosedWithoutCleanup() = fixture { f ->
        f.store().append(listOf(f.event()))
        val original = checkNotNull(f.dir.listFiles()).single()
        val renamed = File(f.dir, original.name.replace(Regex("-[a-f0-9]{32}\\.enc$"), "-" + "e".repeat(32) + ".enc"))
        assertNotEquals(original.name, renamed.name)
        Os.rename(original.absolutePath, renamed.absolutePath)
        denied { f.store().snapshot() }
        Os.rename(renamed.absolutePath, original.absolutePath)
        val raw = original.readBytes()
        original.writeBytes(raw.copyOf(raw.size - 1))
        denied { f.store().snapshot() }
        original.writeBytes(raw)
        val foreign = File(f.dir, "foreign")
        foreign.writeText("test fixture")
        val before = f.disk()
        denied { f.store().snapshot() }
        denied { f.store().append(listOf(f.event(2))) }
        assertEquals(before, f.disk())
        assertTrue(foreign.delete())
        val outside = File(f.base, "synthetic-target").apply { writeText("fixture") }
        val link = File(f.dir, renamed.name)
        Os.symlink(outside.absolutePath, link.absolutePath)
        denied { f.store().snapshot() }
        denied { f.store().append(listOf(f.event(2))) }
        assertTrue(Files.isSymbolicLink(link.toPath()))
        assertEquals("fixture", outside.readText())
    }

    @Test fun readBudgetReportsPartialAndNewBootNeverReexportsPreviousEpoch() = fixture { f ->
        for (index in 0..8) {
            f.now.set(EventClock(7, 1_000L + index, 100L + index))
            f.store().append(listOf(f.event(index.toLong() + 1)))
        }
        val opened = AtomicInteger()
        val result = f.store { if (it == JournalCipherStore.Stage.BEFORE_READ) opened.incrementAndGet() }.snapshot()
        assertTrue(result.partial)
        assertEquals(8, opened.get())
        assertEquals(8, checkNotNull(result.bytes).decodeToString().lineSequence().count { it.isNotBlank() })
        val previous = f.disk()
        f.now.set(EventClock(8, 1_500L, 1L))
        assertNull(f.store().snapshot().bytes)
        assertEquals(previous, f.disk())
        f.store().append(listOf(f.event(42)))
        val fresh = org.json.JSONObject(checkNotNull(f.store().snapshot().bytes).decodeToString())
        assertEquals(42L, fresh.getLong("sequence"))
        assertEquals(8, fresh.getInt("boot"))
    }

    @Test fun archiveUsesStructuredHistoryWithoutReadingOrRewritingItAgain() = fixture { f ->
        f.store().append(listOf(f.event()))
        val before = f.disk()
        val state = org.json.JSONObject().put("generation", 20).put("networkEpoch", 30)
        val calls = AtomicInteger()
        val captured = SupportBundleSources.capture(
            state = { state }, overlay = { null }, checks = { null }, exits = { null },
            versionName = "0.9.70-local-journal", versionCode = 98, sdk = 29,
            journal = {
                assertEquals(1, calls.incrementAndGet())
                LocalDiagnosticJournal.projection(f.store().snapshot(), JournalWriter.Status(false, false, 0, 1))
            },
        )
        val events = captured.single { it.name == DiagnosticArchive.Name.EVENTS }
        assertEquals(DiagnosticArchive.State.TRUNCATED, events.state)
        assertEquals("required_https_ok", org.json.JSONObject(checkNotNull(events.bytes).decodeToString()).getString("code"))
        assertEquals(1, calls.get())
        assertEquals(1, f.reads.get())
        assertEquals(1, f.creates.get())
        assertEquals(before, f.disk())
        val failed = LocalDiagnosticJournal.projection(JournalCipherStore.Snapshot(null, false),
            JournalWriter.Status(false, true, 0, 2))
        assertEquals(DiagnosticArchive.State.ERROR, failed?.state)
        assertNull(failed?.bytes)
    }
}
