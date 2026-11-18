package io.syn443.android

import android.content.Context
import android.system.Os
import android.util.Base64
import androidx.test.core.app.ApplicationProvider
import io.syn443.android.support.DiagnosticArchive
import io.syn443.android.support.SupportBundleController
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.Closeable
import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/** Real private AES/file operations, synthetic sources and clocks only. Never
 * calls the production source provider, device key, VPN or network APIs. */
class SupportBundleControllerTest {
    private class Fixture : Closeable {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val namespace = "test-" + UUID.randomUUID().toString().replace("-", "")
        val directory = File(context.noBackupFilesDir, "support-bundles-$namespace")
        val now = AtomicLong(1_000)
        val calls = AtomicInteger()
        val controllers = mutableListOf<SupportBundleController>()
        val injected = mutableSetOf<File>()
        fun controller(source: () -> List<DiagnosticArchive.Component> = { components() },
            io: (SupportBundleController.IoStage) -> Unit = {}): SupportBundleController =
            SupportBundleController.isolatedForTest(context, namespace, now::get,
                { calls.incrementAndGet(); source() }, io = io).also { controllers += it }
        fun close(controller: SupportBundleController) {
            controller.shutdownForTest()
            controllers.remove(controller)
        }
        fun directory() { Os.mkdir(directory.absolutePath, 448) }
        fun injected(name: String, parent: File = directory): File {
            check('/' !in name && '\\' !in name)
            return File(parent, name).also { injected += it }
        }
        override fun close() {
            try { controllers.toList().forEach(::close) } finally {
                if (Files.isSymbolicLink(directory.toPath())) Files.delete(directory.toPath())
                else if (directory.isFile) check(directory.delete())
                else if (directory.exists()) {
                    directory.listFiles()?.forEach { file ->
                        check(file in injected || file.name.matches(Regex("[a-f0-9]{32}\\.(enc|tmp)")))
                        check(!file.isDirectory || Files.isSymbolicLink(file.toPath()))
                        Files.delete(file.toPath())
                    }
                    check(directory.delete())
                }
                injected.sortedByDescending { it.absolutePath.length }.forEach {
                    if (Files.exists(it.toPath(), java.nio.file.LinkOption.NOFOLLOW_LINKS)) Files.delete(it.toPath())
                }
            }
        }
    }

    private fun await(controller: SupportBundleController, id: String, expected: String): JSONObject {
        val end = System.nanoTime() + TimeUnit.SECONDS.toNanos(20)
        while (true) {
            val state = controller.status(id)
            if (state.getString("state") == expected && !controller.busyForTest()) return state
            check(System.nanoTime() < end) { "finite_bundle_completion_deadline" }
            Thread.sleep(10)
        }
    }

    private fun ignoringInterrupt(latch: CountDownLatch) {
        val end = System.nanoTime() + TimeUnit.SECONDS.toNanos(20)
        while (latch.count > 0) {
            val left = end - System.nanoTime()
            check(left > 0)
            try { check(latch.await(left, TimeUnit.NANOSECONDS)) } catch (_: InterruptedException) { }
        }
    }

    private fun allBytes(controller: SupportBundleController, opened: JSONObject): ByteArray {
        val output = ByteArrayOutputStream()
        var offset = 0
        var chunks = 0
        while (true) {
            check(++chunks <= 17)
            val chunk = controller.read(opened.getString("grant") + ":" + offset)
            assertEquals(setOf("grant", "offset", "data", "nextOffset", "done"), chunk.keys().asSequence().toSet())
            assertEquals(opened.getString("grant"), chunk.getString("grant"))
            assertEquals(offset, chunk.getInt("offset"))
            assertTrue(chunk.toString().toByteArray(Charsets.UTF_8).size <= 45_056)
            val bytes = Base64.decode(chunk.getString("data"), Base64.NO_WRAP)
            assertTrue(bytes.size <= 32_768)
            output.write(bytes)
            val next = chunk.getInt("nextOffset")
            assertEquals(offset + bytes.size, next)
            if (chunk.getBoolean("done")) break
            assertTrue(next > offset)
            offset = next
        }
        return output.toByteArray().also {
            assertEquals(opened.getInt("bytes"), it.size)
            assertEquals(opened.getString("sha256"), hash(it))
        }
    }

    @Test fun encryptedArchiveHasOwnedMetadataAndWholeVerifiedChunkReadback() {
        Fixture().use { f ->
            val controller = f.controller()
            val id = controller.collect().getString("id")
            val ready = await(controller, id, "ready")
            assertEquals(1, f.calls.get())
            assertTrue(ready.getInt("bytes") > 32_768)
            assertTrue(ready.toString().toByteArray(Charsets.UTF_8).size <= 16_384)
            assertFalse(ready.getJSONObject("manifest").getBoolean("complete"))
            val stored = File(f.directory, "$id.enc").readBytes()
            assertTrue(stored.size <= 524_320)
            assertEquals(1, stored[0].toInt())
            assertFalse(stored.toString(Charsets.ISO_8859_1).contains("fixture-payload"))
            ready.getJSONObject("manifest").put("product", "caller-mutation")
            assertEquals("SYN443", controller.status(id).getJSONObject("manifest").getString("product"))
            val opened = controller.open(id)
            assertEquals("open", opened.getString("state"))
            assertTrue(opened.getLong("expiresInMs") in 1..60_000)
            opened.getJSONObject("manifest").put("complete", true)
            assertFalse(controller.status(id).getJSONObject("manifest").getBoolean("complete"))
            val archive = allBytes(controller, opened)
            assertEquals('P'.code, archive[0].toInt())
            assertEquals('K'.code, archive[1].toInt())
            assertEquals(1, f.directory.listFiles()!!.size)
            assertEquals(1, f.calls.get())
        }
    }

    @Test fun cancelledBlockedCollectorRetainsActualSlotAndRejectsLatePublication() {
        Fixture().use { f ->
            val entered = CountDownLatch(1)
            val release = CountDownLatch(1)
            val controller = f.controller(source = {
                entered.countDown(); ignoringInterrupt(release); components()
            })
            val id = controller.collect().getString("id")
            try {
                assertTrue(entered.await(10, TimeUnit.SECONDS))
                assertEquals("cancelled", controller.cancel(id).getString("state"))
                repeat(3) {
                    val busy = controller.collect()
                    assertEquals("busy", busy.getString("state")); assertEquals(id, busy.getString("id"))
                }
                assertTrue(controller.busyForTest())
                assertEquals(1, f.calls.get())
                assertEquals("cancelled", controller.open(id).getString("state"))
            } finally { release.countDown() }
            await(controller, id, "cancelled")
            assertTrue(f.directory.listFiles().isNullOrEmpty())
            val fresh = controller.collect().getString("id")
            assertNotEquals(id, fresh)
            await(controller, fresh, "ready")
            assertEquals(2, f.calls.get())
            assertEquals("not_found", controller.status(id).getString("state"))
        }
        Fixture().use { f ->
            val entered = CountDownLatch(1); val release = CountDownLatch(1)
            val controller = f.controller(io = { stage ->
                if (stage == SupportBundleController.IoStage.BEFORE_RENAME) {
                    entered.countDown(); ignoringInterrupt(release)
                }
            })
            val id = controller.collect().getString("id")
            try {
                assertTrue(entered.await(10, TimeUnit.SECONDS))
                assertTrue(File(f.directory, "$id.tmp").isFile)
                assertEquals("cancelled", controller.cancel(id).getString("state"))
                assertEquals("busy", controller.collect().getString("state"))
                assertTrue(controller.busyForTest())
            } finally { release.countDown() }
            await(controller, id, "cancelled")
            assertTrue(f.directory.listFiles().isNullOrEmpty())
            assertEquals(1, f.calls.get())
        }
    }

    @Test fun grantAndReadyExpiryAndBackwardsClockNeverFreshenAnOldArtifact() {
        Fixture().use { f ->
            val controller = f.controller()
            val id = controller.collect().getString("id")
            await(controller, id, "ready")
            val first = controller.open(id)
            f.now.set(61_000)
            assertEquals("not_found", controller.read(first.getString("grant") + ":0").getString("state"))
            assertEquals("ready", controller.status(id).getString("state"))
            val second = controller.open(id)
            assertNotEquals(first.getString("grant"), second.getString("grant"))
            f.now.set(901_000)
            assertEquals("expired", controller.status(id).getString("state"))
            assertEquals("expired", controller.open(id).getString("state"))
            assertFalse(controller.read(second.getString("grant") + ":0").has("data"))
            // The access TTL does not promise background deletion of ciphertext.
            assertTrue(File(f.directory, "$id.enc").isFile)
            val fresh = controller.collect().getString("id")
            await(controller, fresh, "ready")
            val third = controller.open(fresh)
            f.now.decrementAndGet()
            assertEquals("expired", controller.status(fresh).getString("state"))
            assertFalse(controller.read(third.getString("grant") + ":0").has("data"))
            f.now.set(Long.MAX_VALUE)
            val invalidClock = controller.collect().getString("id")
            await(controller, invalidClock, "expired")
            f.now.set(-1)
            assertEquals("expired", controller.status(invalidClock).getString("state"))
            assertEquals(2, f.calls.get())
        }
    }

    @Test fun grantsAreObjectBoundAndRepeatedReadsNeverReplayCollection() {
        Fixture().use { f ->
            val controller = f.controller()
            val id = controller.collect().getString("id")
            await(controller, id, "ready")
            val first = controller.open(id).getString("grant")
            val one = controller.read("$first:0")
            val again = controller.read("$first:0")
            assertEquals(one.toString(), again.toString())
            val second = controller.open(id).getString("grant")
            assertNotEquals(first, second)
            assertFalse(controller.read("$first:0").has("data"))
            assertTrue(controller.read("$second:0").has("data"))
            repeat(4) { controller.status(id) }
            assertEquals(1, f.calls.get())
            val replacement = controller.collect().getString("id")
            assertFalse(controller.read("$second:0").has("data"))
            await(controller, replacement, "ready")
            assertEquals(2, f.calls.get())
            assertFalse(File(f.directory, "$id.enc").exists())
        }
    }

    @Test fun malformedIdsOffsetsAndUnknownJobsNeverReadOrCreateStorage() {
        Fixture().use { f ->
            val controller = f.controller()
            val known = "a".repeat(32)
            assertEquals("not_found", controller.status(known).getString("state"))
            assertEquals("not_found", controller.open(known).getString("state"))
            assertEquals("not_found", controller.cancel(known).getString("state"))
            assertFalse(controller.read("$known:0").has("data"))
            androidx.test.platform.app.InstrumentationRegistry.getInstrumentation().runOnMainSync {
                try { controller.read("$known:0"); fail("main-thread disk entry admitted") }
                catch (_: IllegalStateException) { }
            }
            for (id in listOf("", "A".repeat(32), "a".repeat(31), "../" + known, "é".repeat(32))) {
                for (operation in listOf<(String) -> JSONObject>(controller::status, controller::cancel, controller::open)) {
                    try { operation(id); fail("invalid identifier admitted") } catch (_: IllegalArgumentException) { }
                }
            }
            for (arg in listOf(known, "$known:", "$known:00", "$known:01", "$known:-1", "$known:+1",
                "$known:1.0", "$known:1e2", "$known:524289", "$known:9999999", "$known:0:0", "A".repeat(32) + ":0")) {
                try { controller.read(arg); fail("invalid range admitted") } catch (_: IllegalArgumentException) { }
            }
            assertEquals(0, f.calls.get())
            assertFalse(f.directory.exists())
        }
    }

    @Test fun corruptedTruncatedAndOversizedCiphertextFailBeforeAnyPlaintextChunk() {
        for (kind in 0..2) Fixture().use { f ->
            val controller = f.controller()
            val id = controller.collect().getString("id")
            await(controller, id, "ready")
            val opened = controller.open(id)
            val file = File(f.directory, "$id.enc")
            val value = file.readBytes()
            when (kind) {
                0 -> { value[value.lastIndex] = (value.last().toInt() xor 1).toByte(); file.writeBytes(value) }
                1 -> file.writeBytes(value.copyOf(20))
                else -> file.writeBytes(ByteArray(524_321))
            }
            val result = controller.read(opened.getString("grant") + ":0")
            assertFalse(result.has("data")); assertEquals("failed", result.getString("state"))
            assertEquals("failed", controller.status(id).getString("state"))
            assertFalse(controller.open(id).has("grant"))
            assertEquals(1, f.calls.get())
        }
    }

    @Test fun recreatedProcessOwnerCannotReuseAKeyGrantOrOldEncryptedArtifact() {
        Fixture().use { f ->
            val first = f.controller()
            val id = first.collect().getString("id")
            await(first, id, "ready")
            val grant = first.open(id).getString("grant")
            val original = File(f.directory, "$id.enc").readBytes()
            f.close(first)
            val second = f.controller()
            assertEquals("not_found", second.status(id).getString("state"))
            assertFalse(second.read("$grant:0").has("data"))
            assertArrayEquals(original, File(f.directory, "$id.enc").readBytes())
            val temporary = f.injected("b".repeat(32) + ".tmp")
            Os.open(temporary.absolutePath, android.system.OsConstants.O_WRONLY or android.system.OsConstants.O_CREAT or
                android.system.OsConstants.O_EXCL, 384).let { fd -> java.io.FileOutputStream(fd).use { it.write(byteArrayOf(1)) } }
            val newId = second.collect().getString("id")
            await(second, newId, "ready")
            assertFalse(File(f.directory, "$id.enc").exists())
            assertFalse(temporary.exists())
            assertEquals(listOf("$newId.enc"), f.directory.listFiles()!!.map { it.name })
        }
    }

    @Test fun foreignFilesAndSymlinkFilesOrDirectoriesArePreservedAndFailClosed() {
        for (kind in 0..2) Fixture().use { f ->
            val external = f.injected("bundle-target-" + f.namespace, f.context.noBackupFilesDir)
            if (kind == 2) {
                Os.mkdir(external.absolutePath, 448)
                val marker = f.injected("marker", external).apply { writeText("fixture-payload") }
                Os.symlink(external.absolutePath, f.directory.absolutePath)
                assertEquals("fixture-payload", marker.readText())
            } else {
                f.directory()
                external.writeText("fixture-payload")
                if (kind == 0) f.injected("foreign.txt").writeText("fixture-payload")
                else Os.symlink(external.absolutePath, f.injected("c".repeat(32) + ".enc").absolutePath)
            }
            val controller = f.controller()
            val id = controller.collect().getString("id")
            await(controller, id, "failed")
            assertEquals(0, f.calls.get())
            if (kind == 2) {
                assertTrue(Files.isSymbolicLink(f.directory.toPath()))
                assertEquals("fixture-payload", File(external, "marker").readText())
            } else {
                assertEquals("fixture-payload", external.readText())
                assertTrue(File(f.directory, if (kind == 0) "foreign.txt" else "c".repeat(32) + ".enc").exists())
            }
        }
    }

    @Test fun blockedReadKeepsItsSingleSlotAndCancelledVerifiedBytesCannotPublish() {
        for (kind in 0..1) Fixture().use { f ->
            val entered = CountDownLatch(1)
            val release = CountDownLatch(1)
            val controller = f.controller(io = { stage ->
                if (stage == SupportBundleController.IoStage.AFTER_DECRYPT) {
                    entered.countDown(); ignoringInterrupt(release)
                }
            })
            val id = controller.collect().getString("id")
            await(controller, id, "ready")
            val grant = controller.open(id).getString("grant")
            val reader = Executors.newSingleThreadExecutor()
            try {
                val pending = reader.submit<JSONObject> { controller.read("$grant:0") }
                assertTrue(entered.await(10, TimeUnit.SECONDS))
                assertEquals("busy", controller.read("$grant:0").getString("state"))
                assertEquals("ready", controller.status(id).getString("state"))
                if (kind == 0) assertEquals("cancelled", controller.cancel(id).getString("state"))
                else {
                    f.now.set(61_000)
                    assertEquals("ready", controller.status(id).getString("state"))
                }
                assertTrue(controller.busyForTest())
                release.countDown()
                val result = pending.get(10, TimeUnit.SECONDS)
                assertEquals(if (kind == 0) "cancelled" else "not_found", result.getString("state"))
                assertFalse(result.has("data"))
                assertEquals(1, f.calls.get())
            } finally {
                release.countDown(); reader.shutdownNow(); assertTrue(reader.awaitTermination(10, TimeUnit.SECONDS))
            }
        }
    }

    @Test fun failedSourcesAtomicWriteFailuresAndOverLimitComponentsNeverAutoRetry() {
        Fixture().use { f ->
            val sourceFailure = f.controller(source = { throw IOException("fixture-source-failure") })
            val first = sourceFailure.collect().getString("id")
            assertEquals(setOf("state", "id"), await(sourceFailure, first, "failed").keys().asSequence().toSet())
            repeat(3) { sourceFailure.status(first) }
            assertEquals(1, f.calls.get()); f.close(sourceFailure)
            val writeFailure = f.controller(io = { if (it == SupportBundleController.IoStage.BEFORE_RENAME) throw IOException("fixture-write-failure") })
            val second = writeFailure.collect().getString("id")
            await(writeFailure, second, "failed")
            assertTrue(f.directory.listFiles().isNullOrEmpty()); f.close(writeFailure)
            val oversized = f.controller(source = { listOf(DiagnosticArchive.Component(DiagnosticArchive.Name.HEALTH,
                ByteArray(65_537), DiagnosticArchive.State.AVAILABLE, DiagnosticArchive.Reason.PROJECTION_ONLY)) })
            val third = oversized.collect().getString("id")
            val ready = await(oversized, third, "ready")
            assertFalse(ready.getJSONObject("manifest").getBoolean("complete"))
            val rows = ready.getJSONObject("manifest").getJSONArray("components")
            val health = (0 until rows.length()).map { rows.getJSONObject(it) }.single { it.getString("name") == "health.json" }
            assertEquals("error", health.getString("state")); assertEquals("over_limit", health.getString("reason"))
            assertTrue(ready.getInt("bytes") < 65_536)
            assertEquals(3, f.calls.get())
        }
    }

    companion object {
        private fun components(): List<DiagnosticArchive.Component> = DiagnosticArchive.Name.entries.mapIndexed { index, name ->
            val payload = JSONObject().put("count", index).put("fixture-payload", ('a'.code + index).toChar().toString().repeat(8_000))
                .toString().toByteArray(Charsets.UTF_8)
            DiagnosticArchive.Component(name, payload, DiagnosticArchive.State.AVAILABLE, DiagnosticArchive.Reason.PROJECTION_ONLY)
        }
        private fun hash(value: ByteArray) = MessageDigest.getInstance("SHA-256").digest(value)
            .joinToString("") { "%02x".format(it.toInt() and 255) }
    }
}
