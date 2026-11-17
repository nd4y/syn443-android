package io.syn443.android

import io.syn443.android.support.DiagnosticArchive
import io.syn443.android.support.SupportBundleSources
import java.io.File
import java.nio.file.Files
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class SupportBundleSourcesTest {
    private fun state() = JSONObject().put("phase", "Online").put("generation", 7).put("networkEpoch", 4)
        .put("desiredOn", true).put("engineActive", true)

    @Test fun passiveCaptureLeavesItsSourcesUnchangedAndRunsEachSupplierOnce() {
        val before = state()
        val saved = before.toString()
        var stateReads = 0; var overlayReads = 0; var checkReads = 0; var exitReads = 0
        val parts = SupportBundleSources.capture(
            { stateReads++; JSONObject(saved) }, { overlayReads++; JSONObject().put("mode", "direct") },
            { checkReads++; JSONObject().put("current", true) }, { exitReads++; JSONObject().put("state", "unsupported") },
            "0.9.69-support-bundles", 97, 29,
        )
        assertEquals(saved, before.toString())
        assertEquals(2, stateReads); assertEquals(1, overlayReads); assertEquals(1, checkReads); assertEquals(1, exitReads)
        assertEquals(9, parts.size)
        assertFalse(DiagnosticArchive.create(parts).manifest.getBoolean("complete"))
    }

    @Test fun changedContextRejectsCapturedHealthChecksAndOverlayWithoutRepeatingWork() {
        var reads = 0; var overlays = 0
        val parts = SupportBundleSources.capture(
            { state().put("generation", if (reads++ == 0) 7 else 8) }, { overlays++; JSONObject() }, { JSONObject() }, { JSONObject() },
            "0.9.69-support-bundles", 97, 29,
        )
        for (name in listOf(DiagnosticArchive.Name.HEALTH, DiagnosticArchive.Name.CHECKS, DiagnosticArchive.Name.OVERLAY)) {
            val part = parts.single { it.name == name }
            assertEquals(DiagnosticArchive.State.ERROR, part.state)
            assertEquals(DiagnosticArchive.Reason.INVALID_SOURCE, part.reason)
            assertNull(part.bytes)
        }
        assertEquals(2, reads); assertEquals(1, overlays)
    }

    @Test fun missingOrFailingSourcesBecomePartialWithoutRawExceptionText() {
        val parts = SupportBundleSources.capture(
            { null }, { error("synthetic private marker") }, { error("synthetic private marker") }, { error("synthetic private marker") },
            "0.9.69-support-bundles", 97, 29,
        )
        assertNull(parts.single { it.name == DiagnosticArchive.Name.HEALTH }.bytes)
        assertNull(parts.single { it.name == DiagnosticArchive.Name.EVENTS }.bytes)
        val archive = DiagnosticArchive.create(parts)
        assertFalse(archive.manifest.getBoolean("complete"))
        assertFalse(archive.manifest.toString().contains("synthetic private marker"))
    }

    @Test fun stateFileReadRejectsOversizeDepthUtf8TrailingAndSymlinkWithoutModifyingFiles() {
        val directory = Files.createTempDirectory("syn443-source-").toFile()
        val file = File(directory, "state.json")
        try {
            val valid = state().toString().toByteArray()
            file.writeBytes(valid)
            assertEquals(7, SupportBundleSources.readState(file)!!.getInt("generation"))
            assertArrayEquals(valid, file.readBytes())
            for (raw in listOf(
                ByteArray(SupportBundleSources.MAX_STATE_BYTES + 1) { 32 },
                ("[".repeat(33) + "0" + "]".repeat(33)).toByteArray(),
                byteArrayOf(0xc3.toByte(), 0x28), ("{}{}").toByteArray(),
            )) {
                file.writeBytes(raw)
                assertThrows(Exception::class.java) { SupportBundleSources.readState(file) }
                assertArrayEquals(raw, file.readBytes())
            }
            val alias = File(directory, "alias.json")
            Files.createSymbolicLink(alias.toPath(), file.toPath())
            assertNull(SupportBundleSources.readState(alias))
            assertTrue(Files.isSymbolicLink(alias.toPath()))
            assertTrue(alias.delete())
        } finally { file.delete(); directory.delete() }
    }
}
