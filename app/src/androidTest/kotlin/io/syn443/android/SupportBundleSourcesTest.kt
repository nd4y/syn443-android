package io.syn443.android

import io.syn443.android.support.EffectiveConfig
import io.syn443.android.support.ReadyConfig
import io.syn443.android.vpn.EngineConfig
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

    @Test fun offlineArchiveContainsOnlyCurrentPhysicalFactsAndTypedPortalReason() {
        val owner = state().put("reason", "captive_portal")
        // A persisted field cannot stand in for a current service observation.
        owner.put("physicalLink", JSONObject().put("transport", "WIFI").put("homeProof", "verified"))
        fun exported(link: JSONObject?, replaced: Boolean = false): JSONObject? {
            var reads = 0
            val parts = SupportBundleSources.capture(
                state = { if (++reads == 2 && replaced) state().put("networkEpoch", 5) else owner },
                overlay = { null }, checks = { null }, exits = { null },
                versionName = "0.9.94", versionCode = 122, sdk = 35, physicalLink = { link },
            )
            val archive = DiagnosticArchive.create(parts)
            java.util.zip.ZipInputStream(archive.bytes.inputStream()).use { input ->
                while (true) {
                    val entry = input.nextEntry ?: break
                    if (entry.name == "health.json") return JSONObject(input.readBytes().toString(Charsets.UTF_8))
                }
            }
            return null
        }
        val noLink = checkNotNull(exported(null))
        assertEquals("captive_portal", noLink.getString("reason"))
        assertFalse(noLink.has("physicalLink"))
        val live = JSONObject().put("transport", "WIFI").put("homeProof", "verified")
            .put("ipv4Address", true).put("ipv4Default", false).put("ipv6Address", "invalid")
            .put("ssid", "fixture-private").put("spkiSha256", "fixture-private")
        val health = checkNotNull(exported(live)).getJSONObject("physicalLink")
        assertEquals(setOf("transport", "homeProof", "ipv4Address", "ipv4Default"), health.keys().asSequence().toSet())
        assertTrue(health.getBoolean("ipv4Address")); assertFalse(health.getBoolean("ipv4Default"))
        assertEquals("verified", health.getString("homeProof"))
        val other = checkNotNull(exported(live.put("transport", "OTHER"))).getJSONObject("physicalLink")
        assertFalse(other.has("homeProof"))
        assertNull(exported(live, replaced = true))
    }

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


    private fun configPart(state: JSONObject = state(), snapshot: () -> ReadyConfig?) =
        SupportBundleSources.capture({ state }, { null }, { null }, { null }, "0.9.71", 99, 35,
            readyConfig = snapshot).single { it.name == DiagnosticArchive.Name.EFFECTIVE_CONFIG }

    @Test fun readyEngineExportsOnlyAllowlistedCountsAndRenderedDefaults() {
        val raw = """{"outbounds":[{"type":"http","tag":"synthetic-tag","server":"proxy.example.invalid","server_port":443,"username":"synthetic-user","password":"synthetic-secret"}]}"""
        var ready: ReadyConfig? = null
        EngineConfig.renderObserved(raw, File(".")) { ready = ReadyConfig(7, it) }
        val part = configPart { ready }
        assertEquals(DiagnosticArchive.Reason.PROJECTION_ONLY, part.reason)
        val text = checkNotNull(part.bytes).toString(Charsets.UTF_8)
        val value = JSONObject(text)
        assertEquals(setOf("schemaVersion", "outboundTypes", "routeRuleCount", "dnsServerCount", "adaptiveRouting"),
            value.keys().asSequence().toSet())
        assertEquals(1, value.getJSONObject("outboundTypes").getInt("http"))
        assertEquals(1, value.getInt("routeRuleCount"))
        assertEquals(1, value.getInt("dnsServerCount"))
        assertFalse(value.getBoolean("adaptiveRouting"))
        for (privateValue in listOf("synthetic", "proxy.example.invalid", "physical-dns", "hijack-dns")) assertFalse(text.contains(privateValue))
    }

    @Test fun missingStoppedChangedGenerationAndReplacedEngineOmitConfigBytes() {
        val sanitized = EffectiveConfig.fromRendered(JSONObject("""{"outbounds":[{"type":"private-unrecognized-value"}]}"""))
        val ready = ReadyConfig(7, sanitized)
        val exported = JSONObject(checkNotNull(configPart { ready }.bytes).toString(Charsets.UTF_8))
        assertEquals(setOf("unknown"), exported.getJSONObject("outboundTypes").keys().asSequence().toSet())
        assertFalse(exported.has("dnsServerCount"))
        assertEquals(DiagnosticArchive.State.MISSING, configPart { null }.state)
        for (invalid in listOf(state().put("generation", 8), state().put("generation", "7"),
            state().put("engineActive", false), state().put("desiredOn", false))) {
            val rejected = configPart(invalid) { ready }
            assertEquals(DiagnosticArchive.Reason.INVALID_SOURCE, rejected.reason)
            assertNull(rejected.bytes)
        }
        var reads = 0
        val replaced = configPart { if (reads++ == 0) ready else ReadyConfig(7, sanitized) }
        assertEquals(DiagnosticArchive.State.ERROR, replaced.state)
        assertNull(replaced.bytes)
        assertEquals(2, reads)
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
