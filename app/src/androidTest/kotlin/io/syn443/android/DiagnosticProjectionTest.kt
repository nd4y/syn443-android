package io.syn443.android

import io.syn443.android.support.DiagnosticArchive
import io.syn443.android.support.DiagnosticArchive.Name
import io.syn443.android.support.DiagnosticArchive.Reason
import io.syn443.android.support.DiagnosticArchive.State
import io.syn443.android.support.DiagnosticProjection
import io.syn443.android.support.EmbeddedEngineBuilds
import androidx.test.platform.app.InstrumentationRegistry
import java.math.BigInteger
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class DiagnosticProjectionTest {
    private fun stateFixture() = JSONObject().put("phase", "Online").put("reason", "required_https_ok")
        .put("desiredOn", true).put("engineActive", true).put("resumeRequired", false)
        .put("generation", 12).put("networkEpoch", 3L).put("activationGeneration", 4).put("eventSequence", 7)
        .put("events", JSONArray().put(JSONObject().put("phase", "Online").put("code", "required_https_ok")
            .put("at", 1000L).put("elapsed", 900L).put("sequence", 7).put("intentGeneration", 12).put("networkEpoch", 3)))
    private fun overlayFixture() = JSONObject().put("active", true).put("mode", "direct").put("snapshotAgeMs", 5)
        .put("peer_state", JSONObject().put("management_connected", true).put("signal_connected", false)
            .put("peers", JSONArray().put(JSONObject().put("state", "connected"))))
        .put("diagnostics", JSONObject().put("state", "partial").put("stale", false)
            .put("results", JSONArray().put(JSONObject().put("state", "reply"))))
    private fun checksFixture() = JSONObject().put("current", true).put("ageMs", 5)
        .put("lastBatch", JSONObject().put("sampledElapsedMs", 1000).put("intentGeneration", 12)
            .put("networkEpoch", 3).put("activationGeneration", 4)
            .put("checks", JSONArray().put(JSONObject().put("outcome", "PASS"))))
    private fun exitsFixture() = JSONObject().put("schemaVersion", 1).put("state", "available")
        .put("exits", JSONArray().put(JSONObject().put("kind", "native_crash").put("at", 1000).put("status", 11)))
    private fun project(state: JSONObject = stateFixture(), overlay: JSONObject? = overlayFixture(), checks: JSONObject? = checksFixture(),
        exits: JSONObject? = exitsFixture(), versionName: String = "0.9.64-offline-support", versionCode: Int = 64, sdk: Int = 35, engines: EmbeddedEngineBuilds? = null) =
        DiagnosticProjection.project(state, overlay, checks, exits, versionName, versionCode, sdk, engines = engines)
    private fun json(items: List<DiagnosticArchive.Component>, name: Name) = JSONObject(checkNotNull(items.single { it.name == name }.bytes).toString(Charsets.UTF_8))
    private fun eventRows(items: List<DiagnosticArchive.Component>) = checkNotNull(items.single { it.name == Name.EVENTS }.bytes)
        .toString(Charsets.UTF_8).lineSequence().filter { it.isNotEmpty() }.map(::JSONObject).toList()

    @Test fun knownSnapshotsProjectOnlyFixedPublicFields() {
        val items = project()
        assertEquals(Name.entries.toSet(), items.map { it.name }.toSet())
        assertEquals(9, items.size)
        val health = json(items, Name.HEALTH)
        assertEquals("Online", health.getString("phase")); assertEquals("required_https_ok", health.getString("reason"))
        assertTrue(health.getBoolean("desiredOn")); assertTrue(health.getBoolean("engineActive"))
        assertFalse(health.getBoolean("resumeRequired")); assertEquals(12L, health.getLong("generation"))
        val actualPolicy = json(project(stateFixture().put("policy", JSONObject().put("activationGeneration", 4)
            .put("configRevision", "synthetic-private-value"))), Name.HEALTH).getJSONObject("policy")
        assertEquals(setOf("activationGeneration"), actualPolicy.keys().asSequence().toSet())
        assertEquals(4L, actualPolicy.getLong("activationGeneration"))
        assertEquals("0.9.64-offline-support", json(items, Name.VERSIONS).getString("versionName"))
        assertEquals(64, json(items, Name.VERSIONS).getInt("versionCode"))
        assertEquals(35, json(items, Name.VERSIONS).getInt("sdk"))
        assertFalse(json(items, Name.VERSIONS).has("engineBuilds"))
        val assets = InstrumentationRegistry.getInstrumentation().targetContext.assets
        val builds = requireNotNull(EmbeddedEngineBuilds.read(assets))
        val exported = json(project(engines = builds), Name.VERSIONS).getJSONObject("engineBuilds")
        assertEquals(setOf("schemaVersion", "singBoxRevision", "netBirdRevision"), exported.keys().asSequence().toSet())
        assertEquals(builds.singBoxRevision, exported.getString("singBoxRevision"))
        assertEquals(builds.netBirdRevision, exported.getString("netBirdRevision"))
        assertEquals("offline_allowlist_projection", json(items, Name.CAPABILITIES).getString("collection"))
        assertTrue(json(items, Name.CHECKS).getBoolean("current"))
        assertEquals("direct", json(items, Name.OVERLAY).getString("mode"))
        assertEquals(1, eventRows(items).size)
        assertEquals("native_crash", json(items, Name.CRASHES).getJSONArray("exits").getJSONObject(0).getString("kind"))
        for (item in items.filter { it.bytes != null }) {
            assertEquals(State.AVAILABLE, item.state); assertEquals(Reason.PROJECTION_ONLY, item.reason)
        }
        assertFalse(DiagnosticArchive.create(items).manifest.getBoolean("complete"))
    }

    @Test fun directLogResponseAndEveryArchivedEntryOmitPrivateTransportAndCrashText() {
        val marker = "synthetic-log-privacy"
        val metadata = JSONObject().put("serviceName", "$marker-grpc")
            .put("path", "/account/$marker-path").put("url", "https://fixture.example.invalid/$marker-url")
        val source = stateFixture().put("configRevision", "$marker-config")
            .put("effectiveConfig", JSONObject().put("transport", metadata)).put("reason", "$marker-free-text")
            .put("eventSequence", 71L).put("activationGeneration", 8L)
        val rows = JSONArray()
        for (i in 0 until 70) rows.put(JSONObject().put("sequence", i).put("phase", "Online")
            .put("code", if (i == 69) "$marker-code" else "required_https_ok").put("serviceName", metadata))
        source.put("events", rows)
        val crash = exitsFixture()
        crash.getJSONArray("exits").getJSONObject(0).put("description", "$marker-crash").put("trace", metadata)
        val logs = DiagnosticProjection.logs(source)
        assertEquals(setOf("generation", "networkEpoch", "activationGeneration", "eventSequence", "events"), logs.keys().asSequence().toSet())
        val safe = logs.getJSONArray("events")
        assertEquals(64, safe.length())
        assertEquals(6, safe.getJSONObject(0).getInt("sequence"))
        assertEquals("required_https_ok", safe.getJSONObject(0).getString("code"))
        assertEquals("redacted", safe.getJSONObject(63).getString("code"))
        assertFalse(logs.toString().contains(marker))
        val archive = DiagnosticArchive.create(project(source, overlayFixture().put("transport", metadata), checksFixture(), crash))
        val names = mutableSetOf<String>()
        java.util.zip.ZipInputStream(archive.bytes.inputStream()).use { zip ->
            while (true) {
                val entry = zip.nextEntry ?: break
                val contents = zip.readBytes().toString(Charsets.UTF_8)
                assertTrue(names.add(entry.name))
                assertFalse(entry.name, contents.contains(marker))
                if (entry.name == "events.jsonl") {
                    assertEquals(64, contents.lineSequence().count { it.isNotEmpty() })
                    assertTrue(contents.contains("required_https_ok"))
                }
                zip.closeEntry()
            }
        }
        assertTrue(names.containsAll(listOf("manifest.json", "events.jsonl", "crashes.json")))
    }

    @Test fun nestedSecretsLabelsTargetsAndFreeTextNeverReachComponents() {
        val secret = "synthetic-private-value"
        val sensitive = JSONObject().put("password", secret).put("token", secret)
            .put("url", "https://source.example.invalid/private?token=$secret").put("path", "/private/runtime/$secret")
        val trap = object : JSONObject() {
            override fun toString(): String = error("unexpected_source_serialization")
        }
        val source = stateFixture().put("credentials", sensitive).put("effectiveConfig", sensitive)
            .put("configRevision", secret).put("policy", sensitive).put("unknownSubtree", trap)
        source.getJSONArray("events").getJSONObject(0).put("url", secret).put("message", secret).put("policyRevision", secret)
        source.put("routeHealth", JSONObject().put("routes", JSONArray().put(JSONObject().put("state", "working")
            .put("id", secret).put("label", secret).put("target", sensitive).put("measuredPath", JSONArray().put(secret)))))
        val network = overlayFixture().put("last_failure", secret).put("reason", secret).put("private_identity", sensitive)
        network.getJSONObject("peer_state").put("selected_proxy", secret).put("ip", "203.0.113.17").put("fqdn", "node.example.invalid")
            .getJSONArray("peers").getJSONObject(0).put("id", secret).put("fqdn", "node.example.invalid").put("ip", "203.0.113.17")
        network.getJSONObject("diagnostics").getJSONArray("results").getJSONObject(0).put("target", sensitive).put("fqdn", secret)
        val probe = checksFixture().put("target", sensitive)
        probe.getJSONObject("lastBatch").getJSONArray("checks").getJSONObject(0).put("url", secret).put("headers", sensitive)
        val crash = exitsFixture()
        crash.getJSONArray("exits").getJSONObject(0).put("pid", 54321).put("process", secret).put("description", secret).put("trace", sensitive)
        val items = project(source, network, probe, crash)
        val combined = items.mapNotNull { it.bytes?.toString(Charsets.UTF_8) }.joinToString("\n")
        for (forbidden in listOf(secret, "203.0.113.17", "node.example.invalid", "source.example.invalid", "/private/runtime", "54321", "selected_proxy", "configRevision", "measuredPath"))
            assertFalse(forbidden, combined.contains(forbidden))
        assertFalse(combined.contains("unexpected_source_serialization"))
        val captured = combined
        source.put("generation", 999).getJSONArray("events").getJSONObject(0).put("phase", "Off")
        assertEquals(captured, items.mapNotNull { it.bytes?.toString(Charsets.UTF_8) }.joinToString("\n"))
    }

    @Test fun incorrectBooleanAndNumericTypesStayUnknownRatherThanFalseOrZero() {
        val invalid = listOf(true, "12", 12.0, 12.5, JSONObject.NULL, -1L, 9_007_199_254_740_992L,
            Long.MAX_VALUE, BigInteger("9007199254740991"), JSONArray(), JSONObject())
        for (bad in invalid) {
            val source = stateFixture().put("generation", bad).put("networkEpoch", bad).put("phase", 12).put("reason", "synthetic-private-value")
            val value = json(project(source), Name.HEALTH)
            assertFalse(value.has("generation")); assertFalse(value.has("networkEpoch"))
            assertEquals("unknown", value.getString("phase")); assertEquals("unknown", value.getString("reason"))
        }
        for (bad in listOf("true", "false", 0, 1, 1.0, JSONObject.NULL, JSONObject(), JSONArray())) {
            val value = json(project(stateFixture().put("desiredOn", bad).put("engineActive", bad).put("resumeRequired", bad)), Name.HEALTH)
            for (field in listOf("desiredOn", "engineActive", "resumeRequired")) assertFalse(field, value.has(field))
            val probe = json(project(checks = checksFixture().put("current", bad).put("ageMs", "0")), Name.CHECKS)
            assertFalse(probe.has("current")); assertFalse(probe.has("ageMs"))
        }
        val exact = json(project(stateFixture().put("generation", 9_007_199_254_740_991L).put("networkEpoch", 0)), Name.HEALTH)
        assertEquals(9_007_199_254_740_991L, exact.getLong("generation")); assertEquals(0L, exact.getLong("networkEpoch"))
        assertFalse(json(project(stateFixture().put("desiredOn", false)), Name.HEALTH).getBoolean("desiredOn"))
    }

    @Test fun internetDnsProjectionExportsOnlyObservedCategories() {
        val input = checksFixture()
        input.getJSONObject("lastBatch").put("checks",JSONArray()
            .put(JSONObject().put("outcome","FAIL").put("stage","RESOLVE").put("failure","DNS").put("dnsResult","NXDOMAIN"))
            .put(JSONObject().put("outcome","FAIL").put("stage","RESOLVE").put("failure","DNS").put("dnsResult","SERVFAIL"))
            .put(JSONObject().put("outcome","FAIL").put("stage","RESOLVE").put("failure","DNS").put("dnsResult","private.example.invalid"))
            .put(JSONObject().put("outcome","PASS").put("stage","RESOLVE").put("failure","DNS").put("dnsResult","REFUSED")))
        val receipt=json(project(checks=JSONObject().put("internet",input)),Name.CHECKS)
        val counts=receipt.getJSONObject("internet").getJSONObject("lastBatch").getJSONObject("dnsResults")
        assertEquals(2,counts.length())
        assertEquals(1,counts.getInt("NXDOMAIN"))
        assertEquals(1,counts.getInt("SERVFAIL"))
        assertFalse(receipt.toString().contains("private.example.invalid"))
        assertFalse(json(project(checks=checksFixture().put("internet",JSONObject())),Name.CHECKS).has("internet"))
    }

    @Test fun eventsKeepOnlyLast64OrderedAllowlistedRecords() {
        val rows = JSONArray()
        for (index in 0..128) rows.put(JSONObject().put("phase", "Online").put("code", "required_https_ok")
            .put("sequence", index).put("at", index).put("elapsed", index).put("label", "synthetic-private-value"))
        val items = project(stateFixture().put("events", rows))
        val projected = eventRows(items)
        assertEquals(64, projected.size)
        assertEquals((65..128).map { it.toLong() }, projected.map { it.getLong("sequence") })
        assertTrue(projected.all { it.keys().asSequence().toSet() == setOf("phase", "code", "sequence", "at", "elapsed") })
        rows.getJSONObject(65).put("phase", "foreign-phase")
        rows.getJSONObject(66).put("code", "synthetic-private-value").put("sequence", "66")
        rows.put(127, "synthetic-private-value")
        val filtered = eventRows(project(stateFixture().put("events", rows)))
        assertEquals(62, filtered.size)
        assertEquals("redacted", filtered.first().getString("code"))
        assertFalse(filtered.first().has("sequence"))
        assertTrue(filtered.all { it.getString("phase") == "Online" })
        assertEquals(128L, filtered.last().getLong("sequence"))
        assertEquals(0, eventRows(project(stateFixture().put("events", JSONArray()))).size)
    }

    @Test fun routeAndCheckCollectionsExposeCountsWithoutIdentifiers() {
        val routes = JSONArray()
        val probes = JSONArray()
        for (index in 0..128) {
            routes.put(JSONObject().put("state", if (index % 2 == 0) "working" else "failed").put("id", "synthetic-private-value"))
            probes.put(JSONObject().put("outcome", if (index % 2 == 0) "PASS" else "FAIL").put("target", "synthetic-private-value"))
        }
        routes.put(1, JSONObject().put("state", true))
        probes.put(1, JSONObject().put("outcome", "foreign-outcome"))
        val source = stateFixture().put("routeHealth", JSONObject().put("running", true).put("requiredReady", false).put("routes", routes))
        val probe = checksFixture().also { it.getJSONObject("lastBatch").put("checks", probes) }
        val items = project(source, checks = probe)
        val route = json(items, Name.HEALTH).getJSONObject("routeHealth")
        assertTrue(route.getBoolean("running")); assertFalse(route.getBoolean("requiredReady"))
        val count = route.getJSONObject("counts")
        assertEquals(129, count.getInt("reported")); assertEquals(64, count.getInt("inspected")); assertEquals(1, count.getInt("unknown"))
        assertEquals(32, count.getJSONObject("states").getInt("working")); assertEquals(31, count.getJSONObject("states").getInt("failed"))
        val checked = json(items, Name.CHECKS).getJSONObject("lastBatch").getJSONObject("counts")
        assertEquals(129, checked.getInt("reported")); assertEquals(64, checked.getInt("inspected"))
        assertEquals(32, checked.getJSONObject("states").getInt("PASS")); assertEquals(31, checked.getJSONObject("states").getInt("FAIL"))
        assertEquals(1, checked.getInt("unknown"))
        assertFalse(route.toString().contains("synthetic-private-value"))
        assertFalse(checked.toString().contains("target"))
        val unknown = json(project(stateFixture().put("routeHealth", JSONObject().put("routes", "unknown"))), Name.HEALTH)
        assertFalse(unknown.getJSONObject("routeHealth").has("counts"))
    }

    @Test fun overlayProjectionPreservesTypedConnectionsAndKnownModesOnly() {
        val clean = json(project(), Name.OVERLAY)
        assertEquals("direct", clean.getString("mode"))
        assertTrue(clean.getJSONObject("peer_state").getBoolean("management_connected"))
        assertFalse(clean.getJSONObject("peer_state").getBoolean("signal_connected"))
        assertEquals(1, clean.getJSONObject("peer_state").getJSONObject("counts").getJSONObject("states").getInt("connected"))
        assertEquals("partial", clean.getJSONObject("diagnostics").getString("state"))
        assertEquals(1, clean.getJSONObject("diagnostics").getJSONObject("counts").getJSONObject("states").getInt("reply"))
        assertEquals("vless", json(project(overlay = overlayFixture().put("mode", "vless")), Name.OVERLAY).getString("mode"))
        for (bad in listOf("true", 1, JSONObject.NULL, JSONObject())) {
            val input = overlayFixture().put("active", bad).put("mode", bad).put("snapshotAgeMs", "0")
            input.getJSONObject("peer_state").put("management_connected", bad).put("signal_connected", bad)
            val output = json(project(overlay = input), Name.OVERLAY)
            assertFalse(output.has("active")); assertFalse(output.has("mode")); assertFalse(output.has("snapshotAgeMs"))
            assertFalse(output.getJSONObject("peer_state").has("management_connected"))
            assertFalse(output.getJSONObject("peer_state").has("signal_connected"))
        }
        for (marker in listOf(true, "false", 0, JSONObject.NULL)) {
            val input = overlayFixture()
            input.getJSONObject("peer_state").put("connection_unknown", marker).put("metadata_unknown", marker)
            input.getJSONObject("diagnostics").put("metadata_unknown", marker)
            val output = json(project(overlay = input), Name.OVERLAY)
            if (marker == true) {
                val peer = output.getJSONObject("peer_state")
                assertEquals(setOf("connection_unknown", "metadata_unknown"), peer.keys().asSequence().toSet())
                assertTrue(peer.getBoolean("connection_unknown"))
                assertTrue(peer.getBoolean("metadata_unknown"))
            } else {
                assertFalse(output.has("peer_state"))
            }
            assertFalse(output.getJSONObject("diagnostics").has("counts"))
        }
    }

    @Test fun crashesReprojectOnlyClosedKindsTimesAndStatuses() {
        val rows = JSONArray()
        rows.put(JSONObject().put("kind", "native_crash").put("at", 1).put("status", 255).put("pid", 54321))
        rows.put(JSONObject().put("kind", "java_crash").put("at", 2).put("status", 11).put("description", "synthetic-private-value"))
        rows.put(JSONObject().put("kind", "anr").put("at", 3).put("status", "11").put("trace", "synthetic-private-value"))
        rows.put(JSONObject().put("kind", "signal").put("at", 4).put("status", 256))
        rows.put(JSONObject().put("kind", "self_exit").put("at", 5).put("status", 0))
        val output = json(project(exits = JSONObject().put("state", "available").put("exits", rows)), Name.CRASHES).getJSONArray("exits")
        assertEquals(4, output.length()); assertEquals(255, output.getJSONObject(0).getInt("status"))
        for (index in 1..3) assertFalse(output.getJSONObject(index).has("status"))
        assertFalse(output.toString().contains("pid")); assertFalse(output.toString().contains("synthetic-private-value"))
        for (bad in listOf(JSONObject().put("kind", "private-kind").put("at", 1),
            JSONObject().put("kind", "signal").put("at", "1"), JSONObject().put("kind", "signal").put("at", 0),
            JSONObject().put("kind", "signal").put("at", 9_007_199_254_740_992L))) {
            val invalid = json(project(exits = JSONObject().put("state", "available").put("exits", JSONArray().put(bad))), Name.CRASHES)
            assertEquals(0, invalid.getJSONArray("exits").length())
        }
        for (state in listOf("unsupported", "unavailable")) {
            val missing = json(project(exits = JSONObject().put("state", state).put("exits", rows)), Name.CRASHES)
            assertEquals(state, missing.getString("state")); assertFalse(missing.has("exits"))
        }
    }


    @Test fun emptyOrUnknownCheckAndOverlaySourcesAreMissingWhileMeasuredZeroIsAvailable() {
        val noBatch = JSONObject().put("lastBatch", JSONObject.NULL).put("ageMs", JSONObject.NULL)
        val noOverlay = JSONObject().put("phase", "Unknown")
        for ((probe, network) in listOf(
            noBatch to noOverlay,
            JSONObject().put("lastBatch", JSONObject().put("privateTarget", "synthetic")) to
                JSONObject().put("peer_state", JSONObject()).put("diagnostics", JSONObject()),
        )) {
            val items = project(checks = probe, overlay = network)
            for (name in listOf(Name.CHECKS, Name.OVERLAY)) {
                val part = items.single { it.name == name }
                assertEquals(State.MISSING, part.state)
                assertEquals(Reason.UNAVAILABLE, part.reason)
                assertNull(part.bytes)
            }
        }
        val observed = project(checks = JSONObject().put("lastBatch", JSONObject().put("checks", JSONArray())),
            overlay = JSONObject().put("active", false))
        assertEquals(0, json(observed, Name.CHECKS).getJSONObject("lastBatch").getJSONObject("counts").getInt("reported"))
        assertFalse(json(observed, Name.OVERLAY).getBoolean("active"))
    }

    @Test fun unavailableSourcesAndInvalidVersionsRemainExplicitAndBounded() {
        val items = project(JSONObject(), null, null, null)
        for (name in listOf(Name.EFFECTIVE_CONFIG, Name.NATIVE_STACKS, Name.CHECKS, Name.OVERLAY, Name.CRASHES, Name.EVENTS)) {
            val item = items.single { it.name == name }
            assertEquals(State.MISSING, item.state); assertNull(item.bytes)
            assertEquals(if (name == Name.NATIVE_STACKS) Reason.UNSUPPORTED else Reason.UNAVAILABLE, item.reason)
        }
        val health = json(items, Name.HEALTH)
        assertEquals("unknown", health.getString("phase")); assertFalse(health.has("desiredOn")); assertFalse(health.has("generation"))
        for (bad in listOf("", "https://example.invalid/", "../private", "0.9.64\nprivate", "0.9.64-" + "x".repeat(97), "0.9.64-PRIVATE")) {
            val item = project(versionName = bad).single { it.name == Name.VERSIONS }
            assertEquals(State.ERROR, item.state); assertEquals(Reason.INVALID_SOURCE, item.reason); assertNull(item.bytes)
        }
        assertEquals(State.ERROR, project(versionCode = -1).single { it.name == Name.VERSIONS }.state)
        assertEquals(State.ERROR, project(sdk = 0).single { it.name == Name.VERSIONS }.state)
        assertTrue(items.all { (it.bytes?.size ?: 0) <= DiagnosticArchive.MAX_COMPONENT })
        assertTrue(items.sumOf { it.bytes?.size ?: 0 } <= DiagnosticArchive.MAX_TOTAL)
        assertFalse(DiagnosticArchive.create(items).manifest.getBoolean("complete"))
    }
}
