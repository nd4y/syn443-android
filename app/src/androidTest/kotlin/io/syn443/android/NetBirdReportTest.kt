package io.syn443.android

import io.syn443.android.vpn.NetBirdPresentation
import io.syn443.android.vpn.OverlaySnapshot
import java.time.Instant
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

/** Synthetic bounded reports only; no SDK, identity, provider or network access. */
internal object NetBirdReportFixture {
    const val NOW = 1_800_000_000_000L
    fun overlay(total: Int = 40, retained: Int = minOf(total, 1024), peerPage: Int = 0, diagnosticPage: Int = 0,
        peerRequest: String = "", diagnosticRequest: String = ""): JSONObject {
        fun section(page: Int, request: String, diagnostics: Boolean): JSONObject {
            val shown = minOf(16, maxOf(0, retained - page * 16))
            val rows = JSONArray()
            repeat(shown) { offset ->
                val index = page * 16 + offset
                rows.put(JSONObject().put("fqdn", "synthetic-$index.example.invalid").put("ip", "192.0.2.7")
                    .put("ip_valid", true).put("fqdn_truncated", false)
                    .put("state", if (diagnostics) "reply" else "connected").put("relayed", false).put("rtt_ms", 7))
            }
            val value = JSONObject().put(if (diagnostics) "results" else "peers", rows).put("metadata_unknown", false)
                .put("view", JSONObject().put("page", page).put("page_size", 16).put("total", total)
                    .put("retained", retained).put("shown", shown).put("omitted", total - retained)
                    .put("pages", (retained + 15) / 16).put("request", request))
            if (diagnostics) value.put("state", if (total == retained) "completed" else "partial")
                .put("stale", false).put("coverage", JSONObject().put("total", total).put("planned", retained)
                    .put("checked", retained).put("unprobed", total - retained).put("omitted", total - retained))
            else value.put("active", true).put("mode", "direct").put("selected_proxy", "")
                .put("management_connected", true).put("signal_connected", true)
                .put("sampled_at", Instant.ofEpochMilli(NOW).toString())
            return value
        }
        return JSONObject().put("active", true).put("phase", "Connected").put("mode", "direct")
            .put("snapshotAgeMs", 0).put("peer_state", section(peerPage, peerRequest, false))
            .put("diagnostics", section(diagnosticPage, diagnosticRequest, true))
    }
}

class NetBirdReportTest {
    private fun read(value: JSONObject) = NetBirdPresentation.read(value, NetBirdReportFixture.NOW)

    @Test fun unknownConnectionFieldsNeverBecomeDisconnectedZeroPeersOrVless() {
        val unknown = read(JSONObject())
        assertNull(unknown.active); assertNull(unknown.management); assertNull(unknown.signal)
        assertNull(unknown.peers.reported); assertNull(unknown.peers.view)
        assertEquals("Cloud: н/д; signal: н/д", unknown.connection)
        assertEquals("Способ подключения: неизвестно", unknown.transport)
        assertFalse(unknown.canDiagnose)
        for (bad in listOf("true", 1, JSONObject.NULL, JSONObject())) {
            val value = NetBirdReportFixture.overlay(total = 2)
            value.put("active", bad).put("mode", bad)
            value.getJSONObject("peer_state").put("management_connected", bad).put("signal_connected", bad).put("active", bad)
            val report = read(value)
            assertNull(report.active); assertNull(report.management); assertNull(report.signal)
            assertFalse(report.canDiagnose)
            assertFalse(report.transport.contains("VLESS"))
            assertFalse(report.connection.contains("false"))
        }
        for (unknownMarker in listOf(true, "false", 1, JSONObject.NULL)) {
            val value = NetBirdReportFixture.overlay(total = 2)
            value.getJSONObject("peer_state").put("connection_unknown", unknownMarker)
            val report = read(value)
            assertNull(report.management); assertNull(report.signal)
            assertEquals("Cloud: н/д; signal: н/д", report.connection)
            assertEquals("Подключение напрямую; relay используется как резерв", report.transport)
            assertFalse(report.canDiagnose)
        }
    }

    @Test fun knownAndLegacySnapshotsRetainExplicitConnectionAndProxyLabels() {
        val value = NetBirdReportFixture.overlay(total = 2)
        val direct = read(value)
        assertEquals("Cloud: true; signal: true", direct.connection)
        assertEquals("Подключение напрямую; relay используется как резерв", direct.transport)
        assertTrue(direct.canDiagnose); assertFalse(direct.stale)
        for (message in listOf("connection refused", "tls_failed", "Нет ответа от узла", "я".repeat(256))) {
            value.put("last_failure", message)
            assertEquals(message, read(value).failure)
        }
        value.put("last_failure_truncated", true)
        assertEquals(true, read(value).failureTruncated)
        assertEquals("NetBirdReport([redacted])", read(value).toString())
        value.put("last_failure_truncated", "true")
        assertNull(read(value).failureTruncated)
        value.put("last_failure_truncated", false)
        assertEquals(false, read(value).failureTruncated)
        for (bad in listOf("", "connection\nrefused", "control\u0085value", "x".repeat(513), "я".repeat(257), "\uD800",
            1, true, JSONObject.NULL, JSONObject())) {
            value.put("last_failure", bad)
            assertNull(read(value).failure)
        }
        value.put("last_failure", "connection refused").put("last_failure_truncated", true)
        value.getJSONObject("peer_state").put("connection_unknown", false).put("metadata_unknown", true)
        val boundedFallback = read(value)
        assertEquals("Cloud: true; signal: true", boundedFallback.connection)
        assertNull(boundedFallback.peers.view)
        value.getJSONObject("peer_state").put("metadata_unknown", false)
        value.put("mode", "vless")
        value.getJSONObject("peer_state").put("mode", "vless").put("selected_proxy", "synthetic-egress")
        assertEquals("Через VLESS: synthetic-egress", read(value).transport)
        value.getJSONObject("peer_state").put("management_connected", false)
        assertEquals("Cloud: false; signal: true", read(value).connection)
        value.getJSONObject("peer_state").remove("view")
        value.getJSONObject("diagnostics").remove("view")
        value.getJSONObject("diagnostics").remove("coverage")
        val legacy = read(value)
        assertEquals(2, legacy.peers.rows.size); assertEquals(2, legacy.peers.reported)
        assertNull(legacy.peers.view); assertNull(legacy.coverage)
        assertTrue(legacy.diagnosticLabel.contains("полный охват не подтверждён"))
        assertEquals("NetBirdReport([redacted])", legacy.toString())
        assertEquals("NetBirdRow([redacted])", legacy.peers.rows.first().toString())
    }

    @Test fun pagedPeerCountsDistinguishDisplayedRetainedAndOmittedRows() {
        val report = read(NetBirdReportFixture.overlay(total = 5_000, retained = 1024, peerPage = 63, diagnosticPage = 63))
        val view = checkNotNull(report.peers.view)
        assertEquals(5_000, view.total); assertEquals(1024, view.retained); assertEquals(16, view.shown)
        assertEquals(3976, view.omitted); assertEquals(64, view.pages); assertEquals(63, view.page)
        assertEquals(16, report.peers.rows.size)
        assertEquals("synthetic-1008.example.invalid", report.peers.rows.first().fqdn)
        try { (report.peers.rows as MutableList<*>).clear(); fail("mutable rows") } catch (_: UnsupportedOperationException) { }
        val legacy = NetBirdReportFixture.overlay(total = 0)
        val rows = JSONArray()
        repeat(128) { rows.put(JSONObject().put("fqdn", "legacy-$it.example.invalid").put("state", "connected")) }
        legacy.getJSONObject("peer_state").put("peers", rows).remove("view")
        val bounded = read(legacy)
        assertEquals(16, bounded.peers.rows.size); assertEquals(128, bounded.peers.reported)
        assertNull(bounded.peers.view)
        val empty = checkNotNull(read(NetBirdReportFixture.overlay(total = 0)).peers.view)
        assertEquals(0, empty.total); assertEquals(0, empty.pages); assertEquals(0, empty.shown)
    }

    @Test fun completedPartialCancelledAndUnknownCoverageNeverClaimAllChecked() {
        assertEquals("Завершена", read(NetBirdReportFixture.overlay(total = 2)).diagnosticLabel)
        val value = NetBirdReportFixture.overlay(total = 100, retained = 80)
        val diagnostics = value.getJSONObject("diagnostics")
        diagnostics.getJSONObject("coverage").put("checked", 50).put("unprobed", 50)
        assertEquals("Частичная", read(value).diagnosticLabel)
        assertEquals(50, checkNotNull(read(value).coverage).unprobed)
        for (state in listOf("cancelled", "unavailable", "completed", "unexpected")) {
            diagnostics.put("state", state)
            val report = read(value)
            assertFalse(checkNotNull(report.coverage).complete)
            assertNotEquals("Завершена", report.diagnosticLabel)
        }
        for (bad in listOf("50", 50.0, true, JSONObject.NULL)) {
            diagnostics.getJSONObject("coverage").put("checked", bad)
            assertNull(read(value).coverage)
        }
        diagnostics.put("coverage", JSONObject().put("total", 100).put("planned", 80).put("checked", 50)
            .put("unprobed", 50).put("omitted", 20))
        diagnostics.put("metadata_unknown", true)
        assertNull(read(value).coverage); assertNull(read(value).diagnostics.view)
    }

    @Test fun malformedPagesFieldsUtf8AndOverLimitPayloadsFailBounded() {
        val mutations = listOf<(JSONObject) -> Unit>(
            { it.put("page", 64) }, { it.put("page_size", 17) }, { it.put("pages", 65) },
            { it.put("shown", 17) }, { it.put("retained", 1025) }, { it.put("total", "2") },
            { it.put("total", 2.0) }, { it.put("total", true) }, { it.put("omitted", 1) },
            { it.put("request", "x".repeat(65)) }, { it.put("extra", 1) },
        )
        for (mutate in mutations) {
            val value = NetBirdReportFixture.overlay(total = 2)
            mutate(value.getJSONObject("peer_state").getJSONObject("view"))
            assertNull(read(value).peers.view)
        }
        val value = NetBirdReportFixture.overlay(total = 2)
        val rows = value.getJSONObject("peer_state").getJSONArray("peers")
        rows.put(0, JSONObject.NULL)
        rows.getJSONObject(1).put("fqdn", "я".repeat(48)).put("fqdn_truncated", true)
        assertEquals("неизвестно", read(value).peers.rows.first().state)
        assertEquals("я".repeat(48), read(value).peers.rows[1].fqdn)
        assertTrue(read(value).peers.rows[1].truncated)
        rows.getJSONObject(1).put("fqdn", "я".repeat(49)).put("ip", "x".repeat(65))
        assertNull(read(value).peers.rows[1].fqdn); assertNull(read(value).peers.rows[1].ip)
        value.getJSONObject("peer_state").put("metadata_unknown", "false")
        assertNull(read(value).peers.view)
        try {
            val empty = "{\"pad\":\"\"}"
            val exact = empty.replace("\"\"", "\"" + "a".repeat(65_536 - empty.toByteArray().size) + "\"")
            OverlaySnapshot.update(exact, 1, 1)
            for (raw in listOf(JSONObject().put("pad", "я".repeat(32_768)).toString(), "{", "{\"pad\":\"\uD800\"}")) {
                try { OverlaySnapshot.update(raw, 1, 1); fail("invalid report admitted") }
                catch (_: IllegalArgumentException) { } catch (_: org.json.JSONException) { }
                assertEquals(65_536 - empty.toByteArray().size, OverlaySnapshot.read().getString("pad").length)
            }
        } finally { OverlaySnapshot.clear() }
    }
}
