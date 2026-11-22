package io.syn443.android

import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.test.assertTextContains
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import io.syn443.android.support.EffectiveConfig
import io.syn443.android.support.ReadyConfig
import io.syn443.android.vpn.NetBirdConnectionState
import io.syn443.android.vpn.VpnStatusSummary
import java.time.Instant
import io.syn443.android.vpn.NetBirdControls
import io.syn443.android.vpn.OverlaySnapshot
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test

class NetBirdProfileStateTest {
    @get:Rule val compose = createComposeRule()

    @Test fun runningProfileEvidenceRequiresAReadyCurrentOwnerAndSuppressesRetiredRows() {
        fun ready(type: String) = ReadyConfig(8, EffectiveConfig.fromRendered(
            JSONObject("""{"outbounds":[{"type":"$type"}]}""")))
        val direct = ready("direct")
        assertEquals(false, direct.netBirdFor(8, true, true))
        assertEquals(true, ready("netbird").netBirdFor(8, true, true))
        assertNull(direct.netBirdFor(7, true, true))
        assertNull(direct.netBirdFor(8, false, true))
        assertNull(direct.netBirdFor(8, true, false))
        val previous = NetBirdReportFixture.overlay()
        previous.put("active", false)
        val absent = OverlaySnapshot.withProfile(previous, false)
        assertEquals(setOf("phase","active","configuredInRunningProfile"), absent.keys().asSequence().toSet())
        assertEquals(false, absent.getBoolean("configuredInRunningProfile"))
        assertFalse(absent.has("peer_state"))
        val live = NetBirdReportFixture.overlay()
        assertTrue(OverlaySnapshot.withProfile(live, false).isNull("configuredInRunningProfile"))
        assertTrue(live.has("peer_state"))
        assertTrue(OverlaySnapshot.withProfile(JSONObject(), null).isNull("configuredInRunningProfile"))
    }

    @Test fun profileWithoutNetBirdHasOneExplanationAndConfiguredModuleKeepsItsControls() {
        val report = mutableStateOf(OverlaySnapshot.withProfile(JSONObject(), false))
        compose.setContent { NetBirdControls(report.value) { _, _ -> error("unexpected command") } }
        compose.onNodeWithTag("netbird-profile-absent").assertTextContains("В текущей конфигурации VPN нет NetBird")
        for (tag in listOf("netbird-diagnose","netbird-peers-counts","netbird-connection"))
            compose.onNodeWithTag(tag).assertDoesNotExist()

        compose.runOnIdle { report.value = OverlaySnapshot.withProfile(NetBirdReportFixture.overlay(), true) }
        compose.onNodeWithTag("netbird-profile-absent").assertDoesNotExist()
        compose.onNodeWithTag("netbird-diagnose").assertExists()
        compose.onNodeWithTag("netbird-peers-counts").assertExists()
        compose.runOnIdle { report.value = JSONObject().put("phase", "Unknown") }
        compose.onNodeWithTag("netbird-profile-absent").assertDoesNotExist()
        compose.onNodeWithTag("netbird-status").assertExists()
    }

    @Test fun mainConnectionUsesFreshScopedControlChannelsWithoutPromotingPeerResults() {
        val now = NetBirdReportFixture.NOW
        val overlay = NetBirdReportFixture.overlay().put("phase", "Started")
        val peer = overlay.getJSONObject("peer_state").put("connection_unknown", false)
        fun state(age: Long = 0, since: Long = now - 30_000, elapsed: Long = 30_000) =
            NetBirdConnectionState.from(overlay, age, now, since, elapsed)
        assertEquals(NetBirdConnectionState.DIRECT, state())
        peer.put("peers", org.json.JSONArray().put(JSONObject().put("state", "disconnected")))
        overlay.getJSONObject("diagnostics").put("state", "unavailable")
        assertEquals(NetBirdConnectionState.DIRECT, state())
        peer.put("mode", "vless")
        assertEquals(NetBirdConnectionState.CONTROL, state())
        overlay.put("mode", "vless")
        assertEquals(NetBirdConnectionState.VLESS, state())
        peer.put("signal_connected", false)
        assertEquals(NetBirdConnectionState.NO_SIGNAL, state())
        peer.put("management_connected", false)
        assertEquals(NetBirdConnectionState.NO_CONTROL, state())
        peer.put("signal_connected", true)
        assertEquals(NetBirdConnectionState.NO_MANAGEMENT, state())
        peer.put("connection_unknown", true)
        assertEquals(NetBirdConnectionState.UNKNOWN, state())
        peer.put("connection_unknown", false)
        for (sample in listOf(now + 1, now - 25_001, now - 30_000)) {
            peer.put("sampled_at", Instant.ofEpochMilli(sample).toString())
            assertEquals(NetBirdConnectionState.UNKNOWN, state())
        }
        peer.put("sampled_at", Instant.ofEpochMilli(now - 5).toString())
        assertEquals(NetBirdConnectionState.UNKNOWN, state(since = now - 5))
        assertEquals(NetBirdConnectionState.UNKNOWN, state(elapsed = 4))
        assertEquals(NetBirdConnectionState.UNKNOWN, state(age = 25_001))
        assertEquals(NetBirdConnectionState.UNKNOWN, state(age = -1))
        assertEquals(NetBirdConnectionState.NO_MANAGEMENT, state(age = 5, since = now - 6, elapsed = 5))
        overlay.put("phase", "NeedsAction")
        assertEquals(NetBirdConnectionState.NEEDS_ACTION, state())
        overlay.put("phase", "Recovering")
        assertEquals(NetBirdConnectionState.RECOVERING, state())
        overlay.put("phase", "Starting")
        assertEquals(NetBirdConnectionState.STARTING, state())
        overlay.put("phase", "Off").put("active", false)
        assertEquals(NetBirdConnectionState.OFF, state())
    }

    @Test fun statusDoesNotReuseOverlayObservationFromAnotherGenerationOrPhysicalNetwork() {
        val previous = ReadyConfig.current
        try {
            val active = ReadyConfig(8, EffectiveConfig.fromRendered(JSONObject("""{"outbounds":[{"type":"netbird"}]}""")))
            ReadyConfig.publish(active)
            OverlaySnapshot.clear()
            val data = JSONObject().put("active", true).put("phase", "NeedsAction")
            OverlaySnapshot.update(data.toString(), 8, 12)
            fun read(generation: Long, epoch: Long) = OverlaySnapshot.forStatus(generation, epoch, true, true)
            assertEquals("NEEDS_ACTION", read(8, 12).getString("connectionState"))
            assertEquals("UNKNOWN", read(8, 13).getString("connectionState"))
            assertFalse(read(9, 12).has("connectionState"))
            OverlaySnapshot.clear()
            assertEquals("UNKNOWN", read(8, 12).getString("connectionState"))
            OverlaySnapshot.update(data.toString(), 7, 12)
            assertEquals("UNKNOWN", read(8, 12).getString("connectionState"))
            assertFalse(OverlaySnapshot.forStatus(8, 12, false, true).has("connectionState"))
        } finally {
            OverlaySnapshot.clear()
            ReadyConfig.publish(previous)
        }
    }

    @Test fun primaryScreenShowsOverlayLimitationAlongsideRunningVPN() {
        fun status(configured: Boolean?, connection: String) = JSONObject()
            .put("desiredOn", true).put("engineActive", true).put("engineStateKnown", true).put("phase", "Online")
            .put("netbird", JSONObject().put("configuredInRunningProfile", configured ?: JSONObject.NULL)
                .put("connectionState", connection))
        val snapshot = mutableStateOf(status(true, "NO_MANAGEMENT"))
        compose.setContent { VpnStatusSummary(snapshot.value, true, false) }
        val overlay = compose.onNodeWithTag("vpn-netbird-summary")
        compose.onNodeWithTag("vpn-status").assertTextContains("Работает")
        overlay.assertTextContains("NetBird · сервер управления недоступен")
        compose.runOnIdle { snapshot.value = status(true, "VLESS") }
        overlay.assertTextContains("NetBird через VLESS · управление и сигнализация доступны")
        compose.runOnIdle { snapshot.value = status(true, "future-state") }
        overlay.assertTextContains("NetBird · ждём свежие данные")
        compose.runOnIdle { snapshot.value = status(false, "DIRECT") }
        overlay.assertDoesNotExist()
        compose.runOnIdle { snapshot.value = status(null, "DIRECT") }
        overlay.assertDoesNotExist()
        compose.runOnIdle { snapshot.value = status(true, "DIRECT").put("desiredOn", false) }
        overlay.assertDoesNotExist()
        compose.runOnIdle { snapshot.value = status(true, "DIRECT").put("engineStateKnown", false) }
        overlay.assertDoesNotExist()
    }
}
