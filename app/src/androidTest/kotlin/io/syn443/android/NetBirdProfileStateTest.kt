package io.syn443.android

import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.test.assertTextContains
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import io.syn443.android.support.EffectiveConfig
import io.syn443.android.support.ReadyConfig
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
}
