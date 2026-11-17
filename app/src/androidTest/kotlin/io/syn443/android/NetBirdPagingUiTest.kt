package io.syn443.android

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.Modifier
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createComposeRule
import io.syn443.android.vpn.NetBirdControls
import java.util.UUID
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test

/** Pure presentation callbacks; no provider, Binder, SDK or diagnostic work. */
class NetBirdPagingUiTest {
    @get:Rule val compose = createComposeRule()

    @Test fun onlyCurrentViewResponseCompletesPendingPageWithoutExtraCommands() {
        val value = mutableStateOf(NetBirdReportFixture.overlay())
        val commands = mutableListOf<Pair<String, String?>>()
        compose.setContent { MaterialTheme(colorScheme = darkColorScheme()) {
            Column(Modifier.verticalScroll(rememberScrollState())) { NetBirdControls(value.value) { method, arg -> commands += method to arg } }
        } }
        compose.onNodeWithTag("netbird-peers-next").performScrollTo().performClick()
        compose.onNodeWithTag("netbird-peers-next").assertIsNotEnabled()
        lateinit var request: String
        compose.runOnIdle {
            assertEquals(1, commands.size); assertEquals("netbird-view", commands.single().first)
            val frame = JSONObject(checkNotNull(commands.single().second))
            assertEquals(setOf("kind", "section", "page", "request"), frame.keys().asSequence().toSet())
            assertEquals("overlay-view", frame.getString("kind")); assertEquals("peers", frame.getString("section"))
            assertEquals(1, frame.getInt("page"))
            request = frame.getString("request")
            assertEquals(request, UUID.fromString(request).toString())
            value.value = NetBirdReportFixture.overlay(peerPage = 1, peerRequest = "unrelated", diagnosticRequest = request)
        }
        compose.onNodeWithTag("netbird-peers-pending").assertExists()
        compose.onNodeWithTag("netbird-peers-next").assertIsNotEnabled()
        compose.runOnIdle {
            assertEquals(1, commands.size)
            // Roster shrink legitimately clamps requested page1 to actualpage0.
            value.value = NetBirdReportFixture.overlay(total = 3, peerRequest = request)
        }
        compose.onNodeWithTag("netbird-peers-pending").assertDoesNotExist()
        compose.runOnIdle { value.value = NetBirdReportFixture.overlay() }
        compose.onNodeWithTag("netbird-peers-next").performScrollTo().assertIsEnabled()
        compose.mainClock.autoAdvance = false
        compose.onNodeWithTag("netbird-peers-next").performClick()
        compose.mainClock.advanceTimeByFrame()
        compose.onNodeWithTag("netbird-peers-pending").assertExists()
        lateinit var retiredRequest: String
        compose.runOnIdle {
            retiredRequest = JSONObject(checkNotNull(commands.last().second)).getString("request")
            value.value = NetBirdReportFixture.overlay().also {
                it.getJSONObject("peer_state").put("connection_unknown", true)
            } // A replacement owner has no echo of the prior outstanding UUID.
        }
        compose.mainClock.advanceTimeByFrame()
        compose.onNodeWithTag("netbird-connection").assertTextEquals("Cloud: н/д; signal: н/д")
        compose.onNodeWithTag("netbird-diagnose").assertIsNotEnabled()
        compose.onNodeWithTag("netbird-peers-pending").assertExists()
        compose.runOnIdle {
            value.value = NetBirdReportFixture.overlay().also {
                it.getJSONObject("peer_state").put("connection_unknown", false)
            } // A new SDK sample still has no prior request echo.
        }
        compose.mainClock.advanceTimeByFrame()
        compose.onNodeWithTag("netbird-peers-pending").assertExists()
        compose.mainClock.advanceTimeBy(8_100)
        compose.mainClock.advanceTimeByFrame()
        compose.onNodeWithTag("netbird-peers-timeout").assertExists()
        compose.onNodeWithTag("netbird-peers-next").assertIsEnabled()
        compose.runOnIdle { assertEquals(2, commands.size) }
        compose.onNodeWithTag("netbird-peers-next").performClick()
        compose.mainClock.advanceTimeByFrame()
        lateinit var fresh: String
        compose.runOnIdle {
            assertEquals(3, commands.size)
            fresh = JSONObject(checkNotNull(commands.last().second)).getString("request")
            assertNotEquals(retiredRequest, fresh)
            value.value = NetBirdReportFixture.overlay(peerPage = 1, peerRequest = retiredRequest)
        }
        compose.mainClock.advanceTimeByFrame()
        compose.onNodeWithTag("netbird-peers-pending").assertExists()
        compose.runOnIdle {
            value.value = NetBirdReportFixture.overlay(peerPage = 1, peerRequest = fresh).also {
                it.getJSONObject("peer_state").put("connection_unknown", false)
            }
        }
        compose.mainClock.advanceTimeByFrame()
        compose.onNodeWithTag("netbird-peers-pending").assertDoesNotExist()
        compose.runOnIdle { assertEquals(3, commands.size) }
        compose.mainClock.autoAdvance = true
    }

    @Test fun peerAndDiagnosticPagingControlsRespectBoundsAndOutstandingRequests() {
        val value = mutableStateOf(NetBirdReportFixture.overlay(total = 1024))
        val commands = mutableListOf<Pair<String, String?>>()
        compose.setContent { MaterialTheme(colorScheme = darkColorScheme()) {
            Column(Modifier.verticalScroll(rememberScrollState())) { NetBirdControls(value.value) { method, arg -> commands += method to arg } }
        } }
        compose.waitForIdle()
        compose.mainClock.autoAdvance = false
        compose.onNodeWithTag("netbird-peer-16").assertDoesNotExist()
        compose.onNodeWithTag("netbird-result-16").assertDoesNotExist()
        compose.onNodeWithTag("netbird-peers-prev").assertIsNotEnabled()
        compose.onNodeWithTag("netbird-peers-next").performScrollTo().performClick()
        compose.mainClock.advanceTimeByFrame()
        compose.onNodeWithTag("netbird-diagnostics-next").performScrollTo().assertIsEnabled().performClick()
        compose.mainClock.advanceTimeByFrame()
        compose.onNodeWithTag("netbird-peers-next").assertIsNotEnabled()
        compose.onNodeWithTag("netbird-diagnostics-next").assertIsNotEnabled()
        lateinit var peer: String
        lateinit var diagnostic: String
        compose.runOnIdle {
            assertEquals(2, commands.size)
            val first = JSONObject(checkNotNull(commands[0].second))
            val second = JSONObject(checkNotNull(commands[1].second))
            assertEquals("peers", first.getString("section")); assertEquals("diagnostics", second.getString("section"))
            peer = first.getString("request"); diagnostic = second.getString("request")
            assertNotEquals(peer, diagnostic)
            value.value = NetBirdReportFixture.overlay(total = 1024, peerPage = 1, diagnosticPage = 1,
                peerRequest = peer, diagnosticRequest = "unrelated")
        }
        compose.mainClock.advanceTimeByFrame()
        compose.onNodeWithTag("netbird-peers-prev").assertIsEnabled()
        compose.onNodeWithTag("netbird-diagnostics-next").assertIsNotEnabled()
        compose.runOnIdle {
            value.value = NetBirdReportFixture.overlay(total = 1024, peerPage = 63, diagnosticPage = 63,
                diagnosticRequest = diagnostic)
        }
        compose.mainClock.advanceTimeByFrame()
        compose.onNodeWithTag("netbird-peers-next").assertIsNotEnabled()
        compose.onNodeWithTag("netbird-diagnostics-next").assertIsNotEnabled()
        compose.onNodeWithTag("netbird-peers-prev").assertIsEnabled()
        compose.onNodeWithTag("netbird-diagnostics-prev").assertIsEnabled()
        compose.onNodeWithTag("netbird-peer-0").assertTextContains("synthetic-1008.example.invalid", substring = true)
        compose.onNodeWithTag("netbird-result-0").assertTextContains("synthetic-1008.example.invalid", substring = true)
        compose.onNodeWithTag("netbird-diagnose").performScrollTo().performClick()
        compose.mainClock.advanceTimeByFrame()
        compose.onNodeWithTag("netbird-refresh").performScrollTo().performClick()
        compose.mainClock.advanceTimeByFrame()
        compose.runOnIdle {
            assertEquals(listOf("netbird-view", "netbird-view", "netbird-diagnose", "status"), commands.map { it.first })
            value.value = JSONObject().put("active", "true").put("peer_state", JSONObject().put("active", "true"))
        }
        compose.mainClock.advanceTimeByFrame()
        compose.onNodeWithTag("netbird-diagnose").assertIsNotEnabled()
        compose.onNodeWithTag("netbird-connection").assertTextEquals("Cloud: н/д; signal: н/д")
        compose.onNodeWithTag("netbird-transport").assertTextEquals("Способ подключения: неизвестно")
        compose.mainClock.autoAdvance = true
    }
}
