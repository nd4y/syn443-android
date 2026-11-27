package io.syn443.android

import androidx.compose.foundation.layout.Column
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.assertTextEquals
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import io.syn443.android.vpn.LifecycleAccess
import io.syn443.android.vpn.VpnHomeStatus
import io.syn443.android.vpn.VpnPrimaryAction
import io.syn443.android.vpn.VpnSnapshotDiagnostics
import io.syn443.android.vpn.VpnStatusSummary
import io.syn443.android.vpn.hasBlockedAccountPolicy
import io.syn443.android.vpn.vpnStatusLabel
import io.syn443.android.vpn.vpnTileIntent
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

class VpnPrimaryActionTest {
    @get:Rule val compose = createComposeRule()

    @Test fun statusRequiresCurrentEngineProofAndKeepsUnrecognizedIntentVisible() {
        val status = mutableStateOf(JSONObject())
        val available = mutableStateOf<Boolean?>(null)
        val policyBlocked = mutableStateOf(false)
        compose.setContent { MaterialTheme { VpnStatusSummary(status.value, available.value, policyBlocked.value) } }
        val label = compose.onNodeWithTag("vpn-status")
        fun expect(phase: String, desired: Boolean?, known: Boolean, active: Boolean, text: String) {
            compose.runOnIdle {
                available.value = true
                status.value = JSONObject().put("phase", phase).put("desiredOn", desired ?: JSONObject.NULL)
                    .put("engineStateKnown", known).put("engineActive", active)
            }
            label.assertTextEquals(text)
        }
        val checking = "Проверяем состояние VPN"
        label.assertTextEquals(checking)
        expect("Online", true, true, true, "Работает")
        expect("Online", true, false, true, checking)
        expect("Degraded", true, false, false, checking)
        expect("Degraded", true, true, true, "Частично работает")
        expect("Connecting", true, true, false, "Подключаемся")
        expect("BlockedByPolicy", true, false, false, "Доступ ограничен политикой")
        expect("Future", true, true, false, checking)
        expect("Off", true, true, false, checking)
        expect("NeedsUnlock", null, false, false, "Нужно разблокировать телефон")
        expect("Online", false, true, true, "Останавливаем VPN")
        expect("Off", false, false, false, checking)
        expect("", false, true, false, "Отключён")
        compose.runOnIdle { policyBlocked.value = true }
        label.assertTextEquals("Ожидаем конфигурацию от сервера")
        compose.runOnIdle { available.value = false }
        label.assertTextEquals("Состояние VPN временно недоступно")
    }

    @Test fun tileDistinguishesPortalLoginAndUnknownIntentWithoutACommandGuess() {
        val status = JSONObject().put("phase", "NoNetwork").put("desiredOn", true)
            .put("engineStateKnown", true).put("engineActive", true).put("reason", "captive_portal")
        fun expect(text: String) = assertEquals(text, vpnStatusLabel(status, true, status.hasBlockedAccountPolicy()))
        expect("Войдите в сеть Wi-Fi")
        assertEquals(true, vpnTileIntent(status))
        status.put("reason", "network_unavailable")
        expect("Ожидание сети")
        status.put("phase", "NeedsLogin")
        expect("Требуется вход в аккаунт")
        status.put("phase", "NeedsUnlock")
        expect("Нужно разблокировать телефон")
        assertNull(vpnTileIntent(status))
        status.put("phase", "Off").put("desiredOn", false).put("engineActive", false)
            .put("policy", JSONObject().put("source", "account").put("phase", "blocked"))
        assertEquals(false, vpnTileIntent(status))
        expect("Ожидаем конфигурацию от сервера")
        status.put("desiredOn", "false")
        assertNull(vpnTileIntent(status))
        assertNull(vpnTileIntent(null))
        expect("Проверяем состояние VPN")
        assertEquals("Состояние VPN временно недоступно", vpnStatusLabel(JSONObject(), false, false))
    }

    @Test fun diagnosticsHideCachedResultsAndActionsUntilTheControllerRecovers() {
        fun snapshot(generation: Int, routeState: String, policyPhase: String): JSONObject {
            val route = JSONObject().put("id", "synthetic-route").put("label", "Fixture").put("type", "direct")
                .put("configured", true).put("required", false).put("state", routeState).put("reason", "ok")
            return JSONObject().put("generation", generation).put("desiredOn", true).put("engineActive", true)
                .put("routeHealth", JSONObject().put("routes", JSONArray().put(route)))
                .put("policy", JSONObject().put("managed", true).put("source", "account").put("phase", policyPhase))
        }
        val model = mutableStateOf(VpnHomeStatus())
        val old = snapshot(1, "working", "active")
        compose.setContent {
            MaterialTheme {
                Column {
                    VpnPrimaryAction(model.value.status.opt("desiredOn") as? Boolean, model.value.available == true,
                        { error("No Connect was requested") }, { error("No Stop was requested") })
                    VpnSnapshotDiagnostics(model.value.status, model.value.available) { _, _ ->
                        error("No diagnostic command was requested")
                    }
                }
            }
        }
        val unknown = compose.onNodeWithTag("vpn-diagnostics-unknown")
        val route = compose.onNodeWithTag("route-1-state")
        val check = compose.onNodeWithTag("routes-check")
        val policy = compose.onNodeWithTag("policy-status")
        val stop = compose.onNodeWithTag("vpn-disconnect")
        unknown.assertTextEquals("Проверяем доступность диагностики")
        route.assertDoesNotExist()

        compose.runOnIdle { model.value = model.value.afterPoll(old) }
        route.assertTextEquals("Проверка назначенной цели успешна")
        check.assertIsEnabled()
        policy.assertTextEquals("Политика: active")

        compose.runOnIdle { model.value = model.value.awaitingPoll() }
        unknown.assertTextEquals("Проверяем доступность диагностики")
        route.assertDoesNotExist()
        stop.assertIsEnabled()

        compose.runOnIdle { model.value = model.value.afterPoll(null) }
        unknown.assertTextEquals("Текущая диагностика VPN недоступна")
        route.assertDoesNotExist()
        check.assertDoesNotExist()
        policy.assertDoesNotExist()
        stop.assertIsEnabled()
        compose.onNodeWithTag("vpn-system-settings").assertIsEnabled()

        compose.runOnIdle {
            model.value = model.value.afterPoll(old)
            // The command acknowledgement itself may include old diagnostic fields.
            val ack = JSONObject(old.toString()).put("generation", 2)
            model.value = model.value.afterIntent(ack)
            assertFalse(model.value.status.has("routeHealth"))
            assertFalse(model.value.status.has("engineActive"))
        }
        unknown.assertTextEquals("Проверяем доступность диагностики")
        route.assertDoesNotExist()
        stop.assertIsEnabled()

        compose.runOnIdle { model.value = model.value.afterPoll(old) }
        unknown.assertTextEquals("Текущая диагностика VPN недоступна")
        route.assertDoesNotExist()
        stop.assertIsEnabled()

        compose.runOnIdle { model.value = model.value.afterPoll(snapshot(2, "stale", "refreshing")) }
        unknown.assertDoesNotExist()
        route.assertTextEquals("Результат устарел")
        check.assertIsEnabled()
        policy.assertTextEquals("Политика: refreshing")

        compose.runOnIdle {
            model.value = model.value.afterIntent(JSONObject().put("generation", 3).put("desiredOn", false))
        }
        stop.assertDoesNotExist()
        compose.onNodeWithTag("vpn-connect").assertIsNotEnabled()
        unknown.assertTextEquals("Проверяем доступность диагностики")
        route.assertDoesNotExist()
    }

    @Test fun statusAcceptsOnlyTypedCurrentGenerationsOrExplicitLockedBoot() {
        val initial = JSONObject().put("generation", 0).put("desiredOn", false)
        assertEquals(true, VpnHomeStatus().afterPoll(initial).available)
        val active = JSONObject().put("phase", "Online").put("generation", 3).put("desiredOn", true)
        val state = VpnHomeStatus().afterPoll(active)
        for (bad in listOf(null, JSONObject.NULL, -1, 2, "3", 3.0, true)) {
            val reply = JSONObject(active.toString()).put("generation", bad)
            val rejected = state.afterPoll(reply)
            assertEquals(false, rejected.available)
            assertSame(active, rejected.status)
            assertSame(state, state.afterIntent(reply))
        }
        for (missing in listOf("generation", "desiredOn", "desiredOnKnown", "reason")) {
            val malformed = LifecycleAccess.lockedStatus().apply { remove(missing) }
            assertEquals(false, state.afterPoll(malformed).available)
        }
        val locked = state.afterPoll(LifecycleAccess.lockedStatus())
        assertEquals(true, locked.available)
        assertEquals("Нужно разблокировать телефон", vpnStatusLabel(locked.status, locked.available, false))
        assertNull(vpnTileIntent(locked.status))
        assertEquals(false, locked.afterPoll(JSONObject(active.toString()).put("generation", 2L)).available)
        val unlocked = locked.afterPoll(JSONObject(active.toString()).put("generation", Int.MAX_VALUE.toLong() + 1))
        assertEquals(true, unlocked.available)
        assertTrue(unlocked.status.getBoolean("desiredOn"))
    }

    @Test fun startRequiresKnownReadyStateAndStopDoesNotRequireReadiness() {
        val intent = mutableStateOf<Boolean?>(null)
        val ready = mutableStateOf(false)
        val commands = mutableListOf<String>()
        compose.setContent {
            MaterialTheme {
                VpnPrimaryAction(intent.value, ready.value, { commands.add("connect") }, { commands.add("disconnect") })
            }
        }
        val connect = compose.onNodeWithTag("vpn-connect")
        val stop = compose.onNodeWithTag("vpn-disconnect")
        connect.assertIsNotEnabled()
        stop.assertDoesNotExist()
        compose.runOnIdle { intent.value = false }
        connect.assertIsNotEnabled()
        compose.runOnIdle { ready.value = true }
        connect.assertIsEnabled().performClick()
        compose.runOnIdle {
            intent.value = true
            ready.value = false
        }
        connect.assertDoesNotExist()
        stop.assertIsEnabled().performClick()
        compose.runOnIdle { assertEquals(listOf("connect", "disconnect"), commands) }
    }
}
