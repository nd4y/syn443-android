package io.syn443.android

import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.assertTextEquals
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import io.syn443.android.vpn.VpnPrimaryAction
import io.syn443.android.vpn.VpnStatusSummary
import io.syn443.android.vpn.hasBlockedAccountPolicy
import io.syn443.android.vpn.vpnStatusLabel
import io.syn443.android.vpn.vpnTileIntent
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
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
