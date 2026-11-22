package io.syn443.android

import android.content.ActivityNotFoundException
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import io.syn443.android.vpn.SystemVpnProtection
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test

class SystemVpnProtectionTest {
    @get:Rule val compose = createComposeRule()

    @Test fun systemProtectionsRequireFreshBooleanEvidenceForEachSetting() {
        val policy = mutableStateOf<JSONObject?>(null)
        compose.setContent { SystemVpnProtection(policy.value) {} }
        fun show(value: JSONObject?) = compose.runOnIdle { policy.value = value }
        fun visible(text: String) = compose.onNodeWithText(text, substring = true).assertIsDisplayed()
        visible("Состояние постоянного VPN неизвестно")
        visible("Состояние блокировки соединений без VPN неизвестно")
        show(JSONObject().put("known", false).put("alwaysOn", true).put("lockdown", true))
        visible("Состояние постоянного VPN неизвестно")
        visible("Состояние блокировки соединений без VPN неизвестно")
        for (alwaysOn in listOf(false, true)) {
            for (lockdown in listOf(false, true)) {
                show(JSONObject().put("known", true).put("alwaysOn", alwaysOn).put("lockdown", lockdown))
                visible(if (alwaysOn) "Постоянный VPN включён" else "Постоянный VPN выключен")
                visible(if (lockdown) "Android блокирует соединения" else "Блокировка соединений без VPN выключена")
            }
        }
        show(JSONObject().put("known", true).put("alwaysOn", false).put("lockdown", "false"))
        visible("Постоянный VPN выключен")
        visible("Состояние блокировки соединений без VPN неизвестно")
    }

    @Test fun unavailableSettingsExplainManualAccessAndAllowRetry() {
        var attempts = 0
        compose.setContent {
            SystemVpnProtection(null) {
                attempts++
                when (attempts) {
                    1 -> throw ActivityNotFoundException()
                    2 -> throw SecurityException()
                    else -> Unit
                }
            }
        }
        val button = compose.onNodeWithTag("vpn-system-settings")
        val manual = compose.onNodeWithText("Откройте системные настройки и найдите раздел VPN.")
        repeat(2) { button.performClick(); manual.assertIsDisplayed() }
        button.performClick()
        manual.assertDoesNotExist()
        compose.runOnIdle { assertEquals(3, attempts) }
    }
}
