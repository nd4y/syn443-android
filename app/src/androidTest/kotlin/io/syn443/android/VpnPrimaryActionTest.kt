package io.syn443.android

import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import io.syn443.android.vpn.VpnPrimaryAction
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test

class VpnPrimaryActionTest {
    @get:Rule val compose = createComposeRule()

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
