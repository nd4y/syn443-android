package io.syn443.android

import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import io.syn443.android.vpn.AccountExitControls
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test

class AccountExitControlsTest {
    @get:Rule val ui=createComposeRule()

    @Test fun registeredExitCanBeDismissedAndStaleConfirmationDisappears() {
        val revision=mutableStateOf(8L)
        val visible=mutableStateOf(true)
        val submitted=mutableListOf<Long>()
        ui.setContent {
            val displayed=revision.value
            MaterialTheme {
                AccountExitControls(visible.value,"BROWSER",3L,displayed,true) { submitted.add(displayed) }
            }
        }
        ui.onNodeWithText("Выйти и отвязать устройство").performClick()
        ui.onNodeWithTag("auth-keep-binding").performClick()
        ui.onNodeWithTag("auth-confirm-unlink").assertDoesNotExist()
        ui.onNodeWithTag("auth-cancel").performClick()
        ui.runOnIdle {revision.value=9L}
        ui.onNodeWithTag("auth-confirm-unlink").assertDoesNotExist()
        ui.onNodeWithTag("auth-cancel").performClick()
        ui.runOnIdle {visible.value=false}
        ui.onNodeWithTag("auth-confirm-unlink").assertDoesNotExist()
        ui.runOnIdle {visible.value=true;assertEquals(emptyList<Long>(),submitted)}
        ui.onNodeWithTag("auth-cancel").performClick()
        ui.onNodeWithTag("auth-confirm-unlink").assertIsDisplayed().performClick()
        ui.runOnIdle {assertEquals(listOf(9L),submitted)}
    }

    @Test fun pendingLoginCanBeCancelledAndUnreadableAccountHasNoUnlinkAction() {
        val phase=mutableStateOf("BROWSER")
        var calls=0
        ui.setContent {MaterialTheme {
            AccountExitControls(true,phase.value,1L,2L,false) {calls++}
        }}
        ui.onNodeWithText("Отменить вход").performClick()
        ui.onNodeWithTag("auth-confirm-unlink").assertDoesNotExist()
        for (hidden in listOf("RETIRING","SIGNED_OUT","BLOCKED")) {
            ui.runOnIdle {phase.value=hidden}
            ui.onNodeWithTag("auth-cancel").assertDoesNotExist()
        }
        ui.runOnIdle {assertEquals(1,calls)}
    }
}
