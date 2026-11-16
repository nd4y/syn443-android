package io.syn443.android

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.foundation.layout.Column
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createComposeRule
import io.syn443.android.vpn.AdminEntryControls
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test

class AdminEntryControlsTest {
    @get:Rule val compose=createComposeRule()

    @Test fun separateAdminAccountDoesNotRequireWebGrantAndStaysCollapsedByDefault() {
        var opened=0
        compose.setContent {MaterialTheme(colorScheme=darkColorScheme()) {Column {
            AdminEntryControls(provisioned=true,mainAccess=false,busy=false) {opened++}
        }}}
        compose.onNodeWithTag("auth-admin-panel").assertDoesNotExist()
        compose.onNodeWithTag("auth-separate-admin-login").assertDoesNotExist()
        compose.onNodeWithTag("auth-additional-options").performClick()
        compose.onNodeWithTag("auth-separate-admin-login").assertIsDisplayed().performClick()
        compose.runOnIdle {assertEquals(1,opened)}
        compose.onNodeWithTag("auth-admin-panel").assertDoesNotExist()
    }

    @Test fun currentWebGrantShowsHomeShortcutAndUnprovisionedAccountCannotOfferSeparateLogin() {
        var opened=0
        compose.setContent {MaterialTheme(colorScheme=darkColorScheme()) {Column {
            AdminEntryControls(provisioned=false,mainAccess=true,busy=false) {opened++}
        }}}
        compose.onNodeWithTag("auth-admin-panel").assertIsDisplayed().performClick()
        compose.onNodeWithTag("auth-additional-options").assertDoesNotExist()
        compose.onNodeWithTag("auth-separate-admin-login").assertDoesNotExist()
        compose.runOnIdle {assertEquals(1,opened)}
    }
}
