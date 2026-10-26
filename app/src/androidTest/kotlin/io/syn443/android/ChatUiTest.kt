package io.syn443.android

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onAllNodesWithTag
import io.syn443.android.chat.SupportActivity
import org.junit.Rule
import org.junit.Test

class ChatUiTest {
    @get:Rule val compose=createAndroidComposeRule<SupportActivity>()
    @Test fun supportChatHasVisibleTitleAndConnectionStatus() {
        compose.waitUntil(5000) {compose.onAllNodesWithTag("chat-title").fetchSemanticsNodes().isNotEmpty()}
        compose.onNodeWithTag("chat-title").assertIsDisplayed()
        compose.onNodeWithTag("chat-status").assertIsDisplayed()
    }
}
