package io.syn443.android

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.lifecycle.Lifecycle
import io.syn443.android.chat.SupportActivity
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

class ChatUiTest {
    @get:Rule val compose=createAndroidComposeRule<SupportActivity>()
    @Test fun supportChatHasVisibleTitleAndConnectionStatus() {
        assertReady()
    }
    @Test fun supportChatKeepsItsRootAcrossRepeatedRecreation() {
        assertReady()
        repeat(5) {
            compose.activityRule.scenario.recreate()
            assertReady()
        }
    }
    @Test fun supportChatResumesAfterRepeatedBackgroundTransitions() {
        assertReady()
        repeat(5) {
            compose.activityRule.scenario.moveToState(Lifecycle.State.CREATED)
            compose.activityRule.scenario.moveToState(Lifecycle.State.RESUMED)
            assertReady()
        }
    }
    private fun assertReady() {
        compose.activityRule.scenario.onActivity {activity->
            val root=activity.findViewById<android.view.ViewGroup>(android.R.id.content)
            assertTrue("SupportActivity must install its content root during startup",root.childCount>0)
        }
        compose.waitUntil(5000) {compose.onAllNodesWithTag("chat-title").fetchSemanticsNodes().isNotEmpty()}
        compose.onNodeWithTag("chat-title").assertIsDisplayed()
        compose.onNodeWithTag("chat-status").assertIsDisplayed()
    }
}
