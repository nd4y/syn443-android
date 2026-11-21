package io.syn443.android

import androidx.compose.foundation.layout.Column
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.input.key.Key
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.text.TextRange
import androidx.compose.ui.text.input.TextFieldValue
import io.syn443.android.chat.ChatComposer
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test

class ChatComposerTest {
    @get:Rule val compose = createComposeRule()

    @Test fun composingChatInputRequiresExplicitSendAfterCommit() {
        val value = mutableStateOf(TextFieldValue("編", TextRange(1), TextRange(0, 1)))
        val sent = mutableListOf<String>()
        compose.setContent {
            MaterialTheme { Column {
                ChatComposer(value.value, { value.value = it }, false, 1, {}, {}, { sent.add(it) })
            } }
        }
        val send = compose.onNodeWithTag("chat-send")
        val field = compose.onNodeWithTag("chat-text")
        send.assertIsNotEnabled()
        field.performClick().performKeyInput { pressKey(Key.Enter) }
        compose.runOnIdle {
            assertEquals(emptyList<String>(), sent)
            value.value = TextFieldValue("\uD800")
        }
        send.assertIsNotEnabled()
        val finalText = "編\n🛰️ \uFFFD"
        field.performTextReplacement(finalText)
        send.assertIsEnabled()
        compose.runOnIdle { assertEquals(emptyList<String>(), sent) }
        send.performClick()
        compose.runOnIdle { assertEquals(listOf(finalText), sent) }
    }
}
