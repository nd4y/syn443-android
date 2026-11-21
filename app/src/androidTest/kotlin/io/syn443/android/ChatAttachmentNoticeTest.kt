package io.syn443.android

import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.test.assertTextEquals
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import io.syn443.android.chat.AttachmentProblem
import io.syn443.android.chat.ChatAttachmentNotice
import org.junit.Rule
import org.junit.Test

class ChatAttachmentNoticeTest {
    @get:Rule val compose = createComposeRule()
    @Test fun composerExplainsLocalStorageFailureAndClearsItForRetry() {
        val problem = mutableStateOf<AttachmentProblem?>(AttachmentProblem.STORAGE_FULL)
        compose.setContent { MaterialTheme { problem.value?.let { ChatAttachmentNotice(it) } } }
        val notice = compose.onNodeWithTag("chat-attachment-problem")
        notice.assertTextEquals("На устройстве не хватает места. Освободите место и добавьте файл ещё раз.")
        compose.runOnIdle { problem.value = AttachmentProblem.UNSUPPORTED_MEDIA }
        notice.assertTextEquals("Не удалось сжать видео. Выберите другой файл или отправьте оригинал до 25 МБ.")
        compose.runOnIdle { problem.value = null }
        notice.assertDoesNotExist()
    }
}
