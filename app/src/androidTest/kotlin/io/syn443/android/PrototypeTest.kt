package io.syn443.android

import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import org.junit.Rule
import org.junit.Test

class PrototypeTest {
    @get:Rule val compose = createAndroidComposeRule<MainActivity>()

    @Test fun selectionAndStaleNetworkResult() {
        compose.onNodeWithTag("prototype").assertTextContains("VPN ещё не подключается.", substring = true)
        compose.onNodeWithTag("state").assertTextEquals("Остановлено")
        compose.onNodeWithTag("start").performClick()
        compose.onNodeWithTag("apply").performClick()
        compose.onNodeWithTag("outcome").assertTextEquals("Выбран тестовый маршрут: stable")
        compose.onNodeWithTag("network").performClick()
        compose.onNodeWithTag("apply").performClick()
        compose.onNodeWithTag("outcome").assertTextEquals("Устаревший результат отклонён")
        compose.onNodeWithTag("start").performClick()
        compose.onNodeWithTag("apply").performClick()
        compose.onNodeWithTag("outcome").assertTextEquals("Выбран тестовый маршрут: stable")
    }

    @Test fun explicitStopRejectsLateCompletion() {
        compose.onNodeWithTag("start").performClick()
        compose.onNodeWithTag("stop").performClick()
        compose.onNodeWithTag("apply").performClick()
        compose.onNodeWithTag("state").assertTextEquals("Остановлено")
        compose.onNodeWithTag("outcome").assertTextEquals("Устаревший результат отклонён")
    }
}

