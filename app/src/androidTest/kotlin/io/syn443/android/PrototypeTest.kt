package io.syn443.android

import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.graphics.toPixelMap
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

class PrototypeTest {
    @get:Rule val compose = createAndroidComposeRule<MainActivity>()

    @OptIn(ExperimentalTestApi::class)
    @Test fun darkThemeByDefault() {
        compose.onNodeWithTag("prototype").assertExists()
        val screen = compose.onRoot().captureToImage().toPixelMap()
        val background = screen[1, screen.height - 2].luminance()
        assertTrue("Default surface is not dark", background < 0.1f)
        val title = compose.onNodeWithText("SYN443").captureToImage().toPixelMap()
        var foreground = 0f
        for (y in 0 until title.height) for (x in 0 until title.width) {
            foreground = maxOf(foreground, title[x, y].luminance())
        }
        assertTrue("Title lacks readable contrast on dark surface", (foreground + 0.05f) / (background + 0.05f) >= 4.5f)
    }

    @Test fun selectionAndStaleNetworkResult() {
        val titleTop = compose.onNodeWithText("SYN443").fetchSemanticsNode().boundsInWindow.top
        val safeTop = compose.runOnIdle {
            checkNotNull(ViewCompat.getRootWindowInsets(compose.activity.window.decorView))
                .getInsets(WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout()).top
        }
        assertTrue("Title overlaps system bars/cutout", titleTop >= safeTop)
        compose.onNodeWithTag("prototype").assertTextContains("тестовые данные", substring = true)
        compose.onNodeWithTag("state").assertTextEquals("Остановлено")
        compose.onNodeWithTag("start").performScrollTo().performClick()
        compose.onNodeWithTag("apply").performScrollTo().performClick()
        compose.onNodeWithTag("outcome").assertTextEquals("Выбран тестовый маршрут: stable")
        compose.onNodeWithTag("network").performScrollTo().performClick()
        compose.onNodeWithTag("apply").performScrollTo().performClick()
        compose.onNodeWithTag("outcome").assertTextEquals("Устаревший результат отклонён")
        compose.onNodeWithTag("start").performScrollTo().performClick()
        compose.onNodeWithTag("apply").performScrollTo().performClick()
        compose.onNodeWithTag("outcome").assertTextEquals("Выбран тестовый маршрут: stable")
    }

    @Test fun explicitStopRejectsLateCompletion() {
        compose.onNodeWithTag("start").performScrollTo().performClick()
        compose.onNodeWithTag("stop").performScrollTo().performClick()
        compose.onNodeWithTag("apply").performScrollTo().performClick()
        compose.onNodeWithTag("state").assertTextEquals("Остановлено")
        compose.onNodeWithTag("outcome").assertTextEquals("Устаревший результат отклонён")
    }
}

