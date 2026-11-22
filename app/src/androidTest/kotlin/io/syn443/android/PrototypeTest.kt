package io.syn443.android

import android.content.Context
import android.content.pm.PackageManager
import android.content.res.Configuration
import android.graphics.Color as AndroidColor
import android.os.Build
import android.view.ContextThemeWrapper
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.graphics.toPixelMap
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

class PrototypeTest {
    @get:Rule val compose = createAndroidComposeRule<MainActivity>()

    @Test fun resourceSnapshotIsExplicitAndVisible() {
        compose.onNodeWithTag("resource-status").assertDoesNotExist()
        compose.onNodeWithTag("vpn-details").performScrollTo().performClick()
        compose.onNodeWithTag("resource-refresh").performScrollTo().performClick()
        compose.waitUntil(10_000) { compose.onAllNodesWithTag("resource-status").fetchSemanticsNodes().isNotEmpty() }
        compose.onNodeWithTag("resource-status").assertTextContains("без фонового сбора", substring = true)
    }

    @Test fun launchWindowUsesTheSameDarkSurfaceInBothSystemModes() {
        val app = compose.activity.applicationContext
        val activities = requireNotNull(app.packageManager
            .getPackageInfo(app.packageName, PackageManager.GET_ACTIVITIES).activities)
        assertTrue(activities.isNotEmpty())
        val attributes = mutableListOf(android.R.attr.windowBackground, android.R.attr.statusBarColor,
            android.R.attr.navigationBarColor)
        if (Build.VERSION.SDK_INT >= 31) attributes += android.R.attr.windowSplashScreenBackground
        for (mode in listOf(Configuration.UI_MODE_NIGHT_NO, Configuration.UI_MODE_NIGHT_YES)) {
            val config = Configuration(app.resources.configuration)
            config.uiMode = (config.uiMode and Configuration.UI_MODE_NIGHT_MASK.inv()) or mode
            val configured = app.createConfigurationContext(config)
            val expected = configured.getColor(R.color.syn443_surface)
            assertEquals(255, AndroidColor.alpha(expected))
            assertTrue(AndroidColor.luminance(expected) < 0.1f)
            for (activity in activities) {
                val window: Context = ContextThemeWrapper(configured, activity.themeResource)
                val colors = window.obtainStyledAttributes(attributes.toIntArray())
                try {
                    for (index in attributes.indices) assertEquals(activity.name, expected, colors.getColor(index, 0))
                } finally {
                    colors.recycle()
                }
                val icons = window.obtainStyledAttributes(intArrayOf(android.R.attr.windowLightStatusBar,
                    android.R.attr.windowLightNavigationBar, android.R.attr.forceDarkAllowed))
                try {
                    for (index in 0 until icons.length()) assertTrue(activity.name, !icons.getBoolean(index, true))
                } finally {
                    icons.recycle()
                }
            }
        }
    }

    @OptIn(ExperimentalTestApi::class)
    @Test fun darkThemeByDefault() {
        compose.onNodeWithTag("prototype").assertDoesNotExist()
        val screen = compose.onRoot().captureToImage()
        // Read the exact same background pixel without copying the whole screen
        // into a second multi-megabyte IntArray on low-memory Android images.
        val rendered = screen.toPixelMap(startX=1,startY=screen.height-2,width=1,height=1)[0,0]
        assertEquals("Rendered home surface differs from the launch window",
            compose.activity.getColor(R.color.syn443_surface), rendered.toArgb())
        val background = rendered.luminance()
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
        compose.onNodeWithTag("developer-tools").performScrollTo().performClick()
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
        compose.onNodeWithTag("developer-tools").performScrollTo().performClick()
        compose.onNodeWithTag("start").performScrollTo().performClick()
        compose.onNodeWithTag("stop").performScrollTo().performClick()
        compose.onNodeWithTag("apply").performScrollTo().performClick()
        compose.onNodeWithTag("state").assertTextEquals("Остановлено")
        compose.onNodeWithTag("outcome").assertTextEquals("Устаревший результат отклонён")
    }

    @Test fun homeShowsVpnBeforeAccountAndKeepsToolsCollapsed() {
        val action = compose.onNode(hasTestTag("vpn-connect") or hasTestTag("vpn-disconnect"))
        val top = action.assertIsDisplayed().fetchSemanticsNode().boundsInWindow.top
        val account = compose.onNodeWithTag("manual-enrollment").fetchSemanticsNode().boundsInWindow.top
        assertTrue("Account action is above the VPN action", top < account)
        compose.onNodeWithTag("routes-title").assertDoesNotExist()
        compose.onNodeWithTag("prototype").assertDoesNotExist()
        compose.onNodeWithTag("vpn-details").performScrollTo().performClick()
        val heading = compose.onNodeWithTag("routes-title")
        compose.waitUntil(8_000) { heading.isDisplayed() }
        heading.assertIsDisplayed()
        compose.onNodeWithTag("vpn-details").performScrollTo().performClick()
        heading.assertDoesNotExist()
        compose.activityRule.scenario.recreate()
        heading.assertDoesNotExist()
    }
}

