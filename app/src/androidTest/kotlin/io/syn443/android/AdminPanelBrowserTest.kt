package io.syn443.android

import android.content.ActivityNotFoundException
import android.content.Context
import android.content.ContextWrapper
import android.content.Intent
import android.os.Bundle
import android.provider.Browser
import androidx.browser.customtabs.CustomTabsIntent
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.syn443.android.vpn.AdminPanelBrowser
import io.syn443.identity.Identity
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Intent/URL contracts only. These tests do not authenticate a browser,
 * manipulate its cookies, open Keycloak or claim live administrative access. */
@RunWith(AndroidJUnit4::class)
class AdminPanelBrowserTest {
    private val origin="https://control.example.invalid"
    private val device=Identity.hash("synthetic-current-admin-device".toByteArray())
    private val toolbar=0xff20242a.toInt()
    private val navigation=0xff101419.toInt()

    @Test fun currentDeviceTargetBuildsDarkTitledCustomTabWithoutCredentialExtras() {
        val url=AdminPanelBrowser.target(origin, device)
        assertEquals("$origin/#device=$device", url)
        val intent=AdminPanelBrowser.customTab(url, toolbar, navigation).intent
        assertEquals(Intent.ACTION_VIEW, intent.action)
        assertEquals(url, intent.dataString)
        assertEquals("device=$device", intent.data?.fragment)
        assertNull(intent.data?.query); assertNull(intent.data?.userInfo)
        assertTrue("ordinary browser intent lost Custom Tabs metadata", intent.hasExtra(CustomTabsIntent.EXTRA_SESSION))
        assertEquals(CustomTabsIntent.COLOR_SCHEME_DARK, intent.getIntExtra(CustomTabsIntent.EXTRA_COLOR_SCHEME, -1))
        assertEquals(CustomTabsIntent.SHOW_PAGE_TITLE, intent.getIntExtra(CustomTabsIntent.EXTRA_TITLE_VISIBILITY_STATE, -1))
        assertEquals(toolbar, intent.getIntExtra(CustomTabsIntent.EXTRA_TOOLBAR_COLOR, 0))
        assertEquals(navigation, intent.getIntExtra(CustomTabsIntent.EXTRA_NAVIGATION_BAR_COLOR, 0))
        assertFalse(intent.getBooleanExtra(CustomTabsIntent.EXTRA_ENABLE_URLBAR_HIDING, false))
        assertFalse(intent.hasExtra(Browser.EXTRA_HEADERS))
        assertNull(intent.component); assertNull(intent.`package`)
        assertEquals(0, intent.flags and Intent.FLAG_ACTIVITY_NEW_TASK)
        assertEquals("https://control.example.invalid:8443/#device=$device",
            AdminPanelBrowser.target("https://control.example.invalid:8443", device))
    }

    @Test fun malformedOriginAndNoncanonicalDeviceCannotBecomeNavigationTarget() {
        for(bad in listOf("http://control.example.invalid", "syn443://control", "javascript:alert(1)",
            "$origin/", "$origin/path", "$origin?foreign=1", "$origin#foreign", "https://user@control.example.invalid",
            "https://CONTROL.example.invalid", "https://control.example.invalid.", "https://control.example.invalid:443",
            "$origin\n", "$origin:bad")) {
            assertThrows("untrusted origin shape accepted", IllegalArgumentException::class.java) {AdminPanelBrowser.target(bad, device)}
        }
        for(bad in listOf("", "device-a", "a".repeat(42), "a".repeat(44), "A".repeat(42)+"B",
            "$device#other", "$device?other=1", "%2F", "устройство", "$device\n")) {
            assertThrows("foreign/malformed device shape accepted", IllegalArgumentException::class.java) {AdminPanelBrowser.target(origin, bad)}
        }
    }

    @Test fun completeTargetRejectsInjectedPathQueryAuthorityAndFragment() {
        val valid=AdminPanelBrowser.target(origin, device)
        for(bad in listOf(origin, "$origin#device=$device", "$origin/path#device=$device", "$origin// #device=$device",
            "$origin/?auth=foreign#device=$device", "$origin/#device=$device&token=foreign", "$origin/#device=$device#other",
            "$origin/#device=${device.dropLast(1)}%41", "$origin/#Device=$device", "$origin/#device=//foreign.example.invalid/",
            "https://user@control.example.invalid/#device=$device", "$origin/#device=$device\n", valid.replace("https:", "http:"))) {
            assertThrows("noncanonical complete target accepted", IllegalArgumentException::class.java) {
                AdminPanelBrowser.customTab(bad, toolbar, navigation)
            }
        }
    }

    @Test fun unavailableBrowserFailsOneExactCustomTabLaunchWithoutAuthorityFallback() {
        val application=ApplicationProvider.getApplicationContext<Context>()
        val attempts=mutableListOf<Intent>()
        val unavailable=object:ContextWrapper(application) {
            override fun startActivity(intent: Intent) {attempts+=intent; throw ActivityNotFoundException("synthetic_browser_unavailable")}
            override fun startActivity(intent: Intent, options: Bundle?) {startActivity(intent)}
        }
        val target=AdminPanelBrowser.target(origin, device)
        assertThrows(ActivityNotFoundException::class.java) {AdminPanelBrowser.open(unavailable, target, toolbar, navigation)}
        assertEquals(1, attempts.size)
        assertEquals(target, attempts.single().dataString)
        assertTrue(attempts.single().hasExtra(CustomTabsIntent.EXTRA_SESSION))
        assertFalse(attempts.single().hasExtra(Browser.EXTRA_HEADERS))
    }
}
