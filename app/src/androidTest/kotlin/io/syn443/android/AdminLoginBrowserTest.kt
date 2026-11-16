package io.syn443.android

import android.content.ActivityNotFoundException
import android.content.Context
import android.content.ContextWrapper
import android.content.Intent
import android.os.Bundle
import android.provider.Browser
import androidx.browser.customtabs.CustomTabsIntent
import androidx.test.core.app.ApplicationProvider
import io.syn443.android.admin.AdminLoginBrowser
import io.syn443.android.admin.AdminBrowserLaunch
import io.syn443.identity.AdminBootstrap
import io.syn443.identity.Identity
import org.junit.Assert.*
import org.junit.Test

/** Browser intent/shape only. No real browser, account, cookie or MFA state. */
class AdminLoginBrowserTest {
    private val issuer="https://admin-id.example.invalid/realms/control"
    private val digest=Identity.hash("synthetic-admin-browser-proof".toByteArray())
    private val toolbar=0xff20242a.toInt();private val navigation=0xff101419.toInt()
    private fun parameters()=linkedMapOf("client_id" to AdminBootstrap.CLIENT_ID,"redirect_uri" to AdminBootstrap.CALLBACK,
        "response_type" to "code","scope" to AdminBootstrap.SCOPE,"state" to digest,"nonce" to digest,
        "code_challenge_method" to "S256","code_challenge" to digest,"dpop_jkt" to digest,"acr_values" to AdminBootstrap.ASSURANCE_ACR)
    private fun url()=issuer+"/protocol/openid-connect/auth?"+Identity.form(parameters())

    @Test fun trustedControllerAdminLoginUsesDarkTitledCustomTabWithoutAppHeaders() {
        val raw=url();val intent=AdminLoginBrowser.customTab(raw,toolbar,navigation).intent
        assertEquals(Intent.ACTION_VIEW,intent.action);assertEquals(raw,intent.dataString)
        assertNull(intent.data?.fragment);assertNull(intent.data?.userInfo)
        assertTrue(intent.hasExtra(CustomTabsIntent.EXTRA_SESSION))
        assertEquals(CustomTabsIntent.COLOR_SCHEME_DARK,intent.getIntExtra(CustomTabsIntent.EXTRA_COLOR_SCHEME,-1))
        assertEquals(CustomTabsIntent.SHOW_PAGE_TITLE,intent.getIntExtra(CustomTabsIntent.EXTRA_TITLE_VISIBILITY_STATE,-1))
        assertEquals(toolbar,intent.getIntExtra(CustomTabsIntent.EXTRA_TOOLBAR_COLOR,0))
        assertEquals(navigation,intent.getIntExtra(CustomTabsIntent.EXTRA_NAVIGATION_BAR_COLOR,0))
        assertFalse(intent.hasExtra(Browser.EXTRA_HEADERS))
        assertFalse(intent.getBooleanExtra(CustomTabsIntent.EXTRA_ENABLE_URLBAR_HIDING,false))
        assertNull(intent.component);assertNull(intent.`package`)
    }
    @Test fun unsafeOriginsInjectedFieldsDeviceCallbacksAndWeakProofsNeverBecomeBrowserIntents() {
        val raw=url()
        val invalid=mutableListOf(raw.replace("https:","http:"),raw+"#",raw.replace("https://admin-id","https://user@admin-id"),
            raw.replace("admin-id.example.invalid","ADMIN-ID.example.invalid"),raw.replace(".invalid/",".invalid:443/"),
            raw.replace("/realms/control/","/other/control/"),raw.replace("/realms/control/","/realms/%63ontrol/"),
            raw+"&state=$digest",raw+"&st%61te=$digest",raw+"&access_token=foreign",raw.replace("state=$digest","state=%FF"))
        for((name,value) in listOf("client_id" to "syn443-android","redirect_uri" to "syn443://oauth/callback",
            "scope" to "openid syn443.control offline_access","response_type" to "token","code_challenge_method" to "plain",
            "state" to "x","nonce" to (digest+"="),"code_challenge" to ("A".repeat(42)+"B"),"dpop_jkt" to "foreign",
            "acr_values" to "urn:syn443:loa:1")) {
            invalid+=issuer+"/protocol/openid-connect/auth?"+Identity.form(parameters().apply {put(name,value)})
        }
        invalid+=issuer+"/protocol/openid-connect/auth?"+Identity.form(parameters().apply {remove("nonce")})
        for(target in invalid)assertThrows(Exception::class.java) {AdminLoginBrowser.customTab(target,toolbar,navigation)}
    }
    @Test fun explicitSeparateIssuerIsPreservedWithoutDeviceOrWebPanelFallback() {
        val target=url().replace("https://admin-id.example.invalid","https://separate-control.example.invalid:8443")
        assertEquals(target,AdminLoginBrowser.customTab(target,toolbar,navigation).intent.dataString)
        val prefixed=url().replace("/realms/control/","/auth/custom/realms/control/")
        assertEquals(prefixed,AdminLoginBrowser.customTab(prefixed,toolbar,navigation).intent.dataString)
        val handoff=AdminBrowserLaunch(target,6000)
        assertFalse(handoff.fresh(-1));assertTrue(handoff.fresh(0));assertTrue(handoff.fresh(5999));assertFalse(handoff.fresh(6000))
        assertEquals("AdminBrowserLaunch([redacted])",handoff.toString())
        assertThrows(Exception::class.java) {AdminLoginBrowser.customTab("https://control.example.invalid/#device=$digest",toolbar,navigation)}
        assertThrows(Exception::class.java) {AdminLoginBrowser.customTab(AdminBootstrap.CALLBACK+"?code=foreign",toolbar,navigation)}
    }
    @Test fun unavailableBrowserAttemptsOneExactCustomTabAndDoesNotFallback() {
        val application=ApplicationProvider.getApplicationContext<Context>();val attempts=mutableListOf<Intent>()
        val context=object:ContextWrapper(application) {
            override fun startActivity(intent:Intent) {attempts+=intent;throw ActivityNotFoundException("synthetic_missing_browser")}
            override fun startActivity(intent:Intent,options:Bundle?) {startActivity(intent)}
        }
        assertThrows(ActivityNotFoundException::class.java) {AdminLoginBrowser.open(context,AdminBrowserLaunch(url(),Long.MAX_VALUE),toolbar,navigation)}
        assertEquals(1,attempts.size);assertEquals(url(),attempts.single().dataString)
        assertTrue(attempts.single().hasExtra(CustomTabsIntent.EXTRA_SESSION));assertFalse(attempts.single().hasExtra(Browser.EXTRA_HEADERS))
        val expired=AdminBrowserLaunch(url(),android.os.SystemClock.elapsedRealtime())
        assertThrows(IllegalArgumentException::class.java) {AdminLoginBrowser.open(context,expired,toolbar,navigation)}
        assertEquals("expired original handoff reached startActivity",1,attempts.size)
    }
}
