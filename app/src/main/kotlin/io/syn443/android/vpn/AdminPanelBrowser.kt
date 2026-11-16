package io.syn443.android.vpn

import android.content.Context
import androidx.browser.customtabs.CustomTabColorSchemeParams
import androidx.browser.customtabs.CustomTabsIntent
import androidx.core.net.toUri
import io.syn443.identity.Identity
import io.syn443.policy.Policy
import java.net.URI

/** Navigation only. The caller must supply the current generation-fenced,
 * trusted bootstrap origin and device. The browser owns its independent BFF
 * session, Keycloak login and MFA; no VPN credential becomes browser authority. */
internal object AdminPanelBrowser {
    private val deviceDigest=Regex("[A-Za-z0-9_-]{43}")
    private const val prefix="device="
    private const val maxTarget=2048+2+7+43

    fun target(origin: String, device: String): String {
        try {Identity.controlOrigin(origin)} catch(_: Exception) {throw IllegalArgumentException("invalid_admin_origin")}
        require(deviceDigest.matches(device) && Policy.decode64(device).size==32)
        return "$origin/#$prefix$device"
    }

    /** This checks the complete canonical navigation shape, not a new origin
     * trust decision. Only LoginController's same-UID result supplies this URL. */
    private fun checkedTarget(raw: String): String {
        require(raw.length in 1..maxTarget && raw.all {it.code in 33..126})
        val uri=try {URI(raw)} catch(_: Exception) {throw IllegalArgumentException("invalid_admin_target")}
        require(uri.rawPath=="/" && uri.rawQuery==null && !uri.rawFragment.isNullOrEmpty() && uri.rawFragment==uri.fragment)
        val fragment=checkNotNull(uri.rawFragment)
        require(fragment.startsWith(prefix))
        val device=fragment.removePrefix(prefix)
        val origin="${uri.scheme}://${uri.rawAuthority}"
        require(raw==target(origin, device))
        return raw
    }

    fun customTab(raw: String, toolbarColor: Int, navigationColor: Int): CustomTabsIntent {
        val target=checkedTarget(raw)
        val colors=CustomTabColorSchemeParams.Builder().setToolbarColor(toolbarColor)
            .setNavigationBarColor(navigationColor).build()
        return CustomTabsIntent.Builder().setColorScheme(CustomTabsIntent.COLOR_SCHEME_DARK)
            .setDefaultColorSchemeParams(colors).setShowTitle(true).build().also {it.intent.data=target.toUri()}
    }

    /** A missing browser propagates the ordinary finite UI launch error. There
     * is no WebView, alternate authority, injected header or credential path. */
    fun open(context: Context, raw: String, toolbarColor: Int, navigationColor: Int) {
        val tab=customTab(raw, toolbarColor, navigationColor)
        tab.launchUrl(context, checkNotNull(tab.intent.data))
    }
}
