package io.syn443.android.admin

import android.content.Context
import android.provider.Browser
import android.os.SystemClock
import androidx.browser.customtabs.CustomTabColorSchemeParams
import androidx.browser.customtabs.CustomTabsIntent
import androidx.core.net.toUri
import io.syn443.identity.AdminBootstrap
import io.syn443.identity.Identity
import io.syn443.policy.Policy
import java.io.ByteArrayOutputStream
import java.net.URI

/** Shape validation only. Authority is supplied exclusively by the same-UID
 * controller's current-generation admin-browser response, never by an Intent. */
internal object AdminLoginBrowser {
    private val fields=setOf("client_id","redirect_uri","response_type","scope","state","nonce",
        "code_challenge_method","code_challenge","dpop_jkt","acr_values","max_age")
    private fun decode(raw:String):String {
        val out=ByteArrayOutputStream();var at=0
        while(at<raw.length) {
            val c=raw[at++]
            when(c) {
                '%'->{require(at+2<=raw.length && raw.substring(at,at+2).all {it in "0123456789ABCDEFabcdef"})
                    out.write(raw.substring(at,at+2).toInt(16));at+=2}
                '+'->out.write(32)
                else->{require(c.code in 33..126);out.write(c.code)}
            }
        }
        return Policy.utf8(out.toByteArray()).also {require(it.none(Char::isISOControl))}
    }
    internal fun checked(raw:String):String {
        require(raw.length in 1..8192 && raw.all {it.code in 33..126})
        val uri=URI(raw)
        require(uri.scheme=="https" && uri.rawUserInfo==null && uri.rawFragment==null && !uri.isOpaque)
        Identity.controlOrigin("https://${uri.rawAuthority}")
        Identity.https(raw.substringBefore('?'))
        val endpoint="/protocol/openid-connect/auth"
        require(uri.rawPath==uri.path && uri.path.endsWith(endpoint) &&
            Regex("(?:/[^/]+)*/realms/[^/]+").matches(uri.path.removeSuffix(endpoint)))
        val query=linkedMapOf<String,String>()
        requireNotNull(uri.rawQuery).split('&').forEach {entry->
            require(query.size<11 && '=' in entry)
            val pair=entry.split('=',limit=2);val name=decode(pair[0]);require(name !in query)
            query[name]=decode(pair[1])
        }
        require(query.keys==fields && query["client_id"]==AdminBootstrap.CLIENT_ID &&
            query["redirect_uri"]==AdminBootstrap.CALLBACK && query["response_type"]=="code" &&
            query["scope"]==AdminBootstrap.SCOPE && query["code_challenge_method"]=="S256" &&
            query["acr_values"]==AdminBootstrap.ASSURANCE_ACR && query["max_age"]=="300")
        for(name in listOf("state","nonce","code_challenge","dpop_jkt")) {
            val value=query.getValue(name)
            require(value.matches(Regex("[A-Za-z0-9_-]{43}")) && Policy.decode64(value).size==32)
        }
        return raw
    }
    fun customTab(raw:String,toolbarColor:Int,navigationColor:Int):CustomTabsIntent {
        val target=checked(raw)
        val colors=CustomTabColorSchemeParams.Builder().setToolbarColor(toolbarColor).setNavigationBarColor(navigationColor).build()
        return CustomTabsIntent.Builder().setColorScheme(CustomTabsIntent.COLOR_SCHEME_DARK)
            .setDefaultColorSchemeParams(colors).setShowTitle(true).build().also {
                it.intent.removeExtra(Browser.EXTRA_HEADERS)
                it.intent.data=target.toUri()
            }
    }
    fun open(context:Context,launch:AdminBrowserLaunch,toolbarColor:Int,navigationColor:Int) {
        val tab=customTab(launch.url,toolbarColor,navigationColor)
        require(launch.fresh(SystemClock.elapsedRealtime()))
        tab.launchUrl(context,checkNotNull(tab.intent.data))
    }
}
