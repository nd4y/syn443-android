package io.syn443.android.vpn

import android.content.Context
import android.content.SharedPreferences
import io.syn443.decision.FailoverAlgorithm
import io.syn443.identity.Identity
import io.syn443.identity.TechnicalTelemetry
import org.json.JSONObject

/** Consent is keyed to the enrollment's pseudonym, never a username or endpoint. */
internal class TelemetryCapture(context:Context,namespace:String="technical-telemetry-consent-v1") {
    data class Consent(val scope:String,val session:String,val through:Long,val attemptedAt:Long) {
        override fun toString()="TelemetryConsent([redacted])"
    }
    init {require(namespace.matches(Regex("[a-z0-9-]{8,64}")))}
    private val prefs=context.getSharedPreferences(namespace,Context.MODE_PRIVATE)
    // The KTX extension returns Unit even with commit=true. Consent and the
    // durable upload cursor require the actual result of the synchronous write.
    @android.annotation.SuppressLint("UseKtx")
    private fun commit(edit:SharedPreferences.Editor.()->Unit):Boolean=prefs.edit().apply(edit).commit()
    @Synchronized fun consent(scope:String):Consent? {
        if(prefs.getString("scope",null)!=scope)return null
        return Consent(scope,prefs.getString("session",null) ?: return null,prefs.getLong("through",0),prefs.getLong("attempt",0))
    }
    @Synchronized fun enable(scope:String,sequence:Long) {
        require(sequence>=0)
        if(consent(scope)==null)check(commit {
            clear();putString("scope",scope);putString("session",Identity.random());putLong("through",sequence)
        })
    }
    @Synchronized fun disable() {check(commit {clear()})}
    @Synchronized fun recorded(value:Consent,through:Long):Boolean {
        val latest=consent(value.scope) ?: return false
        if(latest.session!=value.session || through<latest.through)return false
        return commit {putLong("through",through)}
    }
    @Synchronized fun attempted(value:Consent,nowMs:Long):Boolean {
        val latest=consent(value.scope) ?: return false
        if(latest.session!=value.session || nowMs<latest.attemptedAt || latest.attemptedAt>0 && nowMs-latest.attemptedAt<300_000)return false
        return commit {putLong("attempt",nowMs)}
    }
    fun sample(state:JSONObject,consent:Consent,build:Int):Pair<List<TechnicalTelemetry.Queued>,Long> {
        val rows=state.optJSONArray("events") ?: return emptyList<TechnicalTelemetry.Queued>() to consent.through
        val output=ArrayList<TechnicalTelemetry.Queued>()
        var through=consent.through
        for(i in 0 until rows.length().coerceAtMost(64)) {
            val row=rows.optJSONObject(i) ?: continue
            val sequence=row.optLong("sequence")
            if(sequence<=through)continue
            through=sequence
            val (kind,code)=when(row.optString("code")) {
                "dns_resolution_failed" -> "probe" to "dns_failure"
                "dns_timeout" -> "probe" to "dns_timeout"
                "tcp_timeout" -> "probe" to "tcp_timeout"
                "tls_timeout" -> "probe" to "tls_timeout"
                "tls_failed" -> "probe" to "tls_failure"
                "transport_eof" -> "probe" to "transport_eof"
                "managed_route_recheck" -> "route" to "reselected"
                "vpn_permission_revoked" -> "vpn" to "permission_revoked"
                else -> when(row.optString("phase")) {
                    "Online" -> "vpn" to "online"
                    "Degraded" -> "vpn" to "degraded"
                    "Recovering" -> "vpn" to "recovering"
                    "NoNetwork" -> "network" to "lost"
                    "Off" -> "vpn" to "off"
                    else -> continue
                }
            }
            val id=Identity.hash(("${consent.session}/$sequence").toByteArray(Charsets.US_ASCII))
            val event=TechnicalTelemetry.Event(id,row.optLong("at"),row.optLong("elapsed",-1),
                row.optLong("networkEpoch",-1),kind,code,"unknown")
            val isRouteSelection=kind=="route" && code=="reselected"
            val policyRevision=if(isRouteSelection)row.optLong("policyRevision").takeIf {it in 1..9_007_199_254_740_991L} ?: 0 else 0
            val algorithmRevision=if(policyRevision>0 &&
                FailoverAlgorithm.fromRevision(row.optString("algorithmRevision"))==FailoverAlgorithm.CONFIRMED)2 else 1
            if(runCatching {event.validate()}.isSuccess)output+=TechnicalTelemetry.Queued(
                TechnicalTelemetry.Key(consent.session,build,policyRevision,algorithmRevision),event)
        }
        return output to through
    }
}
