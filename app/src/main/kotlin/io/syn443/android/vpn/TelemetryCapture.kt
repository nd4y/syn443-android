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
    companion object {
        const val ROUTINE_MS = 300_000L
        const val URGENT_MS = 60_000L

        private fun criticalEvent(code: String) = when (code) {
            "native_disconnected" -> "engine" to "unexpected_exit"
            "policy_rollback" -> "policy" to "rolled_back"
            "vpn_permission_revoked" -> "vpn" to "permission_revoked"
            else -> null
        }

        /** Only inspect the existing, bounded lifecycle ring on an existing supervisor tick. */
        fun hasNewPressure(snapshot: JSONObject, through: Long): Boolean {
            val events = snapshot.optJSONArray("events") ?: return false
            var pending = 0
            for (i in 0 until minOf(events.length(), 64)) {
                val row = events.optJSONObject(i) ?: continue
                if (row.optLong("sequence") <= through) continue
                pending++
                if (criticalEvent(row.optString("code")) != null || pending >= TechnicalTelemetry.MAX_BATCH) return true
            }
            return false
        }

        fun isUrgent(queue: TechnicalTelemetry.Snapshot): Boolean =
            queue.entries.size >= TechnicalTelemetry.MAX_BATCH || queue.entries.any {
                val event = it.event
                (event.kind == "engine" && event.code == "unexpected_exit") ||
                    (event.kind == "policy" && event.code == "rolled_back") ||
                    (event.kind == "vpn" && event.code == "permission_revoked")
            }
    }

    @Synchronized fun routineDelay(value: Consent, nowMs: Long): Long? {
        val latest = consent(value.scope)?.takeIf { it.session == value.session } ?: return null
        if (latest.attemptedAt == 0L) return 0
        return ROUTINE_MS - (nowMs - latest.attemptedAt).coerceIn(0, ROUTINE_MS)
    }

    @Synchronized fun attempted(value: Consent, nowMs: Long, batch: TechnicalTelemetry.Batch, urgent: Boolean): Boolean {
        val latest = consent(value.scope) ?: return false
        if (latest.session != value.session || batch.session != latest.session || nowMs <= 0 || nowMs < latest.attemptedAt) return false
        val first = batch.events.firstOrNull()?.id ?: return false
        // A failed or ambiguously acknowledged batch keeps its ordinary retry interval across restarts.
        val interval = if (urgent && first != prefs.getString("attemptFirst", null)) URGENT_MS else ROUTINE_MS
        if (latest.attemptedAt > 0 && nowMs - latest.attemptedAt < interval) return false
        return commit { putLong("attempt", nowMs); putString("attemptFirst", first) }
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
            val eventCode = row.optString("code")
            val (kind,code)=criticalEvent(eventCode) ?: when(eventCode) {
                "dns_resolution_failed" -> "probe" to "dns_failure"
                "dns_timeout" -> "probe" to "dns_timeout"
                "tcp_timeout" -> "probe" to "tcp_timeout"
                "tls_timeout" -> "probe" to "tls_timeout"
                "tls_failed" -> "probe" to "tls_failure"
                "transport_eof" -> "probe" to "transport_eof"
                "managed_route_recheck", "adaptive_route_reselected" -> "route" to "reselected"
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
            val adaptive = row.optString("code") == "adaptive_route_reselected"
            val rawRevision = row.opt("policyRevision")
            val revision = row.optLong("policyRevision").takeIf {
                it in 1..9_007_199_254_740_991L && (!adaptive || rawRevision is Int || rawRevision is Long)
            }
            val variant = when {
                adaptive && row.optString("algorithmRevision") == io.syn443.policy.Policy.ADAPTIVE_ALGORITHM && build >= 128 -> 3
                !adaptive && kind == "route" && code == "reselected" -> when (FailoverAlgorithm.fromRevision(row.optString("algorithmRevision"))) {
                    FailoverAlgorithm.CONFIRMED -> 2
                    FailoverAlgorithm.BASELINE -> 1
                    null -> null
                }
                else -> null
            }
            val policyRevision = if (variant != null) revision ?: 0 else 0
            val algorithmRevision = if (policyRevision > 0) checkNotNull(variant) else 1
            val mode = when {
                policyRevision == 0L -> "unknown"
                adaptive -> row.optString("networkMode").takeIf { it in setOf("home_wifi","wifi","cellular_restricted","cellular","unknown") } ?: "unknown"
                else -> "wifi"
            }
            val event=TechnicalTelemetry.Event(id,row.optLong("at"),row.optLong("elapsed",-1),
                row.optLong("networkEpoch",-1),kind,code,mode)
            if(runCatching {event.validate()}.isSuccess)output+=TechnicalTelemetry.Queued(
                TechnicalTelemetry.Key(consent.session,build,policyRevision,algorithmRevision),event)
        }
        return output to through
    }
}
