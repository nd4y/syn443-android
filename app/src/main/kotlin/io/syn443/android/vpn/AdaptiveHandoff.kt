package io.syn443.android.vpn

import io.syn443.decision.AdaptiveProbeBudget
import io.syn443.decision.Decision
import org.json.JSONObject

/** Private APP-to-host envelope only. Its deadline admits no route, proof or
 * native receipt; the native command and all native ownership guards stay intact. */
internal object AdaptiveHandoff {
    const val DEADLINE = "admissionUntilElapsedMs"
    private val scope = Regex("[a-f0-9]{64}")

    data class Rejection(val request: String, val nativeEpoch: Long, val scope: String) {
        override fun toString() = "AdaptiveHandoff.Rejection([redacted])"
    }

    fun frame(command: JSONObject, latestStartMs: Long): String {
        val result = JSONObject().put("kind", "adaptive").put("commandJson", command.toString())
        if (command.opt("command") as? String == "start") {
            require(latestStartMs in 1..Decision.MAX_TIME)
            result.put(DEADLINE, latestStartMs)
        }
        return result.toString()
    }

    /** Rechecked by the actual host worker, after its queue/GC/suspend delay.
     * A legacy two-key frame cannot start a newly budgeted native operation. */
    fun allowed(envelope: JSONObject, now: Long): Boolean {
        if (envelope.keys().asSequence().toSet() != setOf("kind", "commandJson", DEADLINE) ||
            envelope.opt("kind") as? String != "adaptive") return false
        val command = envelope.opt("commandJson") as? String ?: return false
        if (command.length !in 1..4096) return false
        return withinDeadline(envelope, now)
    }

    fun withinDeadline(envelope: JSONObject, now: Long): Boolean {
        val latest = integer(envelope.opt(DEADLINE)) ?: return false
        return now in 0..latest && latest - now <= AdaptiveProbeBudget.MAX_HANDOFF_MS
    }

    /** Only an unstarted request's opaque matching fields are returned. A
     * rejection is not a route outcome or permission to release a running job. */
    fun rejection(command: JSONObject): String? {
        if (command.opt("command") as? String != "start") return null
        val value = fields(command) ?: return null
        return JSONObject().put("admissionRejected", JSONObject().put("request", value.request)
            .put("nativeEpoch", value.nativeEpoch).put("scope", value.scope)).toString()
    }

    fun parseRejection(envelope: JSONObject): Rejection? {
        if (envelope.keys().asSequence().toSet() != setOf("admissionRejected")) return null
        val value = envelope.opt("admissionRejected") as? JSONObject ?: return null
        if (value.keys().asSequence().toSet() != setOf("request", "nativeEpoch", "scope")) return null
        return fields(value)
    }

    private fun fields(value: JSONObject): Rejection? {
        val request = value.opt("request") as? String ?: return null
        val epoch = integer(value.opt("nativeEpoch")) ?: return null
        val boundScope = value.opt("scope") as? String ?: return null
        if (request.length !in 1..80 || !scope.matches(boundScope)) return null
        return Rejection(request, epoch, boundScope)
    }

    private fun integer(value: Any?): Long? = when (value) {
        is Int -> value.toLong()
        is Long -> value
        else -> null
    }?.takeIf { it in 1..Decision.MAX_TIME }
}
