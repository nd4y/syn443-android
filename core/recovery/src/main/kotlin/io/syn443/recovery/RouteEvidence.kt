package io.syn443.recovery

/** Memory-only scope. No wall-clock timestamps can resurrect earlier evidence. */
data class RouteScope(val intent: Long, val network: Long, val activation: Long, val engine: String, val config: String)
data class RouteObservation(val scope: RouteScope, val elapsedMs: Long, val complete: Boolean, val ok: Boolean)
enum class RouteState { OFF, UNAVAILABLE, UNVERIFIED, CHECKING, WORKING, FAILED, STALE, INCOMPLETE }
enum class RouteActivation { WAIT, READY, FAILED }
object RouteEvidence {
    fun classify(on: Boolean, ownerReady: Boolean, current: RouteScope, result: RouteObservation?,
                 checking: Boolean, now: Long, ttlMs: Long = 120_000): RouteState {
        require(now >= 0 && ttlMs in 1_000..300_000)
        if (!on) return RouteState.OFF
        if (!ownerReady) return RouteState.UNAVAILABLE
        if (result == null || result.scope != current) return if (checking) RouteState.CHECKING else RouteState.UNVERIFIED
        if (result.elapsedMs > now || now - result.elapsedMs > ttlMs) return if (checking) RouteState.CHECKING else RouteState.STALE
        if (!result.complete) return RouteState.INCOMPLETE
        return if (result.ok) RouteState.WORKING else RouteState.FAILED
    }
    fun requiredReady(states: List<Pair<Boolean, RouteState>>) = states.all { !it.first || it.second == RouteState.WORKING }
    /** Optional outages cannot veto activation; required uncertainty never grants a commit. */
    fun activation(states: List<Pair<Boolean, RouteState>>): RouteActivation {
        val required = states.filter { it.first }.map { it.second }
        if (required.any { it == RouteState.FAILED }) return RouteActivation.FAILED
        return if (required.all { it == RouteState.WORKING }) RouteActivation.READY else RouteActivation.WAIT
    }
}
