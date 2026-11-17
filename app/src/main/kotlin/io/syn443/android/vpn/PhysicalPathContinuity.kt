package io.syn443.android.vpn

import io.syn443.recovery.PhysicalProbeContext

/** Process-local negative-history hint only. No path data, authority, equality
 * override, serialization or readiness belongs to this identity token. */
internal class PhysicalPathToken internal constructor() {
    override fun toString() = "PhysicalPathToken([redacted])"
}

/** Confined to the live service's ordered physical-network callbacks. A token
 * recognizes only the same observed OS path, never a verified route or peer. */
internal class PhysicalPathContinuity {
    private var observed: PhysicalProbeContext? = null
    var currentToken: PhysicalPathToken? = null
        private set

    fun observe(context: PhysicalProbeContext?): PhysicalPathToken? {
        if (context == null || context.network.handle <= 0 || context.network.captive) {
            clear()
            return null
        }
        val previous = observed
        if (previous == null || previous.network.handle != context.network.handle ||
            previous.linkSignature != context.linkSignature || previous.network.transport != context.network.transport) {
            currentToken = PhysicalPathToken()
        }
        observed = context
        return currentToken
    }

    fun lost(handle: Long) {
        if (observed?.network?.handle == handle) clear()
    }

    private fun clear() {
        observed = null
        currentToken = null
    }

    override fun toString() = "PhysicalPathContinuity([redacted])"
}
