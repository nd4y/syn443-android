package io.syn443.recovery

enum class PhysicalTransport { WIFI, CELLULAR, OTHER }

data class PhysicalCandidate(
    val handle: Long,
    val transport: PhysicalTransport,
    val validated: Boolean,
    val captive: Boolean,
    val metered: Boolean,
)

data class PhysicalProbeContext(val network: PhysicalCandidate, val linkSignature: String) {
    companion object {
        fun pathChanged(previous: PhysicalProbeContext?, current: PhysicalProbeContext?): Boolean =
            previous?.network?.handle != current?.network?.handle ||
                previous?.linkSignature != current?.linkSignature
    }
}

/** Rank only physical Network capabilities. No home identity or LTE allowlist is inferred. */
object PhysicalNetworkSelection {
    const val MAX_CANDIDATES = 32

    fun choose(candidates: List<PhysicalCandidate>, current: Long?, currentVpnVerified: Boolean): Long? {
        require(candidates.size <= MAX_CANDIDATES)
        return candidates.asSequence().filterNot { it.captive }.minWithOrNull(compareBy<PhysicalCandidate>(
            { if (it.validated || (it.handle == current && currentVpnVerified)) 0 else 1 },
            {
                when {
                    it.transport == PhysicalTransport.WIFI -> 0
                    !it.metered -> 1
                    it.transport == PhysicalTransport.CELLULAR -> 2
                    else -> 3
                }
            },
            { it.handle != current },
            { it.handle },
        ))?.handle
    }
}
