package io.syn443.identity

import io.syn443.policy.Canonical
import io.syn443.policy.Policy
import kotlinx.serialization.Serializable

/** A local activation decision for one exact signed envelope. It grants no runtime permit. */
@Serializable data class DeviceActivationReport(
    val version: Int,
    val policyRevision: Long,
    val envelopeHash: String,
    val activationGeneration: Long,
    val outcome: String,
    val activePolicyRevision: Long
) {
    init {
        require(version == 1 && policyRevision in 1..9_007_199_254_740_991L && activationGeneration in 1..9_007_199_254_740_991L)
        require(envelopeHash.length == 43 && Identity.encode(Policy.decode64(envelopeHash)) == envelopeHash)
        require(when (outcome) {
            "committed", "degraded" -> activePolicyRevision == policyRevision
            "rolled_back" -> activePolicyRevision in 0L until policyRevision
            else -> false
        })
    }
    internal fun body(): String = Canonical.encode(Canonical.json.encodeToJsonElement(serializer(), this))
    override fun toString() = "DeviceActivationReport([redacted])"
}
