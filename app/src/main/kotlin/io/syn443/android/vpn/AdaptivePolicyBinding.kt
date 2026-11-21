package io.syn443.android.vpn

/** Worker-prepared metadata, never a replacement for an assignment permit.
 * Readers must recheck their current ticket, exact envelope, boot and time. */
internal class AdaptivePolicyBinding(
    val revision: Long,
    val contentHash: String,
    val semanticAuthority: String,
    val leaseDeadlineElapsed: Long,
    internal val boot: Int,
    val homeProof: io.syn443.policy.HomeWiFiProof? = null,
) {
    init {
        require(revision in 1..9_007_199_254_740_991L && contentHash.matches(Regex("[a-f0-9]{64}")) &&
            semanticAuthority.matches(Regex("[a-f0-9]{64}")) && leaseDeadlineElapsed>0 && boot>=0)
    }
    override fun toString()="AdaptivePolicyBinding([redacted])"
}
