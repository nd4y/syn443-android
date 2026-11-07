package io.syn443.identity

import kotlinx.serialization.Serializable

object DeviceSubscription {
    const val CLAIM_PATH="/v1/device/sources/claim"
    const val RESULT_PATH="/v1/device/sources/result"
    const val MAX_BODY=10*1024*1024
    const val MAX_FRAME=MAX_BODY+88
    private val identifier=Regex("[A-Za-z0-9_-]{43}")
    private val modes=setOf("home_wifi","wifi","cellular_restricted","cellular")

    @Serializable data class Lease(val jobId:String,val lease:String,val until:Long,val networkModes:List<String>,
        val credential:SubscriptionCredential) {
        override fun toString()="DeviceSubscriptionLease([redacted])"
        fun validate() {
            require(identifier.matches(jobId) && identifier.matches(lease) && until in 1L..9_007_199_254_740L)
            require(networkModes.size in 1..4 && networkModes.distinct().size==networkModes.size && modes.containsAll(networkModes))
        }
        internal fun frame(raw:ByteArray):ByteArray {
            validate();require(raw.size in 1..MAX_BODY)
            val prefix="$jobId\n$lease\n".toByteArray(Charsets.US_ASCII)
            return prefix+raw
        }
    }

    data class Claim(val lease:Lease?,val available:Boolean,val time:TrustedTime) {
        override fun toString()="DeviceSubscriptionClaim([redacted])"
    }
}
