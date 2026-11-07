package io.syn443.identity

import io.syn443.policy.Canonical
import java.time.ZoneOffset
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import java.util.Locale
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

object DeviceSubscription {
    const val CLAIM_PATH="/v1/device/sources/claim"
    const val RESULT_PATH="/v1/device/sources/result"
    const val CONDITIONAL_CLAIM_PATH="/v1/device/sources/v2/claim"
    const val CONDITIONAL_RESULT_PATH="/v1/device/sources/v2/result"
    const val MAX_BODY=10*1024*1024
    const val MAX_FRAME=MAX_BODY+88
    private const val METADATA_LIMIT=4096
    const val CONDITIONAL_FRAME=MAX_FRAME+METADATA_LIMIT+8
    private val identifier=Regex("[A-Za-z0-9_-]{43}")
    private val modes=setOf("home_wifi","wifi","cellular_restricted","cellular")
    private val magic=byteArrayOf(0,'S'.code.toByte(),'4'.code.toByte(),'4'.code.toByte(),'3'.code.toByte(),2)
    internal fun resultLimit(path:String):Int?=when(path) {
        RESULT_PATH -> MAX_FRAME
        CONDITIONAL_RESULT_PATH -> CONDITIONAL_FRAME
        else -> null
    }
    internal fun isClaim(path:String)=path==CLAIM_PATH || path==CONDITIONAL_CLAIM_PATH
    private fun etag(value:String):Boolean {
        val tag=value.removePrefix("W/")
        return value.length<=512 && tag.length>=2 && tag.first()=='"' && tag.last()=='"' &&
            tag.substring(1,tag.length-1).all {it.code in 33..126 && it!='"'}
    }
    private fun date(value:String):String? {
        if(value.length !in 1..128 || !value.all {it.code in 32..126})return null
        return runCatching {
            ZonedDateTime.parse(value,DateTimeFormatter.RFC_1123_DATE_TIME).withZoneSameInstant(ZoneOffset.UTC)
                .format(DateTimeFormatter.ofPattern("EEE, dd MMM yyyy HH:mm:ss 'GMT'",Locale.US))
        }.getOrNull()
    }

    @Serializable data class Validators(val etag:String="",val lastModified:String="") {
        override fun toString()="DeviceSubscriptionValidators([redacted])"
        internal fun validate() {
            require(etag.isNotEmpty() || lastModified.isNotEmpty())
            require(etag.isEmpty() || DeviceSubscription.etag(etag))
            require(lastModified.isEmpty() || DeviceSubscription.date(lastModified)!=null)
        }
    }
    @Serializable data class Lease(val jobId:String,val lease:String,val until:Long,val networkModes:List<String>,
        val credential:SubscriptionCredential,val validators:Validators?=null) {
        override fun toString()="DeviceSubscriptionLease([redacted])"
        fun validate() {
            require(identifier.matches(jobId) && identifier.matches(lease) && until in 1L..9_007_199_254_740L)
            require(networkModes.size in 1..4 && networkModes.distinct().size==networkModes.size && modes.containsAll(networkModes))
            validators?.validate()
        }
        private fun prefix()="$jobId\n$lease\n".toByteArray(Charsets.US_ASCII)
        internal fun frame(raw:ByteArray):ByteArray {
            validate();require(raw.size in 1..MAX_BODY)
            return prefix()+raw
        }
        internal fun conditionalFrame(reply:Reply):ByteArray {
            validate()
            val success=reply.status==200 || reply.status==304
            require(reply.status==200 && reply.body.size in 1..MAX_BODY ||
                reply.status==304 && reply.body.isEmpty() && validators!=null ||
                reply.status in setOf(401,403,404,410,429) || reply.status in 500..599)
            val tag=if(success)reply.single("etag")?.takeIf {DeviceSubscription.etag(it)} else null
            val modified=if(success)reply.single("last-modified")?.let {DeviceSubscription.date(it)} else null
            val quota=if(success)reply.single("subscription-userinfo") else null
            require(quota==null || quota.length<=1024 && quota.all {it.code in 32..126})
            val metadata=Canonical.encode(buildJsonObject {
                put("status",reply.status)
                tag?.let {put("etag",it)}
                modified?.let {put("lastModified",it)}
                quota?.let {put("quota",it)}
            }).toByteArray(Charsets.UTF_8)
            try {
                require(metadata.size in 1..METADATA_LIMIT)
                val size=byteArrayOf((metadata.size ushr 8).toByte(),metadata.size.toByte())
                val frame=prefix()+magic+size+metadata
                return if(reply.status==200)frame+reply.body else frame
            } finally {metadata.fill(0)}
        }
    }

    data class Claim(val lease:Lease?,val available:Boolean,val time:TrustedTime,val conditional:Boolean=false) {
        override fun toString()="DeviceSubscriptionClaim([redacted])"
    }
}
