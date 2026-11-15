package io.syn443.identity

import io.syn443.policy.Canonical
import kotlinx.serialization.Serializable

/** Coarse client evidence, never a traffic attestation or an authority renewal. */
object RuntimeObservation {
    const val PATH = "/v1/device/runtime"
    const val MAX_BYTES = 1024
    private const val MAX_INTEGER = 9_007_199_254_740_991L
    @Serializable data class Report(val version:Int, val sequence:Long, val build:Int,
        val phase:String, val policyRevision:Long, val engineKnown:Boolean,
        val engineActive:Boolean, val network:String, val sampledAtMs:Long) {
        fun validate() {
            require(version==1 && sequence in 1..MAX_INTEGER && build in 1..2_100_000_000)
            require(policyRevision in 0..MAX_INTEGER && sampledAtMs in 1..MAX_INTEGER)
            require(engineKnown || !engineActive)
            require(phase in setOf("off","starting","online","recovering","no_network","blocked","unknown"))
            require(phase!="online" || engineKnown && engineActive && policyRevision>0)
            require(phase!="off" || engineKnown && !engineActive)
            require(network in setOf("none","wifi","cellular","unknown"))
        }
        fun body():ByteArray {
            validate()
            return Canonical.encode(Canonical.json.encodeToJsonElement(serializer(),this))
                .toByteArray(Charsets.UTF_8).also {require(it.size<=MAX_BYTES)}
        }
        private fun facts()=copy(sequence=1,sampledAtMs=1)
        internal fun sameFacts(other:Report)=facts()==other.facts()
        override fun toString()="RuntimeObservation([redacted])"
    }
    /** One encrypted pending body and a durable per-key cursor. Session rotation
     * does not reset this cursor. Millisecond server time also bounds recovery
     * after restoring an older queue; the phone wall clock is never consulted. */
    @Serializable data class Snapshot(val version:Int, val scope:String, val cursor:Long, val pending:Report?) {
        fun validate() {
            require(version==1 && scope.matches(Regex("[A-Za-z0-9_-]{43}")) && cursor in 0..MAX_INTEGER)
            pending?.let {it.validate();require(it.sequence==cursor)}
        }
        fun offer(current:String,sample:Report):Snapshot {
            validate();require(current==scope);sample.validate()
            val old=pending
            if(old!=null && old.sameFacts(sample) && sample.sampledAtMs>=old.sampledAtMs &&
                sample.sampledAtMs-old.sampledAtMs<90_000)return this
            val next=maxOf(Math.addExact(cursor,1),sample.sampledAtMs)
            return copy(cursor=next,pending=sample.copy(sequence=next)).also {it.validate()}
        }
        fun acknowledged(current:String,sent:Report):Snapshot {
            validate();require(current==scope && pending==sent)
            return copy(pending=null)
        }
        fun discard(current:String):Snapshot {validate();require(current==scope);return copy(pending=null)}
        override fun toString()="RuntimeObservationQueue([redacted])"
    }
    fun empty(scope:String)=Snapshot(1,scope,0,null).also {it.validate()}
    fun sampleTime(time:TimeWindow):Long {
        require(time.lowerMs>0 && time.upperMs>=time.lowerMs && time.upperMs-time.lowerMs<=50_000)
        return Math.addExact(time.lowerMs,(time.upperMs-time.lowerMs)/2)
    }
}
