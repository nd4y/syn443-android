package io.syn443.identity

import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

object TechnicalTelemetry {
    const val PATH="/v1/device/telemetry"
    const val MAX_BYTES=16_384
    const val MAX_BATCH=32
    const val MAX_QUEUE=128
    private const val MAX_TIME=9_007_199_254_740_991L
    private const val RETRY_WINDOW=7*24*60*60*1000L
    private val opaque=Regex("[A-Za-z0-9_-]{43}")
    private val wire=Json { encodeDefaults=false; explicitNulls=false }
    private val modes=setOf("unknown","home_wifi","wifi","cellular_restricted","cellular")
    private val codes=mapOf(
        "network" to setOf("available","lost","changed","not_validated","captive"),
        "vpn" to setOf("online","degraded","recovering","off","permission_revoked"),
        "probe" to setOf("ok","dns_timeout","dns_failure","tcp_timeout","tls_timeout","tls_failure",
            "transport_eof","target_failure","capacity","cancelled","unknown"),
        "route" to setOf("confirmed_failure","reserve_verified","reselected","quarantined","revalidated"),
        "policy" to setOf("prepared","committed","rolled_back","expired","revoked"),
        "engine" to setOf("started","restarted","java_crash","native_crash","unexpected_exit"),
        "overlay" to setOf("direct","relay","degraded","unavailable"),
    )

    @Serializable data class Event(val id:String,val atMs:Long,val elapsedMs:Long,val networkEpoch:Long,
        val kind:String,val code:String,val mode:String,val path:String?=null,val durationMs:Int?=null) {
        override fun toString()="TechnicalEvent([redacted])"
        fun validate() {
            require(opaque.matches(id) && atMs in 1..MAX_TIME && elapsedMs in 0..MAX_TIME && networkEpoch in 0..MAX_TIME)
            require(mode in modes && code in codes[kind].orEmpty())
            require(path==null || opaque.matches(path))
            require(durationMs==null || durationMs in 0..600_000)
        }
    }

    @Serializable data class Batch(val schemaVersion:Int,val session:String,val build:Int,val policyRevision:Long,
        val algorithmRevision:Int,val events:List<Event>) {
        override fun toString()="TechnicalBatch([redacted])"
        fun body():ByteArray {
            require(schemaVersion==1 && opaque.matches(session) && build in 1..2_100_000_000 &&
                policyRevision in 0..MAX_TIME && algorithmRevision in 1..1_000_000 && events.size in 1..MAX_BATCH)
            events.forEach(Event::validate)
            require(events.map {it.id}.toSet().size==events.size)
            return wire.encodeToString(this).toByteArray(Charsets.UTF_8).also {require(it.size<=MAX_BYTES)}
        }
    }

    @Serializable data class Key(val session:String,val build:Int,val policyRevision:Long,val algorithmRevision:Int) {
        override fun toString()="TechnicalQueueKey([redacted])"
    }
    @Serializable data class Queued(val key:Key,val event:Event) {
        override fun toString()="TechnicalQueueEvent([redacted])"
    }
    @Serializable data class Snapshot(val version:Int,val scope:String,val entries:List<Queued>) {
        override fun toString()="TechnicalQueueSnapshot([redacted])"
        fun validate() {
            require(version==1 && opaque.matches(scope) && entries.size<=MAX_QUEUE)
            require(entries.map {it.event.id}.toSet().size==entries.size)
            for((key,event) in entries) {
                event.validate()
                require(opaque.matches(key.session) && key.build in 1..2_100_000_000 &&
                    key.policyRevision in 0..MAX_TIME && key.algorithmRevision in 1..1_000_000)
            }
        }
        fun offer(current:String,item:Queued):Snapshot {
            validate();require(current==scope)
            if(entries.any {it.event.id==item.event.id})return this
            return copy(entries=(entries+item).takeLast(MAX_QUEUE)).also(Snapshot::validate)
        }
        fun expired(current:String,nowMs:Long):Snapshot {
            validate();require(current==scope && nowMs in 1..(MAX_TIME-300_000))
            return copy(entries=entries.filter {it.event.atMs in (nowMs-RETRY_WINDOW)..(nowMs+300_000)})
        }
        fun peek(current:String):Batch? {
            validate();require(current==scope)
            val first=entries.firstOrNull() ?: return null
            val key=first.key
            return Batch(1,key.session,key.build,key.policyRevision,key.algorithmRevision,
                entries.takeWhile {it.key==key}.take(MAX_BATCH).map {it.event})
        }
        fun acknowledged(current:String,batch:Batch):Snapshot {
            validate()
            require(current==scope && batch.schemaVersion==1 && batch.events.size in 1..MAX_BATCH)
            val key=Key(batch.session,batch.build,batch.policyRevision,batch.algorithmRevision)
            require(entries.take(batch.events.size)==batch.events.map {Queued(key,it)})
            return copy(entries=entries.drop(batch.events.size))
        }
    }
}
