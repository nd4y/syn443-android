package io.syn443.identity

import java.util.concurrent.atomic.AtomicReference

/** Verified current service metadata. No public construction, copying, serialization or device identity projection. */
class AdminDiscovery internal constructor(metadata:AdminBootstrap,val binding:String,
    internal val issuedAtSeconds:Long,internal val notBeforeSeconds:Long,internal val expiresSeconds:Long) {
    val metadata:AdminBootstrap=metadata.copy()
    internal fun identity()=AdminIdentity(metadata,binding)
    internal fun same(other:AdminDiscovery)=binding==other.binding && metadata==other.metadata &&
        issuedAtSeconds==other.issuedAtSeconds && notBeforeSeconds==other.notBeforeSeconds && expiresSeconds==other.expiresSeconds
    internal fun covers(window:TimeWindow) {
        require(Math.multiplyExact(issuedAtSeconds,1000)<=Math.addExact(window.lowerMs,30_000) &&
            Math.multiplyExact(notBeforeSeconds,1000)<=window.lowerMs &&
            Math.multiplyExact(expiresSeconds,1000)>window.upperMs)
    }
    override fun toString()="AdminDiscovery([redacted])"
}

/** Synchronous background-worker admission. A ticket is current metadata, never a role/session grant. */
internal class AdminDiscoveryGuard(private val initial:AdminDiscovery,private val source:()->AdminDiscovery?,
    private val boot:()->Int,private val elapsed:()->Long) {
    private val discovered=AtomicReference<TrustedTime?>()
    fun check(time:TrustedTime?=null,requireDiscovered:Boolean=false,anonymous:Boolean=false) {
        try {
            val current=source()?:throw AdminException(AdminFailure.REAUTHENTICATE)
            if(!initial.same(current))throw AdminException(AdminFailure.REAUTHENTICATE)
            val prior=discovered.get()
            if(requireDiscovered && prior==null)throw AdminException(AdminFailure.REAUTHENTICATE)
            if(!anonymous)prior?.let {current.covers(it.window(boot(),elapsed()))}
            time?.let {current.covers(it.window(boot(),elapsed()))}
        } catch(error:Exception) {
            // A controller-owned operation may expire/cancel while its source
            // lookup is blocked. That failed operation grants nothing and must
            // not turn a still-valid account into a logout. The next operation
            // must perform all source/time admission again.
            if(error is AdminException && error.reason==AdminFailure.CANCELLED)throw error
            throw AdminException(AdminFailure.REAUTHENTICATE)
        }
    }
    /** A last-good same-BOOT clock is a floor, not disposable cache after an invalid reply. */
    fun priorTime():TrustedTime? {
        val prior=discovered.get()?:return null
        if(prior.boot!=boot())return null
        try {prior.window(boot(),elapsed())}
        catch(_:Exception) {throw AdminException(AdminFailure.REAUTHENTICATE)}
        return prior
    }
    // Publish only after the enclosing IdentityScope has completed its final cancellation check.
    fun record(time:TrustedTime):TrustedTime {
        val currentBoot=boot();val now=elapsed()
        return try {recordAt(time,currentBoot,now)}
        catch(_:Exception) {throw AdminException(AdminFailure.REAUTHENTICATE)}
    }
    @Synchronized private fun recordAt(time:TrustedTime,currentBoot:Int,now:Long):TrustedTime {
        val incoming=time.window(currentBoot,now)
        val previous=discovered.get()?.takeIf {it.boot==currentBoot}?.window(currentBoot,now)
        val merged=TrustedTime(currentBoot,now,maxOf(incoming.lowerMs,previous?.lowerMs?:incoming.lowerMs),
            maxOf(incoming.upperMs,previous?.upperMs?:incoming.upperMs))
        initial.covers(merged.window(currentBoot,now))
        discovered.set(merged)
        return merged
    }
    override fun toString()="AdminDiscoveryGuard([redacted])"
}
