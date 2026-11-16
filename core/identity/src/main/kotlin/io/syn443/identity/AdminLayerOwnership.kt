package io.syn443.identity

/** Bounded current-account value snapshot. It contains no token, role or grant. */
class AdminLayerOwnership internal constructor(val serviceHash:String,val actor:String,val apiOrigin:String,
    val time:TimeWindow,val bootCount:Int,val observedElapsedMs:Long,val sessionUntilElapsedMs:Long) {
    override fun toString()="AdminLayerOwnership([redacted])"
}
