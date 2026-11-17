package io.syn443.android.vpn

import io.syn443.decision.AdaptiveProbeBudget

/** Start accounting only. An allowed result is neither route evidence nor an
 * instruction to dispatch: the caller must still own its original context and
 * deadline, and must dispatch no later than latestStartMs. */
internal interface AdaptiveStartAdmission {
    data class Result(val allowed:Boolean,val observedAtMs:Long,val latestStartMs:Long)
    /** False means the owner did not accept this request; no callback follows. */
    fun request(nowMs:Long,routine:Boolean,callback:(Result)->Unit):Boolean
    fun canStart(nowMs:Long,routine:Boolean):Boolean
    /** Fresh monotonic sample at a controller effect boundary; never file I/O. */
    fun currentTimeMs():Long
    /** A clock seal only. Storage unavailability is a soft admission wait. */
    fun invalidated():Boolean
    fun routineCadence(groupCount:Int):Long
}

/** Existing virtual-clock fixtures retain their exact synchronous start charge. */
internal class ImmediateAdaptiveStartAdmission(private val budget:AdaptiveProbeBudget):AdaptiveStartAdmission {
    override fun request(nowMs:Long,routine:Boolean,callback:(AdaptiveStartAdmission.Result)->Unit):Boolean {
        callback(AdaptiveStartAdmission.Result(budget.start(nowMs,routine),nowMs,nowMs))
        return true
    }
    override fun canStart(nowMs:Long,routine:Boolean)=budget.canStart(nowMs,routine)
    override fun currentTimeMs()=budget.checkpoint().observedAtMs
    override fun invalidated()=budget.invalidated()
    override fun routineCadence(groupCount:Int)=budget.routineCadence(groupCount)
}
