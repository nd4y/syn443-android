package io.syn443.identity

import io.syn443.policy.Verified

/** Immutable worker-verified lease. Its use performs no crypto, disk or network operation. */
class AssignmentPermit internal constructor(private val identity:AssignmentIdentity,private val receipt:String,
    private val activation:Long,private val candidate:Boolean,private val boot:Int,private val issuedElapsed:Long,
    val deadlineElapsed:Long,private val value:Verified) {
    private fun alive(currentBoot:Int,elapsed:Long) {require(currentBoot==boot && elapsed>=issuedElapsed && elapsed<deadlineElapsed)}
    fun authorized(login:LoginIntent,state:AssignmentState,currentBoot:Int,elapsed:Long):Verified {
        LoginRecovery.validate(login);alive(currentBoot,elapsed)
        require(login.phase==LoginPhase.POLICY_CACHED || login.phase==LoginPhase.REFRESHING && login.refreshReturnPhase==LoginPhase.POLICY_CACHED)
        require(identity==AssignmentIdentity(login.authority,login.generation,login.deviceId,login.thumbprint) && state.identity==identity)
        require(login.policyHash==receipt && state.journal.activationGeneration==activation)
        require((state.journal.phase=="applying")==candidate)
        require((if(candidate)state.journal.candidate else state.journal.active)==value.envelope)
        require(value.payload.revision>=state.journal.floor && value.payload.securityEpoch>=state.journal.epoch)
        return value
    }
    /** The owner must still fence its native token. An expired TUN is never revived by renewal. */
    fun renew(next:AssignmentPermit,login:LoginIntent,state:AssignmentState,currentBoot:Int,elapsed:Long):AssignmentPermit {
        alive(currentBoot,elapsed);next.authorized(login,state,currentBoot,elapsed)
        require(next.identity==identity && next.value.payload.contentHash==value.payload.contentHash)
        return next
    }
    override fun toString()="AssignmentPermit([redacted])"
}
