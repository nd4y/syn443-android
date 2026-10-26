package io.syn443.identity

import io.syn443.policy.Journal
import io.syn443.policy.Policy
import io.syn443.policy.Verified
import kotlinx.serialization.Serializable

/** No token/key is duplicated into the separately encrypted activation journal. */
@Serializable data class AssignmentIdentity(val authority:String,val loginGeneration:Long,
    val deviceId:String,val keyThumbprint:String) {
    override fun toString()="AssignmentIdentity([redacted])"
}
@Serializable data class AssignmentState(val identity:AssignmentIdentity?=null,
    val journal:Journal=Journal(),val time:TrustedTime?=null) {
    override fun toString()="AssignmentState(phase=${journal.phase}, [redacted])"
}

/** Disk/CAS and native-owner retirement are supplied by the controller. No unsigned fallback. */
object Assignments {
    private fun identity(login:LoginIntent,payload:LoginPayload):AssignmentIdentity {
        payload.requireBound(login);require(payload.session!=null)
        require(login.phase in setOf(LoginPhase.PROVISIONING,LoginPhase.POLICY_CACHED,LoginPhase.REFRESHING))
        return AssignmentIdentity(login.authority,login.generation,login.deviceId,login.thumbprint)
    }
    private fun bound(state:AssignmentState,login:LoginIntent,payload:LoginPayload) {
        require(state.identity==identity(login,payload) && state.time!=null)
    }
    private fun verify(raw:String,login:LoginIntent,payload:LoginPayload,time:TrustedTime,boot:Int,elapsed:Long):Verified {
        val window=time.window(boot,elapsed)
        return Policy.verifyBound(raw,payload.bootstrap.roots,login.deviceId,login.thumbprint,window.upperMs).also {
            require(it.payload.notBeforeMs<=window.lowerMs)
            // Enrollment currently advertises these implemented capabilities. Extra native
            // modules must acquire a managed credential namespace before being advertised.
            require(IdentityOperation.requiredCapabilities.containsAll(it.payload.requiredCapabilities))
            require(it.payload.operation=="configure")
        }
    }
    /** Persist this journal first; then record its receipt in the login intent. */
    fun receive(state:AssignmentState,login:LoginIntent,payload:LoginPayload,reply:PolicyReply,
                boot:Int,elapsed:Long):AssignmentState {
        val expected=identity(login,payload)
        if(state.identity==null)require(state==AssignmentState()) else bound(state,login,payload)
        val window=reply.time.window(boot,elapsed)
        state.time?.takeIf {it.boot==boot}?.let {
            val previous=it.window(boot,elapsed)
            require(window.upperMs>=previous.lowerMs && window.lowerMs<=Math.addExact(previous.upperMs,30_000))
        }
        val verified=verify(reply.envelope,login,payload,reply.time,boot,elapsed)
        val j=state.journal
        require(verified.payload.revision>=j.floor && verified.payload.securityEpoch>=j.epoch)
        if(reply.envelope==j.desired || reply.envelope==j.active || reply.envelope==j.candidate)
            return state.copy(time=reply.time)
        require(j.phase!="applying") // Finish/retire an activation before admitting another candidate.
        val base=if(j.phase=="prepared")j.copy(phase="rejected",candidate=null) else j
        return AssignmentState(expected,Policy.stage(base,verified),reply.time)
    }
    /** Repeating this after a crash completes a same-generation journal/intent handoff. */
    fun receipt(state:AssignmentState,login:LoginIntent,payload:LoginPayload,boot:Int,elapsed:Long):String {
        bound(state,login,payload)
        val desired=checkNotNull(state.journal.desired)
        verify(desired,login,payload,checkNotNull(state.time),boot,elapsed)
        return Identity.hash(desired.toByteArray(Charsets.UTF_8))
    }
    /** No configuration can be consumed until the matching durable receipt was acknowledged. */
    fun authorized(state:AssignmentState,login:LoginIntent,payload:LoginPayload,boot:Int,elapsed:Long,
                   candidate:Boolean=false):Verified {
        bound(state,login,payload)
        require(login.phase==LoginPhase.POLICY_CACHED || login.phase==LoginPhase.REFRESHING && login.refreshReturnPhase==LoginPhase.POLICY_CACHED)
        require(login.policyHash==Identity.hash(checkNotNull(state.journal.desired).toByteArray(Charsets.UTF_8)))
        val raw=if(candidate) {
            require(state.journal.phase in setOf("prepared","applying"));state.journal.candidate
        } else state.journal.active
        val value=verify(checkNotNull(raw),login,payload,checkNotNull(state.time),boot,elapsed)
        require(value.payload.revision>=state.journal.floor && value.payload.securityEpoch>=state.journal.epoch)
        return value
    }
    fun begin(state:AssignmentState,login:LoginIntent,payload:LoginPayload,baseline:List<Boolean>,boot:Int,elapsed:Long):AssignmentState {
        val candidate=authorized(state,login,payload,boot,elapsed,true)
        require(baseline.size==candidate.payload.activation.checks.size)
        return state.copy(journal=Policy.begin(state.journal,baseline))
    }
    fun finish(state:AssignmentState,login:LoginIntent,payload:LoginPayload,actual:List<Boolean>,
               engineStarted:Boolean,boot:Int,elapsed:Long):AssignmentState {
        val candidate=authorized(state,login,payload,boot,elapsed,true)
        return state.copy(journal=Policy.finish(state.journal,candidate,actual,engineStarted))
    }
    /** Called only after the native owner is gone and namespace credential erasure is confirmed. */
    fun retire(state:AssignmentState,login:LoginIntent,nativeOwnerGone:Boolean,namespaceErased:Boolean):AssignmentState {
        LoginRecovery.validate(login)
        require(login.phase==LoginPhase.RETIRING && nativeOwnerGone && namespaceErased)
        state.identity?.let {require(it.loginGeneration<login.generation)}
        return AssignmentState()
    }
}
