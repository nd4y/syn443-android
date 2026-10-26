package io.syn443.android.vpn

import android.os.Looper
import io.syn443.identity.*
import io.syn443.policy.Verified
import org.json.JSONObject

/** Immutable worker-built view. Binder/native reads never decrypt or verify signatures. */
internal class AssignedPolicyRuntime(private val boot:()->Int,private val elapsed:()->Long) {
    internal data class Ticket(val loginGeneration:Long,val receipt:String,val activation:Long) {
        override fun toString()="AssignmentTicket([redacted])"
    }
    internal class Prepared internal constructor(val login:LoginIntent,val state:AssignmentState,val candidate:Verified?,
        val candidateDeadline:Long,val permit:AssignmentPermit?) {
        override fun toString()="AssignedPolicyView([redacted])"
    }
    @Volatile private var value:Prepared?=null
    fun clear() {value=null}
    fun prepare(login:LoginIntent,payload:LoginPayload,state:AssignmentState):Prepared {
        check(Looper.myLooper()!=Looper.getMainLooper())
        payload.requireBound(login)
        val currentBoot=boot();val now=elapsed()
        val candidate=runCatching {Assignments.authorized(state,login,payload,currentBoot,now,true).also {
            EngineConfig.validateAssigned(it.engineConfig)
        }}.getOrNull()
        val candidateDeadline=if(candidate==null)0 else Math.addExact(now,candidate.payload.offlineUntilMs-checkNotNull(state.time).window(currentBoot,now).upperMs)
        val permit=runCatching {Assignments.permit(state,login,payload,currentBoot,now).also {
            EngineConfig.validateAssigned(it.authorized(login,state,currentBoot,now).engineConfig)
        }}.getOrNull()
        return Prepared(login,state,candidate,candidateDeadline,permit)
    }
    /** Caller must hold its current-generation fence; preparation never holds that lock. */
    fun publish(prepared:Prepared) {value=prepared}
    private fun current(login:LoginIntent):Prepared {
        LoginRecovery.validate(login)
        require(login.phase==LoginPhase.POLICY_CACHED || login.phase==LoginPhase.REFRESHING && login.refreshReturnPhase==LoginPhase.POLICY_CACHED)
        val view=checkNotNull(value)
        require(login.generation==view.login.generation && login.authority==view.login.authority &&
            login.deviceId==view.login.deviceId && login.thumbprint==view.login.thumbprint && login.policyHash==view.login.policyHash)
        return view
    }
    fun ticket(login:LoginIntent):Ticket {
        val view=current(login)
        return Ticket(login.generation,login.policyHash,view.state.journal.activationGeneration)
    }
    fun contains(login:LoginIntent,state:AssignmentState):Boolean = runCatching {current(login).state==state}.getOrDefault(false)
    fun config(login:LoginIntent):String {
        val view=current(login)
        return checkNotNull(view.permit).authorized(login,view.state,boot(),elapsed()).engineConfig
    }
    fun leaseDeadline(login:LoginIntent,hash:String):Long {
        val view=current(login);val permit=checkNotNull(view.permit)
        require(permit.authorized(login,view.state,boot(),elapsed()).payload.contentHash==hash)
        return permit.deadlineElapsed
    }
    fun status(login:LoginIntent):JSONObject = runCatching {
        val view=current(login);val now=elapsed()
        val candidateValid=view.candidate!=null && view.state.time?.boot==boot() && now>=checkNotNull(view.state.time).elapsedMs && now<view.candidateDeadline
        val runtimeValid=runCatching {checkNotNull(view.permit).authorized(login,view.state,boot(),now)}.isSuccess
        JSONObject().put("phase",view.state.journal.phase).put("revision",view.state.journal.maxRevision)
            .put("candidateValidated",candidateValid).put("runtimeAuthorized",runtimeValid)
    }.getOrElse {JSONObject().put("phase","unavailable").put("candidateValidated",false).put("runtimeAuthorized",false)}
}
