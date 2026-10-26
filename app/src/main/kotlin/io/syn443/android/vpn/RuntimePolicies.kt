package io.syn443.android.vpn

import android.content.Context
import android.os.SystemClock
import android.provider.Settings
import io.syn443.policy.Journal
import io.syn443.policy.Verified
import org.json.JSONObject

/** The legacy operator journal and enrolled journal are exclusive authorities, never mirrors. */
internal class RuntimePolicies(private val context:Context) {
    internal data class Snapshot(val managed:Boolean,val enrolled:Boolean,val journal:Journal,
        val applyDeadlineElapsed:Long=0,val binding:PolicyBinding?=null,
        val legacy:PolicyDisk?=null,val ticket:AssignedPolicyRuntime.Ticket?=null) {
        override fun toString()="RuntimePolicySnapshot([redacted])"
    }
    private val legacy=ManagedPolicyStore.get(context)
    private val login get()=LoginController.get(context)
    fun managed()=login.ownsPolicy() || legacy.managed()
    fun read():Snapshot {
        if(!login.ownsPolicy()) {
            val d=legacy.read()
            return Snapshot(d.binding!=null,false,d.journal,d.applyDeadlineElapsed,d.binding,d)
        }
        return runCatching {login.assignedRead {s->
            val view=login.assignedRuntime.read(s)
            Snapshot(true,true,view.state.journal,view.state.applyDeadlineElapsed,ticket=login.assignedRuntime.ticket(s))
        }}.getOrElse {Snapshot(true,true,Journal(phase="blocked",reason="assigned_policy_unavailable"))}
    }
    fun config(original:()->String?):String? = if(login.ownsPolicy())login.assignedRead {login.assignedRuntime.config(it)} else legacy.config(original())
    fun leaseDeadline(hash:String):Long = if(login.ownsPolicy())login.assignedRead {login.assignedRuntime.leaseDeadline(it,hash)} else legacy.leaseDeadline(hash)
    fun allowed(raw:String?,d:Snapshot=read()):Verified? {
        if(!d.enrolled)return if(login.ownsPolicy())null else legacy.allowed(raw,checkNotNull(d.legacy))
        return runCatching {login.assignedRead {s->
            require(login.assignedRuntime.ticket(s)==d.ticket)
            require(login.assignedRuntime.read(s).state.journal==d.journal)
            login.assignedRuntime.allowed(s,raw)
        }}.getOrNull()
    }
    fun now(d:Snapshot):Long {
        if(!d.enrolled)return legacy.now(checkNotNull(d.legacy))
        return login.assignedRead {s->require(login.assignedRuntime.ticket(s)==d.ticket)
        checkNotNull(login.assignedRuntime.read(s).state.time).window(
            Settings.Global.getInt(context.contentResolver,Settings.Global.BOOT_COUNT,-1),SystemClock.elapsedRealtime()).upperMs
        }
    }
    fun begin(values:List<Boolean>):Boolean {
        val d=read()
        return if(d.enrolled)login.beginAssignment(checkNotNull(d.ticket),values) else {legacy.begin(values);true}
    }
    fun finish(values:List<Boolean>,started:Boolean):Boolean {
        val d=read()
        return if(d.enrolled)login.finishAssignment(checkNotNull(d.ticket),values,started) else {legacy.finish(values,started);true}
    }
    fun rollback(reason:String):Boolean {
        val d=read();if(d.journal.phase!="applying")return false
        return if(d.enrolled)login.abortAssignment(checkNotNull(d.ticket),
            if(reason=="native_configuration_rejected")"native_activation_failed" else reason)
        else {legacy.rollback(reason);true}
    }
    fun discardPrepared(reason:String) {if(!login.ownsPolicy())legacy.discardPrepared(reason)}
    fun recover() {if(!login.ownsPolicy())legacy.recover()}
    fun admitFetch(force:Boolean)=!login.ownsPolicy() && legacy.admitFetch(force)
    fun deliveryConnection(network:android.net.Network,binding:PolicyBinding)=legacy.deliveryConnection(network,binding)
    fun received(raw:String,time:Long,original:String?) {require(!login.ownsPolicy());legacy.received(raw,time,original)}
    fun refreshAssigned(force:Boolean)=login.refreshAssignment(force)
    fun status():JSONObject {
        if(!login.ownsPolicy())return legacy.status()
        val d=read();val j=d.journal
        // Revision metadata is read only from worker-verified values. No envelope parsing here.
        return JSONObject().put("managed",true).put("source","account").put("phase",j.phase).put("reason",j.reason)
            .put("desiredRevision",j.maxRevision).put("activeRevision",allowed(j.active,d)?.payload?.revision)
            .put("lastKnownGoodRevision",allowed(j.lastGood,d)?.payload?.revision)
            .put("candidateRevision",allowed(j.candidate,d)?.payload?.revision)
            .put("activationGeneration",j.activationGeneration).put("securityEpoch",j.epoch).put("revocationFloor",j.floor)
            .put("maxRevision",j.maxRevision)
    }
}
