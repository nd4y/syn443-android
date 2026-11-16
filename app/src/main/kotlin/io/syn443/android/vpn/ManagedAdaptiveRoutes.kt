package io.syn443.android.vpn

import io.syn443.decision.AdaptiveRuntime
import io.syn443.decision.Context
import io.syn443.decision.Decision
import io.syn443.decision.NetworkMode
import io.syn443.decision.PathHealthKey
import io.syn443.decision.PathReadiness
import io.syn443.decision.PlannedPath
import io.syn443.decision.ProbeVerdict
import io.syn443.decision.RouteFrontier
import io.syn443.decision.RouteHealthMemory
import io.syn443.policy.Policy
import io.syn443.recovery.RouteScope
import kotlinx.serialization.json.jsonObject
import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

/** Handler-confined policy coordinator. A plan/score never authorizes packets;
 * only the actual native worker's one-use receipt can commit a path. */
internal class ManagedAdaptiveRoutes private constructor(private val wire:AdaptiveRuntime,private val priorityTag:String) {
    private data class CurrentFailure(val path:PlannedPath,val attempt:Long,val completedAt:Long,val nativeEpoch:Long,val nativeScope:String)
    private data class Group(var frontier:RouteFrontier?=null,var current:PlannedPath?=null,
        var measuredAt:Long=0,var latency:Long=0,var nextAt:Long=0,var exploreAt:Long=0,
        var improvement:String="",var improvementPath:PlannedPath?=null,var improvementCount:Int=0,var recheckFailed:Boolean=false,
        var failure:CurrentFailure?=null)
    private data class Pending(val request:String,val group:String,val path:PlannedPath,val attempt:Long,val startedAt:Long,
        val nativeEpoch:Long,val nativeScope:String,var action:String="probe",var latency:Long=0,var receipt:String="",var retries:Int=0,
        var recovery:CurrentFailure?=null)
    private val groups=wire.graph.groupIDs().associateWith {Group()}
    private val order=groups.keys.sortedWith(compareBy<String>({wire.groupTags()[it]!=priorityTag},{it}))
    private var context:Context?=null
    private var routeScope:RouteScope?=null
    private var memory:RouteHealthMemory?=null
    private var mode=NetworkMode.WIFI
    private var policyScope=""
    private var nativeEpoch=0L
    private var nativeScope=""
    private var nativeRunning=false
    private var nativeReady=false
    private var pending:Pending?=null
    private var attempt=0L
    private var groupCursor=0
    private var policyRevision=0L
    private var previousPolicyScope=""
    private var retireOwner=false
    private var lastCommandAt=Long.MIN_VALUE/2
    private var lastNow=0L
    private val admissions=java.util.ArrayDeque<Long>()

    fun bind(scope:RouteScope,networkMode:NetworkMode,revision:Long) {
        require(revision>0)
        if(routeScope==scope && mode==networkMode && policyRevision==revision)return
        val next=Context(scope.network,scope.activation,"r-$revision",Policy.ADAPTIVE_ALGORITHM,
            scope.intent,Policy.hash("${scope.intent}|${scope.network}|${scope.activation}|${scope.engine}|${scope.config}|${wire.hash}|$networkMode|$revision"))
        require(Decision.validContext(next))
        val sameEngine=routeScope?.engine==scope.engine
        previousPolicyScope=if(sameEngine)policyScope else ""
        if(!sameEngine) {nativeEpoch=0;retireOwner=false}
        context=next;routeScope=scope;mode=networkMode;policyRevision=revision;policyScope=next.dependencyHash
        memory=RouteHealthMemory(next);pending=null;nativeReady=false;nativeScope=""
        groupCursor=0
        groups.values.forEach {it.frontier=null;it.current=null;it.measuredAt=0;it.nextAt=0;it.improvement="";it.improvementPath=null;it.improvementCount=0;it.recheckFailed=false;it.failure=null}
    }
    fun controlFrame():String {check(policyScope.isNotEmpty());return JSONObject().put("schemaVersion",1).put("scope",policyScope).put("mode",mode.name).toString()}
    private fun send(command:JSONObject,now:Long,dispatch:(String)->Unit) {
        lastCommandAt=now
        dispatch(JSONObject().put("kind","adaptive").put("commandJson",command.toString()).toString())
    }
    private fun frame(command:String)=JSONObject().put("command",command).put("nativeEpoch",nativeEpoch).put("scope",nativeScope)
    private fun advanceClock(now:Long):Boolean {
        if(now !in lastNow..(Decision.MAX_TIME-600_000)) {retireOwner=true;return false}
        lastNow=now
        return true
    }
    private fun recoveryFailure(group:Group,work:Pending,now:Long):CurrentFailure?=group.failure?.takeIf {
        group.current?.id==it.path.id && work.path.id!=it.path.id && work.startedAt>=it.completedAt &&
            now-it.completedAt in 0..30_000 && nativeEpoch==it.nativeEpoch && nativeScope==it.nativeScope &&
            work.nativeEpoch==it.nativeEpoch && work.nativeScope==it.nativeScope
    }
    fun report(raw:JSONObject,now:Long,dispatch:(String)->Unit) {
        if(retireOwner || context==null)return
        if(!advanceClock(now) || raw.toString().length>32768)return
        val epoch=raw.optLong("nativeEpoch",0);val scope=raw.optString("scope")
        if(epoch<1 || epoch<nativeEpoch || !scope.matches(Regex("[a-f0-9]{64}")))return
        val reportedPolicy=raw.optString("policyScope")
        if(reportedPolicy!=policyScope && reportedPolicy!=previousPolicyScope)return
        if(epoch!=nativeEpoch || nativeScope.isNotEmpty() && scope!=nativeScope)
            groups.values.forEach {it.failure=null;it.recheckFailed=false}
        nativeEpoch=epoch;nativeRunning=raw.optBoolean("running")
        if(nativeRunning && raw.optLong("workAgeMs",0)>35_000) {retireOwner=true;return}
        if(raw.optString("policyScope")!=policyScope || !raw.optBoolean("ready")) {
            nativeReady=false;nativeScope=""
            if(now-lastCommandAt>=1000)send(JSONObject().put("command","configure").put("schemaVersion",1)
                .put("nativeEpoch",epoch).put("scope",policyScope).put("mode",mode.name),now,dispatch)
            return
        }
        nativeReady=true;nativeScope=scope
        val work=pending ?: return
        if(now-work.startedAt>35_000) {retireOwner=true;return}
        if(epoch!=work.nativeEpoch || scope!=work.nativeScope)return
        if(nativeRunning)return
        if(raw.optString("request")!=work.request) {
            // A rejected/lost command is not evidence of a bad path. A still
            // running native owner above retains admission indefinitely.
            return
        }
        val group=groups.getValue(work.group);val code=raw.optString("code")
        val hops=raw.optJSONArray("hops") ?: return
        if(raw.optString("group")!=work.group || (0 until hops.length()).map {hops.optString(it)}!=work.path.hops)return
        val currentScope=checkNotNull(routeScope)
        if(code=="verified" && work.action!="probe") {
            if(raw.optString("receipt")!=work.receipt)return
            if(now-lastCommandAt>=1000) {
                if(work.retries>=3)work.action="discard"
                if(work.retries>=6) {retireOwner=true;return}
                work.retries++
                send(frame(work.action).put("request",work.request).put("receipt",work.receipt),now,dispatch)
            }
            return
        }
        if(code=="verified" && work.action=="probe") {
            val receipt=raw.optString("receipt")
            if(!receipt.matches(Regex("[a-f0-9]{64}")))return
            val elapsed=raw.optLong("probeMs",-1);if(elapsed !in 0..11999)return
            work.latency=elapsed
            work.receipt=receipt
            val same=group.current?.id==work.path.id
            if(same) {group.failure=null;group.recheckFailed=false}
            work.recovery=recoveryFailure(group,work,now)
            val improvement=group.current!=null && !same && now-group.measuredAt in 0..120_000 &&
                elapsed+15<group.latency && elapsed*5<group.latency*4
            if(improvement) {
                if(group.improvement==work.path.id)group.improvementCount++ else {group.improvement=work.path.id;group.improvementCount=1}
                group.improvementPath=work.path
            } else if(!same) {
                group.improvement="";group.improvementPath=null;group.improvementCount=0
            }
            work.action=if(group.current==null || same || work.recovery!=null || now-group.measuredAt>120_000 || improvement && group.improvementCount>=2)"commit" else "discard"
            send(frame(work.action).put("request",work.request).put("receipt",receipt),now,dispatch)
            return
        }
        if(work.action=="commit" && code=="selected") {
            if(!raw.optBoolean("groupSelected"))return
            // Only an independently verified replacement with a successful
            // previous-selection-bound native commit attributes the old failure.
            work.recovery?.takeIf {it==recoveryFailure(group,work,now)}?.let {
                memory?.record(checkNotNull(context),key(work.group,it.path),it.attempt,now,ProbeVerdict.CONFIRMED_PATH_FAILURE)
            }
            val changed=group.current?.id!=work.path.id
            group.current=work.path;group.measuredAt=now;group.latency=work.latency;group.nextAt=now+60_000
            if(changed || group.exploreAt==0L)group.exploreAt=now+300_000
            group.improvement="";group.improvementPath=null;group.improvementCount=0;group.recheckFailed=false;group.failure=null
            memory?.record(checkNotNull(context),key(work.group,work.path),work.attempt,now,ProbeVerdict.VERIFIED)
            RouteSnapshot.adaptive(currentScope,wire.groupTags().getValue(work.group),true,"ok",work.latency,work.path.hops)
        } else if(work.action=="probe" && code in setOf("probe_unavailable","exit_mismatch","check_failed")) {
            val checkedAt=if(code=="check_failed") {
                if(raw.optString("checkCode") !in checkedFailures)return
                // Native CLOCK_BOOTTIME and elapsedRealtime share the Android
                // boot epoch. Delivery/cleanup delay cannot refresh an old check.
                val stamp=raw.opt("checkCompletedBootMs")
                if(stamp !is Long && stamp !is Int)return
                val value=(stamp as Number).toLong()
                if(value<=0 || value !in work.startedAt..now || now-value>30_000)return
                value
            } else 0L
            if(code=="exit_mismatch")memory?.record(checkNotNull(context),key(work.group,work.path),work.attempt,now,ProbeVerdict.CONFIRMED_PATH_FAILURE)
            if(group.current?.id==work.path.id && !raw.optBoolean("groupSelected"))group.current=null
            if(group.current?.id==work.path.id) {
                group.recheckFailed=code!="probe_unavailable"
                group.failure=if(code=="check_failed")CurrentFailure(work.path,work.attempt,checkedAt,nativeEpoch,nativeScope) else null
                if(code=="check_failed") {group.improvement="";group.improvementPath=null;group.improvementCount=0}
            } else if(group.current==null) {group.failure=null;group.recheckFailed=false}
            group.nextAt=now+5000
            if(group.current==null || group.current?.id==work.path.id)
                RouteSnapshot.adaptive(currentScope,wire.groupTags().getValue(work.group),false,code,null,emptyList())
        } else if(work.action=="discard" && code=="discarded") {
            // A second independent fresh measurement is needed before a latency switch.
            group.nextAt=if(group.improvement==work.path.id)now+5000 else minOf(now+60_000,group.measuredAt+60_000)
        } else if(code !in setOf("commit_rejected","discarded"))return
        pending=null
    }
    private fun key(group:String,path:PlannedPath)=PathHealthKey(path.id,checkNotNull(wire.graph.groupInfo(group)).intent,group)
    fun tick(now:Long,unmetered:Boolean,allowExplore:Boolean,dispatch:(String)->Unit) {
        val current= context ?: return
        if(retireOwner || !advanceClock(now) || !nativeReady || nativeScope.isEmpty() || nativeRunning || pending!=null || now-lastCommandAt<1000)return
        while(admissions.isNotEmpty() && now-admissions.first>=3_600_000)admissions.removeFirst()
        if(admissions.size>=128 || admissions.count {now-it<60_000}>=8 || admissions.lastOrNull()?.let {now-it<5000}==true)return
        val rotated=order.drop(groupCursor)+order.take(groupCursor)
        val groupID=rotated.firstOrNull {id->val g=groups.getValue(id);now>=g.nextAt &&
            (g.current==null || g.recheckFailed || now-g.measuredAt>=60_000 || unmetered && allowExplore && now>=g.exploreAt || g.improvement.isNotEmpty())} ?: return
        val group=groups.getValue(groupID)
        val explore=unmetered && allowExplore && group.current!=null && now>=group.exploreAt
        val recheck=group.current?.takeIf {!explore && !group.recheckFailed && now-group.measuredAt>=60_000}
        val retryImprovement=group.improvementPath
        var candidate=retryImprovement?.takeIf {now-group.measuredAt<=120_000} ?: recheck
        if(candidate==null) {
            if(group.frontier==null)group.frontier=wire.graph.frontier(groupID,current,mode,emptyList(),now,600_000)
            val batch=checkNotNull(group.frontier).next(current,now,1,64)
            if(batch.invalidated || batch.exhausted)group.frontier=null
            candidate=batch.paths.firstOrNull()
            if(candidate==null) {group.nextAt=now+if(group.current==null)60_000 else 300_000;return}
        }
        val health=checkNotNull(memory).view(current,key(groupID,candidate),now)
        if(health.readiness in setOf(PathReadiness.QUARANTINED,PathReadiness.HALF_OPEN,PathReadiness.CONFIG_CHANGE_REQUIRED)) {group.nextAt=now+1000;return}
        attempt++
        if(health.readiness==PathReadiness.REVALIDATE && health.retryAtMs!=null && !checkNotNull(memory).beginRetry(current,key(groupID,candidate),attempt,now))return
        val request=UUID.randomUUID().toString()
        pending=Pending(request,groupID,candidate,attempt,now,nativeEpoch,nativeScope);admissions.addLast(now)
        if(explore)group.exploreAt=now+300_000
        groupCursor=(order.indexOf(groupID)+1)%order.size
        send(frame("start").put("request",request).put("group",groupID).put("hops",JSONArray(candidate.hops)),now,dispatch)
    }
    fun force() {groups.values.forEach {it.nextAt=0;it.measuredAt=0}}
    fun requiresRetirement()=retireOwner
    override fun toString()="ManagedAdaptiveRoutes([redacted])"
    companion object {
        private val checkedFailures=setOf("dial_failed","check_timeout","tls_failed","ssh_banner_mismatch","request_failed","response_failed","exit_evidence_invalid","http_response_mismatch")
        fun read(raw:String?):ManagedAdaptiveRoutes? {
            if(raw==null)return null
            val root=Decision.json.parseToJsonElement(raw).jsonObject
            val adaptive=root["adaptive_routes"] ?: return null
            val wire=AdaptiveRuntime.decode(checkNotNull(protectedAdaptiveWire(raw)))
            val tag=runCatching {JSONObject(raw).getJSONObject("route").getString("final")}.getOrDefault("")
            return ManagedAdaptiveRoutes(wire,tag)
        }
    }
}
