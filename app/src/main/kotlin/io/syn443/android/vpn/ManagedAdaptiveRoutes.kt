package io.syn443.android.vpn

import io.syn443.decision.AdaptiveRuntime
import io.syn443.decision.AdaptiveProbeBudget
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
internal class ManagedAdaptiveRoutes private constructor(private val wire:AdaptiveRuntime,private val priorityTag:String,
    private val budget:AdaptiveStartAdmission) {
    private data class CurrentFailure(val path:PlannedPath,val attempt:Long,val completedAt:Long,val nativeEpoch:Long,val nativeScope:String)
    private data class Group(var frontier:RouteFrontier?=null,var current:PlannedPath?=null,
        var emptyPages:Int=0,var onlyFenced:Boolean=true,var firstRetryAt:Long?=null,
        var measuredAt:Long=0,var latency:Long=0,var nextAt:Long=0,var exploreAt:Long=0,
        var improvement:String="",var improvementPath:PlannedPath?=null,var improvementCount:Int=0,var recheckFailed:Boolean=false,
        var failure:CurrentFailure?=null,var selectionToken:Long=0,var hintSequence:Long=0,var urgentRecheck:Boolean=false,var forceCheck:Boolean=false,
        var search:AdaptiveSearchState=AdaptiveSearchState.WAITING_CONTEXT)
    private data class Pending(val request:String,val group:String,val path:PlannedPath,val attempt:Long,val startedAt:Long,
        val nativeEpoch:Long,val nativeScope:String,var action:String="probe",var latency:Long=0,var receipt:String="",var retries:Int=0,
         var recovery:CurrentFailure?=null,var checkPlan:JSONObject?=null)
    private data class PendingAdmission(val request:String,val group:String,val path:PlannedPath,val attempt:Long,
        val startedAt:Long,val context:Context,val scope:RouteScope?,val mode:NetworkMode,
        val nativeEpoch:Long,val nativeScope:String,val leaseDeadlineElapsed:Long?,val explore:Boolean,
        val isCurrent:()->Boolean,val handoff:(JSONObject,Long)->Boolean)
    private val groups=wire.graph.groupIDs().associateWith {Group()}
    private val order=groups.keys.sortedWith(compareBy<String>({wire.groupTags()[it]!=priorityTag},{it}))
    private var context:Context?=null
    private var routeScope:RouteScope?=null
    private var memory:RouteHealthMemory?=null
    private var mode=NetworkMode.WIFI
    private var policyScope=""
    private var nativeEpoch=0L
    private var nativeScope=""
    private var observedNativeScope=""
    private var drainingSince:Long?=null
    private var nativeRunning=false
    private var nativeReady=false
    private var pending:Pending?=null
    private var pendingAdmission:PendingAdmission?=null
    private var attempt=0L
    private var groupCursor=0
    private val cpuYields=HashSet<String>()
    private var policyRevision=0L
    private var boundPolicy:AdaptivePolicyBinding?=null
    private var boundPhysicalPathToken:PhysicalPathToken?=null
    private var previousPolicyScope=""
    private var retireOwner=false
    private var lastCommandAt=Long.MIN_VALUE/2
    private var lastNow=0L
    private val maintenanceCadence=budget.routineCadence(groups.size)

    fun bind(scope:RouteScope,networkMode:NetworkMode,revision:Long) {
        require(revision>0)
        if(boundPolicy==null && routeScope==scope && mode==networkMode && policyRevision==revision)return
        boundPolicy=null;boundPhysicalPathToken=null
        reset(scope,networkMode,revision,null)
    }
    /** Pure lease renewal labels the same live execution; it is not a native
     * lease acknowledgement, receipt or permission to revive an expired box. */
    fun bind(scope:RouteScope,networkMode:NetworkMode,binding:AdaptivePolicyBinding,now:Long) {
        bind(scope,networkMode,binding,now,null)
    }
    /** The opaque token proves only continuity of the observed OS path inside
     * this live service. It carries no selection, route or network authority. */
    fun bind(scope:RouteScope,networkMode:NetworkMode,binding:AdaptivePolicyBinding,now:Long,
        physicalPathToken:PhysicalPathToken?) {
        if(!advanceClock(now)) {publishSearch();return}
        if(now>=binding.leaseDeadlineElapsed) {retireOwner=true;publishSearch();return}
        val previous=boundPolicy
        if(previous!=null && routeScope?.engine==scope.engine &&
            (previous.boot!=binding.boot || now>=previous.leaseDeadlineElapsed || binding.revision<policyRevision)) {
            retireOwner=true;publishSearch();return
        }
        if(previous!=null && routeScope==scope && mode==networkMode &&
            physicalPathToken===boundPhysicalPathToken &&
            binding.revision>=policyRevision && binding.contentHash==previous.contentHash &&
            binding.semanticAuthority==previous.semanticAuthority) {
            boundPolicy=binding;policyRevision=binding.revision
            return
        }
        val oldScope=routeScope
        val compatibleFailures=previous!=null && oldScope!=null && physicalPathToken!=null &&
            physicalPathToken===boundPhysicalPathToken && mode==networkMode &&
            oldScope.intent==scope.intent && oldScope.activation==scope.activation &&
            oldScope.config==scope.config && oldScope.engine==scope.engine &&
            binding.boot==previous.boot && binding.revision>=policyRevision &&
            binding.contentHash==previous.contentHash && binding.semanticAuthority==previous.semanticAuthority &&
            now<previous.leaseDeadlineElapsed && now<binding.leaseDeadlineElapsed
        if(compatibleFailures && oldScope!=null && scope.network<oldScope.network) {
            // A delayed metadata bind must not replace current cooldown with
            // either an older context or a fresh empty history.
            publishSearch();return
        }
        val preserveFailures=compatibleFailures && oldScope!=null && scope.network>oldScope.network
        if(reset(scope,networkMode,binding.revision,binding.semanticAuthority,preserveFailures)) {
            boundPolicy=binding;boundPhysicalPathToken=physicalPathToken
        }
    }
    private fun reset(scope:RouteScope,networkMode:NetworkMode,revision:Long,authority:String?,preserveFailures:Boolean=false):Boolean {
        val semantic=authority?.let {"|$it"} ?: ""
        val next=Context(scope.network,scope.activation,"r-$revision",Policy.ADAPTIVE_ALGORITHM,
            scope.intent,Policy.hash("${scope.intent}|${scope.network}|${scope.activation}|${scope.engine}|${scope.config}|${wire.hash}|$networkMode|$revision$semantic"))
        require(Decision.validContext(next))
        val nextMemory=if(preserveFailures) {
            val carried=memory?.forkFailureFences(checkNotNull(context),next,lastNow)
            if(carried==null) {
                // Failure to transfer an eligible fence must not silently
                // create an empty history. Keep the old owner retired.
                retireOwner=true;RouteSnapshot.adaptiveOwnerChanged(scope,wire.groupTags().values.toSet());publishSearch();return false
            }
            carried
        } else RouteHealthMemory(next)
        val sameEngine=routeScope?.engine==scope.engine
        previousPolicyScope=if(sameEngine)policyScope else ""
        if(!sameEngine) {nativeEpoch=0;retireOwner=false}
        context=next;routeScope=scope;mode=networkMode;policyRevision=revision;policyScope=next.dependencyHash
        memory=nextMemory;pending=null;pendingAdmission=null;nativeReady=false;nativeScope="";observedNativeScope="";drainingSince=null
        groupCursor=0;cpuYields.clear()
        groups.values.forEach {it.frontier=null;it.current=null;it.measuredAt=0;it.nextAt=0;it.improvement="";it.improvementPath=null;it.improvementCount=0;it.recheckFailed=false;it.failure=null;it.selectionToken=0;it.hintSequence=0;it.urgentRecheck=false;it.forceCheck=false}
        groups.values.forEach {it.search=AdaptiveSearchState.WAITING_CONTEXT}
        RouteSnapshot.adaptiveOwnerChanged(scope,wire.groupTags().values.toSet())
        publishSearch()
        return true
    }
    private fun markSearch(id:String,state:AdaptiveSearchState) {
        val group=groups.getValue(id)
        if(group.search!=AdaptiveSearchState.VERIFIED || lastNow-group.measuredAt !in 0..120_000)group.search=state
    }
    /** Diagnostics only: never calls admission, changes selection or mints evidence. */
    private fun publishSearch() {
        val scope=routeScope ?: return
        val waiting=retireOwner || !nativeReady || nativeScope.isEmpty() || drainingSince!=null
        RouteSnapshot.adaptiveSearch(scope,order.associate {id->wire.groupTags().getValue(id) to
            if(waiting)AdaptiveSearchState.WAITING_CONTEXT else groups.getValue(id).search})
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
    private fun safeInteger(raw:JSONObject,name:String):Long? {
        val value=raw.opt(name)
        if(value !is Int && value !is Long)return null
        return (value as Number).toLong().takeIf {it in 1..9_007_199_254_740_991L}
    }
    /** A passive symptom requests a fresh check, never a route verdict. The
     * outer report already binds the current native and policy scopes. */
    private fun recheckHints(raw:JSONObject,now:Long) {
        if(!raw.has("recheckHints"))return
        val values=raw.optJSONArray("recheckHints") ?: return
        if(values.length()>16)return
        data class Hint(val group:String,val token:Long,val sequence:Long,val completed:Long)
        val hints=ArrayList<Hint>(values.length())
        val seen=HashSet<String>()
        for(index in 0 until values.length()) {
            val value=values.optJSONObject(index) ?: return
            if(value.keys().asSequence().toSet()!=setOf("group","selectionToken","sequence","completedBootMs","code"))return
            val group=value.opt("group") as? String ?: return
            if(group !in groups || !seen.add(group) || value.opt("code")!="traffic_network_failure")return
            hints+=Hint(group,safeInteger(value,"selectionToken") ?: return,safeInteger(value,"sequence") ?: return,
                safeInteger(value,"completedBootMs") ?: return)
        }
        for(hint in hints) {
            val group=groups.getValue(hint.group)
            if(group.current==null || group.selectionToken!=hint.token || hint.sequence<=group.hintSequence ||
                hint.completed>now || now-hint.completed>30_000)continue
            group.hintSequence=hint.sequence
            group.urgentRecheck=true
            group.nextAt=minOf(group.nextAt,now)
            group.improvement="";group.improvementPath=null;group.improvementCount=0
        }
    }
    fun report(raw:JSONObject,now:Long,dispatch:(String)->Unit) {
        try { reportCurrent(raw,now,dispatch) } finally {publishSearch()}
    }
    /** A native scope change revokes selected paths even when Android's route
     * scope did not change. Negative evidence and admission debt stay owned.
     * An old pending command remains a tombstone until a current idle report
     * proves the actual native probe-worker has exited; configure is not ACK. */
    private fun nativeOwnerChanged(now:Long) {
        drainingSince=pending?.startedAt ?: drainingSince ?: now
        pendingAdmission=null
        groups.values.forEach {
            it.frontier=null;it.current=null;it.measuredAt=0;it.latency=0;it.nextAt=now;it.exploreAt=0
            it.improvement="";it.improvementPath=null;it.improvementCount=0;it.recheckFailed=false;it.failure=null
            it.selectionToken=0;it.hintSequence=0;it.urgentRecheck=false;it.forceCheck=false
            it.search=AdaptiveSearchState.WAITING_CONTEXT
        }
        RouteSnapshot.adaptiveOwnerChanged(checkNotNull(routeScope),wire.groupTags().values.toSet())
        if(!checkNotNull(memory).revokeVerified(checkNotNull(context),now))retireOwner=true
    }
    /** invalidate/configure reset the native report before exposing a new
     * owner. An old result or traffic hint cannot establish that transition. */
    private fun nativeResetReport(raw:JSONObject):Boolean {
        if(listOf("request","group","receipt").any {raw.opt(it)!=""})return false
        if(raw.opt("code") !in setOf("idle","not_ready"))return false
        val hops=raw.optJSONArray("hops") ?: return false
        if(hops.length()!=0)return false
        return !raw.has("recheckHints") || raw.optJSONArray("recheckHints")?.length()==0
    }
    private fun reportCurrent(raw:JSONObject,now:Long,dispatch:(String)->Unit) {
        if(retireOwner || context==null)return
        if(!advanceClock(now) || raw.toString().length>32768)return
        val epoch=safeInteger(raw,"nativeEpoch") ?: return
        val scope=raw.opt("scope") as? String ?: return
        if(epoch<nativeEpoch || !scope.matches(Regex("[a-f0-9]{64}")))return
        val reportedPolicy=raw.optString("policyScope")
        if(reportedPolicy!=policyScope && reportedPolicy!=previousPolicyScope)return
        val ownerChanged=nativeEpoch>0 && observedNativeScope.isNotEmpty() && (epoch!=nativeEpoch || scope!=observedNativeScope)
        if(ownerChanged && !nativeResetReport(raw))return
        if(ownerChanged)nativeOwnerChanged(now)
        nativeEpoch=epoch;observedNativeScope=scope
        if(retireOwner)return
        if(drainingSince?.let {now-it>35_000}==true) {retireOwner=true;return}
        // JSONObject.optBoolean also accepts strings and defaults missing data
        // to false. Neither proves completion of the retained native worker.
        val running=raw.opt("running") as? Boolean
        val ready=raw.opt("ready") as? Boolean
        if(running==null || ready==null) {nativeRunning=true;nativeReady=false;nativeScope="";return}
        nativeRunning=running
        if(nativeRunning && raw.optLong("workAgeMs",0)>35_000) {retireOwner=true;return}
        if(reportedPolicy!=policyScope || !ready) {
            nativeReady=false;nativeScope=""
            groups.values.forEach {it.search=AdaptiveSearchState.WAITING_CONTEXT}
            if(now-lastCommandAt>=1000)send(JSONObject().put("command","configure").put("schemaVersion",1)
                .put("nativeEpoch",epoch).put("scope",policyScope).put("mode",mode.name),now,dispatch)
            return
        }
        nativeReady=true;nativeScope=scope
        if(drainingSince!=null) {
            if(nativeRunning || !nativeResetReport(raw) || raw.opt("code")!="idle")return
            // snapshot.running is the real busy owner, cleared only after
            // workerDone closes following cleanup and admission release.
            pending=null;drainingSince=null
        }
        groups.values.filter {it.search==AdaptiveSearchState.WAITING_CONTEXT}.forEach {it.search=AdaptiveSearchState.SEARCH_INCOMPLETE}
        recheckHints(raw,now)
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
            work.checkPlan=RouteSnapshot.adaptiveDiagnostic(currentScope,wire.groupTags().getValue(work.group),raw.optJSONObject("checkPlan"),"TRUE")
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
            if(!raw.optBoolean("groupSelected") || raw.optString("receipt")!=work.receipt)return
            // Only an independently verified replacement with a successful
            // previous-selection-bound native commit attributes the old failure.
            work.recovery?.takeIf {it==recoveryFailure(group,work,now)}?.let {
                memory?.record(checkNotNull(context),key(work.group,it.path),it.attempt,now,ProbeVerdict.CONFIRMED_PATH_FAILURE)
            }
            val changed=group.current?.id!=work.path.id
            group.current=work.path;group.measuredAt=now;group.latency=work.latency;group.nextAt=now+maintenanceCadence
            group.selectionToken=safeInteger(raw,"selectionToken") ?: 0;group.hintSequence=0;group.urgentRecheck=false;group.forceCheck=false
            if(changed || group.exploreAt==0L)group.exploreAt=now+300_000
            group.improvement="";group.improvementPath=null;group.improvementCount=0;group.recheckFailed=false;group.failure=null
            memory?.record(checkNotNull(context),key(work.group,work.path),work.attempt,now,ProbeVerdict.VERIFIED)
            group.search=AdaptiveSearchState.VERIFIED
            RouteSnapshot.adaptive(currentScope,wire.groupTags().getValue(work.group),true,"ok",work.latency,work.path.hops,work.checkPlan)
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
                group.urgentRecheck=false
                group.recheckFailed=code!="probe_unavailable"
                group.failure=if(code=="check_failed")CurrentFailure(work.path,work.attempt,checkedAt,nativeEpoch,nativeScope) else null
                if(code=="check_failed") {group.improvement="";group.improvementPath=null;group.improvementCount=0}
            } else if(group.current==null) {group.failure=null;group.recheckFailed=false}
            group.nextAt=now+5000
            if(group.current==null || group.current?.id==work.path.id) {
                group.search=AdaptiveSearchState.SEARCH_INCOMPLETE
                RouteSnapshot.adaptive(currentScope,wire.groupTags().getValue(work.group),false,code,null,emptyList(),
                    RouteSnapshot.adaptiveDiagnostic(currentScope,wire.groupTags().getValue(work.group),raw.optJSONObject("checkPlan"),if(code=="probe_unavailable")"UNKNOWN" else "FALSE"))
            }
        } else if(work.action=="discard" && code=="discarded") {
            // A second independent fresh measurement is needed before a latency switch.
            group.nextAt=if(group.improvement==work.path.id)now+5000 else minOf(now+maintenanceCadence,group.measuredAt+maintenanceCadence)
        } else if(code !in setOf("commit_rejected","discarded"))return
        pending=null
        markSearch(work.group,AdaptiveSearchState.SEARCH_INCOMPLETE)
    }
    private fun key(group:String,path:PlannedPath)=PathHealthKey(path.id,checkNotNull(wire.graph.groupInfo(group)).intent,group)
    fun tick(now:Long,unmetered:Boolean,allowExplore:Boolean,dispatch:(String)->Unit) {
        tickGuarded(now,unmetered,allowExplore,{true},dispatch)
    }
    fun tickGuarded(now:Long,unmetered:Boolean,allowExplore:Boolean,isCurrent:()->Boolean,dispatch:(String)->Unit) {
        // Existing virtual fixtures retain their two-field Unit dispatcher.
        try {tickCurrent(now,unmetered,allowExplore,isCurrent) {command,_->
            dispatch(JSONObject().put("kind","adaptive").put("commandJson",command.toString()).toString());true
        }} finally {publishSearch()}
    }
    fun tickBudgeted(now:Long,unmetered:Boolean,allowExplore:Boolean,isCurrent:()->Boolean,
        handoff:(String,Long)->Boolean) {
        try {tickCurrent(now,unmetered,allowExplore,isCurrent) {command,latest->
            handoff(AdaptiveHandoff.frame(command,latest),latest)
        }} finally {publishSearch()}
    }
    private fun tickCurrent(now:Long,unmetered:Boolean,allowExplore:Boolean,isCurrent:()->Boolean,
        handoff:(JSONObject,Long)->Boolean) {
        val current= context ?: return
        if(retireOwner || !advanceClock(now))return
        if(drainingSince?.let {now-it>35_000}==true) {retireOwner=true;return}
        if(!nativeReady || nativeScope.isEmpty() || nativeRunning || drainingSince!=null || pending!=null || now-lastCommandAt<1000)return
        pendingAdmission?.let {
            if(now-it.startedAt<=12_000)return
            // A timed-out reservation cannot dispatch later. The storage owner
            // still retains its real busy slot until its I/O actually exits.
            pendingAdmission=null
        }
        if(!runCatching {isCurrent()}.getOrDefault(false))return
        if(!budget.canStart(now,routine=false)) {
            if(budget.invalidated())retireOwner=true
            order.forEach {markSearch(it,AdaptiveSearchState.BUDGET_WAIT)}
            return
        }
        val rotated=order.drop(groupCursor)+order.take(groupCursor)
        val due=rotated.filter {id->val g=groups.getValue(id)
            val recovery=g.current==null || g.recheckFailed || g.urgentRecheck
            now>=g.nextAt && (recovery || budget.canStart(now,routine=true)) &&
            (recovery || g.forceCheck || now-g.measuredAt>=maintenanceCadence || unmetered && allowExplore && now>=g.exploreAt || g.improvement.isNotEmpty())}
        if(due.isEmpty())return
        // Recovery I/O precedes routine I/O, but a group that consumed only a
        // CPU quantum must let every other due group try before competing
        // again. Force cannot erase this bounded fair-round debt.
        val unserved=due.filter {it !in cpuYields}
        val round=if(unserved.isNotEmpty())unserved else due.also {cpuYields.clear()}
        val groupID=round.firstOrNull {id->val g=groups.getValue(id);g.current==null || g.recheckFailed || g.urgentRecheck}
            ?: round.first()
        val group=groups.getValue(groupID)
        markSearch(groupID,AdaptiveSearchState.SEARCH_INCOMPLETE)
        // A bounded CPU quantum must yield even when it cannot emit/dispatch
        // a candidate. Only rotating on I/O can starve other due groups.
        groupCursor=(order.indexOf(groupID)+1)%order.size
        cpuYields.add(groupID)
        val routine=group.current!=null && !group.recheckFailed && !group.urgentRecheck
        val explore=routine && !group.forceCheck && unmetered && allowExplore && now>=group.exploreAt
        val recheck=group.current?.takeIf {!explore && !group.recheckFailed && (group.forceCheck || group.urgentRecheck || now-group.measuredAt>=maintenanceCadence)}
        val retryImprovement=group.improvementPath?.takeIf {!group.urgentRecheck && !group.forceCheck}
        var candidate=retryImprovement?.takeIf {now-group.measuredAt<=120_000} ?: recheck
        var exhausted=false
        if(candidate==null) {
            if(group.frontier==null) {
                group.frontier=wire.graph.frontier(groupID,current,mode,emptyList(),now,600_000)
                group.emptyPages=0;group.onlyFenced=true;group.firstRetryAt=null
            }
            var frontier=checkNotNull(group.frontier)
            var batch=frontier.next(current,now,1,64)
            if(batch.invalidated) {
                // Only a TTL-expired, identically owned metadata cursor can
                // resume. Context/clock changes discard the hint, never borrow
                // native proofs or reset admissions, memory or selected paths.
                val position=frontier.checkpoint(current,now)
                val resumed=position?.let {wire.graph.resumeFrontier(groupID,current,mode,emptyList(),now,600_000,it)}
                if(resumed==null) {
                    group.frontier=null
                    group.nextAt=now+if(group.current==null)60_000 else 300_000
                    return
                }
                frontier=resumed;group.frontier=frontier
                // The invalidated call scanned nothing. This is still one
                // ordinary64-slot CPU quantum and at most one I/O attempt.
                batch=frontier.next(current,now,1,64)
            }
            exhausted=batch.exhausted
            if(exhausted)group.frontier=null
            candidate=batch.paths.firstOrNull()
            if(candidate==null) {
                if(!exhausted && group.current==null) {
                    // There are unvisited signed positions. Yield one bounded CPU
                    // page and back off while no eligible path has been found.
                    val delay=1000L shl group.emptyPages
                    group.emptyPages=(group.emptyPages+1).coerceAtMost(4)
                    group.nextAt=now+delay
                } else {
                    group.nextAt=afterScan(group,now)
                }
                return
            }
            group.emptyPages=0
        }
        val health=checkNotNull(memory).view(current,key(groupID,candidate),now)
        if(health.readiness in setOf(PathReadiness.QUARANTINED,PathReadiness.HALF_OPEN,PathReadiness.CONFIG_CHANGE_REQUIRED)) {
            health.retryAtMs?.let {retry->group.firstRetryAt=minOf(group.firstRetryAt ?: retry,retry)}
            group.nextAt=if(exhausted && group.current==null && group.onlyFenced)afterScan(group,now) else now+1000
            return
        }
        group.onlyFenced=false
        attempt++
        val request=UUID.randomUUID().toString()
        val admission=PendingAdmission(request,groupID,candidate,attempt,now,current,routeScope,mode,nativeEpoch,nativeScope,
            boundPolicy?.leaseDeadlineElapsed,explore,isCurrent,handoff)
        pendingAdmission=admission
        markSearch(groupID,AdaptiveSearchState.BUDGET_WAIT)
        val queued=try {budget.request(now,routine) {result->
            try {admitted(admission,result)} finally {publishSearch()}
        }} catch(_:Exception) {false}
        if(!queued && pendingAdmission===admission)pendingAdmission=null
    }
    private fun afterScan(group:Group,now:Long):Long {
        if(group.current!=null)return now+300_000
        val retry=group.firstRetryAt
        return if(group.onlyFenced && retry!=null)maxOf(now+1000,retry) else now+60_000
    }
    private fun admissionTime(work:PendingAdmission,result:AdaptiveStartAdmission.Result,after:Long):Long? {
        val now=try {budget.currentTimeMs()}catch(_:Exception) {return null}
        if(now !in after..Decision.MAX_TIME || now<work.startedAt || now-work.startedAt>12_000 || now>result.latestStartMs ||
            result.latestStartMs-now>AdaptiveProbeBudget.MAX_HANDOFF_MS || !advanceClock(now))return null
        if(boundPolicy?.let {now>=it.leaseDeadlineElapsed}==true) {retireOwner=true;return null}
        if(work.leaseDeadlineElapsed?.let {now>=it}==true)return null
        return now
    }
    private fun admitted(work:PendingAdmission,result:AdaptiveStartAdmission.Result) {
        if(pendingAdmission!==work)return
        pendingAdmission=null
        if(!result.allowed || retireOwner || context!=work.context || routeScope!=work.scope || mode!=work.mode ||
            !nativeReady || nativeRunning || nativeEpoch!=work.nativeEpoch || nativeScope!=work.nativeScope || pending!=null) return
        // Refresh current authority before taking half-open ownership or
        // creating native pending state, not only in the final Unit dispatch.
        if(!runCatching {work.isCurrent()}.getOrDefault(false))return
        // Policy guards may read or suspend. A pre-guard timestamp cannot
        // authorize a later effect after the original handoff/lease expired.
        val now=admissionTime(work,result,result.observedAtMs) ?: return
        val group=groups.getValue(work.group)
        val health=checkNotNull(memory).view(work.context,key(work.group,work.path),now)
        if(health.readiness in setOf(PathReadiness.QUARANTINED,PathReadiness.HALF_OPEN,PathReadiness.CONFIG_CHANGE_REQUIRED))return
        val command=frame("start").put("request",work.request).put("group",work.group).put("hops",JSONArray(work.path.hops))
        val next=Pending(work.request,work.group,work.path,work.attempt,work.startedAt,work.nativeEpoch,work.nativeScope)
        val latest=minOf(result.latestStartMs,work.startedAt+11_999,work.leaseDeadlineElapsed?.minus(1) ?: Decision.MAX_TIME)
        val at=admissionTime(work,result,now) ?: return
        if(at>latest)return
        // Take retry ownership only after durable admission and local fences.
        if(health.readiness==PathReadiness.REVALIDATE && health.retryAtMs!=null &&
            !checkNotNull(memory).beginRetry(work.context,key(work.group,work.path),work.attempt,at))return
        pending=next
        val handedOff=try {work.handoff(command,latest)}catch(_:Exception) {false}
        if(!handedOff) {
            if(pending===next)pending=null
            group.nextAt=at+5_000
            markSearch(work.group,AdaptiveSearchState.BUDGET_WAIT)
            return
        }
        cpuYields.remove(work.group)
        group.forceCheck=false
        lastCommandAt=at
        markSearch(work.group,AdaptiveSearchState.SEARCHING)
        if(work.explore)group.exploreAt=at+300_000
    }
    /** A closed host rejection proves only that this start was not passed to
     * JNI. It never supplies a route measurement, selection or bad-proxy fact. */
    fun rejectAdmission(rejection:AdaptiveHandoff.Rejection,now:Long) {
        try {
            val work=pending ?: return
            if(work.action!="probe" || rejection.request!=work.request || rejection.nativeEpoch!=work.nativeEpoch ||
                rejection.scope!=work.nativeScope || nativeEpoch!=work.nativeEpoch || nativeScope!=work.nativeScope ||
                now<work.startedAt || !advanceClock(now))return
            pending=null
            groups.getValue(work.group).nextAt=now+5_000
            markSearch(work.group,AdaptiveSearchState.BUDGET_WAIT)
            // An already acquired retry keeps its existing bounded 15s fence;
            // local cancellation must not erase its cooldown or invent failure.
        } finally {publishSearch()}
    }
    fun force() {groups.values.forEach {it.nextAt=0;it.forceCheck=it.current!=null}}
    fun requestGroupCheck(scope:RouteScope, tag:String):Boolean {
        if(scope!=routeScope || retireOwner) return false
        val id=wire.groupTags().entries.singleOrNull {it.value==tag}?.key ?: return false
        val group=groups.getValue(id)
        group.nextAt=0
        group.forceCheck=group.current!=null
        return true
    }
    fun requiresRetirement()=retireOwner
    override fun toString()="ManagedAdaptiveRoutes([redacted])"
    companion object {
        private val checkedFailures=setOf("dial_failed","check_timeout","tls_failed","ssh_banner_mismatch","request_failed","response_failed","exit_evidence_invalid","http_response_mismatch")
        fun read(raw:String?,budget:AdaptiveProbeBudget=AdaptiveProbeBudget()):ManagedAdaptiveRoutes? =
            read(raw) {ImmediateAdaptiveStartAdmission(budget)}
        fun read(raw:String?,admission:()->AdaptiveStartAdmission):ManagedAdaptiveRoutes? {
            if(raw==null)return null
            val root=Decision.json.parseToJsonElement(raw).jsonObject
            val adaptive=root["adaptive_routes"] ?: return null
            val wire=AdaptiveRuntime.decode(checkNotNull(protectedAdaptiveWire(raw)))
            val tag=runCatching {JSONObject(raw).getJSONObject("route").getString("final")}.getOrDefault("")
            return ManagedAdaptiveRoutes(wire,tag,admission())
        }
    }
}
