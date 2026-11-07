package io.syn443.android.vpn

import android.os.SystemClock
import io.syn443.decision.Context
import io.syn443.decision.FailoverAdmission
import io.syn443.decision.ProbeVerdict
import io.syn443.decision.VerifiedPathSample
import io.syn443.recovery.RouteEvidence
import io.syn443.recovery.RouteObservation
import io.syn443.recovery.RouteScope
import io.syn443.recovery.RouteState
import io.syn443.recovery.RouteActivation
import org.json.JSONArray
import org.json.JSONObject
import java.net.URI
import java.util.UUID

/** Controller RAM only. Labels/targets are never written to events or native output. */
object RouteSnapshot {
    internal data class FailoverCommand(val receipt:String,val checkId:String,val group:String,val previous:String,val candidate:String)
    private data class Row(val id: String,val tag: String,val type: String,val required: Boolean,val checks: JSONArray,val chain: List<String>,val rules: Int)
    private var rows = emptyList<Row>()
    private var observations = emptyMap<String,RouteObservation>()
    private var codes = emptyMap<String,String>()
    private var timings = emptyMap<String,Long>()
    private var receipts = emptyMap<String,String>()
    private var live: RouteScope? = null
    private var current: RouteScope? = null
    private var pending = ""
    private var startedAt = 0L
    private var lastStarted = -60_000L
    private var queued = emptySet<String>()
    private var revision = ""
    private var activationAttempt:Pair<RouteScope,Long>?=null
    private var failover:ManagedFailoverPlan?=null
    private var failoverAdmission:FailoverAdmission?=null
    private var batchSequence=0L
    private var completedReceipt=""
    private var confirmingFailure=false
    private val methods=setOf("tcp","tls","https_204","ssh_banner")
    private var measuredPaths=emptyMap<String,JSONArray>()
    private val codesAllowed=setOf("ok","outbound_unavailable","cancelled","dial_failed","unsupported","ssh_banner_mismatch","tls_failed","request_failed","response_failed","http_response_mismatch","path_changed","check_timeout","probe_unavailable")
    private val completedProbeFailures=setOf("dial_failed","ssh_banner_mismatch","tls_failed","request_failed","response_failed","http_response_mismatch","check_timeout")
    fun validate(config: JSONObject) {
        if(!config.has("route_checks"))return
        val settings=config.getJSONArray("route_checks")
        require(settings.length()<=16)
        require(settings.toString().toByteArray(Charsets.UTF_8).size<=24_000)
        val outbounds=config.getJSONArray("outbounds")
        val tags=(0 until outbounds.length()).map {outbounds.getJSONObject(it).getString("tag")}.toSet()
        val seen=mutableSetOf<String>()
        for(i in 0 until settings.length()) {
            val item=settings.getJSONObject(i)
            require(item.keys().asSequence().all {it in setOf("outbound","required","checks")})
            require(item.getString("outbound") in tags && seen.add(item.getString("outbound")))
            if(item.has("required")) require(item.get("required") is Boolean)
            val checks=item.getJSONArray("checks");require(checks.length() in 1..4)
            for(j in 0 until checks.length()) {
                val check=checks.getJSONObject(j)
                require(check.keys().asSequence().toSet()==setOf("method","target"))
                val method=check.getString("method");val target=check.getString("target")
                require(method in methods && target.length in 1..2048)
                val uri=if(method in setOf("tls","https_204")) URI(target) else URI("tcp://$target")
                require(uri.host!=null && uri.userInfo==null && uri.fragment==null)
                require(if(method in setOf("tls","https_204")) uri.scheme=="https" && (uri.port==-1 || uri.port in 1..65535) else uri.port in 1..65535 && uri.rawPath.isNullOrEmpty() && uri.query==null)
            }
        }
    }
    @Synchronized fun configure(raw:String?, hash:String) {
        if(revision==hash && rows.isNotEmpty()) return
        val config=JSONObject(raw ?: """{"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}""")
        validate(config)
        failover=ManagedFailoverPlan.read(config)
        val outbounds=config.getJSONArray("outbounds")
        val tags=(0 until outbounds.length()).associate {outbounds.getJSONObject(it).getString("tag") to "route-${it+1}"}
        val profiles=config.optJSONArray("route_checks") ?: JSONArray()
        val byTag=(0 until profiles.length()).associate {profiles.getJSONObject(it).getString("outbound") to profiles.getJSONObject(it)}
        val route=config.optJSONObject("route");val rules=route?.optJSONArray("rules") ?: JSONArray()
        rows=(0 until outbounds.length()).map {i->
            val o=outbounds.getJSONObject(i);val tag=o.getString("tag");val p=byTag[tag]
            val checks=p?.getJSONArray("checks") ?: JSONArray()
            val seen=mutableSetOf<String>();val chain=mutableListOf<String>()
            var cursor:JSONObject?=o
            while(cursor!=null && seen.add(cursor.getString("tag")) && chain.size<8) {
                chain+=checkNotNull(tags[cursor.getString("tag")])
                val next=cursor.optString("detour");cursor=(0 until outbounds.length()).map {outbounds.getJSONObject(it)}.firstOrNull {it.optString("tag")==next}
            }
            Row(checkNotNull(tags[tag]),tag,o.getString("type"),p?.optBoolean("required")==true,checks,chain,
                (0 until rules.length()).count {rules.optJSONObject(it)?.optString("outbound")==tag} + if(route?.optString("final")==tag) 1 else 0)
        }
        revision=hash;invalidate()
    }
    @Synchronized fun invalidate() {current=null;pending="";queued=emptySet();observations=emptyMap();codes=emptyMap();timings=emptyMap();receipts=emptyMap();measuredPaths=emptyMap();lastStarted=-60_000;activationAttempt=null
        completedReceipt="";failoverAdmission=null;batchSequence=0;confirmingFailure=false}
    @Synchronized fun due(intervalMs:Long=60_000):Boolean {
        require(intervalMs in 10_000..60_000)
        return rows.any {it.checks.length()>0} && SystemClock.elapsedRealtime()-lastStarted>=intervalMs
    }
    @Synchronized fun owner(scope:RouteScope?){if(live!=scope){invalidate();live=scope}}
    @Synchronized fun prepareActivation(scope:RouteScope,startedElapsed:Long):Boolean {
        require(startedElapsed>=0)
        val attempt=scope to startedElapsed
        if(activationAttempt==attempt)return false
        invalidate();activationAttempt=attempt
        return true
    }
    @Synchronized fun activation(scope:RouteScope,startedElapsed:Long=0):RouteActivation {
        require(startedElapsed>=0)
        if(revision!=scope.config || live!=scope)return RouteActivation.WAIT
        val values=read(true,true,scope).getJSONArray("routes")
        return RouteEvidence.activation((0 until values.length()).map {i->
            val row=values.getJSONObject(i)
            val state=if((observations[row.getString("id")]?.elapsedMs ?: -1)<startedElapsed)RouteState.UNVERIFIED
                else RouteState.valueOf(row.getString("state").uppercase(java.util.Locale.ROOT))
            row.getBoolean("required") to state
        })
    }
    @Synchronized fun accepts(only:String?)=rows.any {(only==null || it.id==only) && it.checks.length()>0}
    @Synchronized fun view(status:JSONObject):JSONObject = read(status.optBoolean("desiredOn"),status.optBoolean("engineActive") && live!=null,
        live?.copy(intent=status.optLong("generation"),network=status.optLong("networkEpoch")))
    private fun failoverContext(scope:RouteScope) =
        Context(scope.network,scope.activation,"active","wifi-internal-v1",scope.intent,scope.config)

    @Synchronized fun request(scope:RouteScope, only:String?=null, force:Boolean=false, deferCoolingReserves:Boolean=false):String? {
        val now=SystemClock.elapsedRealtime()
        if(pending.isNotEmpty() && now-startedAt<35_000) return null
        if(!force && now-lastStarted<60_000) return null
        if(only!=null && rows.none {it.id==only})return null
        val admission=failoverAdmission?.takeIf {deferCoolingReserves && only==null && live==scope}
        val context=failoverContext(scope)
        val selected=rows.filter {row->
            (only==null || row.id==only) && row.checks.length()>0 &&
                (row.required || admission?.deferReserveProbe(context,row.tag,now)!=true)
        }
        if(selected.isEmpty())return null
        // Never stamp a previous observation with this new scope.
        current=scope;pending=UUID.randomUUID().toString();startedAt=now;lastStarted=now;queued=selected.map {it.id}.toSet()
        completedReceipt="";batchSequence++
        return JSONObject().put("request",pending).put("routes",JSONArray(selected.map {row->JSONObject().put("id",row.id).put("outbound",row.tag).put("checks",row.checks)})).toString()
    }
    @Synchronized fun update(scope:RouteScope,raw:String):Boolean {
        if(raw.length>16_384 || current!=scope || pending.isEmpty())return false
        val value=JSONObject(raw)
        if(value.optString("request")!=pending) return false
        val running=value.getBoolean("running")
        val results=value.getJSONArray("results");require(results.length()<=queued.size)
        val now=SystemClock.elapsedRealtime();val seen=mutableSetOf<String>()
        var nextObservations=observations;var nextCodes=codes;var nextTimings=timings;var nextReceipts=receipts;var nextPaths=measuredPaths
        for(i in 0 until results.length()) {
            val r=results.getJSONObject(i);val id=r.getString("id");val code=r.getString("code")
            require(id in queued && seen.add(id) && code in codesAllowed && r.getLong("elapsedMs") in 0..35_000)
            val complete=r.getBoolean("complete");val ok=r.getBoolean("ok")
            val sampled=r.getLong("sampledElapsedMs");require(sampled in 0..now)
            require(!ok || (complete && code=="ok"))
            val path=r.optJSONArray("path") ?: JSONArray()
            require(path.length()<=64 && (0 until path.length()).all {n->rows.any {it.id==path.getString(n)}})
            // First receipt time is retained across repeated heartbeat snapshots.
            if(receipts[id]!=pending) {
                nextObservations=nextObservations+(id to RouteObservation(scope,sampled,complete,ok));nextCodes=nextCodes+(id to code);nextTimings=nextTimings+(id to r.getLong("elapsedMs"));nextReceipts=nextReceipts+(id to pending)
                nextPaths=nextPaths+(id to path)
            }
        }
        observations=nextObservations;codes=nextCodes;timings=nextTimings;receipts=nextReceipts;measuredPaths=nextPaths
        if(!running) {
            for(id in queued-seen) {observations=observations+(id to RouteObservation(scope,now,false,false));codes=codes+(id to "cancelled")}
            completedReceipt=pending
            pending="";queued=emptySet()
        }
        return true
    }
    @Synchronized fun cancelled(resetInterval:Boolean=false){pending="";queued=emptySet();current=null;completedReceipt="";confirmingFailure=false;if(resetInterval)lastStarted=-60_000}
    @Synchronized internal fun confirmingFailover(scope:RouteScope):Boolean=live==scope && confirmingFailure
    @Synchronized internal fun hasManagedFailover(scope:RouteScope):Boolean=live==scope && failover!=null && completedReceipt.isNotEmpty()
    @Synchronized internal fun failoverAdvice(scope:RouteScope):FailoverCommand? {
        val plan=failover ?: return null
        val receipt=completedReceipt
        if(live!=scope || current!=scope || receipt.isEmpty())return null
        val group=rows.singleOrNull {it.tag==plan.selector} ?: return null
        if(receipts[group.id]!=receipt)return null
        val path=measuredPaths[group.id] ?: return null
        if(path.length()<2 || path.getString(0)!=group.id)return null
        val selected=rows.singleOrNull {it.id==path.getString(1) && it.tag in plan.members} ?: return null
        if(path.length()!=selected.chain.size+1 || selected.chain.indices.any {path.optString(it+1)!=selected.chain[it]})return null
        val groupSample=observations[group.id]?.takeIf {it.scope==scope} ?: return null
        val now=SystemClock.elapsedRealtime()
        val comparison="internal-check"
        val reserves=rows.filter {it.tag in plan.members && it.id!=selected.id && receipts[it.id]==receipt}.mapNotNull {row->
            val sample=observations[row.id]?.takeIf {it.scope==scope && it.complete && now-it.elapsedMs in 0L until 15_000} ?: return@mapNotNull null
            val measured=measuredPaths[row.id] ?: return@mapNotNull null
            if(measured.length()!=row.chain.size || row.chain.indices.any {measured.optString(it)!=row.chain[it]})return@mapNotNull null
            val verdict=when {
                sample.ok -> ProbeVerdict.VERIFIED
                codes[row.id] in completedProbeFailures -> ProbeVerdict.CONFIRMED_PATH_FAILURE
                else -> return@mapNotNull null
            }
            VerifiedPathSample(row.tag,receipt,comparison,sample.elapsedMs,verdict,timings[row.id] ?: 0)
        }
        val verdict=when {
            groupSample.complete && groupSample.ok -> ProbeVerdict.VERIFIED
            groupSample.complete && codes[group.id] in completedProbeFailures &&
                reserves.any {it.verdict==ProbeVerdict.VERIFIED} -> ProbeVerdict.CONFIRMED_PATH_FAILURE
            else -> ProbeVerdict.UNKNOWN
        }
        confirmingFailure=verdict==ProbeVerdict.CONFIRMED_PATH_FAILURE
        val context=failoverContext(scope)
        val admission=failoverAdmission ?: FailoverAdmission(context,plan.members.toSet(),comparison,
            rows.filter {it.tag in plan.members}.associate {it.tag to (it.chain.size-1).coerceIn(0,2)})
            .also {failoverAdmission=it}
        val choice=admission.decide(context,batchSequence,receipt,now,selected.tag,
            VerifiedPathSample(selected.tag,receipt,comparison,groupSample.elapsedMs,verdict,timings[group.id] ?: 0),reserves) ?: return null
        val candidate=rows.singleOrNull {it.tag==choice.candidate} ?: return null
        return FailoverCommand(choice.receipt,candidate.id,group.tag,choice.previous,choice.candidate)
    }
    @Synchronized fun read(on:Boolean,ready:Boolean,scope:RouteScope?):JSONObject {
        val now=SystemClock.elapsedRealtime()
        if(pending.isNotEmpty() && now-startedAt>=35_000) {
            current?.let {s->for(id in queued) if(receipts[id]!=pending) {observations=observations+(id to RouteObservation(s,now,false,false));codes=codes+(id to "cancelled")}}
            pending="";queued=emptySet()
        }
        val values=rows.map {row->
            val sample=observations[row.id]
            val state=if(scope==null) {if(on) RouteState.UNAVAILABLE else RouteState.OFF} else RouteEvidence.classify(on,ready,scope,sample,row.id in queued,now)
            JSONObject().put("id",row.id).put("label",row.tag.take(80)).put("type",row.type).put("required",row.required).put("state",state.name.lowercase(java.util.Locale.ROOT))
                .put("configured",row.checks.length()>0).put("chain",JSONArray(row.chain)).put("routingRules",row.rules)
                .put("measuredPath",if(sample?.scope==scope)measuredPaths[row.id] ?: JSONArray() else JSONArray())
                .put("reason",if(sample?.scope==scope)codes[row.id] ?: "not_checked" else "not_checked")
                .put("ageMs",if(sample!=null && sample.scope==scope && now>=sample.elapsedMs)now-sample.elapsedMs else JSONObject.NULL)
                .put("latencyMs",if(sample?.scope==scope)timings[row.id] ?: JSONObject.NULL else JSONObject.NULL)
                .also {value->
                    if(scope!=null && scope==live)failoverAdmission?.cooldown(row.tag,now)?.let {cooldown->
                        value.put("selectionState",cooldown.readiness.name.lowercase(java.util.Locale.ROOT))
                            .put("retryInMs",(checkNotNull(cooldown.retryAtMs)-now).coerceAtLeast(0))
                    }
                }
        }
        return JSONObject().put("routes",JSONArray(values)).put("running",pending.isNotEmpty()).put("requiredReady",RouteEvidence.requiredReady(values.map {it.getBoolean("required") to RouteState.valueOf(it.getString("state").uppercase(java.util.Locale.ROOT))}))
    }
}
