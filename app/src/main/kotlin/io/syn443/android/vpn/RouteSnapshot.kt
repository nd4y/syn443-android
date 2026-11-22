package io.syn443.android.vpn

import android.net.InetAddresses
import android.os.SystemClock
import io.syn443.decision.Context
import io.syn443.decision.FailoverAdmission
import io.syn443.decision.FailoverAlgorithm
import io.syn443.decision.ProbeVerdict
import io.syn443.decision.VerifiedPathSample
import io.syn443.recovery.RouteEvidence
import io.syn443.recovery.RouteFailureCause
import io.syn443.recovery.RouteObservation
import io.syn443.recovery.RouteScope
import io.syn443.recovery.RouteState
import io.syn443.recovery.RouteActivation
import io.syn443.policy.RouteCheckProfile
import org.json.JSONArray
import org.json.JSONObject
import java.net.Inet6Address
import java.net.URI
import java.util.UUID

/** Controller RAM only. Labels/targets are never written to events or native output. */
object RouteSnapshot {
    internal data class FailoverCommand(val receipt:String,val checkId:String,val group:String,val previous:String,val candidate:String)
    private data class Row(val id: String,val tag: String,val type: String,val required: Boolean,val checks: JSONArray,val profile: RouteCheckProfile?,val chain: List<String>,val rules: Int)
    private fun Row.configured() = profile != null || checks.length() > 0
    private var rows = emptyList<Row>()
    private var observations = emptyMap<String,RouteObservation>()
    private var searchScope:RouteScope?=null
    private var searches=emptyMap<String,AdaptiveSearchState>()
    private var codes = emptyMap<String,String>()
    private var timings = emptyMap<String,Long>()
    private var durations = emptyMap<String,RouteProbeDurations>()
    private val applicationMethods = setOf("https_204", "https_status", "https_exit_ip", "https_exit_country", "ssh_banner")
    private fun Row.hasSingleApplicationCheck() =
        profile == null && checks.length() == 1 && checks.getJSONObject(0).getString("method") in applicationMethods
    private var receipts = emptyMap<String,String>()
    private var live: RouteScope? = null
    private var current: RouteScope? = null
    private var validatedBatch: RouteScope? = null
    private var pending = ""
    private var startedAt = 0L
    private var lastStarted = -60_000L
    private var queued = emptySet<String>()
    private var revision = ""
    private var adaptiveConfig = false
    private var manualContext: String? = null
    private fun Row.individuallyCheckable() = configured() && (!adaptiveConfig || type=="syn443-adaptive")
    private var activationAttempt:Pair<RouteScope,Long>?=null
    private var failover:ManagedFailoverPlan?=null
    private data class ReserveRecoveryHint(val selected: String, val observedAt: Long)
    private var reserveRecovery: ReserveRecoveryHint? = null
    private val transientCauses = setOf(RouteFailureCause.CONNECTION_REFUSED, RouteFailureCause.DNS_TIMEOUT, RouteFailureCause.TIMEOUT)
    private fun transientDial(code:String?, observation:RouteObservation) =
        code=="dial_failed" && observation.cause in transientCauses
    private var failoverAdmission:Pair<FailoverAlgorithm,FailoverAdmission>?=null
    private var failoverShadow:FailoverShadow?=null
    private var batchSequence=0L
    private var completedReceipt=""
    private var confirmingFailure=false
    private var skippedMeteredReserves=false
    private val methods=setOf("tcp","tls","https_204","ssh_banner","https_exit_ip","https_exit_country","https_status")
    private val tlsMethods=setOf("tls","https_204","https_exit_ip","https_exit_country","https_status")
    private val ipv4Literal=Regex("(?:0|[1-9][0-9]{0,2})(?:\\.(?:0|[1-9][0-9]{0,2})){3}")
    private val ipv6Literal=Regex("[0-9a-fA-F:.]{2,45}")
    private var measuredPaths=emptyMap<String,JSONArray>()
    private var checkPlans=emptyMap<String,JSONObject>()
    private val codesAllowed=setOf("ok","outbound_unavailable","cancelled","dial_failed","unsupported","ssh_banner_mismatch","tls_failed","request_failed","response_failed","http_response_mismatch","exit_evidence_invalid","exit_ip_mismatch","exit_country_mismatch","path_changed","check_timeout","probe_unavailable")
    private val completedProbeFailures=setOf("dial_failed","ssh_banner_mismatch","tls_failed","request_failed","response_failed","http_response_mismatch","check_timeout")

    private fun validExitIP(value: Any?): Boolean {
        if (value !is String) return false
        val ipv6 = ':' in value
        if (!(if (ipv6) ipv6Literal else ipv4Literal).matches(value)) return false
        return runCatching { (InetAddresses.parseNumericAddress(value) is Inet6Address) == ipv6 }.getOrDefault(false)
    }

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
            require(item.keys().asSequence().all {it in setOf("outbound","required","checks","profile")})
            require(item.getString("outbound") in tags && seen.add(item.getString("outbound")))
            if(item.has("required")) require(item.get("required") is Boolean)
            if(RouteCheckPlans.profile(item)!=null)continue
            val checks=item.getJSONArray("checks");require(checks.length() in 1..4)
            for(j in 0 until checks.length()) {
                val check=checks.getJSONObject(j)
                val method=check.getString("method");val target=check.getString("target")
                val fields=when(method) {
                    "https_exit_ip" -> setOf("method","target","expected_ip")
                    "https_exit_country" -> setOf("method","target","expected_exit_class")
                    "https_status" -> setOf("method","target","http_method","expected_status")
                    else -> setOf("method","target")
                }
                require(check.keys().asSequence().toSet()==fields)
                if(method=="https_exit_ip")require(validExitIP(check.get("expected_ip")))
                if(method=="https_exit_country")require(check.get("expected_exit_class") in setOf("RU","NON_RU"))
                if(method=="https_status") {
                    require(check.get("http_method") in setOf("GET", "HEAD"))
                    val status = check.get("expected_status") as? Int
                    require(status != null && status in 200..599)
                }
                require(method in methods && target.length in 1..2048)
                val uri=if(method in tlsMethods) URI(target) else URI("tcp://$target")
                require(uri.host!=null && uri.userInfo==null && uri.fragment==null)
                require(if(method in tlsMethods) uri.scheme=="https" && (uri.port==-1 || uri.port in 1..65535) else uri.port in 1..65535 && uri.rawPath.isNullOrEmpty() && uri.query==null)
                if(method=="https_exit_country")require((uri.rawPath.isNullOrEmpty() || uri.rawPath=="/") && uri.rawQuery==null &&
                    target.all {it.code in 33..126} && '\\' !in target && '#' !in target && !uri.rawAuthority.endsWith(":"))
            }
        }
        RouteCheckPlans.requireConcrete(config)
    }
    @Synchronized fun configure(raw:String?, hash:String) {
        val config=JSONObject(raw ?: """{"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}""")
        if(raw!=null && RouteCheckPlans.hasProfiles(config))io.syn443.policy.RouteCheckProfiles.inspectEngine(raw)
        if(revision==hash && rows.isNotEmpty()) return
        validate(config)
        failover=ManagedFailoverPlan.read(config)
        val outbounds=config.getJSONArray("outbounds")
        val tags=(0 until outbounds.length()).associate {outbounds.getJSONObject(it).getString("tag") to "route-${it+1}"}
        val profiles=config.optJSONArray("route_checks") ?: JSONArray()
        val byTag=(0 until profiles.length()).associate {profiles.getJSONObject(it).getString("outbound") to profiles.getJSONObject(it)}
        val route=config.optJSONObject("route");val rules=route?.optJSONArray("rules") ?: JSONArray()
        rows=(0 until outbounds.length()).map {i->
            val o=outbounds.getJSONObject(i);val tag=o.getString("tag");val p=byTag[tag]
            val profile=p?.let {RouteCheckPlans.profile(it)}
            val checks=if(profile==null)p?.getJSONArray("checks") ?: JSONArray() else JSONArray()
            val seen=mutableSetOf<String>();val chain=mutableListOf<String>()
            var cursor:JSONObject?=o
            while(cursor!=null && seen.add(cursor.getString("tag")) && chain.size<8) {
                chain+=checkNotNull(tags[cursor.getString("tag")])
                val next=cursor.optString("detour");cursor=(0 until outbounds.length()).map {outbounds.getJSONObject(it)}.firstOrNull {it.optString("tag")==next}
            }
            Row(checkNotNull(tags[tag]),tag,o.getString("type"),p?.optBoolean("required")==true,checks,profile,chain,
                (0 until rules.length()).count {rules.optJSONObject(it)?.optString("outbound")==tag} + if(route?.optString("final")==tag) 1 else 0)
        }
        adaptiveConfig=config.has("adaptive_routes")
        revision=hash;invalidate()
    }
    /** Only the active configuration's concrete checks can authorize a native switch. */
    @Synchronized internal fun nativeSelectionPlan(configHash: String): String {
        val plan = failover?.takeIf { revision == configHash } ?: return ""
        val paths = rows.filter { it.tag in plan.members }.map { row ->
            RouteCheckPlans.wire(row.id,row.tag,row.checks,row.profile)
        }
        return JSONObject().put("selector", plan.selector).put("paths", JSONArray(paths)).toString().also {
            require(it.toByteArray(Charsets.UTF_8).size<=32768)
        }
    }

    @Synchronized fun invalidate() {current=null;validatedBatch=null;pending="";queued=emptySet();observations=emptyMap();searchScope=null;searches=emptyMap();codes=emptyMap();timings=emptyMap();durations=emptyMap();receipts=emptyMap();measuredPaths=emptyMap();checkPlans=emptyMap();lastStarted=-60_000;activationAttempt=null
        completedReceipt="";reserveRecovery=null;failoverAdmission=null;failoverShadow=null;batchSequence=0;confirmingFailure=false;skippedMeteredReserves=false;manualContext=null}
    @Synchronized fun due(intervalMs:Long=60_000):Boolean {
        require(intervalMs in 10_000..60_000)
        return rows.any {it.configured()} && SystemClock.elapsedRealtime()-lastStarted>=intervalMs
    }
    @Synchronized fun owner(scope:RouteScope?){if(live!=scope){invalidate();live=scope}}
    /** Coordinator-prepared diagnostics only; never route evidence. */
    @Synchronized internal fun adaptiveSearch(scope:RouteScope,states:Map<String,AdaptiveSearchState>) {
        if(scope!=live || states.size>16)return
        // Copy only configured adaptive rows. No graph IDs, paths, receipts or
        // native scopes are exposed by this additive diagnostic projection.
        searchScope=scope
        searches=rows.filter {it.type=="syn443-adaptive"}.mapNotNull {row->states[row.tag]?.let {row.id to it}}.toMap()
    }

    /** Native ownership revocation is not a failed route measurement. Retract
     * only these adaptive rows; ordinary/NetBird evidence and the Java owner
     * remain unchanged. Compatible negative cooldown lives in its own memory. */
    @Synchronized internal fun adaptiveOwnerChanged(scope:RouteScope,tags:Set<String>) {
        if(scope!=live || tags.size>16)return
        val ids=rows.filter {it.type=="syn443-adaptive" && it.tag in tags}.map {it.id}.toSet()
        observations=observations-ids;codes=codes-ids;timings=timings-ids;receipts=receipts-ids
        measuredPaths=measuredPaths-ids;checkPlans=checkPlans-ids;durations=durations-ids
    }

    /** Called only after the bound native adaptive owner reports a real result. */
    @Synchronized internal fun adaptiveDiagnostic(scope:RouteScope,tag:String,value:JSONObject?,expected:String):JSONObject? {
        if(scope!=live)return null
        val profile=rows.singleOrNull {it.tag==tag && it.type=="syn443-adaptive"}?.profile ?: return null
        return RouteCheckPlans.projection(value,profile,expected)
    }
    @Synchronized internal fun adaptive(scope:RouteScope,tag:String,ok:Boolean,code:String,latency:Long?,hops:List<String>,checkPlan:JSONObject?=null,receipt:String?=null,measuredAt:Long=SystemClock.elapsedRealtime()) {
        if(scope!=live || code !in setOf("ok","probe_unavailable","exit_mismatch","check_failed"))return
        val row=rows.singleOrNull {it.tag==tag && it.type=="syn443-adaptive"} ?: return
        observations=observations+(row.id to RouteObservation(scope,measuredAt,ok || code=="exit_mismatch" || code=="check_failed",ok))
        codes=codes+(row.id to code)
        timings = if (latency != null && latency in 0..30_000) timings + (row.id to latency) else timings - row.id
        durations = if (ok && code == "ok" && scope.config == revision && row.hasSingleApplicationCheck() &&
            !receipt.isNullOrEmpty() && hops.size in 1..4 && latency != null && latency in 0..30_000) {
            durations + (row.id to RouteProbeDurations.append(durations[row.id], hops, receipt, measuredAt, latency))
        } else durations - row.id
        measuredPaths=measuredPaths+(row.id to JSONArray(hops.take(4)))
        val projection=row.profile?.let {RouteCheckPlans.projection(checkPlan,it,if(ok)"TRUE" else if(code=="probe_unavailable")"UNKNOWN" else "FALSE")}
        checkPlans=if(projection!=null)checkPlans+(row.id to projection) else checkPlans-row.id
    }
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
    @Synchronized fun accepts(only:String?)=rows.any {(only==null || it.id==only) && it.configured()}
    private fun checkContext() = manualContext ?: UUID.randomUUID().toString().also { manualContext=it }
    @Synchronized internal fun captureManualCheck(id:String, generation:Long, displayed:String?):String? {
        val scope=live ?: return null
        if(scope.intent!=generation || scope.config!=revision || rows.none {it.id==id && it.individuallyCheckable()}) return null
        return checkContext().takeIf { displayed==null || displayed==it }
    }
    @Synchronized internal fun resolveManualCheck(scope:RouteScope, id:String, stamp:String?):String? {
        if(scope!=live || scope.config!=revision || stamp==null || stamp!=manualContext) return null
        return rows.singleOrNull {it.id==id && it.individuallyCheckable()}?.tag
    }
    @Synchronized fun view(status:JSONObject):JSONObject {
        val scope = live?.copy(intent=status.optLong("generation"),network=status.optLong("networkEpoch"))
        val on = status.optBoolean("desiredOn")
        val ready = status.optBoolean("engineActive") && live != null
        val sameConfig = live?.config == revision && status.optString("configRevision") == revision
        return readAt(on,ready,scope,SystemClock.elapsedRealtime(),sameConfig).also { report ->
            if (on && ready && scope != null && scope == live && scope.config == revision &&
                revision == status.optString("configRevision")) report.put("measurementRevision", revision)
        }
    }
    private fun failoverContext(scope:RouteScope, algorithm:FailoverAlgorithm) =
        Context(scope.network,scope.activation,"active",algorithm.revision,scope.intent,scope.config)

    @Synchronized internal fun awaitingValidatedBatch(scope:RouteScope):Boolean =
        live==scope && failover!=null && validatedBatch!=scope

    @Synchronized fun request(scope:RouteScope, only:String?=null, force:Boolean=false, deferCoolingReserves:Boolean=false,
                              validatedManagedWifi:Boolean=false, meteredMaintenance:Boolean=false):String? {
        val now=SystemClock.elapsedRealtime()
        if(pending.isNotEmpty() && now-startedAt<35_000) return null
        val firstValidated=only==null && validatedManagedWifi && awaitingValidatedBatch(scope)
        if(!force && !firstValidated && now-lastStarted<60_000) return null
        if(only!=null && rows.none {it.id==only})return null
        val admission=failoverAdmission?.takeIf {deferCoolingReserves && only==null && live==scope}
        val omittedReserves = if (meteredMaintenance && only==null && live==scope &&
            !force && !firstValidated && !confirmingFailure) failover?.members.orEmpty() else emptyList()
        val early = reserveRecovery?.takeIf { now-it.observedAt in 0L until 15_000 }?.let { hint ->
            admission?.let { (algorithm,state) ->
                state.beginEarlyReserve(failoverContext(scope,algorithm),hint.selected,batchSequence+1,now)
            }
        }
        reserveRecovery=null
        val selected=rows.filter {row->
            (only==null || row.id==only) && row.configured() &&
                (row.required || row.tag==early || row.tag !in omittedReserves &&
                    admission?.let {(algorithm, state)->state.deferReserveProbe(failoverContext(scope,algorithm),row.tag,now)}!=true)
        }
        if(selected.isEmpty())return null
        val request=UUID.randomUUID().toString()
        val wire=JSONObject().put("request",request).put("routes",JSONArray(selected.map {row->RouteCheckPlans.wire(row.id,row.tag,row.checks,row.profile)})).toString()
        require(wire.toByteArray(Charsets.UTF_8).size<=32768)
        skippedMeteredReserves=omittedReserves.isNotEmpty()
        // Never stamp a previous observation with this new scope.
        current=scope;pending=request;startedAt=now;lastStarted=now;queued=selected.map {it.id}.toSet()
        if(firstValidated)validatedBatch=scope
        completedReceipt="";batchSequence++
        return wire
    }
    @Synchronized fun update(scope:RouteScope,raw:String):Boolean {
        if(raw.length>16_384 || current!=scope || pending.isEmpty())return false
        val value=JSONObject(raw)
        if(value.optString("request")!=pending) return false
        val running=value.getBoolean("running")
        val results=value.getJSONArray("results");require(results.length()<=queued.size)
        val now=SystemClock.elapsedRealtime();val seen=mutableSetOf<String>()
        var nextObservations=observations;var nextCodes=codes;var nextTimings=timings;var nextReceipts=receipts;var nextPaths=measuredPaths;var nextPlans=checkPlans
        val nextDurations = durations.toMutableMap()
        for(i in 0 until results.length()) {
            val r=results.getJSONObject(i);val id=r.getString("id");val code=r.getString("code")
            require(id in queued && seen.add(id) && code in codesAllowed && r.getLong("elapsedMs") in 0..35_000)
            val complete=r.getBoolean("complete");val ok=r.getBoolean("ok")
            val row=rows.single {it.id==id}
            val profile=row.profile
            val diagnostic=profile?.let {RouteCheckPlans.projection(r.optJSONObject("checkPlan"),it,if(ok)"TRUE" else if(complete)"FALSE" else "UNKNOWN")}
            val sampled=r.getLong("sampledElapsedMs");require(sampled in 0..now)
            require(!ok || (complete && code=="ok"))
            val path=r.optJSONArray("path") ?: JSONArray()
            require(path.length()<=64 && (0 until path.length()).all {n->rows.any {it.id==path.getString(n)}})
            // First receipt time is retained across repeated heartbeat snapshots.
            if(receipts[id]!=pending) {
                val cause = if (complete && !ok) RouteFailureCause.fromWire(code, r.optString("cause")) else null
                nextObservations=nextObservations+(id to RouteObservation(scope,sampled,complete,ok,cause));nextCodes=nextCodes+(id to code);nextTimings=nextTimings+(id to r.getLong("elapsedMs"));nextReceipts=nextReceipts+(id to pending)
                if (ok && row.type != "syn443-adaptive" && scope == live && scope.config == revision &&
                    row.hasSingleApplicationCheck() && path.optString(0) == id) {
                    val measured = (0 until path.length()).map { path.getString(it) }
                    nextDurations[id] = RouteProbeDurations.append(durations[id], measured, pending, sampled, r.getLong("elapsedMs"))
                } else nextDurations.remove(id)
                nextPaths=nextPaths+(id to path)
                nextPlans=if(diagnostic!=null)nextPlans+(id to diagnostic) else nextPlans-id
            }
        }
        durations=nextDurations
        observations=nextObservations;codes=nextCodes;timings=nextTimings;receipts=nextReceipts;measuredPaths=nextPaths;checkPlans=nextPlans
        if(!running) {
            for (id in queued - seen) recordMissingResult(id, scope, now)
            completedReceipt=pending
            pending="";queued=emptySet()
        }
        return true
    }
    /** A canceled measurement has its own timestamp but no path, duration or leaf results. */
    private fun recordMissingResult(id: String, scope: RouteScope, now: Long) {
        observations = observations + (id to RouteObservation(scope, now, false, false))
        codes = codes + (id to "cancelled")
        timings = timings - id
        durations = durations - id
        measuredPaths = measuredPaths - id
        checkPlans = checkPlans - id
        receipts = receipts - id
    }
    @Synchronized fun cancelled(resetInterval:Boolean=false){pending="";queued=emptySet();current=null;completedReceipt="";reserveRecovery=null;confirmingFailure=false;skippedMeteredReserves=false;if(resetInterval)lastStarted=-60_000}
    @Synchronized internal fun confirmingFailover(scope:RouteScope):Boolean=live==scope && confirmingFailure
    @Synchronized internal fun hasManagedFailover(scope:RouteScope):Boolean=live==scope && failover!=null && completedReceipt.isNotEmpty()
    @Synchronized internal fun failoverAdvice(scope:RouteScope,trackReserveFailures:Boolean=false,
        algorithm:FailoverAlgorithm=FailoverAlgorithm.BASELINE):FailoverCommand? {
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
                trackReserveFailures && codes[row.id] in completedProbeFailures -> ProbeVerdict.CONFIRMED_PATH_FAILURE
                else -> return@mapNotNull null
            }
            VerifiedPathSample(row.tag,plan.intent,receipt,comparison,sample.elapsedMs,verdict,timings[row.id] ?: 0,
                transientTransportFailure=transientDial(codes[row.id],sample))
        }
        val measuredFailure=groupSample.complete && codes[group.id] in completedProbeFailures &&
            now-groupSample.elapsedMs in 0L until 15_000
        val verdict=when {
            groupSample.complete && groupSample.ok -> ProbeVerdict.VERIFIED
            measuredFailure && reserves.any {it.verdict==ProbeVerdict.VERIFIED} -> ProbeVerdict.CONFIRMED_PATH_FAILURE
            else -> ProbeVerdict.UNKNOWN
        }
        // A failed selector in a reduced survey needs one full comparison, but
        // does not itself count as an independent path failure.
        confirmingFailure=verdict==ProbeVerdict.CONFIRMED_PATH_FAILURE || measuredFailure && skippedMeteredReserves
        val context=failoverContext(scope,algorithm)
        fun evaluator(version:FailoverAlgorithm) = FailoverAdmission(failoverContext(scope,version),plan.intent,plan.members.toSet(),comparison,
            rows.filter {it.tag in plan.members}.associate {it.tag to (it.chain.size-1).coerceIn(0,2)},version)
        val compare=algorithm==FailoverAlgorithm.CONFIRMED && !trackReserveFailures
        if (!compare) failoverShadow=null
        val admission=failoverAdmission?.takeIf {it.first==algorithm}?.second ?: evaluator(algorithm).also {
            failoverAdmission=algorithm to it
            if (compare) failoverShadow=FailoverShadow(failoverContext(scope,FailoverAlgorithm.BASELINE),
                evaluator(FailoverAlgorithm.BASELINE))
        }
        val active=VerifiedPathSample(selected.tag,plan.intent,receipt,comparison,groupSample.elapsedMs,verdict,timings[group.id] ?: 0)
        val choice=admission.decide(context,batchSequence,receipt,now,selected.tag,active,reserves)
        if (admission.consumed(batchSequence))
            failoverShadow?.observe(batchSequence,receipt,now,selected.tag,active,reserves,choice)
        reserveRecovery = if (trackReserveFailures && measuredFailure && transientDial(codes[group.id],groupSample) &&
            reserves.none { it.verdict==ProbeVerdict.VERIFIED } && admission.earlyReserve(context,selected.tag,now)!=null)
            ReserveRecoveryHint(selected.tag,groupSample.elapsedMs) else null
        if(reserveRecovery!=null)confirmingFailure=true
        if(choice==null)return null
        val candidate=rows.singleOrNull {it.tag==choice.candidate} ?: return null
        return FailoverCommand(choice.receipt,candidate.id,group.tag,choice.previous,choice.candidate)
    }
    @Synchronized fun read(on:Boolean,ready:Boolean,scope:RouteScope?):JSONObject {
        return readAt(on,ready,scope,SystemClock.elapsedRealtime())
    }
    /** Internal deterministic test seam. Production callers cannot supply a clock. */
    @Synchronized internal fun readAt(on:Boolean,ready:Boolean,scope:RouteScope?,now:Long,sameConfig:Boolean=true):JSONObject {
        require(now>=0)
        val sameOwner = sameConfig && scope != null && scope == live
        val activeOwner = on && ready && sameOwner
        val currentSnapshot = activeOwner && scope?.config == revision
        if(sameOwner && pending.isNotEmpty() && now-startedAt>=35_000) {
            current?.let { scope -> for (id in queued) if (receipts[id] != pending) recordMissingResult(id, scope, now) }
            pending="";queued=emptySet()
        }
        val values=rows.map {row->
            val sample = observations[row.id]?.takeIf { sameOwner && it.scope == scope }
            val checking = activeOwner && row.id in queued
            val state=if(scope==null) {if(on) RouteState.UNAVAILABLE else RouteState.OFF} else RouteEvidence.classify(on,ready,scope,sample,checking,now)
            JSONObject().put("id",row.id).put("label",row.tag.take(80)).put("type",row.type).put("required",row.required).put("state",state.name.lowercase(java.util.Locale.ROOT))
                .put("configured",row.configured()).put("chain",JSONArray(row.chain)).put("routingRules",row.rules)
                .put("individualCheck",currentSnapshot && row.individuallyCheckable())
                .put("checkPending",checking)
                .put("measuredPath",if(sample!=null)measuredPaths[row.id] ?: JSONArray() else JSONArray())
                .put("reason",if(sample!=null)codes[row.id] ?: "not_checked" else "not_checked")
                .put("ageMs",if(sample!=null && now>=sample.elapsedMs)now-sample.elapsedMs else JSONObject.NULL)
                .put("latencyMs",if(sample!=null)timings[row.id] ?: JSONObject.NULL else JSONObject.NULL)
                .also {value->
                    if (currentSnapshot && state == RouteState.WORKING && row.id !in queued) {
                        durations[row.id]?.summary(now)?.let { value.put("durationDistribution", it) }
                    }
                    if (state == RouteState.FAILED && scope == live && row.id !in queued) {
                        sample?.cause?.let { value.put("cause", it.wire) }
                    }
                    row.profile?.let {profile->value.put("checkPlan",if(activeOwner && sample!=null && !checking && state in setOf(RouteState.WORKING,RouteState.FAILED,RouteState.INCOMPLETE))
                        checkPlans[row.id]?.let {JSONObject(it.toString())} ?: RouteCheckPlans.unknown(profile) else RouteCheckPlans.unknown(profile))}
                    if(row.type=="syn443-adaptive") {
                        val search=if(!activeOwner || searchScope!=scope)
                            AdaptiveSearchState.WAITING_CONTEXT else searches[row.id] ?: AdaptiveSearchState.WAITING_CONTEXT
                        // A selected acknowledgement alone cannot keep a UI
                        // claim fresh across TTL, readiness or scope changes.
                        val visible=if(search==AdaptiveSearchState.VERIFIED && state!=RouteState.WORKING)
                            AdaptiveSearchState.SEARCH_INCOMPLETE else search
                        value.put("search",JSONObject().put("state",visible.name))
                    }
                    if(currentSnapshot)failoverAdmission?.second?.cooldown(row.tag,now)?.let {cooldown->
                        value.put("selectionState",cooldown.readiness.name.lowercase(java.util.Locale.ROOT))
                            .put("retryInMs",(checkNotNull(cooldown.retryAtMs)-now).coerceAtLeast(0))
                    }
                }
        }
        return JSONObject().put("routes",JSONArray(values)).put("running",activeOwner && pending.isNotEmpty()).put("requiredReady",activeOwner && RouteEvidence.requiredReady(values.map {it.getBoolean("required") to RouteState.valueOf(it.getString("state").uppercase(java.util.Locale.ROOT))})).also { result ->
            if(currentSnapshot && rows.any {it.individuallyCheckable()})
                result.put("checkContext",checkContext())
            if (activeOwner) failoverShadow?.status()?.let {result.put("decisionShadow",it)}
        }
    }
}
/** Read-only search progress. These values never authorize a route or packets. */
internal enum class AdaptiveSearchState { WAITING_CONTEXT, SEARCHING, BUDGET_WAIT, SEARCH_INCOMPLETE, VERIFIED }
