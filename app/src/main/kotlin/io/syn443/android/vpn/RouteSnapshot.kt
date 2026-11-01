package io.syn443.android.vpn

import android.os.SystemClock
import io.syn443.recovery.RouteEvidence
import io.syn443.recovery.RouteObservation
import io.syn443.recovery.RouteScope
import io.syn443.recovery.RouteState
import org.json.JSONArray
import org.json.JSONObject
import java.net.URI
import java.util.UUID

/** Controller RAM only. Labels/targets are never written to events or native output. */
object RouteSnapshot {
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
    private val methods=setOf("tcp","tls","https_204","ssh_banner")
    private var measuredPaths=emptyMap<String,JSONArray>()
    private val codesAllowed=setOf("ok","outbound_unavailable","cancelled","dial_failed","unsupported","ssh_banner_mismatch","tls_failed","request_failed","response_failed","http_response_mismatch","path_changed","check_timeout")
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
    @Synchronized fun invalidate() {current=null;pending="";queued=emptySet();observations=emptyMap();codes=emptyMap();timings=emptyMap();receipts=emptyMap();measuredPaths=emptyMap();lastStarted=-60_000}
    @Synchronized fun due()=rows.any {it.checks.length()>0} && SystemClock.elapsedRealtime()-lastStarted>=60_000
    @Synchronized fun owner(scope:RouteScope?){live=scope}
    @Synchronized fun view(status:JSONObject):JSONObject = read(status.optBoolean("desiredOn"),status.optBoolean("engineActive") && live!=null,
        live?.copy(intent=status.optLong("generation"),network=status.optLong("networkEpoch")))
    @Synchronized fun request(scope:RouteScope, only:String?=null, force:Boolean=false):String? {
        val now=SystemClock.elapsedRealtime()
        if(pending.isNotEmpty() && now-startedAt<35_000) return null
        if(!force && now-lastStarted<60_000) return null
        require(only==null || rows.any {it.id==only})
        val selected=rows.filter {(only==null || it.id==only) && it.checks.length()>0}
        if(selected.isEmpty())return null
        // Never stamp a previous observation with this new scope.
        current=scope;pending=UUID.randomUUID().toString();startedAt=now;lastStarted=now;queued=selected.map {it.id}.toSet()
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
            pending="";queued=emptySet()
        }
        return true
    }
    @Synchronized fun cancelled(resetInterval:Boolean=false){pending="";queued=emptySet();current=null;if(resetInterval)lastStarted=-60_000}
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
        }
        return JSONObject().put("routes",JSONArray(values)).put("running",pending.isNotEmpty()).put("requiredReady",RouteEvidence.requiredReady(values.map {it.getBoolean("required") to RouteState.valueOf(it.getString("state").uppercase(java.util.Locale.ROOT))}))
    }
}
