package io.syn443.android

import android.os.SystemClock
import io.syn443.android.vpn.EngineConfig
import io.syn443.android.vpn.RouteSnapshot
import io.syn443.decision.FailoverAlgorithm
import io.syn443.policy.Policy
import io.syn443.recovery.RouteScope
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class ManagedFailoverTest {
    private val config="""{
      "outbounds":[{"tag":"primary","type":"http"},{"tag":"reserve","type":"socks"},
        {"tag":"internal","type":"selector","outbounds":["primary","reserve"],"interrupt_exist_connections":false},
        {"tag":"public","type":"direct"}],
      "route":{"final":"public","rules":[{"domain":["home.example.invalid"],"action":"route","outbound":"internal"}]},
      "route_checks":[
        {"outbound":"internal","required":true,"checks":[{"method":"tcp","target":"home.example.invalid:22"}]},
        {"outbound":"primary","required":false,"checks":[{"method":"tcp","target":"home.example.invalid:22"}]},
        {"outbound":"reserve","required":false,"checks":[{"method":"tcp","target":"home.example.invalid:22"}]}],
      "route_failover":{"selector":"internal","network_mode":"wifi","intent":"INTERNAL","members":["primary","reserve"]}
    }"""

    @Test fun twoSameScopeBatchesSelectOnlyTheVerifiedConcreteReserve() =
        assertSelection(FailoverAlgorithm.BASELINE)

    @Test fun conservativeRevisionRequiresThirdCurrentRouteBatch() =
        assertSelection(FailoverAlgorithm.CONFIRMED)

    @Test fun referenceDivergenceIsCountedOnceAndNeverSwitchesTheLiveSelector() =
        assertSelection(FailoverAlgorithm.CONFIRMED, compare = true)

    @Test fun differentProbePlanKeepsLiveFailoverWithoutAShadowReport() =
        assertSelection(FailoverAlgorithm.CONFIRMED, compare = true, reserveCooldown = true)

    @Test fun sharedHttpTargetFailureNeverQuarantinesPathsWithoutAVerifiedComparator() {
        val engine = JSONObject(config)
        val rows = engine.getJSONArray("route_checks")
        for (i in 0 until rows.length()) {
            rows.getJSONObject(i).getJSONArray("checks").getJSONObject(0)
                .put("method", "https_204").put("target", "https://home.example.invalid/generate_204")
        }
        val raw = engine.toString()
        EngineConfig.validate(raw)
        val scope = RouteScope(10, 20, 30, "synthetic-shared-check-target", Policy.hash(raw))
        RouteSnapshot.configure(raw, scope.config)
        RouteSnapshot.owner(scope)
        val algorithm = FailoverAlgorithm.CONFIRMED
        fun batch(reservePassed: Boolean) {
            val request = JSONObject(checkNotNull(RouteSnapshot.request(scope, force = true, deferCoolingReserves = true)))
            assertEquals(3, request.getJSONArray("routes").length())
            val now = SystemClock.elapsedRealtime()
            fun result(id: String, passed: Boolean, path: List<String>) = JSONObject().put("id", id)
                .put("complete", true).put("ok", passed).put("code", if (passed) "ok" else "http_response_mismatch")
                .put("elapsedMs", 20).put("sampledElapsedMs", now).put("path", JSONArray(path))
            val reply = JSONObject().put("request", request.getString("request")).put("running", false)
                .put("results", JSONArray(listOf(
                    result("route-1", false, listOf("route-1")),
                    result("route-2", reservePassed, listOf("route-2")),
                    result("route-3", false, listOf("route-3", "route-1"))
                )))
            assertTrue(RouteSnapshot.update(scope, reply.toString()))
        }
        try {
            repeat(algorithm.confirmations + 1) {
                batch(reservePassed = false)
                assertNull(RouteSnapshot.failoverAdvice(scope, trackReserveFailures = true, algorithm = algorithm))
                assertFalse(RouteSnapshot.confirmingFailover(scope))
                val health = RouteSnapshot.read(true, true, scope)
                assertFalse(health.getBoolean("requiredReady"))
                val routes = health.getJSONArray("routes")
                assertEquals("http_response_mismatch", routes.getJSONObject(2).getString("reason"))
                for (index in 0..1) assertFalse(routes.getJSONObject(index).has("selectionState"))
            }
            repeat(algorithm.confirmations - 1) {
                batch(reservePassed = true)
                assertNull(RouteSnapshot.failoverAdvice(scope, trackReserveFailures = true, algorithm = algorithm))
            }
            batch(reservePassed = true)
            val change = checkNotNull(RouteSnapshot.failoverAdvice(scope, trackReserveFailures = true, algorithm = algorithm))
            assertEquals("primary", change.previous)
            assertEquals("reserve", change.candidate)
        } finally {
            RouteSnapshot.owner(null)
            RouteSnapshot.configure(null, "")
        }
    }

    @Test fun failoverMembersMustMatchSelectorHTTPMethodAndStatus() {
        val engine = JSONObject(config)
        val rows = engine.getJSONArray("route_checks")
        for (i in 0 until rows.length()) {
            val check = rows.getJSONObject(i).getJSONArray("checks").getJSONObject(0)
            check.put("method", "https_status").put("target", "https://service.example.invalid/")
                .put("http_method", "HEAD").put("expected_status", 200)
        }
        EngineConfig.validate(engine.toString())
        val member = rows.getJSONObject(1).getJSONArray("checks").getJSONObject(0)
        member.put("http_method", "GET")
        assertTrue(runCatching { EngineConfig.validate(engine.toString()) }.isFailure)
        member.put("http_method", "HEAD").put("expected_status", 302)
        assertTrue(runCatching { EngineConfig.validate(engine.toString()) }.isFailure)
    }

    @Test fun internalSelectorAcceptsExplicitDestinationsAndRejectsScopeWidening() {
        fun settings(): JSONObject = JSONObject(config)
        fun rule(value: JSONObject): JSONObject = value.getJSONObject("route").getJSONArray("rules").getJSONObject(0)
        val scoped = settings()
        rule(scoped).put("invert", false).put("domain_suffix", ".home.example.invalid")
            .put("ip_cidr", JSONArray(listOf("192.0.2.0/24", "2001:db8::/32"))).put("port", 22)
        EngineConfig.validate(scoped.toString())

        val unsafe: List<(JSONObject) -> Unit> = listOf(
            { rule(it).put("invert", true) },
            { rule(it).put("type", "logical").put("mode", "or") },
            { rule(it).put("ip_is_private", true) },
            { rule(it).put("ip_cidr", "0.0.0.0/0") },
            { rule(it).put("ip_cidr", "::/0") },
            { rule(it).put("domain_suffix", ".") },
            { it.getJSONObject("route").put("final", "") },
            { it.getJSONObject("route").put("Final", "internal") },
            { rule(it).put("Outbound", "internal") },
            { it.put("dns", JSONObject().put("servers", JSONArray().put(JSONObject().put("outbound", "internal")))) },
        )
        for ((index, change) in unsafe.withIndex()) {
            val invalid = settings().also(change)
            assertTrue("widened selector scope $index was accepted", runCatching { EngineConfig.validate(invalid.toString()) }.isFailure)
        }
    }

    @Test fun nativeSelectionPlanContainsOnlyConcreteChecksForTheExactConfig() {
        val hash = Policy.hash(config)
        RouteSnapshot.configure(config, hash)
        try {
            assertEquals("", RouteSnapshot.nativeSelectionPlan("different-config"))
            val plan = JSONObject(RouteSnapshot.nativeSelectionPlan(hash))
            assertEquals("internal", plan.getString("selector"))
            val paths = plan.getJSONArray("paths")
            assertEquals(2, paths.length())
            for ((index, tag) in listOf("primary", "reserve").withIndex()) {
                val path = paths.getJSONObject(index)
                assertEquals("route-"+(index+1), path.getString("id"))
                assertEquals(tag, path.getString("outbound"))
                assertEquals("home.example.invalid:22", path.getJSONArray("checks").getJSONObject(0).getString("target"))
            }
        } finally {RouteSnapshot.owner(null);RouteSnapshot.configure(null,"")}
    }

    private fun assertSelection(algorithm: FailoverAlgorithm, compare:Boolean=false, reserveCooldown:Boolean=false) {
        EngineConfig.validate(config)
        val scope=RouteScope(10,20,30,"synthetic-engine",Policy.hash(config))
        RouteSnapshot.configure(config,scope.config)
        RouteSnapshot.owner(scope)
        fun batch():String {
            val request=JSONObject(checkNotNull(RouteSnapshot.request(scope,force=true))).getString("request")
            val now=SystemClock.elapsedRealtime()
            fun result(id:String,ok:Boolean,path:List<String>)=JSONObject().put("id",id).put("complete",true)
                .put("ok",ok).put("code",if(ok)"ok" else "dial_failed").put("elapsedMs",20)
                .put("sampledElapsedMs",now).put("path",JSONArray(path))
            val reply=JSONObject().put("request",request).put("running",false).put("results",JSONArray(listOf(
                result("route-1",false,listOf("route-1")),result("route-2",true,listOf("route-2")),
                result("route-3",false,listOf("route-3","route-1")))))
            assertTrue(RouteSnapshot.update(scope,reply.toString()))
            return request
        }
        try {
            repeat(algorithm.confirmations - 1) { index ->
                batch()
                assertNull(RouteSnapshot.failoverAdvice(scope, reserveCooldown, algorithm))
                assertTrue(RouteSnapshot.confirmingFailover(scope))
                assertNull(RouteSnapshot.failoverAdvice(scope, reserveCooldown, algorithm))
                if (compare) {
                    val status=RouteSnapshot.read(true,true,scope)
                    assertFalse(status.getBoolean("running"))
                    val report=status.optJSONObject("decisionShadow")
                    if(reserveCooldown) assertNull(report) else {
                        val observed=checkNotNull(report)
                        assertEquals(setOf("liveRevision","referenceRevision","outcome","comparedBatches"),observed.keys().asSequence().toSet())
                        assertEquals(algorithm.revision,observed.getString("liveRevision"))
                        assertEquals(FailoverAlgorithm.BASELINE.revision,observed.getString("referenceRevision"))
                        assertEquals((index+1).toLong(),observed.getLong("comparedBatches"))
                        assertEquals(if(index==0)"agree" else "reference_only",observed.getString("outcome"))
                    }
                }
            }
            val receipt=batch()
            val command=checkNotNull(RouteSnapshot.failoverAdvice(scope, reserveCooldown, algorithm))
            assertEquals(receipt,command.receipt);assertEquals("route-2",command.checkId)
            assertEquals("internal",command.group);assertEquals("primary",command.previous);assertEquals("reserve",command.candidate)
            val primary=RouteSnapshot.read(true,true,scope).getJSONArray("routes").getJSONObject(0)
            if(compare && !reserveCooldown) {
                assertEquals(2L,RouteSnapshot.read(true,true,scope).getJSONObject("decisionShadow").getLong("comparedBatches"))
                assertFalse(RouteSnapshot.read(false,true,scope).has("decisionShadow"))
                assertFalse(RouteSnapshot.read(true,false,scope).has("decisionShadow"))
            }
            assertEquals("quarantined",primary.getString("selectionState"))
            assertTrue(primary.getLong("retryInMs") in 1L..36_000L)
            for (status in listOf(RouteSnapshot.read(false,true,scope), RouteSnapshot.read(true,false,scope),
                RouteSnapshot.read(true,true,scope.copy(network=21)))) {
                val hidden=status.getJSONArray("routes").getJSONObject(0)
                assertFalse(hidden.has("selectionState"))
                assertFalse(hidden.has("retryInMs"))
            }
            val changed=scope.copy(network=21)
            RouteSnapshot.owner(changed)
            assertFalse(RouteSnapshot.read(true,true,changed).has("decisionShadow"))
            assertNull(RouteSnapshot.failoverAdvice(scope));assertNull(RouteSnapshot.failoverAdvice(changed))
        } finally {RouteSnapshot.owner(null);RouteSnapshot.configure(null,"")}
    }

    @Test fun wifiInternalPlanCannotEnableDirectOrMismatchedCheckFallback() {
        assertThrows(IllegalArgumentException::class.java){EngineConfig.validate(config.replace("\"wifi\"","\"cellular\""))}
        for (exit in listOf("RU", "NON_RU")) {
            assertThrows(IllegalArgumentException::class.java){EngineConfig.validate(config.replace("\"INTERNAL\"", "\"$exit\""))}
        }
        assertThrows(IllegalArgumentException::class.java){EngineConfig.validate(config.replace("\"socks\"","\"direct\""))}
        assertThrows(IllegalArgumentException::class.java){EngineConfig.validate(config.replace("[\"home.example.invalid\"]","[]"))}
        val json=JSONObject(config)
        json.getJSONArray("route_checks").getJSONObject(2).getJSONArray("checks").getJSONObject(0)
            .put("target","other.example.invalid:22")
        assertThrows(IllegalArgumentException::class.java){EngineConfig.validate(json.toString())}
    }

    @Test fun routineBatchesDeferOnlyCoolingReserveAndKeepRequiredSelector() {
        val scope=RouteScope(10,22,30,"synthetic-engine",Policy.hash(config))
        RouteSnapshot.configure(config,scope.config)
        RouteSnapshot.owner(scope)
        fun request(scope:RouteScope,defer:Boolean=false,only:String?=null)=JSONObject(checkNotNull(
            RouteSnapshot.request(scope,only=only,force=true,deferCoolingReserves=defer)))
        fun tags(request:JSONObject)=request.getJSONArray("routes").let { routes->
            (0 until routes.length()).map {routes.getJSONObject(it).getString("outbound")}.toSet()
        }
        fun batch(reservePath:String="route-2",reserveCode:String="dial_failed",track:Boolean=true) {
            val request=request(scope).getString("request")
            val now=SystemClock.elapsedRealtime()
            fun result(id:String,code:String,path:List<String>)=JSONObject().put("id",id).put("complete",true)
                .put("ok",code=="ok").put("code",code).put("elapsedMs",20).put("sampledElapsedMs",now)
                .put("path",JSONArray(path))
            val report=JSONObject().put("request",request).put("running",false).put("results",JSONArray(listOf(
                result("route-1","ok",listOf("route-1")),result("route-2",reserveCode,listOf(reservePath)),
                result("route-3","ok",listOf("route-3","route-1")))))
            assertTrue(RouteSnapshot.update(scope,report.toString()))
            assertNull(RouteSnapshot.failoverAdvice(scope,trackReserveFailures=track))
        }
        try {
            repeat(2) { batch(track=false) }
            assertEquals(setOf("primary","reserve","internal"),tags(request(scope,true)))
            RouteSnapshot.cancelled()
            batch(reservePath="route-1")
            batch(reserveCode="probe_unavailable")
            batch()
            assertEquals(setOf("primary","reserve","internal"),tags(request(scope,true)))
            RouteSnapshot.cancelled()
            batch()
            assertEquals(setOf("primary","internal"),tags(request(scope,true)))
            RouteSnapshot.cancelled()
            assertEquals(setOf("primary","reserve","internal"),tags(request(scope)))
            RouteSnapshot.cancelled()
            assertEquals(setOf("reserve"),tags(request(scope,true,only="route-2")))
            val newNetwork=scope.copy(network=23)
            RouteSnapshot.owner(newNetwork)
            assertEquals(setOf("primary","reserve","internal"),tags(request(newNetwork,true)))
        } finally {RouteSnapshot.owner(null);RouteSnapshot.configure(null,"")}
    }

    @Test fun failedActiveWifiGetsOneEarlyReserveProbeAndStillNeedsTwoVerifiedBatches() {
        val scope=RouteScope(10,29,30,"synthetic-early-engine",Policy.hash(config))
        RouteSnapshot.configure(config,scope.config);RouteSnapshot.owner(scope)
        fun request()=JSONObject(checkNotNull(RouteSnapshot.request(scope,force=true,deferCoolingReserves=true)))
        fun batch(wire:JSONObject, primaryOK:Boolean, reserveOK:Boolean):RouteSnapshot.FailoverCommand? {
            val results=JSONArray()
            val checks=wire.getJSONArray("routes")
            for(i in 0 until checks.length()) {
                val row=checks.getJSONObject(i)
                val id=row.getString("id")
                val ok=if(id=="route-2")reserveOK else primaryOK
                val path=if(id=="route-3")listOf(id,"route-1") else listOf(id)
                val entry=JSONObject().put("id",id).put("complete",true).put("ok",ok)
                    .put("code",if(ok)"ok" else "dial_failed").put("elapsedMs",20)
                    .put("sampledElapsedMs",android.os.SystemClock.elapsedRealtime()).put("path",JSONArray(path))
                if(!ok)entry.put("cause","connection_refused")
                results.put(entry)
            }
            val report=JSONObject().put("request",wire.getString("request")).put("running",false).put("results",results)
            assertTrue(RouteSnapshot.update(scope,report.toString()))
            return RouteSnapshot.failoverAdvice(scope,trackReserveFailures=true)
        }
        fun reserveIncluded(wire:JSONObject):Boolean {
            val list=wire.getJSONArray("routes")
            return (0 until list.length()).any {list.getJSONObject(it).getString("id")=="route-2"}
        }
        try {
            repeat(2){assertNull(batch(request(),true,false))}
            val fenced=request()
            assertFalse(reserveIncluded(fenced))
            android.os.SystemClock.sleep(10_100)
            assertNull(batch(fenced,false,false))
            val trial=request()
            assertTrue(reserveIncluded(trial))
            assertNull(batch(trial,false,true))
            val switch=checkNotNull(batch(request(),false,true))
            assertEquals("primary",switch.previous);assertEquals("reserve",switch.candidate)
        } finally {RouteSnapshot.owner(null);RouteSnapshot.configure(null,"")}
    }

    @Test fun meteredMaintenanceKeepsRequiredChecksAndOnlyFullComparisonsCountTowardSwitch() {
        val scope=RouteScope(10,26,30,"synthetic-engine",Policy.hash(config))
        RouteSnapshot.configure(config,scope.config)
        RouteSnapshot.owner(scope)
        fun batch(full:Boolean,reserveWorks:Boolean=false) {
            val request=JSONObject(checkNotNull(RouteSnapshot.request(scope,force=full,meteredMaintenance=true)))
            val paths=request.getJSONArray("routes")
            val tags=(0 until paths.length()).map {paths.getJSONObject(it).getString("outbound")}.toSet()
            assertEquals(if(full)setOf("primary","reserve","internal") else setOf("internal"),tags)
            val now=SystemClock.elapsedRealtime()
            fun result(id:String,ok:Boolean,path:List<String>)=JSONObject().put("id",id).put("complete",true)
                .put("ok",ok).put("code",if(ok)"ok" else "dial_failed").put("elapsedMs",20)
                .put("sampledElapsedMs",now).put("path",JSONArray(path))
            val results=mutableListOf(result("route-3",false,listOf("route-3","route-1")))
            if(full) {
                results+=result("route-1",false,listOf("route-1"))
                results+=result("route-2",reserveWorks,listOf("route-2"))
            }
            assertTrue(RouteSnapshot.update(scope,JSONObject().put("request",request.getString("request"))
                .put("running",false).put("results",JSONArray(results)).toString()))
        }
        try {
            batch(full=false)
            assertNull(RouteSnapshot.failoverAdvice(scope))
            assertTrue(RouteSnapshot.confirmingFailover(scope))
            batch(full=true)
            assertNull(RouteSnapshot.failoverAdvice(scope))
            assertFalse(RouteSnapshot.confirmingFailover(scope))
            RouteSnapshot.cancelled(resetInterval=true)
            batch(full=false)
            assertNull(RouteSnapshot.failoverAdvice(scope))
            assertTrue(RouteSnapshot.confirmingFailover(scope))
            batch(full=true,reserveWorks=true)
            assertNull(RouteSnapshot.failoverAdvice(scope))
            batch(full=true,reserveWorks=true)
            assertEquals("reserve",RouteSnapshot.failoverAdvice(scope)?.candidate)
        } finally {RouteSnapshot.owner(null);RouteSnapshot.configure(null,"")}
    }

    @Test fun firstValidatedManagedBatchBypassesCadenceOnceWithoutCancellingInFlightWork() {
        val scope=RouteScope(10,24,30,"synthetic-engine",Policy.hash(config))
        RouteSnapshot.configure(config,scope.config)
        RouteSnapshot.owner(scope)
        try {
            assertNotNull(RouteSnapshot.request(scope))
            assertTrue(RouteSnapshot.awaitingValidatedBatch(scope))
            assertNull(RouteSnapshot.request(scope,validatedManagedWifi=true))
            assertTrue(RouteSnapshot.awaitingValidatedBatch(scope))
            RouteSnapshot.cancelled()
            assertNull(RouteSnapshot.request(scope))
            assertNotNull(RouteSnapshot.request(scope,validatedManagedWifi=true))
            assertFalse(RouteSnapshot.awaitingValidatedBatch(scope))
            RouteSnapshot.cancelled()
            assertNull(RouteSnapshot.request(scope,validatedManagedWifi=true))
            val next=scope.copy(network=25)
            RouteSnapshot.owner(next)
            assertTrue(RouteSnapshot.awaitingValidatedBatch(next))
            assertNotNull(RouteSnapshot.request(next,validatedManagedWifi=true))
            assertFalse(RouteSnapshot.awaitingValidatedBatch(next))
        } finally {RouteSnapshot.owner(null);RouteSnapshot.configure(null,"")}
    }
}
