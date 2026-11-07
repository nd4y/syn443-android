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

    private fun assertSelection(algorithm: FailoverAlgorithm) {
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
            repeat(algorithm.confirmations - 1) {
                batch()
                assertNull(RouteSnapshot.failoverAdvice(scope, algorithm = algorithm))
                assertTrue(RouteSnapshot.confirmingFailover(scope))
                assertNull(RouteSnapshot.failoverAdvice(scope, algorithm = algorithm))
            }
            val receipt=batch()
            val command=checkNotNull(RouteSnapshot.failoverAdvice(scope, algorithm = algorithm))
            assertEquals(receipt,command.receipt);assertEquals("route-2",command.checkId)
            assertEquals("internal",command.group);assertEquals("primary",command.previous);assertEquals("reserve",command.candidate)
            val primary=RouteSnapshot.read(true,true,scope).getJSONArray("routes").getJSONObject(0)
            assertEquals("quarantined",primary.getString("selectionState"))
            assertTrue(primary.getLong("retryInMs") in 1L..36_000L)
            val changed=scope.copy(network=21)
            RouteSnapshot.owner(changed)
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
