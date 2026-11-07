package io.syn443.android

import android.os.SystemClock
import io.syn443.android.vpn.EngineConfig
import io.syn443.android.vpn.RouteSnapshot
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

    @Test fun twoSameScopeBatchesSelectOnlyTheVerifiedConcreteReserve() {
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
            batch()
            assertNull(RouteSnapshot.failoverAdvice(scope))
            assertTrue(RouteSnapshot.confirmingFailover(scope))
            assertNull(RouteSnapshot.failoverAdvice(scope))
            val receipt=batch()
            val command=checkNotNull(RouteSnapshot.failoverAdvice(scope))
            assertEquals(receipt,command.receipt);assertEquals("route-2",command.checkId)
            assertEquals("internal",command.group);assertEquals("primary",command.previous);assertEquals("reserve",command.candidate)
            val changed=scope.copy(network=21)
            RouteSnapshot.owner(changed)
            assertNull(RouteSnapshot.failoverAdvice(scope));assertNull(RouteSnapshot.failoverAdvice(changed))
        } finally {RouteSnapshot.owner(null);RouteSnapshot.configure(null,"")}
    }

    @Test fun wifiInternalPlanCannotEnableDirectOrMismatchedCheckFallback() {
        assertThrows(IllegalArgumentException::class.java){EngineConfig.validate(config.replace("\"wifi\"","\"cellular\""))}
        assertThrows(IllegalArgumentException::class.java){EngineConfig.validate(config.replace("\"socks\"","\"direct\""))}
        assertThrows(IllegalArgumentException::class.java){EngineConfig.validate(config.replace("[\"home.example.invalid\"]","[]"))}
        val json=JSONObject(config)
        json.getJSONArray("route_checks").getJSONObject(2).getJSONArray("checks").getJSONObject(0)
            .put("target","other.example.invalid:22")
        assertThrows(IllegalArgumentException::class.java){EngineConfig.validate(json.toString())}
    }
}
