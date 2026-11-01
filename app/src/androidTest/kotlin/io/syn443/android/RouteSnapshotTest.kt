package io.syn443.android

import io.syn443.android.vpn.RouteSnapshot
import io.syn443.android.vpn.EngineConfig
import io.syn443.android.vpn.LifecycleAccess
import io.syn443.recovery.RouteScope
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

/** Memory-only fixtures: do not change the physical phone's saved configuration. */
class RouteSnapshotTest {
    private val config="""{"outbounds":[{"type":"direct","tag":"public"},{"type":"direct","tag":"internal"},{"type":"direct","tag":"unused"}],"route":{"final":"public"},"route_checks":[{"outbound":"public","required":true,"checks":[{"method":"https_204","target":"https://probe.example.org/generate_204"}]},{"outbound":"internal","checks":[{"method":"ssh_banner","target":"192.0.2.9:22"}]}]}"""
    private val scope=RouteScope(4,2,3,"test-session","config-test")
    private fun setup(){RouteSnapshot.configure(config,"test-${java.util.UUID.randomUUID()}");RouteSnapshot.owner(scope)}
    private fun report(request:String,ok:Boolean,running:Boolean=false)=JSONObject().put("request",JSONObject(request).getString("request")).put("running",running).put("results",org.json.JSONArray()
        .put(JSONObject().put("id","route-1").put("complete",true).put("ok",ok).put("code",if(ok)"ok" else "dial_failed").put("elapsedMs",5).put("sampledElapsedMs",android.os.SystemClock.elapsedRealtime()).put("path",org.json.JSONArray().put("route-1")))
        .put(JSONObject().put("id","route-2").put("complete",true).put("ok",false).put("code","ssh_banner_mismatch").put("elapsedMs",8).put("sampledElapsedMs",android.os.SystemClock.elapsedRealtime()).put("path",org.json.JSONArray().put("route-2")))).toString()
    @Test fun independentRoutesKeepOptionalFailureAndUnconfiguredUnknown() {
        setup();val request=checkNotNull(RouteSnapshot.request(scope));assertTrue(RouteSnapshot.update(scope,report(request,true)))
        val view=RouteSnapshot.read(true,true,scope);val rows=view.getJSONArray("routes")
        assertEquals(3,rows.length());assertEquals("working",rows.getJSONObject(0).getString("state"));assertEquals("failed",rows.getJSONObject(1).getString("state"))
        assertEquals("unverified",rows.getJSONObject(2).getString("state"));assertFalse(rows.getJSONObject(2).getBoolean("configured"));assertTrue(view.getBoolean("requiredReady"))
        assertFalse(view.toString().contains("192.0.2.9"));assertFalse(view.toString().contains("probe.example.org"))
    }
    @Test fun routeLateNetworkAndEngineResultsCannotOverrideStop() {
        setup();assertFalse(RouteSnapshot.accepts("route-99"));assertFalse(RouteSnapshot.accepts("route-3"))
        assertNull(RouteSnapshot.request(scope,only="route-99",force=true))
        val request=checkNotNull(RouteSnapshot.request(scope))
        assertFalse(RouteSnapshot.update(scope.copy(network=3),report(request,true)))
        assertFalse(RouteSnapshot.update(scope.copy(engine="new-engine"),report(request,true)))
        assertEquals("off",RouteSnapshot.read(false,true,scope).getJSONArray("routes").getJSONObject(0).getString("state"))
        assertFalse(RouteSnapshot.read(true,true,scope.copy(network=3)).getBoolean("requiredReady"))
    }
    @Test fun duplicateRouteHeartbeatCannotRefreshAgeAndNewBatchCanReplaceResult() {
        setup();val first=checkNotNull(RouteSnapshot.request(scope))
        val invalid=JSONObject(report(first,true,true));invalid.getJSONArray("results").getJSONObject(1).put("id","route-99")
        assertThrows(IllegalArgumentException::class.java){RouteSnapshot.update(scope,invalid.toString())}
        assertEquals("checking",RouteSnapshot.read(true,true,scope).getJSONArray("routes").getJSONObject(0).getString("state"))
        assertTrue(RouteSnapshot.update(scope,report(first,true,true)))
        val before=RouteSnapshot.read(true,true,scope).getJSONArray("routes").getJSONObject(0).getLong("ageMs")
        Thread.sleep(30);assertTrue(RouteSnapshot.update(scope,report(first,true,true)))
        assertTrue(RouteSnapshot.read(true,true,scope).getJSONArray("routes").getJSONObject(0).getLong("ageMs")>=before+20)
        assertTrue(RouteSnapshot.update(scope,report(first,true)))
        val next=checkNotNull(RouteSnapshot.request(scope,force=true));assertTrue(RouteSnapshot.update(scope,report(next,false)))
        assertFalse(RouteSnapshot.read(true,true,scope).getBoolean("requiredReady"))
    }
    @Test fun routeProfilesRejectUnsupportedTargetsDuplicatesAndWrongTypes() {
        EngineConfig.validate(config)
        val invalid=listOf(config.replace("https_204","icmp"),config.replace("https://probe.example.org/generate_204","http://probe.example.org/"),config.replace("192.0.2.9:22","192.0.2.9:65536"),config.replace("\"outbound\":\"internal\"","\"outbound\":\"public\""),config.replace("\"required\":true","\"required\":\"yes\""))
        for(raw in invalid)assertThrows(IllegalArgumentException::class.java){EngineConfig.validate(raw)}
        assertThrows(IllegalArgumentException::class.java){EngineConfig.validate(config.replace("\"tag\":\"unused\"","\"tag\":\""+"я".repeat(129)+"\""))}
        val large=JSONObject(config);large.put("route_checks",org.json.JSONArray(listOf("public","internal","unused").map {tag->
            JSONObject().put("outbound",tag).put("checks",org.json.JSONArray(List(4){JSONObject().put("method","https_204").put("target","https://probe.example.org/"+"x".repeat(2000))}))
        }))
        assertThrows(IllegalArgumentException::class.java){EngineConfig.validate(large.toString())}
        assertThrows(org.json.JSONException::class.java){EngineConfig.validate("""{"outbounds":[{"type":"direct","tag":"direct"}],"route_checks":false}""")}
    }
    @Test fun routeClientMetadataNeverReachesNativeConfiguration() {
        val context=androidx.test.platform.app.InstrumentationRegistry.getInstrumentation().targetContext
        val rendered=JSONObject(EngineConfig.render(config,context.noBackupFilesDir))
        assertFalse(rendered.has("route_checks"));assertEquals(3,rendered.getJSONArray("outbounds").length())
        assertThrows(IllegalArgumentException::class.java){EngineConfig.validateAssigned(config)}
    }
    @Test fun lockedBootStatusHasUnknownIntentAndNoCredentialFields() {
        val locked=LifecycleAccess.lockedStatus()
        assertEquals("NeedsUnlock",locked.getString("phase"));assertTrue(locked.isNull("desiredOn"));assertFalse(locked.getBoolean("desiredOnKnown"));assertFalse(locked.getBoolean("engineActive"))
        assertEquals(setOf("phase","reason","desiredOn","desiredOnKnown","generation","engineActive","osPolicy"),locked.keys().asSequence().toSet())
    }
}
