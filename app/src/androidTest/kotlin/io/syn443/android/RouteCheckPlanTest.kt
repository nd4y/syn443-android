package io.syn443.android

import android.os.SystemClock
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.test.assertTextEquals
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import io.syn443.android.vpn.*
import io.syn443.identity.IdentityOperation
import io.syn443.decision.NetworkMode
import io.syn443.policy.Canonical
import io.syn443.policy.Policy
import io.syn443.recovery.RouteScope
import kotlinx.serialization.json.Json
import org.json.JSONArray
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import java.io.File
import java.util.Base64

/** Synthetic metadata/report checks only; no enrollment, network, SDK or device settings. */
class RouteCheckPlanTest {
    @get:Rule val compose=createComposeRule()
    @After fun clear() {RouteSnapshot.owner(null)}
    private fun profile()=JSONObject("""{"schemaVersion":2,"id":"connectivity","revision":1,"deadlineMs":12000,"leaves":[{"id":"a","check":{"method":"tcp","target":"a.example.invalid:443"}},{"id":"b","check":{"method":"tcp","target":"b.example.invalid:443"}}],"gates":[],"stages":[{"any":[{"leaf":"a"},{"leaf":"b"}]}]}""")
    private fun config()=JSONObject().put("outbounds",JSONArray().put(JSONObject().put("type","http").put("tag","entry").put("server","192.0.2.1").put("server_port",443)))
        .put("route",JSONObject().put("final","entry")).put("route_checks",JSONArray().put(JSONObject().put("outbound","entry").put("required",true).put("profile",profile())))
    private fun row(value:JSONObject)=value.getJSONArray("route_checks").getJSONObject(0)
    private fun configure(value:JSONObject=config()):RouteScope {
        RouteSnapshot.owner(null)
        val raw=value.toString();EngineConfig.validate(raw)
        val scope=RouteScope(1,2,3,"synthetic-composition",Policy.hash(raw))
        RouteSnapshot.configure(raw,scope.config);RouteSnapshot.owner(scope)
        return scope
    }
    private fun view(scope:RouteScope)=RouteSnapshot.read(true,true,scope).getJSONArray("routes").getJSONObject(0)
    private fun diagnostic(outcome:String="TRUE")=JSONObject().put("id","connectivity").put("revision",1).put("outcome",outcome)
        .put("leaves",JSONArray().put(JSONObject().put("id","a").put("outcome",if(outcome=="TRUE")"TRUE" else "UNKNOWN").put("code",if(outcome=="TRUE")"ok" else "cancelled"))
            .put(JSONObject().put("id","b").put("outcome","SKIPPED").put("code","not_checked")))
    private fun report(request:JSONObject,ok:Boolean=true,plan:JSONObject=diagnostic())=JSONObject().put("request",request.getString("request")).put("running",false)
        .put("results",JSONArray().put(JSONObject().put("id","route-1").put("complete",ok).put("ok",ok).put("code",if(ok)"ok" else "cancelled")
            .put("elapsedMs",5).put("sampledElapsedMs",SystemClock.elapsedRealtime()).put("path",JSONArray().put("route-1")).put("checkPlan",plan))).toString()

    @Test fun onlyFreshMatchedCountryEvidenceIsShownForTheCurrentMeasuredPath() {
        val value = config()
        val plan = row(value).getJSONObject("profile")
        plan.getJSONArray("leaves").getJSONObject(1).put("check", JSONObject()
            .put("method", "https_exit_country").put("target", "https://country.example.invalid/")
            .put("expected_exit_class", "NON_RU"))
        plan.put("gates", JSONArray().put("b")).put("stages", JSONArray().put(JSONObject().put("leaf", "a")))
        val scope = configure(value)
        fun snapshot(at: Long) = JSONObject().put("routeHealth", RouteSnapshot.readAt(true, true, scope, at))
        val pending = JSONObject(requireNotNull(RouteSnapshot.request(scope)))
        val skipped = JSONObject(report(pending))
        assertTrue(RouteSnapshot.update(scope, skipped.toString()))
        assertFalse(view(scope).has("verifiedExit"))

        val request = JSONObject(requireNotNull(RouteSnapshot.request(scope, force = true)))
        val proof = diagnostic()
        proof.getJSONArray("leaves").getJSONObject(1).put("outcome", "TRUE").put("code", "ok")
        val response = JSONObject(report(request, plan = proof))
        val at = response.getJSONArray("results").getJSONObject(0).getLong("sampledElapsedMs")
        assertTrue(RouteSnapshot.update(scope, response.toString()))
        val current = snapshot(at)
        val observed = current.getJSONObject("routeHealth").getJSONArray("routes").getJSONObject(0).getJSONObject("verifiedExit")
        assertEquals(setOf("class", "source", "validForMs"), observed.keys().asSequence().toSet())
        assertEquals("NON_RU", observed.getString("class"))
        assertEquals("https_exit_country", observed.getString("source"))
        assertEquals(io.syn443.recovery.RouteEvidence.DEFAULT_TTL_MS, observed.getLong("validForMs"))
        assertFalse(current.toString().contains("country.example.invalid"))

        val model = mutableStateOf(current)
        compose.setContent { MaterialTheme { RouteControls(model.value) { _, _ -> error("read-only") } } }
        val label = compose.onNodeWithTag("route-1-verified-exit")
        label.assertTextEquals("Выход: вне России · подтверждён HTTPS-проверкой · ещё 120 с")
        compose.runOnIdle { model.value = snapshot(at + 119_500) }
        label.assertTextEquals("Выход: вне России · подтверждён HTTPS-проверкой · ещё 1 с")
        compose.runOnIdle { model.value = snapshot(at + 120_001) }
        label.assertDoesNotExist()
        assertFalse(RouteSnapshot.read(true, false, scope).getJSONArray("routes").getJSONObject(0).has("verifiedExit"))
        assertFalse(RouteSnapshot.read(true, true, scope.copy(network = 8)).getJSONArray("routes").getJSONObject(0).has("verifiedExit"))
    }

    @Test fun canceledBatchClearsEarlierSuccessfulLeafOutcomes() {
        val scope = configure()
        val first = JSONObject(checkNotNull(RouteSnapshot.request(scope)))
        assertTrue(RouteSnapshot.update(scope, report(first)))
        assertEquals("TRUE", view(scope).getJSONObject("checkPlan").getString("outcome"))
        val retry = JSONObject(checkNotNull(RouteSnapshot.request(scope, force = true)))
        val terminal = JSONObject(report(retry)).put("results", JSONArray())
        assertTrue(RouteSnapshot.update(scope, terminal.toString()))
        val row = view(scope)
        assertEquals("incomplete", row.getString("state"))
        val plan = row.getJSONObject("checkPlan")
        assertEquals("UNKNOWN", plan.getString("outcome"))
        assertTrue((0 until plan.getJSONArray("leaves").length()).none {
            plan.getJSONArray("leaves").getJSONObject(it).getString("outcome") == "TRUE"
        })
        assertFalse(RouteSnapshot.read(true, true, scope).getBoolean("requiredReady"))
    }
    @Test fun ordinaryRequestOwnsWholeProfileAndNeverFlattensOrBorrowsMutatedInput() {
        val config=config();val scope=configure(config)
        row(config).getJSONObject("profile").put("revision",2)
        val request=JSONObject(checkNotNull(RouteSnapshot.request(scope,force=true)))
        val plan=request.getJSONArray("routes").getJSONObject(0)
        assertTrue(plan.has("profile"));assertFalse(plan.has("checks"))
        assertEquals(1,plan.getJSONObject("profile").getInt("revision"))
        assertEquals("any",plan.getJSONObject("profile").getJSONArray("stages").getJSONObject(0).keys().next())
        assertTrue(request.toString().toByteArray().size<=32768)
        assertTrue(RouteSnapshot.accepts("route-1"))
        assertTrue(row(JSONObject(EngineConfig.render(config.toString(),File("/synthetic/composition")))).has("profile"))
    }
    @Test fun originalDuplicateNumericNullAndMixedProfileFieldsFailBeforeActivation() {
        val raw=config().toString()
        for(invalid in listOf(raw.replace("\"revision\":1","\"revision\":1.0"),
            raw.replace("\"schemaVersion\":2","\"schemaVersion\":2e0"),
            raw.replace("\"revision\":1","\"revision\":1,\"\\u0072evision\":1"),
            raw.replace("\"profile\":","\"checks\":[],\"profile\":"),
            raw.replace("\"profile\":","\"Profile\":"),
            config().also {row(it).put("profile",JSONObject.NULL)}.toString(),raw.dropLast(1)+",\"unrelated\":tru}")) {
            assertThrows(Exception::class.java) {EngineConfig.validate(invalid)}
        }
        assertThrows(Exception::class.java) {EngineConfig.validate(raw.replace("\"route_checks\":[","\"route_checks\":["+" ".repeat(24001)))}
        for(value in listOf<Any>(JSONObject.NULL,1,"true")) assertThrows(Exception::class.java) {EngineConfig.validate(config().also {row(it).put("required",value)}.toString())}
        assertThrows(Exception::class.java) {EngineConfig.validate(config().also {row(it).remove("required")}.toString())}
        for(value in listOf<Any>(JSONObject.NULL,1,"")) assertThrows(Exception::class.java) {EngineConfig.validate(config().also {row(it).put("outbound",value)}.toString())}
        assertThrows(Exception::class.java) {EngineConfig.validate(raw.replace("\"required\":true","\"required\":true,\"\\u0072equired\":true"))}
    }
    @Test fun concretePathIncludesTerminalDirectButRejectsVariableOverlayCycleAndFailover() {
        val valid=config();valid.getJSONArray("outbounds").put(JSONObject().put("type","direct").put("tag","physical"))
        valid.getJSONArray("outbounds").getJSONObject(0).put("detour","physical")
        EngineConfig.validate(valid.toString())
        val direct=config();direct.put("outbounds",JSONArray().put(JSONObject().put("type","direct").put("tag","entry")))
        EngineConfig.validate(direct.toString())
        for(kind in listOf("selector","urltest","netbird","syn443-adaptive")) {
            val changed=JSONObject(valid.toString());changed.getJSONArray("outbounds").getJSONObject(1).put("type",kind)
            assertThrows(Exception::class.java) {EngineConfig.validate(changed.toString())}
        }
        val cycle=JSONObject(valid.toString());cycle.getJSONArray("outbounds").getJSONObject(1).put("detour","entry")
        assertThrows(Exception::class.java) {EngineConfig.validate(cycle.toString())}
        for(value in listOf(JSONObject.NULL,JSONObject())) assertThrows(Exception::class.java) {EngineConfig.validate(config().put("route_failover",value).toString())}
        val long=config();var current=long.getJSONArray("outbounds").getJSONObject(0)
        repeat(4) {i->current.put("detour","extra-$i");val next=JSONObject().put("type","http").put("tag","extra-$i").put("server","192.0.2.1").put("server_port",443);long.getJSONArray("outbounds").put(next);current=next}
        assertThrows(Exception::class.java) {EngineConfig.validate(long.toString())}
    }
    @Test fun adaptiveCountryMustBeUnconditionalMatchingGateAndWholeProfileReachesNativeRender() {
        val config=JSONObject(ManagedAdaptiveRoutesFairnessTest().config(choices=1,groupCount=1))
        val wire=config.getJSONObject("adaptive_routes")
        val graph=JSONObject(String(Base64.getUrlDecoder().decode(wire.getString("graphB64")),Charsets.UTF_8))
        graph.getJSONArray("groups").getJSONObject(0).put("intent","RU")
        graph.getJSONArray("hops").getJSONObject(0).put("exitClass","RU")
        wire.put("graphB64",Base64.getUrlEncoder().withoutPadding().encodeToString(Canonical.encode(Json.parseToJsonElement(graph.toString())).toByteArray()))
        val country=JSONObject("""{"schemaVersion":2,"id":"country","revision":1,"deadlineMs":12000,"leaves":[{"id":"country","check":{"method":"https_exit_country","target":"https://country.example.invalid/","expected_exit_class":"RU"}}],"gates":["country"],"stages":[]}""")
        val route=row(config);route.remove("checks");route.put("profile",country)
        EngineConfig.validate(config.toString())
        val rendered=JSONObject(EngineConfig.render(config.toString(),File("/synthetic/composition")))
        assertTrue(row(rendered).has("profile"));assertFalse(row(rendered).has("checks"))
        val wrong=JSONObject(config.toString());row(wrong).getJSONObject("profile").getJSONArray("leaves").getJSONObject(0).getJSONObject("check").put("expected_exit_class","NON_RU")
        assertThrows(Exception::class.java) {EngineConfig.validate(wrong.toString())}
        val missing=JSONObject(config.toString());row(missing).put("profile",profile())
        assertThrows(Exception::class.java) {EngineConfig.validate(missing.toString())}
    }
    @Test fun leafProjectionIsOwnedRedactedAndScopeBoundWithoutGrantingReadiness() {
        val scope=configure();val request=JSONObject(checkNotNull(RouteSnapshot.request(scope,force=true)))
        assertEquals("UNKNOWN",view(scope).getJSONObject("checkPlan").getString("outcome"))
        assertFalse(RouteSnapshot.read(true,true,scope).getBoolean("requiredReady"))
        val plan=diagnostic();val raw=report(request,plan=plan)
        assertFalse(RouteSnapshot.update(scope.copy(network=scope.network+1),raw))
        assertTrue(RouteSnapshot.update(scope,raw));plan.put("outcome","FALSE")
        val result=view(scope);assertEquals("TRUE",result.getJSONObject("checkPlan").getString("outcome"))
        assertFalse(result.toString().contains("example.invalid"));assertFalse(result.toString().contains("192.0.2"))
        result.getJSONObject("checkPlan").put("outcome","FALSE")
        assertEquals("TRUE",view(scope).getJSONObject("checkPlan").getString("outcome"))
        RouteSnapshot.owner(scope.copy(engine="next-synthetic-owner"))
        assertEquals("UNKNOWN",view(scope.copy(engine="next-synthetic-owner")).getJSONObject("checkPlan").getString("outcome"))
    }
    @Test fun unknownCancelledAndForeignDiagnosticNeverBecomeFailedProxyOrWorkingRoute() {
        val scope=configure();val request=JSONObject(checkNotNull(RouteSnapshot.request(scope,force=true)))
        assertTrue(RouteSnapshot.update(scope,report(request,ok=false,plan=diagnostic())))
        assertEquals("incomplete",view(scope).getString("state"))
        assertEquals("UNKNOWN",view(scope).getJSONObject("checkPlan").getString("outcome"))
        assertFalse(RouteSnapshot.read(true,true,scope).getBoolean("requiredReady"))
        val next=JSONObject(checkNotNull(RouteSnapshot.request(scope,force=true)))
        val foreign=diagnostic().put("target","https://private.example.invalid/")
        assertTrue(RouteSnapshot.update(scope,report(next,ok=false,plan=foreign)))
        assertEquals("UNKNOWN",view(scope).getJSONObject("checkPlan").getString("outcome"))
        assertFalse(view(scope).toString().contains("private.example"))
        val valid=JSONObject(checkNotNull(RouteSnapshot.request(scope,force=true)))
        assertTrue(RouteSnapshot.update(scope,report(valid,ok=false,plan=diagnostic("UNKNOWN"))))
        assertEquals("cancelled",view(scope).getJSONObject("checkPlan").getJSONArray("leaves").getJSONObject(0).getString("code"))
        assertFalse(RouteSnapshot.read(true,true,scope).getBoolean("requiredReady"))
    }
    @Test fun legacyArraysRemainCompatibleWhenNewEnrollmentsAdvertiseNamedChecks() {
        assertTrue(Policy.ROUTE_CHECK_PLAN in Policy.capabilities)
        assertTrue(Policy.ROUTE_CHECK_PLAN in IdentityOperation.supportedCapabilities)
        assertFalse(Policy.ROUTE_CHECK_PLAN in IdentityOperation.requiredCapabilities)
        val config=config();val row=row(config);row.remove("profile")
        val checks=JSONArray().put(JSONObject().put("method","tcp").put("target","a.example.invalid:443"))
        row.put("checks",checks)
        val scope=configure(config);val native=JSONObject(checkNotNull(RouteSnapshot.request(scope,force=true))).getJSONArray("routes").getJSONObject(0)
        assertEquals(checks.toString(),native.getJSONArray("checks").toString());assertFalse(native.has("profile"))
        assertFalse(JSONObject(EngineConfig.render(config.toString(),File("/synthetic/composition"))).has("route_checks"))
        // Existing unmanaged APP validation had no262KiB whole-engine cap.
        config.getJSONArray("outbounds").getJSONObject(0).put("password","synthetic-padding".repeat(20000))
        assertTrue(config.toString().toByteArray().size>262144)
        EngineConfig.validate(config.toString())
        RouteSnapshot.configure(config.toString(),Policy.hash(config.toString()))
        assertFalse(JSONObject(EngineConfig.render(config.toString(),File("/synthetic/composition"))).has("route_checks"))
    }
    @Test fun readOnlyPlanLabelsAreFiniteAndRecompositionDoesNotDispatch() {
        val scope=configure();val model=mutableStateOf(JSONObject().put("routeHealth",RouteSnapshot.read(true,true,scope)))
        val commands=mutableListOf<String>()
        compose.setContent {MaterialTheme {RouteControls(model.value) {command,_->commands+=command}}}
        compose.onNodeWithTag("route-1-check-plan").assertTextEquals("План проверки connectivity: результат не определён")
        compose.onNodeWithTag("route-1-check-leaf-1").assertTextEquals("1/2 a: проверка не выполнялась")
        for(outcome in listOf("TRUE","FALSE","UNKNOWN","SKIPPED","https://private.example.invalid/")) {
            assertFalse(checkPlanOutcomeLabel(outcome).contains("private"))
            compose.runOnIdle {model.value=JSONObject(model.value.toString())}
        }
        compose.waitForIdle();assertTrue(commands.isEmpty())
    }
    @Test fun adaptiveProjectionWaitsForExactSelectedReceiptOwnsValuesAndClearsOnRebind() {
        val config=JSONObject(ManagedAdaptiveRoutesFairnessTest().config(choices=1,groupCount=1))
        row(config).remove("checks");row(config).put("profile",profile())
        val scope=configure(config)
        fun snapshot(owner:RouteScope, now:Long) = RouteSnapshot.readAt(true,true,owner,now)
        fun currentPlan()=snapshot(scope,1000).getJSONArray("routes").getJSONObject(0).getJSONObject("checkPlan")
        val controller=checkNotNull(ManagedAdaptiveRoutes.read(config.toString()))
        controller.bind(scope,NetworkMode.WIFI,1)
        val policy=JSONObject(controller.controlFrame()).getString("scope")
        val native=Policy.hash("synthetic-composition-native")
        val commands=mutableListOf<JSONObject>()
        val dispatch:(String)->Unit={commands+=JSONObject(JSONObject(it).getString("commandJson"))}
        fun status()=JSONObject().put("nativeEpoch",1).put("scope",native).put("policyScope",policy)
            .put("ready",true).put("running",false).put("request","").put("code","idle").put("group","").put("hops",JSONArray())
        controller.report(status(),1000,dispatch)
        controller.tick(1000,true,true,dispatch)
        val start=commands.single {it.getString("command")=="start"}
        val receipt=Policy.hash(start.getString("request")+"-receipt")
        val report=status().put("request",start.getString("request")).put("group",start.getString("group"))
            .put("hops",JSONArray(start.getJSONArray("hops").toString())).put("code","verified")
            .put("probeMs",20).put("elapsedMs",100).put("receipt",receipt).put("groupSelected",false).put("checkPlan",diagnostic())
        controller.report(report,1000,dispatch)
        assertEquals("commit",commands.last().getString("command"))
        assertEquals("UNKNOWN",currentPlan().getString("outcome"))
        assertFalse(snapshot(scope,1000).getBoolean("requiredReady"))
        report.getJSONObject("checkPlan").getJSONArray("leaves").getJSONObject(0).put("id","foreign")
        controller.report(JSONObject(report.toString()).put("code","selected").put("groupSelected",true).put("receipt",Policy.hash("wrong")),1000,dispatch)
        assertEquals("UNKNOWN",currentPlan().getString("outcome"))
        controller.report(report.put("code","selected").put("groupSelected",true),1000,dispatch)
        assertEquals("TRUE",currentPlan().getString("outcome"))
        assertEquals("a",currentPlan().getJSONArray("leaves").getJSONObject(0).getString("id"))
        val next=scope.copy(network=scope.network+1)
        RouteSnapshot.owner(next);controller.bind(next,NetworkMode.WIFI,2)
        controller.report(report,1001,dispatch)
        assertEquals("UNKNOWN",snapshot(next,1001).getJSONArray("routes").getJSONObject(0).getJSONObject("checkPlan").getString("outcome"))
        assertFalse(snapshot(next,1001).getBoolean("requiredReady"))
    }
}
