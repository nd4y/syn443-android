package io.syn443.android

import io.syn443.android.vpn.RouteSnapshot
import io.syn443.android.vpn.EngineConfig
import io.syn443.android.vpn.LifecycleAccess
import io.syn443.recovery.RouteScope
import io.syn443.recovery.RouteActivation
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
        EngineConfig.validateAssigned(config)
        assertThrows(IllegalArgumentException::class.java){EngineConfig.validateAssigned("""{"outbounds":[{"type":"netbird","tag":"overlay"}]}""")}
    }
    @Test fun routeExitProofIsRequiredAndReportsMismatchWithoutExposingAddresses() {
        val raw = config.replace("\"method\":\"https_204\"", "\"method\":\"https_exit_ip\",\"expected_ip\":\"2001:db8::9\"")
        EngineConfig.validate(raw)
        for (invalid in listOf("exit.example.invalid", "192.0.2.09", "fe80::1%wifi", "::ffff:192.0.2.9", "2001:db8::/32")) {
            assertThrows(IllegalArgumentException::class.java) { EngineConfig.validate(raw.replace("2001:db8::9", invalid)) }
        }
        assertThrows(IllegalArgumentException::class.java) { EngineConfig.validate(raw.replace("https_exit_ip", "https_204")) }

        RouteSnapshot.configure(raw, scope.config)
        RouteSnapshot.owner(scope)
        val request = checkNotNull(RouteSnapshot.request(scope))
        val check = JSONObject(request).getJSONArray("routes").getJSONObject(0).getJSONArray("checks").getJSONObject(0)
        assertEquals("2001:db8::9", check.getString("expected_ip"))
        val mismatch = JSONObject(report(request, false))
        mismatch.getJSONArray("results").getJSONObject(0).put("code", "exit_ip_mismatch")
        assertTrue(RouteSnapshot.update(scope, mismatch.toString()))
        val result = RouteSnapshot.read(true, true, scope)
        assertFalse(result.getBoolean("requiredReady"))
        assertEquals("failed", result.getJSONArray("routes").getJSONObject(0).getString("state"))
        assertFalse(result.toString().contains("2001:db8::9"))
        assertFalse(result.toString().contains("probe.example.org"))
    }
    @Test fun sshWithoutServerPinCannotBeImportedAssignedOrRendered() {
        val root = androidx.test.platform.app.InstrumentationRegistry.getInstrumentation().targetContext.noBackupFilesDir
        val config = JSONObject("""{"outbounds":[{"type":"ssh","tag":"ssh-hop","server":"proxy.example.invalid","server_port":22,"user":"fixture"}]}""")
        val ssh = config.getJSONArray("outbounds").getJSONObject(0)
        // RFC 8032 public test vector encoded as an OpenSSH authorized key.
        val syntheticPublicPin = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3B1Ea"
        val invalid = listOf(null, JSONObject.NULL, "", " \t", 12, org.json.JSONArray(),
            org.json.JSONArray().put(syntheticPublicPin).put(JSONObject.NULL),
            org.json.JSONArray(List(17) { syntheticPublicPin }), "x".repeat(8193), "x\u0000y")
        for (pins in invalid) {
            ssh.put("host_key", pins)
            val raw = config.toString()
            for (admit in listOf<(String) -> Unit>(EngineConfig::validate, EngineConfig::validateAssigned, { EngineConfig.render(it, root); Unit })) {
                assertEquals("ssh_host_key_required", assertThrows(IllegalArgumentException::class.java) { admit(raw) }.message)
            }
        }
        for (pins in listOf(syntheticPublicPin, org.json.JSONArray().put(syntheticPublicPin))) {
            ssh.put("host_key", pins)
            val raw = config.toString()
            EngineConfig.validate(raw)
            EngineConfig.validateAssigned(raw)
            val rendered = JSONObject(EngineConfig.render(raw, root)).getJSONArray("outbounds").getJSONObject(0)
            assertEquals(pins.toString(), rendered.get("host_key").toString())
        }
        ssh.put("HOST_KEY", org.json.JSONArray())
        assertEquals("ssh_host_key_required", assertThrows(IllegalArgumentException::class.java) {
            EngineConfig.validate(config.toString())
        }.message)
        ssh.remove("HOST_KEY")
        ssh.put("type", "direct").put("TYPE", "ssh").remove("host_key")
        assertEquals("ambiguous_outbound_type", assertThrows(IllegalArgumentException::class.java) {
            EngineConfig.validate(config.toString())
        }.message)
    }
    @Test fun insecureProxyAndDnsTlsCannotBeImportedAssignedOrRendered() {
        val root = androidx.test.platform.app.InstrumentationRegistry.getInstrumentation().targetContext.noBackupFilesDir
        val proxy = """{"outbounds":[{"type":"http","tag":"proxy","server":"proxy.example.invalid","server_port":443,"tls":{"enabled":true,"insecure":FLAG}}]}"""
        val dns = """{"outbounds":[{"type":"direct","tag":"direct"}],"dns":{"servers":[{"type":"https","tag":"resolver","server":"dns.example.invalid","tls":{"enabled":true,"insecure":FLAG}}],"final":"resolver"}}"""
        val admit = listOf<(String) -> Unit>(EngineConfig::validate, EngineConfig::validateAssigned, { EngineConfig.render(it, root); Unit })
        for (config in listOf(proxy, dns)) for (apply in admit) {
            apply(config.replace("FLAG", "false"))
            apply(config.replace(",\"insecure\":FLAG", ""))
            for (flag in listOf("true", "null", "\"false\"")) {
                assertEquals("tls_verification_required", assertThrows(IllegalArgumentException::class.java) {
                    apply(config.replace("FLAG", flag))
                }.message)
            }
            assertEquals("tls_verification_required", assertThrows(IllegalArgumentException::class.java) {
                apply(config.replace("\"tls\"", "\"TLS\"").replace("\"insecure\"", "\"Insecure\"").replace("FLAG", "true"))
            }.message)
        }
    }
    @Test fun assignedActivationWaitsForCandidateRoutesAndIgnoresOptionalFailure() {
        val candidate=scope.copy(config="assigned-${java.util.UUID.randomUUID()}")
        RouteSnapshot.configure(config,candidate.config);RouteSnapshot.owner(candidate)
        assertEquals(RouteActivation.WAIT,RouteSnapshot.activation(candidate))
        val request=checkNotNull(RouteSnapshot.request(candidate))
        assertEquals(RouteActivation.WAIT,RouteSnapshot.activation(candidate))
        assertTrue(RouteSnapshot.update(candidate,report(request,true)))
        assertEquals(RouteActivation.READY,RouteSnapshot.activation(candidate))
        val next=checkNotNull(RouteSnapshot.request(candidate,force=true))
        assertTrue(RouteSnapshot.update(candidate,report(next,false)))
        assertEquals(RouteActivation.FAILED,RouteSnapshot.activation(candidate))
    }
    @Test fun assignedActivationCannotReusePriorScopeOrIncompleteRouteProof() {
        val initial=scope.copy(config="assigned-${java.util.UUID.randomUUID()}")
        RouteSnapshot.configure(config,initial.config);RouteSnapshot.owner(initial)
        val request=checkNotNull(RouteSnapshot.request(initial))
        assertTrue(RouteSnapshot.update(initial,report(request,true)))
        val started=android.os.SystemClock.elapsedRealtime()
        assertTrue(RouteSnapshot.prepareActivation(initial,started))
        assertFalse(RouteSnapshot.prepareActivation(initial,started))
        assertFalse(RouteSnapshot.update(initial,report(request,true)))
        assertEquals(RouteActivation.WAIT,RouteSnapshot.activation(initial,started))
        for(candidate in listOf(initial.copy(intent=5),initial.copy(network=3),initial.copy(activation=4),initial.copy(engine="replacement"),initial.copy(config="other"))) {
            assertEquals(RouteActivation.WAIT,RouteSnapshot.activation(candidate))
        }
        val candidate=initial.copy(activation=4);RouteSnapshot.owner(candidate)
        assertTrue(RouteSnapshot.due(10_000));assertFalse(RouteSnapshot.update(initial,report(request,true)))
        assertEquals(RouteActivation.WAIT,RouteSnapshot.activation(candidate))
        val fresh=checkNotNull(RouteSnapshot.request(candidate))
        val incomplete=JSONObject(report(fresh,false));incomplete.getJSONArray("results").getJSONObject(0).put("complete",false).put("code","cancelled")
        assertTrue(RouteSnapshot.update(candidate,incomplete.toString()))
        assertEquals(RouteActivation.WAIT,RouteSnapshot.activation(candidate))
        assertFalse(RouteSnapshot.due(10_000))
        RouteSnapshot.owner(null)
        assertEquals(RouteActivation.WAIT,RouteSnapshot.activation(candidate))
    }
    @Test fun lockedBootStatusHasUnknownIntentAndNoCredentialFields() {
        val locked=LifecycleAccess.lockedStatus()
        assertEquals("NeedsUnlock",locked.getString("phase"));assertTrue(locked.isNull("desiredOn"));assertFalse(locked.getBoolean("desiredOnKnown"));assertFalse(locked.getBoolean("engineActive"))
        assertEquals(setOf("phase","reason","desiredOn","desiredOnKnown","generation","engineActive","osPolicy"),locked.keys().asSequence().toSet())
    }
    @Test fun savedEngineCheckpointCannotClaimAnUnownedLiveProcess() {
        fun saved()=JSONObject().put("engineActive",true).put("desiredOn",true)
            .put("generation",7).put("phase","Recovering")
        val stopped=JSONObject().put("engineActive",false).put("desiredOn",false)
        val absent=LifecycleAccess.engineStatus(stopped,false,false)
        assertFalse(absent.getBoolean("engineActive"));assertTrue(absent.getBoolean("engineStateKnown"))
        // A saved start remains unresolved until retirement clears its checkpoint,
        // even if the old process has already disappeared.
        for(present in listOf(true,false,null)) {
            val unknown=LifecycleAccess.engineStatus(saved(),false,present)
            assertTrue(unknown.isNull("engineActive"));assertFalse(unknown.getBoolean("engineStateKnown"))
            assertTrue(unknown.getBoolean("desiredOn"));assertEquals(7,unknown.getInt("generation"))
            assertEquals("Recovering",unknown.getString("phase"))
        }
        val live=LifecycleAccess.engineStatus(saved(),true,true)
        assertTrue(live.getBoolean("engineActive"));assertTrue(live.getBoolean("engineStateKnown"))
        val readyAfterHandshake=LifecycleAccess.engineStatus(JSONObject().put("engineActive",false),true,null)
        assertTrue(readyAfterHandshake.getBoolean("engineActive"))
    }
}
