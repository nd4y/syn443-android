package io.syn443.android

import io.syn443.android.vpn.RouteProbeDurations
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
    @Test fun ordinaryHttpsAndConflictingCountryChecksCannotConfirmAnExitClass() {
        fun status(vararg requiredClasses: String): JSONObject {
            val raw = JSONObject(config)
            val checks = raw.getJSONArray("route_checks").getJSONObject(0).getJSONArray("checks")
            for (exit in requiredClasses) {
                checks.put(JSONObject().put("method", "https_exit_country")
                    .put("target", "https://exit.example.invalid/").put("expected_exit_class", exit))
            }
            val owner = scope.copy(config = java.util.UUID.randomUUID().toString())
            RouteSnapshot.configure(raw.toString(), owner.config)
            RouteSnapshot.owner(owner)
            val request = requireNotNull(RouteSnapshot.request(owner, force = true))
            assertTrue(RouteSnapshot.update(owner, report(request, true)))
            return RouteSnapshot.read(true, true, owner).getJSONArray("routes").getJSONObject(0)
        }
        try {
            assertFalse(status().has("verifiedExit"))
            assertEquals("RU", status("RU").getJSONObject("verifiedExit").getString("class"))
            assertFalse(status("RU", "NON_RU").has("verifiedExit"))
        } finally {
            RouteSnapshot.owner(null)
        }
    }

    @Test fun applicationDurationsCountDistinctSuccessesAndRetireOnLossOfRouteEvidence() {
        val owner = scope.copy(config = java.util.UUID.randomUUID().toString())
        RouteSnapshot.configure(config, owner.config)
        RouteSnapshot.owner(owner)
        fun row(index: Int = 0) = RouteSnapshot.read(true, true, owner).getJSONArray("routes").getJSONObject(index)
        fun sample(ms: Long, ok: Boolean = true, doubleRead: Boolean = false) {
            val request = requireNotNull(RouteSnapshot.request(owner, force = true))
            val result = JSONObject(report(request, ok, running = doubleRead))
            result.getJSONArray("results").getJSONObject(0).put("elapsedMs", ms)
            assertTrue(RouteSnapshot.update(owner, result.toString()))
            if (doubleRead) assertTrue(RouteSnapshot.update(owner, result.put("running", false).toString()))
        }
        try {
            sample(0, doubleRead = true)
            assertFalse(row().has("durationDistribution"))
            sample(51)
            val stats = row().getJSONObject("durationDistribution")
            assertEquals(2, stats.getInt("samples"))
            assertEquals(0, stats.getLong("p50Ms"))
            assertEquals(51, stats.getLong("p95Ms"))
            assertFalse(row(1).has("durationDistribution"))
            sample(700, ok = false)
            assertFalse(row().has("durationDistribution"))
            sample(19)
            assertFalse(row().has("durationDistribution"))
            sample(21)
            assertTrue(row().has("durationDistribution"))
            val later = android.os.SystemClock.elapsedRealtime() + 120_001
            assertFalse(RouteSnapshot.readAt(true, true, owner, later).getJSONArray("routes").getJSONObject(0).has("durationDistribution"))
            RouteSnapshot.owner(owner.copy(network = owner.network + 1))
            assertFalse(row().has("durationDistribution"))
        } finally { RouteSnapshot.owner(null) }
    }

    @Test fun routeDurationWindowBoundsSamplesLifetimeAndPathIdentity() {
        var window: RouteProbeDurations? = null
        val path = listOf("entry", "exit")
        for (i in 1L..23L) {
            window = RouteProbeDurations.append(window, path, "sample-$i", i, i)
        }
        val current = requireNotNull(window)
        val stats = requireNotNull(current.summary(23))
        assertEquals(20, stats.getInt("samples"))
        assertEquals(13, stats.getLong("p50Ms"))
        assertEquals(22, stats.getLong("p95Ms"))
        val duplicate = RouteProbeDurations.append(current, path, "sample-23", 24, 1000)
        assertSame(current, duplicate)
        assertNull(current.summary(22))
        assertEquals(2, requireNotNull(current.summary(900_021)).getInt("samples"))
        assertNull(current.summary(900_022))
        val moved = RouteProbeDurations.append(current, listOf("entry", "new-exit"), "next", 25, 9)
        assertNull(moved.summary(25))
    }

    @Test fun terminalOmissionAndDeadlineClearOnlyMissingMeasurements() {
        for (deadline in listOf(false, true)) {
            setup()
            val first = checkNotNull(RouteSnapshot.request(scope))
            assertTrue(RouteSnapshot.update(scope, report(first, true)))
            val retry = checkNotNull(RouteSnapshot.request(scope, force = true))
            val partial = JSONObject(report(retry, true, running = true))
            partial.getJSONArray("results").remove(1)
            assertTrue(RouteSnapshot.update(scope, partial.toString()))
            if (!deadline) assertTrue(RouteSnapshot.update(scope, partial.put("running", false).toString()))
            val now = android.os.SystemClock.elapsedRealtime()
            val snapshot = RouteSnapshot.readAt(true, true, scope, if (deadline) now + 35_001 else now)
            assertFalse(snapshot.getBoolean("running"))
            val routes = snapshot.getJSONArray("routes")
            assertEquals(5, routes.getJSONObject(0).getLong("latencyMs"))
            assertEquals(1, routes.getJSONObject(0).getJSONArray("measuredPath").length())
            val missing = routes.getJSONObject(1)
            assertEquals("incomplete", missing.getString("state"))
            assertEquals("cancelled", missing.getString("reason"))
            assertTrue(missing.isNull("latencyMs"))
            assertEquals(0, missing.getJSONArray("measuredPath").length())
        }
    }
    @Test fun replacedPolicyCannotShowAnotherBatchPendingOrFailed() {
        val owner = scope.copy(config = "current-policy")
        RouteSnapshot.owner(null)
        RouteSnapshot.configure(config, owner.config)
        RouteSnapshot.owner(owner)
        try {
            val status = JSONObject().put("desiredOn", true).put("engineActive", true)
                .put("networkEpoch", owner.network).put("generation", owner.intent).put("configRevision", "replaced")
            val request = checkNotNull(RouteSnapshot.request(owner))
            val other = RouteSnapshot.view(status)
            assertFalse(other.getBoolean("running"))
            assertFalse(other.getJSONArray("routes").getJSONObject(0).getBoolean("checkPending"))
            status.put("configRevision", owner.config)
            assertTrue(RouteSnapshot.view(status).getBoolean("running"))
            assertTrue(RouteSnapshot.update(owner, report(request, false)))
            val current = RouteSnapshot.view(status).getJSONArray("routes").getJSONObject(0)
            assertEquals("failed", current.getString("state"))
            assertEquals("dial_failed", current.getString("reason"))
            val old = RouteSnapshot.view(status.put("configRevision", "replaced")).getJSONArray("routes").getJSONObject(0)
            assertEquals("unverified", old.getString("state"))
            assertEquals("not_checked", old.getString("reason"))
            assertTrue(old.isNull("latencyMs"))
            assertEquals(0, old.getJSONArray("measuredPath").length())
        } finally {
            RouteSnapshot.owner(null)
        }
    }

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
    @Test fun currentFailedProbeOnlyShowsKnownCauseForItsStage() {
        setup()
        fun row(on: Boolean = true, active: RouteScope = scope) =
            RouteSnapshot.read(on, true, active).getJSONArray("routes").getJSONObject(0)
        fun accept(reason: String, detail: String, ok: Boolean = false) {
            val request = checkNotNull(RouteSnapshot.request(scope, force = true))
            val frame = JSONObject(report(request, ok))
            frame.getJSONArray("results").getJSONObject(0).put("code", reason).put("cause", detail)
            assertTrue(RouteSnapshot.update(scope, frame.toString()))
        }
        accept("dial_failed", "dns_not_found")
        assertEquals("failed", row().getString("state"))
        assertEquals("dial_failed", row().getString("reason"))
        assertEquals("dns_not_found", row().getString("cause"))
        assertFalse(row(false).has("cause"))
        assertFalse(row(active = scope.copy(network = 9)).has("cause"))
        val stale = RouteSnapshot.readAt(true, true, scope, android.os.SystemClock.elapsedRealtime()+120001)
        assertFalse(stale.getJSONArray("routes").getJSONObject(0).has("cause"))
        accept("tls_failed", "dns_not_found")
        assertFalse(row().has("cause"))
        accept("tls_failed", "sensitive.invalid")
        assertFalse(row().toString().contains("sensitive.invalid"))
        accept("tls_failed", "certificate_untrusted")
        assertEquals("certificate_untrusted", row().getString("cause"))
        accept("ok", "connection_refused", ok = true)
        assertFalse(row().has("cause"))
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
    @Test fun countryExitCheckKeepsStrictFieldsAndReportsMismatchPrivately() {
        val raw = config.replace("\"method\":\"https_204\"", "\"method\":\"https_exit_country\",\"expected_exit_class\":\"RU\"")
            .replace("https://probe.example.org/generate_204", "https://probe.example.org/")
        EngineConfig.validate(raw)
        EngineConfig.validate(raw.replace("\"RU\"", "\"NON_RU\""))
        for (bad in listOf(raw.replace("\"RU\"", "\"INTERNAL\""), raw.replace("\"RU\"", "true"),
            raw.replace("\"RU\"", "null"), raw.replace("\"RU\"", "\"ru\""), raw.replace("https_exit_country", "https_204"),
            raw.replace("\"expected_exit_class\":\"RU\",", ""), raw.replace("\"RU\"", "\"RU\",\"expected_ip\":\"192.0.2.9\""),
            raw.replace("https://probe.example.org/", "https://probe.example.org/192.0.2.9"),
            raw.replace("https://probe.example.org/", "https://probe.example.org/?ip=192.0.2.9"),
            raw.replace("https://probe.example.org/", "https://probe.example.org/%2f"))) {
            assertThrows(IllegalArgumentException::class.java) { EngineConfig.validate(bad) }
        }
        RouteSnapshot.configure(raw, scope.config)
        RouteSnapshot.owner(scope)
        val request = checkNotNull(RouteSnapshot.request(scope))
        val check = JSONObject(request).getJSONArray("routes").getJSONObject(0).getJSONArray("checks").getJSONObject(0)
        assertEquals("RU", check.getString("expected_exit_class"))
        val mismatch = JSONObject(report(request, false))
        mismatch.getJSONArray("results").getJSONObject(0).put("code", "exit_country_mismatch")
        assertTrue(RouteSnapshot.update(scope, mismatch.toString()))
        val view = RouteSnapshot.read(true, true, scope)
        assertFalse(view.getBoolean("requiredReady"))
        assertEquals("failed", view.getJSONArray("routes").getJSONObject(0).getString("state"))
        assertFalse(view.toString().contains("probe.example.org"))
        assertFalse(view.toString().contains("expected_exit_class"))
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
        // Explicit resume fences new starts. A stale checkpoint no longer
        // prevents reporting inactive once the process is confirmed absent.
        val fenced = LifecycleAccess.engineStatus(saved().put("resumeRequired", true), false, false)
        assertFalse(fenced.getBoolean("engineActive"));assertTrue(fenced.getBoolean("engineStateKnown"))
        assertTrue(fenced.getBoolean("desiredOn"))
        for (present in listOf(true, null)) {
            val unresolved = LifecycleAccess.engineStatus(saved().put("resumeRequired", true), false, present)
            assertTrue(unresolved.isNull("engineActive"));assertFalse(unresolved.getBoolean("engineStateKnown"))
        }
        fun interruptedStop() = saved().put("desiredOn",false).put("phase","Off")
        val physicallyStopped = LifecycleAccess.engineStatus(interruptedStop(), false, false, serviceAttached = false)
        assertFalse(physicallyStopped.getBoolean("engineActive"))
        assertTrue(physicallyStopped.getBoolean("engineStateKnown"))
        assertEquals(7, physicallyStopped.getInt("generation"))
        for (present in listOf(true, null)) {
            assertTrue(LifecycleAccess.engineStatus(interruptedStop(), false, present, serviceAttached = false).isNull("engineActive"))
        }
        assertTrue(LifecycleAccess.engineStatus(interruptedStop(), false, false, serviceAttached = true).isNull("engineActive"))
        assertTrue(LifecycleAccess.engineStatus(saved(), false, false, serviceAttached = false).isNull("engineActive"))
        assertTrue(LifecycleAccess.engineStatus(interruptedStop().put("phase","Recovering"), false, false, serviceAttached = false).isNull("engineActive"))
        val live=LifecycleAccess.engineStatus(saved(),true,true)
        assertTrue(live.getBoolean("engineActive"));assertTrue(live.getBoolean("engineStateKnown"))
        val readyAfterHandshake=LifecycleAccess.engineStatus(JSONObject().put("engineActive",false),true,null)
        assertTrue(readyAfterHandshake.getBoolean("engineActive"))
    }
}
