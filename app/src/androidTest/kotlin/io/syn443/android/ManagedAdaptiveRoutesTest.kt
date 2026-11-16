package io.syn443.android

import io.syn443.android.vpn.ManagedAdaptiveRoutes
import io.syn443.android.vpn.RouteSnapshot
import io.syn443.decision.Decision
import io.syn443.decision.NetworkMode
import io.syn443.policy.Policy
import io.syn443.recovery.RouteScope
import java.io.Closeable
import java.util.Base64
import kotlinx.serialization.json.*
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

/** Synthetic native-owner reports exercise the actual coordinator. No SDK,
 * network, radio, persisted configuration or physical owner retirement occurs. */
class ManagedAdaptiveRoutesTest {
    private fun canonical(value: JsonElement): String = when (value) {
        is JsonObject -> value.toSortedMap().entries.joinToString(",", "{", "}") { (key, child) -> JsonPrimitive(key).toString() + ":" + canonical(child) }
        is JsonArray -> value.joinToString(",", "[", "]", transform = ::canonical)
        else -> value.toString()
    }
    private fun canonical(value: JSONObject) = canonical(Json.parseToJsonElement(value.toString()))
    private fun b64(raw: String) = Base64.getUrlEncoder().withoutPadding().encodeToString(raw.toByteArray())
    private fun config(groupCount: Int = 1, choices: Int = 2): String {
        val ids = (0 until choices).map { "hop-%02d".format(it) }
        val modes = JSONArray(NetworkMode.entries.map { it.name })
        val catalogue = JSONObject()
        val hops = JSONArray()
        for ((i, id) in ids.withIndex()) {
            catalogue.put(id, JSONObject().put("server", "192.0.2.1").put("server_port", 2000 + i).put("tag", id).put("type", "http"))
            hops.put(JSONObject().put("id", id).put("entryModes", modes).put("exitClass", "INTERNAL").put("features", JSONArray().put("TCP").put("IPV4")))
        }
        val groups = JSONArray(); val tags = JSONObject(); val outbounds = JSONArray(); val checks = JSONArray()
        repeat(groupCount) { i ->
            val group = "group-%02d".format(i); val tag = "managed-%02d".format(i)
            groups.put(JSONObject().put("id", group).put("intent", "INTERNAL").put("features", JSONArray().put("TCP").put("IPV4")).put("templates", JSONArray().put("one")))
            tags.put(group, tag)
            outbounds.put(JSONObject().put("type", "syn443-adaptive").put("tag", tag).put("group", group))
            checks.put(JSONObject().put("outbound", tag).put("required", true).put("checks", JSONArray().put(JSONObject().put("method", "tcp").put("target", "192.0.2.7:22"))))
        }
        val graph = JSONObject().put("schemaVersion", 1).put("hops", hops).put("edges", JSONArray()).put("groups", groups)
            .put("templates", JSONArray().put(JSONObject().put("id", "one").put("slots", JSONArray().put(JSONArray(ids)))))
        val wire = JSONObject().put("schemaVersion", 1).put("graphB64", b64(canonical(graph))).put("catalogueB64", b64(canonical(catalogue))).put("groups", tags)
        return JSONObject().put("outbounds", outbounds).put("route", JSONObject().put("final", "managed-%02d".format(groupCount - 1)))
            .put("route_checks", checks).put("adaptive_routes", wire).toString()
    }

    private class Harness(val raw: String, mode: NetworkMode = NetworkMode.WIFI) : Closeable {
        val controller = checkNotNull(ManagedAdaptiveRoutes.read(raw))
        var scope = RouteScope(1, 2, 3, "synthetic-engine-one", Policy.hash(raw))
        var epoch = 1L
        var nativeScope = Policy.hash("synthetic-native-owner-one")
        val commands = mutableListOf<JSONObject>()
        val frames = mutableListOf<String>()
        val policyScope: String get() = JSONObject(controller.controlFrame()).getString("scope")
        private val dispatch: (String) -> Unit = { raw ->
            val envelope = JSONObject(raw)
            assertEquals(setOf("kind", "commandJson"), envelope.keys().asSequence().toSet())
            assertEquals("adaptive", envelope.getString("kind"))
            frames += raw; commands += JSONObject(envelope.getString("commandJson"))
        }
        init {
            RouteSnapshot.configure(raw, scope.config); RouteSnapshot.owner(scope)
            controller.bind(scope, mode, 1)
        }
        fun rebind(next: RouteScope, mode: NetworkMode = NetworkMode.WIFI, revision: Long = 2) {
            scope = next; RouteSnapshot.owner(next); controller.bind(next, mode, revision)
        }
        fun status(ready: Boolean = true, running: Boolean = false, policy: String = policyScope, nativeEpoch: Long = epoch, native: String = nativeScope): JSONObject =
            JSONObject().put("request", "").put("running", running).put("nativeEpoch", nativeEpoch).put("scope", native)
                .put("policyScope", policy).put("ready", ready).put("group", "").put("hops", JSONArray())
                .put("code", "idle").put("elapsedMs", 0).put("probeMs", 0).put("receipt", "").put("groupSelected", false).put("workAgeMs", 0)
        fun report(frame: JSONObject, now: Long) = controller.report(frame, now, dispatch)
        fun ready(now: Long = 1000) = report(status(), now)
        fun tick(now: Long, unmetered: Boolean = true, explore: Boolean = true): JSONObject? {
            val before = commands.size
            controller.tick(now, unmetered, explore, dispatch)
            return commands.drop(before).singleOrNull { it.getString("command") == "start" }
        }
        fun result(probe: JSONObject, code: String, latency: Long = 100, elapsed: Long = 9000, selected: Boolean = false): JSONObject = status()
            .put("request", probe.getString("request")).put("group", probe.getString("group")).put("hops", JSONArray(probe.getJSONArray("hops").toString()))
            .put("code", code).put("elapsedMs", elapsed).put("probeMs", if (code in setOf("verified", "selected", "discarded")) latency else 0)
            .put("receipt", if (code == "verified") Policy.hash(probe.getString("request") + "-receipt") else "").put("groupSelected", selected)
        fun measured(probe: JSONObject, now: Long, latency: Long, elapsed: Long = 9000): JSONObject {
            val before = commands.size
            report(result(probe, "verified", latency, elapsed), now)
            return commands.drop(before).single()
        }
        fun selected(probe: JSONObject, now: Long, latency: Long = 100) {
            assertEquals("commit", measured(probe, now, latency).getString("command"))
            report(result(probe, "selected", latency, selected = true), now)
        }
        fun starts(): List<JSONObject> = commands.filter { it.getString("command") == "start" }
        fun view(): JSONObject = RouteSnapshot.read(true, true, scope)
        override fun close() { RouteSnapshot.owner(null); RouteSnapshot.configure(null, "") }
    }

    private fun prepareHealthy(h: Harness, latency: Long = 100): JSONObject {
        h.ready()
        val initial = checkNotNull(h.tick(1000))
        h.selected(initial, 1000, latency)
        for (step in 1..4) {
            val now = 1000L + step * 60000
            val confirmation = checkNotNull(h.tick(now))
            assertEquals(initial.getJSONArray("hops").toString(), confirmation.getJSONArray("hops").toString())
            h.selected(confirmation, now, latency)
        }
        return initial
    }

    @Test fun contextEpochAndNewEngineFenceRejectStaleReports() {
        assertNull(ManagedAdaptiveRoutes.read(null))
        assertNull(ManagedAdaptiveRoutes.read("{\"outbounds\":[]}"))
        val unbound = checkNotNull(ManagedAdaptiveRoutes.read(config()))
        assertThrows(IllegalStateException::class.java) { unbound.controlFrame() }
        Harness(config(choices = 1)).use { h ->
            val frame = JSONObject(h.controller.controlFrame())
            assertEquals(setOf("schemaVersion", "scope", "mode"), frame.keys().asSequence().toSet())
            assertEquals(1, frame.getInt("schemaVersion")); assertEquals("WIFI", frame.getString("mode"))
            assertTrue(frame.getString("scope").matches(Regex("[a-f0-9]{64}")))
            h.epoch = 20; h.ready()
            val oldProbe = checkNotNull(h.tick(1000))
            val oldReport = h.result(oldProbe, "verified", 20)
            h.rebind(h.scope.copy(engine = "synthetic-engine-two"))
            assertNotEquals(frame.getString("scope"), h.policyScope)
            h.epoch = 1; h.nativeScope = Policy.hash("synthetic-native-owner-two"); h.ready(6000)
            val fresh = checkNotNull(h.tick(6000))
            val before = h.commands.size
            h.report(oldReport, 6100)
            h.report(h.result(fresh, "verified", 20).put("nativeEpoch", 0), 6200)
            h.report(h.result(fresh, "verified", 20).put("policyScope", "f".repeat(64)).put("nativeEpoch", 99), 6300)
            assertEquals(before, h.commands.size)
            h.selected(fresh, 6400, 20)
            assertTrue(h.view().getBoolean("requiredReady"))
            val priorPolicy = h.policyScope
            val priorStatus = h.status()
            h.rebind(h.scope.copy(network = h.scope.network + 1))
            h.report(priorStatus, 12000)
            val configure = h.commands.last()
            assertEquals("configure", configure.getString("command"))
            assertEquals(h.policyScope, configure.getString("scope")); assertNotEquals(priorPolicy, h.policyScope)
            h.epoch = 2; h.nativeScope = Policy.hash("synthetic-native-network-two"); h.ready(13000)
            val current = checkNotNull(h.tick(13000))
            val beforeLate = h.commands.size
            h.report(h.result(current, "verified", 20).put("nativeEpoch", 1), 13100)
            assertEquals(beforeLate, h.commands.size)
            h.selected(current, 13200, 20)
        }
    }

    @Test fun protectedWireBoundsPreserveOriginalSyntaxAndEscapedRootKeys() {
        val raw = config(choices = 1)
        val wire = JSONObject(raw).getJSONObject("adaptive_routes").toString()
        assertTrue(raw.contains(wire))
        val exact = "{" + " ".repeat(196608 - wire.toByteArray().size) + wire.drop(1)
        assertEquals(196608, exact.toByteArray().size)
        assertNotNull(ManagedAdaptiveRoutes.read(raw.replace(wire, exact)))
        val tooBig = "{ " + exact.drop(1)
        assertEquals(196609, tooBig.toByteArray().size)
        assertThrows(IllegalArgumentException::class.java) { ManagedAdaptiveRoutes.read(raw.replace(wire, tooBig)) }
        assertThrows(IllegalArgumentException::class.java) { ManagedAdaptiveRoutes.read(raw.replace("\"schemaVersion\":1", "\"schemaVersion\":1.0")) }
        assertNotNull(ManagedAdaptiveRoutes.read(raw.replace("\"adaptive_routes\":", "\"adap\\u0074ive_routes\":")))
    }

    @Test fun nativeBusyAndLostAcknowledgementsNeverReleaseAnUnknownOwner() {
        Harness(config(choices = 1)).use { h ->
            h.ready(); val probe = checkNotNull(h.tick(1000))
            h.report(h.result(probe, "probe_unavailable").put("running", true), 37001)
            assertTrue(h.controller.requiresRetirement())
            h.controller.force(); assertNull(h.tick(60000))
            h.report(h.result(probe, "probe_unavailable"), 60001)
            assertNull(h.tick(70000)); assertEquals(1, h.starts().size)
        }
        Harness(config(choices = 1)).use { h ->
            h.ready(); val probe = checkNotNull(h.tick(1000))
            val verified = h.result(probe, "verified", 20)
            h.report(verified, 1000)
            for (step in 1..7) h.report(JSONObject(verified.toString()), 1000L + step * 1000)
            val settlements = h.commands.filter { it.getString("command") in setOf("commit", "discard") }
            assertEquals(4, settlements.count { it.getString("command") == "commit" })
            assertEquals(3, settlements.count { it.getString("command") == "discard" })
            assertTrue(settlements.all { it.getString("request") == probe.getString("request") && it.getString("receipt") == verified.getString("receipt") })
            assertTrue(h.controller.requiresRetirement()); h.controller.force(); assertNull(h.tick(100000))
            assertEquals(1, h.starts().size)
        }
        Harness(config(choices = 1)).use { h ->
            h.ready(); val unknown = checkNotNull(h.tick(1000))
            h.report(h.status().put("request", "unknown-ack"), 10000)
            assertNull(h.tick(20000))
            h.report(h.status().put("request", "unknown-ack"), 37001)
            assertTrue(h.controller.requiresRetirement())
            // This rebind models a separately confirmed physical host exit;
            // the test itself does not establish that physical acceptance.
            h.rebind(h.scope.copy(engine = "confirmed-new-owner"))
            h.epoch = 1; h.nativeScope = Policy.hash("confirmed-new-native"); h.ready(43000)
            val retry = checkNotNull(h.tick(43000))
            assertEquals(unknown.getJSONArray("hops").toString(), retry.getJSONArray("hops").toString())
        }
        Harness(config(choices = 1)).use { h ->
            h.ready(); checkNotNull(h.tick(1000))
            h.rebind(h.scope.copy(network = h.scope.network + 1)); h.epoch = 2
            h.nativeScope = Policy.hash("old-worker-retains-ownership-after-context-change")
            h.report(h.status(running = true).put("workAgeMs", 36001), 37001)
            assertTrue(h.controller.requiresRetirement())
            h.report(h.status(running = false).put("workAgeMs", 0), 38000)
            h.controller.force(); assertNull(h.tick(43000)); assertEquals(1, h.starts().size)
        }
    }

    @Test fun freshBoundReceiptCommitsOnceAndRejectsWrongPaths() {
        Harness(config()).use { h ->
            h.ready(); val probe = checkNotNull(h.tick(1000)); val initial = h.commands.size
            h.report(h.result(probe, "verified", 20).put("hops", JSONArray().put("wrong-hop")), 1000)
            h.report(h.result(probe, "verified", 20).put("group", "wrong-group"), 1000)
            h.report(h.result(probe, "verified", 20).also { it.remove("probeMs") }, 1000)
            h.report(h.result(probe, "verified", 12000), 1000)
            h.report(h.result(probe, "verified", 20).put("receipt", "not-a-proof"), 1000)
            assertEquals(initial, h.commands.size); assertFalse(h.view().getBoolean("requiredReady"))
            val verified = h.result(probe, "verified", 20, elapsed = 29999)
            h.report(verified, 1000)
            val commit = h.commands.last()
            assertEquals("commit", commit.getString("command")); assertEquals(probe.getString("request"), commit.getString("request"))
            assertEquals(h.nativeScope, commit.getString("scope")); assertEquals(h.epoch, commit.getLong("nativeEpoch"))
            assertEquals(verified.getString("receipt"), commit.getString("receipt"))
            h.report(JSONObject(verified.toString()), 1001)
            h.report(JSONObject(verified.toString()).put("receipt", "a".repeat(64)), 1002)
            assertEquals(1, h.commands.count { it.getString("command") == "commit" })
            h.report(h.result(probe, "selected", 20, selected = true), 1003)
            h.report(verified, 3000)
            h.report(h.result(probe, "selected", 20, selected = true), 3001)
            assertEquals(1, h.commands.count { it.getString("command") == "commit" })
            assertTrue(h.view().getBoolean("requiredReady"))
            assertEquals(20, h.view().getJSONArray("routes").getJSONObject(0).getInt("latencyMs"))
        }
    }

    @Test fun roundRobinAndMinuteBudgetRemainSharedAcrossGroups() {
        Harness(config(groupCount = 3, choices = 1)).use { h ->
            h.ready()
            for (i in 0 until 8) {
                val now = 1000L + i * 5000
                val probe = checkNotNull(h.tick(now))
                h.report(h.result(probe, "probe_unavailable"), now)
            }
            assertEquals(listOf("group-02", "group-00", "group-01", "group-02", "group-00", "group-01", "group-02", "group-00"), h.starts().map { it.getString("group") })
            assertNull(h.tick(41000)); assertNull(h.tick(60000))
            assertEquals("group-01", checkNotNull(h.tick(61000)).getString("group"))
            assertEquals(9, h.starts().size)
        }
    }

    @Test fun hourBudgetSurvivesContextRebindAndForce() {
        Harness(config(choices = 1)).use { h ->
            h.ready(); var now = 1000L; var attempts = 0
            while (h.starts().size < 128 && attempts++ < 1000) {
                h.tick(now)?.let { h.report(h.result(it, "probe_unavailable"), now) }
                now += 5000
            }
            assertEquals(128, h.starts().size); assertTrue(now < 3_601_000)
            h.controller.force(); assertNull(h.tick(now))
            h.rebind(h.scope.copy(network = h.scope.network + 1)); h.epoch = 2
            h.nativeScope = Policy.hash("budget-preserved-network"); h.ready(now + 1000)
            h.controller.force(); assertNull(h.tick(now + 5000))
            val resumed = checkNotNull(h.tick(3_601_000))
            assertEquals(129, h.starts().size); assertEquals("hop-00", resumed.getJSONArray("hops").getString(0))
        }
    }

    @Test fun healthyMeteredModesConfirmCurrentWithoutExploration() {
        for ((mode, unmetered, explore) in listOf(Triple(NetworkMode.CELLULAR, false, true), Triple(NetworkMode.CELLULAR_RESTRICTED, false, true), Triple(NetworkMode.WIFI, true, false))) {
            Harness(config(), mode).use { h ->
                h.ready(); val first = checkNotNull(h.tick(1000, unmetered, explore)); h.selected(first, 1000, 100)
                for (i in 1..8) {
                    val now = 1000L + i * 60000
                    val current = checkNotNull(h.tick(now, unmetered, explore))
                    assertEquals(first.getJSONArray("hops").toString(), current.getJSONArray("hops").toString())
                    h.selected(current, now, 100)
                    assertNull(h.tick(now + 30000, unmetered, explore))
                }
            }
        }
    }

    @Test fun latencySwitchRequiresTwoFreshSignificantComparableSamples() {
        for ((baseline, candidate) in listOf(100L to 79L, 60L to 44L)) {
            Harness(config()).use { h ->
                val first = prepareHealthy(h, baseline)
                val reserve = checkNotNull(h.tick(301000))
                assertNotEquals(first.getJSONArray("hops").toString(), reserve.getJSONArray("hops").toString())
                assertEquals("discard", h.measured(reserve, 301000, candidate, elapsed = 29999).getString("command"))
                h.report(h.result(reserve, "discarded", latency = candidate, selected = true), 301000)
                val second = checkNotNull(h.tick(306000))
                assertEquals(reserve.getJSONArray("hops").toString(), second.getJSONArray("hops").toString())
                assertNotEquals(reserve.getString("request"), second.getString("request"))
                h.selected(second, 306000, candidate)
                val view = h.view().getJSONArray("routes").getJSONObject(0)
                assertEquals(candidate, view.getLong("latencyMs"))
                assertEquals(second.getJSONArray("hops").toString(), view.getJSONArray("measuredPath").toString())
            }
        }
        for ((baseline, candidate) in listOf(100L to 80L, 60L to 45L)) {
            Harness(config()).use { h ->
                val first = prepareHealthy(h, baseline)
                val reserve = checkNotNull(h.tick(301000))
                assertEquals("discard", h.measured(reserve, 301000, candidate).getString("command"))
                h.report(h.result(reserve, "discarded", latency = candidate, selected = true), 301000)
                val confirmation = checkNotNull(h.tick(306000))
                assertEquals(first.getJSONArray("hops").toString(), confirmation.getJSONArray("hops").toString())
            }
        }
    }

    @Test fun failedReserveCannotOverwriteHealthyRouteOrLeakEndpoints() {
        Harness(config()).use { h ->
            val first = prepareHealthy(h)
            val reserve = checkNotNull(h.tick(301000))
            h.report(h.result(reserve, "probe_unavailable", selected = true), 301000)
            val view = h.view()
            assertTrue(view.getBoolean("requiredReady"))
            assertEquals(first.getJSONArray("hops").toString(), view.getJSONArray("routes").getJSONObject(0).getJSONArray("measuredPath").toString())
            assertEquals("ManagedAdaptiveRoutes([redacted])", h.controller.toString())
            for (raw in h.frames + view.toString() + h.controller.toString()) {
                assertFalse(raw.contains("192.0.2.1")); assertFalse(raw.contains("192.0.2.7"))
                assertFalse(raw.contains("catalogueB64")); assertFalse(raw.contains("graphB64"))
            }
        }
    }

    @Test fun currentCheckFailureRequiresFreshBoundReplacementAndMonotonicTime() {
        fun failed(h:Harness,probe:JSONObject,now:Long,code:String="dial_failed",selected:Boolean=true,completed:Any?=now) =
            h.report(h.result(probe,"check_failed",selected=selected).put("checkCode",code).put("checkCompletedBootMs",completed),now)
        fun samePath(a:JSONObject,b:JSONObject)=a.getJSONArray("hops").toString()==b.getJSONArray("hops").toString()
        fun initial(h:Harness):JSONObject {h.ready();return checkNotNull(h.tick(1000)).also {h.selected(it,1000,100)}}

        Harness(config()).use {h->
            val a=initial(h)
            val recheck=checkNotNull(h.tick(61000));assertTrue(samePath(a,recheck))
            failed(h,recheck,61000)
            val failedRow=h.view().getJSONArray("routes").getJSONObject(0)
            assertEquals("failed",failedRow.getString("state"));assertEquals("check_failed",failedRow.getString("reason"))
            val b=checkNotNull(h.tick(66000));assertFalse(samePath(a,b))
            val before=h.commands.size
            h.report(h.result(b,"verified",500).put("group","other-group"),66000)
            h.report(h.result(b,"verified",500).put("hops",JSONArray().put("other-hop")),66000)
            assertEquals(before,h.commands.size)
            // A real failure followed by a fresh replacement does not require
            // that the replacement also beats A's old healthy latency.
            assertEquals("commit",h.measured(b,66000,500).getString("command"))
            assertFalse(h.view().getBoolean("requiredReady"))
            h.report(h.result(b,"selected",500,selected=true),66001)
            val row=h.view().getJSONArray("routes").getJSONObject(0)
            assertEquals("working",row.getString("state"))
            assertEquals(b.getJSONArray("hops").toString(),row.getJSONArray("measuredPath").toString())
            assertEquals(500,row.getInt("latencyMs"))
        }
        Harness(config()).use {h->
            h.ready();val first=checkNotNull(h.tick(1000));failed(h,first,1000,selected=false)
            val row=h.view().getJSONArray("routes").getJSONObject(0)
            assertEquals("failed",row.getString("state"));assertEquals("check_failed",row.getString("reason"))
        }
        Harness(config()).use {h->
            val a=initial(h)
            // Repeated admitted failures without any successful replacement
            // must not quarantine A or B, even when every target is down.
            for(i in 0..1) {
                val now=61000L+i*10000
                val current=checkNotNull(h.tick(now,false,false));assertTrue(samePath(a,current));failed(h,current,now)
                val reserve=checkNotNull(h.tick(now+5000,false,false));assertFalse(samePath(a,reserve))
                failed(h,reserve,now+5000,selected=true)
                assertEquals(1,h.commands.count {it.getString("command")=="commit"})
            }
            assertTrue(samePath(a,checkNotNull(h.tick(81000,false,false))))
        }
        for(checkCode in listOf("","dial_failed","constructor_budget")) {
            Harness(config()).use {h->
                val a=prepareHealthy(h)
                // Admission/capacity/construction/budget uncertainty remains
                // probe_unavailable, irrespective of an irrelevant extra code.
                repeat(3) {i->
                    val now=301000L+i*5000
                    val current=checkNotNull(h.tick(now,false,false));assertTrue(samePath(a,current))
                    h.report(h.result(current,"probe_unavailable",selected=true).put("checkCode",checkCode),now)
                    assertEquals("incomplete",h.view().getJSONArray("routes").getJSONObject(0).getString("state"))
                }
                val reserve=checkNotNull(h.tick(316000));assertFalse(samePath(a,reserve))
                assertEquals("discard",h.measured(reserve,316000,500).getString("command"))
            }
        }
        Harness(config()).use {h->
            val a=initial(h);val current=checkNotNull(h.tick(61000))
            val before=h.commands.size
            for(code in listOf("","unknown","tls failure at private.example.invalid"))failed(h,current,61000,code)
            h.report(h.result(current,"unknown_failure",selected=true).put("checkCode","dial_failed"),61000)
            assertEquals(before,h.commands.size);assertNull(h.tick(66000))
            h.report(h.result(current,"probe_unavailable",selected=true),66000)
            assertTrue(samePath(a,checkNotNull(h.tick(71000,false,false))))
            assertFalse(h.view().toString().contains("private.example.invalid"))
        }
        Harness(config()).use {h->
            val a=initial(h);failed(h,checkNotNull(h.tick(61000)),61000)
            val b=checkNotNull(h.tick(66000));assertFalse(samePath(a,b))
            // The B worker is still within its owner deadline, but A's failure
            // is too old to attribute or bypass the latency hold.
            assertEquals("discard",h.measured(b,92001,500).getString("command"))
        }
        Harness(config()).use {h->
            val a=initial(h);val current=checkNotNull(h.tick(61000))
            val before=h.commands.size
            for(stamp in listOf(null,0L,-1L,60000L,61001L,61000.0,"61000"))failed(h,current,61000,completed=stamp)
            assertEquals(before,h.commands.size);assertNull(h.tick(66000))
            failed(h,current,89000,completed=61000L)
            val b=checkNotNull(h.tick(94000));assertFalse(samePath(a,b))
            // Arrival 28s late must not grant A another fresh 30s window.
            assertEquals("discard",h.measured(b,94000,500).getString("command"))
        }
        Harness(config(groupCount=2)).use {h->
            h.ready()
            val a=checkNotNull(h.tick(1000));h.selected(a,1000)
            h.selected(checkNotNull(h.tick(6000)),6000)
            for(i in 1..4) {
                val now=1000L+i*60000
                h.selected(checkNotNull(h.tick(now)),now)
                h.selected(checkNotNull(h.tick(now+5000)),now+5000)
            }
            val current=checkNotNull(h.tick(301000,false,false));assertEquals(a.getString("group"),current.getString("group"))
            failed(h,current,301000)
            val unrelated=checkNotNull(h.tick(306000));assertNotEquals(current.getString("group"),unrelated.getString("group"))
            assertEquals("discard",h.measured(unrelated,306000,500).getString("command"))
        }
        Harness(config()).use {h->
            val a=prepareHealthy(h)
            failed(h,checkNotNull(h.tick(301000,false,false)),301000)
            val b=checkNotNull(h.tick(306000,false,false));assertFalse(samePath(a,b));failed(h,b,306000)
            val confirmed=checkNotNull(h.tick(311000,false,false));assertTrue(samePath(a,confirmed));h.selected(confirmed,311000)
            // A fresh confirmation restores the normal energy-saving interval.
            assertNull(h.tick(316000))
            val reserve=checkNotNull(h.tick(371000));assertFalse(samePath(a,reserve))
            // A former failure cannot bypass the healthy latency hold.
            assertEquals("discard",h.measured(reserve,371000,500).getString("command"))
        }
        Harness(config()).use {h->
            val a=prepareHealthy(h);val b=checkNotNull(h.tick(301000))
            assertFalse(samePath(a,b));failed(h,b,301000,"tls_failed")
            val view=h.view();assertTrue(view.getBoolean("requiredReady"))
            assertEquals(a.getJSONArray("hops").toString(),view.getJSONArray("routes").getJSONObject(0).getJSONArray("measuredPath").toString())
        }
        for(changeEpoch in listOf(false,true)) {
            Harness(config()).use {h->
                initial(h);failed(h,checkNotNull(h.tick(61000)),61000)
                val b=checkNotNull(h.tick(66000));val before=h.commands.size
                val report=h.result(b,"verified",500)
                if(changeEpoch)report.put("nativeEpoch",h.epoch+1) else report.put("scope",Policy.hash("foreign-native-scope"))
                h.report(report,66000)
                assertEquals(before,h.commands.size);assertNull(h.tick(71000))
            }
        }
        Harness(config()).use {h->
            val a=initial(h);failed(h,checkNotNull(h.tick(61000)),61000)
            val b=checkNotNull(h.tick(66000));val old=h.result(b,"verified",500)
            h.rebind(h.scope,NetworkMode.CELLULAR)
            h.report(old,67000)
            assertEquals("configure",h.commands.last().getString("command"))
            h.epoch=2;h.nativeScope=Policy.hash("fresh-mode-owner");h.ready(68000)
            val fresh=checkNotNull(h.tick(71000,false,false));assertTrue(samePath(a,fresh));h.selected(fresh,71000)
            assertTrue(h.view().getBoolean("requiredReady"))
        }
        for(bad in listOf(-1L,999L,Decision.MAX_TIME-599999,Long.MAX_VALUE)) {
            Harness(config()).use {h->
                initial(h);h.tick(bad)
                assertTrue(h.controller.requiresRetirement());h.controller.force();assertNull(h.tick(10000))
                assertEquals(1,h.starts().size)
            }
        }
        Harness(config()).use {h->
            initial(h);h.tick(5000);h.rebind(h.scope.copy(network=h.scope.network+1))
            h.ready(4000)
            assertTrue(h.controller.requiresRetirement());assertNull(h.tick(6000));assertEquals(1,h.starts().size)
        }
        Harness(config()).use {h->
            val upper=Decision.MAX_TIME-600000
            h.ready(upper);assertNotNull(h.tick(upper))
            h.report(h.status(running=true),upper+1)
            assertTrue(h.controller.requiresRetirement());assertEquals(1,h.starts().size)
        }
    }
}
