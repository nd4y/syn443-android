package io.syn443.android

import io.syn443.android.vpn.ManagedAdaptiveRoutes
import io.syn443.android.vpn.AdaptivePolicyBinding
import io.syn443.android.vpn.RouteSnapshot
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

/** Virtual-clock coordinator simulations. Native reports are synthetic; these
 * tests perform no SDK, network, radio, packet or physical retirement work. */
class ManagedAdaptiveRoutesFairnessTest {
    private fun canonical(value: JsonElement): String = when (value) {
        is JsonObject -> value.toSortedMap().entries.joinToString(",", "{", "}") { (key, child) -> JsonPrimitive(key).toString()+":"+canonical(child) }
        is JsonArray -> value.joinToString(",", "[", "]", transform = ::canonical)
        else -> value.toString()
    }
    private fun canonical(value: JSONObject) = canonical(Json.parseToJsonElement(value.toString()))
    private fun b64(raw: String) = Base64.getUrlEncoder().withoutPadding().encodeToString(raw.toByteArray())

    internal fun config(choices: Int = 500, groupCount: Int = 1, publicExit: Boolean = false, blockedFirst: Boolean = false): String {
        val ids = (0 until choices).map { "hop-%03d".format(it) }
        val catalogue = JSONObject(); val hops = JSONArray()
        val features = JSONArray().put("TCP").put("IPV4")
        val exit = if (publicExit) "RU" else "INTERNAL"
        ids.forEachIndexed { index, id ->
            catalogue.put(id, JSONObject().put("type", "http").put("tag", id).put("server", "192.0.2.1").put("server_port", 2000+index))
            val modes = JSONArray().put(if (blockedFirst && index < choices-1) "CELLULAR" else "WIFI")
            hops.put(JSONObject().put("id", id).put("entryModes", modes).put("exitClass", exit).put("features", features))
        }
        val templates = JSONArray()
        if (blockedFirst) {
            templates.put(JSONObject().put("id", "blocked").put("slots", JSONArray().put(JSONArray(ids.dropLast(1)))))
            templates.put(JSONObject().put("id", "working").put("slots", JSONArray().put(JSONArray().put(ids.last()))))
        } else templates.put(JSONObject().put("id", "one").put("slots", JSONArray().put(JSONArray(ids))))
        val groups = JSONArray(); val tags = JSONObject(); val outbounds = JSONArray(); val checks = JSONArray()
        repeat(groupCount) { index ->
            val group = "group-%02d".format(index); val tag = "managed-%02d".format(index)
            groups.put(JSONObject().put("id", group).put("intent", exit).put("features", features)
                .put("templates", JSONArray().put(if (blockedFirst) if (index==0) "blocked" else "working" else "one")))
            tags.put(group, tag)
            outbounds.put(JSONObject().put("type", "syn443-adaptive").put("tag", tag).put("group", group))
            val check = if (publicExit) JSONObject().put("method", "https_exit_country").put("target", "https://exit.invalid/").put("expected_exit_class", "RU")
                else JSONObject().put("method", "tcp").put("target", "192.0.2.7:22")
            checks.put(JSONObject().put("outbound", tag).put("required", true).put("checks", JSONArray().put(check)))
        }
        val graph = JSONObject().put("schemaVersion", 1).put("hops", hops).put("edges", JSONArray()).put("templates", templates).put("groups", groups)
        val wire = JSONObject().put("schemaVersion", 1).put("graphB64", b64(canonical(graph))).put("catalogueB64", b64(canonical(catalogue))).put("groups", tags)
        return JSONObject().put("outbounds", outbounds).put("route", JSONObject().put("final", "managed-00"))
            .put("route_checks", checks).put("adaptive_routes", wire).toString()
    }

    internal class Harness(val raw: String, binding: AdaptivePolicyBinding? = null) : Closeable {
        val controller = checkNotNull(ManagedAdaptiveRoutes.read(raw))
        var scope = RouteScope(1, 2, 3, "synthetic-fair-owner", Policy.hash(raw))
        var epoch = 1L
        var nativeScope = Policy.hash("synthetic-fair-native")
        val commands = mutableListOf<JSONObject>()
        val starts = mutableListOf<Pair<Long, JSONObject>>()
        private val dispatch: (String) -> Unit = { raw ->
            val envelope = JSONObject(raw)
            assertEquals(setOf("kind", "commandJson"), envelope.keys().asSequence().toSet())
            assertEquals("adaptive", envelope.getString("kind"))
            commands += JSONObject(envelope.getString("commandJson"))
        }
        val policyScope: String get() = JSONObject(controller.controlFrame()).getString("scope")
        init {
            RouteSnapshot.configure(raw, scope.config); RouteSnapshot.owner(scope)
            if (binding==null) controller.bind(scope, NetworkMode.WIFI, 1)
            else controller.bind(scope, NetworkMode.WIFI, binding, 1000)
        }
        fun bind(binding: AdaptivePolicyBinding, now: Long) = controller.bind(scope, NetworkMode.WIFI, binding, now)
        fun status(): JSONObject = JSONObject().put("request", "").put("running", false).put("nativeEpoch", epoch).put("scope", nativeScope)
            .put("policyScope", policyScope).put("ready", true).put("group", "").put("hops", JSONArray())
            .put("code", "idle").put("elapsedMs", 0).put("probeMs", 0).put("receipt", "").put("groupSelected", false).put("workAgeMs", 0)
        fun ready(now: Long) = controller.report(status(), now, dispatch)
        fun acknowledge(frame: JSONObject, now: Long) = controller.report(frame, now, dispatch)
        fun tick(now: Long): JSONObject? {
            val before = commands.size
            controller.tick(now, true, true, dispatch)
            val start = commands.drop(before).singleOrNull { it.getString("command")=="start" }
            if (start!=null) {
                starts += now to start
                assertTrue("minute admission budget exceeded", starts.count { now-it.first<60_000 }<=8)
                assertTrue("hour admission budget exceeded", starts.count { now-it.first<3_600_000 }<=128)
            }
            return start
        }
        private fun result(probe: JSONObject, code: String): JSONObject = status().put("request", probe.getString("request"))
            .put("group", probe.getString("group")).put("hops", JSONArray(probe.getJSONArray("hops").toString())).put("code", code)
        fun failed(probe: JSONObject, now: Long, code: String = "check_failed") {
            val report = result(probe, code)
            if (code=="check_failed") report.put("checkCode", "dial_failed").put("checkCompletedBootMs", now)
            controller.report(report, now, dispatch)
        }
        fun verified(probe: JSONObject, now: Long): JSONObject {
            val before = commands.size
            controller.report(result(probe, "verified").put("probeMs", 20).put("receipt", Policy.hash(probe.getString("request"))), now, dispatch)
            return commands.drop(before).single()
        }
        fun selected(probe: JSONObject, now: Long) {
            assertEquals("commit", verified(probe, now).getString("command"))
            controller.report(result(probe, "selected").put("probeMs", 20).put("receipt", Policy.hash(probe.getString("request"))).put("groupSelected", true), now, dispatch)
        }
        fun rebind(now: Long) {
            scope = scope.copy(network=scope.network+1)
            RouteSnapshot.owner(scope); controller.bind(scope, NetworkMode.WIFI, 1); ready(now)
        }
        fun view() = RouteSnapshot.read(true, true, scope)
        override fun close() { RouteSnapshot.owner(null); RouteSnapshot.configure(null, "") }
    }

    @Test fun fiveHundredLastWorkingPathSurvivesTTLAndHourlyPauseWithoutBudgetReset() {
        // Normal control-plane receipts renew every300s, not just a synthetic
        // fixed revision. Every renewal passes real signed Assignments and the
        // worker-prepared current runtime permission before the coordinator.
        AssignedPolicyContinuityFixture(config()).use { assignments ->
        Harness(assignments.raw, assignments.binding()).use { h ->
            h.ready(1000)
            var now = 1000L
            var nextRenewal = 301_000L
            var renewals = 0
            val initialPolicyScope = h.policyScope
            var selected = false
            val paths = mutableListOf<String>()
            while (now<6*3_600_000L && !selected) {
                assignments.elapsed=now
                if (now>=nextRenewal) {
                    val generation=assignments.state.journal.activationGeneration
                    assignments.renew(now)
                    assertEquals(generation, assignments.state.journal.activationGeneration)
                    h.bind(assignments.binding(), now)
                    assertEquals(initialPolicyScope, h.policyScope)
                    nextRenewal+=300_000
                    renewals++
                }
                val probe = h.tick(now)
                if (probe!=null) {
                    val path = probe.getJSONArray("hops").getString(0)
                    assertEquals("hop-%03d".format(paths.size), path)
                    assertFalse(paths.contains(path)); paths += path
                    assertFalse(h.view().getBoolean("requiredReady"))
                    if (path=="hop-499") {
                        val commit = h.verified(probe, now)
                        assertEquals("commit", commit.getString("command"))
                        assertFalse(h.view().getBoolean("requiredReady"))
                        // A position, enumerated candidate or verified-but-not-
                        // committed receipt cannot manufacture a working route.
                        val ack = h.status().put("request", probe.getString("request")).put("group", probe.getString("group"))
                            .put("hops", JSONArray(probe.getJSONArray("hops").toString())).put("code", "selected").put("groupSelected", true)
                            .put("receipt", commit.getString("receipt")).put("probeMs", 20)
                        // Only the synthetic native acknowledgement changes UI.
                        h.acknowledge(ack, now)
                        assertTrue(h.view().getBoolean("requiredReady"))
                        assertEquals(JSONArray().put("hop-499").toString(), h.view().getJSONArray("routes").getJSONObject(0).getJSONArray("measuredPath").toString())
                        selected = true
                    } else h.failed(probe, now)
                }
                now += 1000
            }
            assertTrue("late working path was starved", selected)
            assertEquals(500, paths.size)
            assertTrue("normal five-minute receipts were not exercised", renewals>=36)
            assertTrue("500 attempts bypassed the rolling hourly cap", h.starts.last().first>=3*3_600_000L)
            assertFalse(h.controller.requiresRetirement())
        }
        }
    }

    @Test fun emptyCPUQuantumYieldsToAnotherDueGroupWithoutAnotherProbe() {
        Harness(config(choices=129, groupCount=2, blockedFirst=true)).use { h ->
            h.ready(1000)
            assertNull(h.tick(1000)) // 64 ineligible raw positions; not exhaustion.
            assertTrue(h.starts.isEmpty())
            h.controller.force() // A manual refresh cannot monopolize the cursor.
            val working = checkNotNull(h.tick(2000))
            assertEquals("group-01", working.getString("group"))
            assertEquals("hop-128", working.getJSONArray("hops").getString(0))
            h.selected(working, 2000)
            assertEquals(1, h.starts.size)
            assertFalse(h.view().getBoolean("requiredReady")) // independent blocked group remains unproved.
        }
    }

    @Test fun cooldownCPUQuantumYieldsWithoutBypassingHalfOpenOrHealthyGroup() {
        Harness(config(choices=1, groupCount=2, publicExit=true)).use { h ->
            h.ready(1000)
            val first = checkNotNull(h.tick(1000)); assertEquals("group-00", first.getString("group")); h.failed(first, 1000, "exit_mismatch")
            val healthy = checkNotNull(h.tick(6000)); assertEquals("group-01", healthy.getString("group")); h.selected(healthy, 6000)
            val second = checkNotNull(h.tick(11000)); assertEquals("group-00", second.getString("group")); h.failed(second, 11000, "exit_mismatch")
            var retry: JSONObject? = null
            var retryAt = 0L
            for (now in 16_000L..59_000L step 1000) {
                val probe = h.tick(now)
                if (probe!=null) { retry=probe; retryAt=now; break }
            }
            assertNotNull(retry)
            assertEquals("group-00", checkNotNull(retry).getString("group"))
            h.failed(checkNotNull(retry), retryAt, "exit_mismatch") // third failure: at least48s cooldown.
            val confirmation = checkNotNull(h.tick(66000)); assertEquals("group-01", confirmation.getString("group")); h.selected(confirmation, 66000)
            assertNull(h.tick(71000)) // blocked group consumes a CPU quantum, not I/O.
            h.controller.force()
            val next = checkNotNull(h.tick(72000))
            assertEquals("group-01", next.getString("group"))
            h.selected(next, 72000)
            assertEquals(6, h.starts.size)
        }
    }

    @Test fun realContextNativeEpochAndClockChangesDoNotBorrowPositionsOrResetBudgets() {
        Harness(config(choices=500)).use { h ->
            h.ready(1000)
            repeat(8) { index ->
                val now = 1000L+index*6000
                val probe = checkNotNull(h.tick(now))
                assertEquals("hop-%03d".format(index), probe.getJSONArray("hops").getString(0))
                h.failed(probe, now)
            }
            h.rebind(49000)
            assertNull(h.tick(49000)) // Eight old admissions still consume this minute.
            val fresh = checkNotNull(h.tick(62000))
            assertEquals("hop-000", fresh.getJSONArray("hops").getString(0))
            h.failed(fresh, 62000)
            h.epoch=2; h.nativeScope=Policy.hash("synthetic-second-native"); h.ready(68000)
            val native = checkNotNull(h.tick(68000))
            assertEquals("hop-000", native.getJSONArray("hops").getString(0))
            h.failed(native, 68000)
            h.nativeScope=Policy.hash("synthetic-third-native-scope"); h.ready(74000)
            val scoped = checkNotNull(h.tick(74000))
            assertEquals("hop-000", scoped.getJSONArray("hops").getString(0))
            h.failed(scoped, 74000)
            val before = h.starts.size
            assertNull(h.tick(73999))
            assertEquals(before, h.starts.size)
            assertTrue(h.controller.requiresRetirement())
        }
    }
}
