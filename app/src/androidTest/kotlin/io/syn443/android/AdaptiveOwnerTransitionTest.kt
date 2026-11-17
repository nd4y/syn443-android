package io.syn443.android

import io.syn443.android.vpn.AdaptivePolicyBinding
import io.syn443.android.vpn.ManagedAdaptiveRoutes
import io.syn443.android.vpn.RouteSnapshot
import io.syn443.decision.AdaptiveProbeBudget
import io.syn443.decision.NetworkMode
import io.syn443.policy.Policy
import io.syn443.recovery.RouteScope
import java.io.Closeable
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

/** Synthetic reports exercise the actual Java coordinator and route projection.
 * These cases perform no native, SDK, network, radio, identity or settings work. */
class AdaptiveOwnerTransitionTest {
    private fun config(groups: Int = 1, choices: Int = 1, publicExit: Boolean = false) =
        ManagedAdaptiveRoutesFairnessTest().config(choices = choices, groupCount = groups, publicExit = publicExit)

    private class Harness(val raw: String, val budget: AdaptiveProbeBudget = AdaptiveProbeBudget(),
        binding: AdaptivePolicyBinding? = null) : Closeable {
        val controller = checkNotNull(ManagedAdaptiveRoutes.read(raw, budget))
        val scope = RouteScope(1, 2, 3, "synthetic-owner-transition", Policy.hash(raw))
        var epoch = 1L
        var nativeScope = Policy.hash("synthetic-native-owner-a")
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
            RouteSnapshot.configure(raw, scope.config)
            RouteSnapshot.owner(scope)
            if (binding == null) controller.bind(scope, NetworkMode.WIFI, 1)
            else controller.bind(scope, NetworkMode.WIFI, binding, 1_000)
        }
        fun status(ready: Boolean = true, running: Boolean = false): JSONObject =
            JSONObject().put("request", "").put("running", running).put("nativeEpoch", epoch)
                .put("scope", nativeScope).put("policyScope", policyScope).put("ready", ready)
                .put("group", "").put("hops", JSONArray()).put("code", "idle")
                .put("elapsedMs", 0).put("probeMs", 0).put("receipt", "")
                .put("groupSelected", false).put("workAgeMs", 0)
        fun report(value: JSONObject, now: Long) = controller.report(value, now, dispatch)
        fun ready(now: Long) = report(status(), now)
        fun tick(now: Long): JSONObject? {
            val before = commands.size
            controller.tick(now, false, false, dispatch)
            val probe = commands.drop(before).singleOrNull { it.getString("command") == "start" }
            if (probe != null) {
                if (starts.isNotEmpty()) assertTrue("five-second admission spacing lost", now - starts.last().first >= 5_000)
                starts += now to probe
                assertTrue(starts.count { now - it.first < 60_000 } <= 8)
                assertTrue(starts.count { now - it.first < 3_600_000 } <= 128)
            }
            return probe
        }
        fun result(probe: JSONObject, code: String, latency: Long = 37): JSONObject = status()
            .put("nativeEpoch", probe.getLong("nativeEpoch")).put("scope", probe.getString("scope"))
            .put("request", probe.getString("request")).put("group", probe.getString("group"))
            .put("hops", JSONArray(probe.getJSONArray("hops").toString())).put("code", code)
            .put("probeMs", latency).put("receipt", Policy.hash(probe.getString("request") + "-receipt"))
        fun measured(probe: JSONObject, now: Long, latency: Long = 37): JSONObject {
            val before = commands.size
            report(result(probe, "verified", latency), now)
            return commands.drop(before).single()
        }
        fun selected(probe: JSONObject, now: Long, latency: Long = 37) {
            val commit = measured(probe, now, latency)
            assertEquals("commit", commit.getString("command"))
            report(result(probe, "selected", latency).put("receipt", commit.getString("receipt"))
                .put("groupSelected", true), now)
        }
        fun failed(probe: JSONObject, now: Long) = report(result(probe, "exit_mismatch"), now)
        fun changeOwner(now: Long, running: Boolean = false, ready: Boolean = true, sameEpoch: Boolean = false) {
            if (!sameEpoch) epoch++
            nativeScope = Policy.hash("synthetic-owner-$epoch-$now")
            report(status(ready, running), now)
        }
        fun bind(binding: AdaptivePolicyBinding, now: Long) = controller.bind(scope, NetworkMode.WIFI, binding, now)
        fun view() = RouteSnapshot.read(true, true, scope)
        fun row(index: Int = 0) = view().getJSONArray("routes").getJSONObject(index)
        fun assertRetracted() {
            val value = view()
            assertFalse(value.getBoolean("requiredReady"))
            val rows = value.getJSONArray("routes")
            for (index in 0 until rows.length()) {
                val row = rows.getJSONObject(index)
                assertNotEquals("working", row.getString("state"))
                assertNotEquals("failed", row.getString("state"))
                assertEquals(0, row.getJSONArray("measuredPath").length())
                assertTrue(row.isNull("latencyMs"))
                assertNotEquals("VERIFIED", row.getJSONObject("search").getString("state"))
            }
        }
        override fun close() { RouteSnapshot.owner(null); RouteSnapshot.configure(null, "") }
    }

    @Test fun nativeEpochChangeRetractsReadinessAndUsesRecoveryBeforeRoutineCadence() {
        val budget = AdaptiveProbeBudget()
        repeat(16) { minute -> repeat(6) { slot ->
            assertTrue(budget.start(minute * 60_000L + slot * 5_000L, true))
        } }
        assertFalse(budget.canStart(1_000_000, true))
        assertTrue(budget.canStart(1_000_000, false))
        Harness(config(groups = 2), budget).use { h ->
            h.ready(1_000_000)
            h.selected(checkNotNull(h.tick(1_000_000)), 1_000_000)
            h.selected(checkNotNull(h.tick(1_005_000)), 1_005_000)
            assertTrue(h.view().getBoolean("requiredReady"))
            val javaScope = h.scope
            val policyScope = h.policyScope
            h.changeOwner(1_006_000)
            assertEquals(javaScope, h.scope)
            assertEquals(policyScope, h.policyScope)
            h.assertRetracted()
            assertNull(h.tick(1_009_999)) // Existing admission debt is not reset.
            val recovery = checkNotNull(h.tick(1_010_000))
            assertEquals(h.epoch, recovery.getLong("nativeEpoch"))
            assertEquals(h.nativeScope, recovery.getString("scope"))
            assertFalse(h.view().getBoolean("requiredReady"))
            h.selected(recovery, 1_010_000)
            assertFalse(h.view().getBoolean("requiredReady")) // Other group needs its own fresh proof.
            h.selected(checkNotNull(h.tick(1_015_000)), 1_015_000)
            assertTrue(h.view().getBoolean("requiredReady"))
            assertEquals(4, h.starts.size)
            assertFalse(budget.canStart(1_020_000, true)) // All96 routine records are still retained.
            assertFalse(h.controller.requiresRetirement())
        }
    }

    @Test fun sameEpochScopeChangeCannotReuseSelectionReceiptOrLatency() {
        Harness(config(choices = 2)).use { h ->
            h.ready(1_000)
            h.selected(checkNotNull(h.tick(1_000)), 1_000, 37)
            assertEquals("working", h.row().getString("state"))
            assertEquals(37L, h.row().getLong("latencyMs"))
            h.controller.force()
            val old = checkNotNull(h.tick(6_000))
            val oldCommit = h.measured(old, 6_000, 5)
            val staleSelected = h.result(old, "selected", 5).put("groupSelected", true)
                .put("receipt", oldCommit.getString("receipt"))
            val unchangedEpoch = h.epoch
            h.changeOwner(7_000, running = true, sameEpoch = true)
            assertEquals(unchangedEpoch, h.epoch)
            h.assertRetracted()
            val commands = h.commands.size
            // A valid prior same-epoch scope is conservatively another change,
            // never a reusable selection proof or positive measurement.
            h.report(staleSelected, 7_100)
            assertEquals(commands, h.commands.size)
            h.assertRetracted()
            h.ready(7_200)
            val fresh = checkNotNull(h.tick(11_000))
            assertNotEquals(old.getString("request"), fresh.getString("request"))
            assertEquals(h.nativeScope, fresh.getString("scope"))
            val freshCommit = h.measured(fresh, 11_000, 91)
            h.report(h.result(fresh, "selected", 5).put("groupSelected", true)
                .put("receipt", oldCommit.getString("receipt")), 11_100)
            h.assertRetracted()
            h.report(h.result(fresh, "selected", 91).put("groupSelected", true)
                .put("receipt", freshCommit.getString("receipt")), 11_200)
            assertTrue(h.view().getBoolean("requiredReady"))
            assertEquals(91L, h.row().getLong("latencyMs"))
            assertEquals(fresh.getJSONArray("hops").toString(), h.row().getJSONArray("measuredPath").toString())
        }
    }

    @Test fun oldNativeWorkerRetainsBarrierUntilTypedCurrentIdleReport() {
        Harness(config()).use { h ->
            h.ready(1_000)
            h.selected(checkNotNull(h.tick(1_000)), 1_000)
            h.controller.force()
            checkNotNull(h.tick(6_000))
            h.changeOwner(7_000, running = true)
            h.assertRetracted()
            assertNull(h.tick(11_000))
            h.report(h.status(ready = false), 12_000)
            assertEquals("configure", h.commands.last().getString("command"))
            assertNull(h.tick(13_000))
            h.report(h.status(running = true), 14_000)
            assertNull(h.tick(15_000))
            h.report(h.status().also { it.remove("running") }, 16_000)
            assertNull(h.tick(16_100))
            h.report(h.status().put("running", "false"), 17_000)
            assertNull(h.tick(17_100))
            assertEquals(2, h.starts.size)
            h.ready(18_000)
            val recovery = checkNotNull(h.tick(18_000))
            assertEquals(3, h.starts.size)
            assertFalse(h.view().getBoolean("requiredReady"))
            h.selected(recovery, 18_000)
            assertTrue(h.view().getBoolean("requiredReady"))
            assertFalse(h.controller.requiresRetirement())
        }
    }

    @Test fun foreignAndMalformedReportsCannotReleaseAnOwnerTransition() {
        Harness(config()).use { h ->
            h.ready(1_000)
            checkNotNull(h.tick(1_000))
            h.changeOwner(2_000, running = true)
            val cases = listOf<(JSONObject) -> Unit>(
                { it.put("nativeEpoch", 1) },
                { it.put("policyScope", Policy.hash("synthetic-foreign-policy")) },
                { it.put("scope", "invalid-scope") },
                { it.put("nativeEpoch", "2") },
                { it.put("nativeEpoch", 2.5) },
                { it.remove("nativeEpoch") },
                { it.remove("ready") },
                { it.put("ready", "true") },
                { it.remove("running") },
                { it.put("running", "false") },
                { it.put("running", JSONObject.NULL) },
                { it.put("running", 0) },
            )
            for ((index, mutate) in cases.withIndex()) {
                val frame = h.status()
                mutate(frame)
                val now = 3_000L + index * 1_000
                h.report(frame, now)
                h.controller.force()
                assertNull("malformed owner frame $index released work", h.tick(now + 100))
                assertEquals(1, h.starts.size)
                h.assertRetracted()
                assertFalse(h.controller.requiresRetirement())
            }
            h.ready(20_000)
            h.selected(checkNotNull(h.tick(20_000)), 20_000)
            assertEquals(2, h.starts.size)
            assertTrue(h.view().getBoolean("requiredReady"))
        }
    }

    @Test fun ownerTransitionTimeoutRetiresWithoutDispatchingAReplacement() {
        Harness(config()).use { h ->
            h.ready(1_000)
            h.selected(checkNotNull(h.tick(1_000)), 1_000)
            h.controller.force()
            checkNotNull(h.tick(6_000))
            h.changeOwner(7_000, running = true, ready = false)
            h.assertRetracted()
            h.controller.force()
            assertNull(h.tick(41_000)) // Original pending started at6_000; timeout is strict >35_000.
            assertFalse(h.controller.requiresRetirement())
            assertNull(h.tick(41_001))
            assertTrue(h.controller.requiresRetirement())
            h.ready(41_002)
            h.controller.force()
            assertNull(h.tick(50_000))
            assertEquals(2, h.starts.size)
            h.assertRetracted()
        }
        val raw = config()
        val binding = AdaptivePolicyBinding(1, Policy.hash(raw), Policy.hash("synthetic-lease-authority"), 10_000, 1)
        Harness(raw, binding = binding).use { h ->
            h.ready(1_000)
            h.selected(checkNotNull(h.tick(1_000)), 1_000)
            h.controller.force()
            checkNotNull(h.tick(6_000))
            h.changeOwner(7_000, running = true)
            h.bind(binding, 11_000)
            assertTrue(h.controller.requiresRetirement())
            h.ready(11_100)
            assertNull(h.tick(20_000))
            assertEquals(2, h.starts.size)
            h.assertRetracted()
        }
    }

    @Test fun ownerChangeKeepsCompatibleNegativeCooldownAndHalfOpenDebt() {
        Harness(config(groups = 2, publicExit = true)).use { h ->
            h.ready(1_000)
            val first = checkNotNull(h.tick(1_000))
            assertEquals("group-00", first.getString("group"))
            h.failed(first, 1_000)
            val healthy = checkNotNull(h.tick(6_000))
            assertEquals("group-01", healthy.getString("group"))
            h.selected(healthy, 6_000)
            val second = checkNotNull(h.tick(11_000))
            assertEquals("group-00", second.getString("group"))
            h.failed(second, 11_000)
            h.changeOwner(12_000)
            h.assertRetracted()
            val revalidated = checkNotNull(h.tick(16_000))
            assertEquals("group-01", revalidated.getString("group"))
            h.selected(revalidated, 16_000)
            assertNull(h.tick(21_000)) // Negative cooldown outlives native ownership.
            var trial: JSONObject? = null
            var trialAt = 0L
            for (now in 26_000L..60_000L step 1_000) {
                val probe = h.tick(now)
                if (probe != null) { trial = probe; trialAt = now; break }
            }
            val oldTrial = checkNotNull(trial)
            assertEquals("group-00", oldTrial.getString("group"))
            assertTrue(trialAt >= 41_000)
            h.changeOwner(trialAt + 100, running = true)
            h.ready(trialAt + 200)
            h.report(h.result(oldTrial, "verified"), trialAt + 300) // Lower native epoch cannot settle the trial.
            h.assertRetracted()
            for (offset in listOf(5_000L, 10_000L)) {
                h.tick(trialAt + offset)?.let { probe ->
                    assertEquals("half-open debt was erased", "group-01", probe.getString("group"))
                    h.selected(probe, trialAt + offset)
                }
            }
            val afterTrial = checkNotNull(h.tick(trialAt + 15_000))
            assertEquals("group-00", afterTrial.getString("group"))
            h.selected(afterTrial, trialAt + 15_100)
            assertTrue(h.view().getBoolean("requiredReady"))
            assertFalse(h.controller.requiresRetirement())
        }
    }
}
