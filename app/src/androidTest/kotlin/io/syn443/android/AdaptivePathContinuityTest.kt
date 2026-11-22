package io.syn443.android

import io.syn443.android.vpn.AdaptivePolicyBinding
import io.syn443.android.vpn.ManagedAdaptiveRoutes
import io.syn443.android.vpn.PhysicalPathContinuity
import io.syn443.android.vpn.PhysicalPathToken
import io.syn443.android.vpn.RouteSnapshot
import io.syn443.decision.AdaptiveProbeBudget
import io.syn443.decision.Decision
import io.syn443.decision.NetworkMode
import io.syn443.policy.Policy
import io.syn443.recovery.PhysicalCandidate
import io.syn443.recovery.PhysicalProbeContext
import io.syn443.recovery.PhysicalTransport
import io.syn443.recovery.RouteScope
import java.io.Closeable
import java.util.Base64
import kotlinx.serialization.json.*
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

/** RAM-only synthetic coordinator scenarios. Network modes are fixture values,
 * never a radio operation; these cases establish no native/physical route proof. */
class AdaptivePathContinuityTest {
    private fun physical(validated: Boolean = true, metered: Boolean = false) = PhysicalProbeContext(
        PhysicalCandidate(31, PhysicalTransport.WIFI, validated, false, metered), "synthetic-link-a")
    private fun canonical(value: JsonElement): String = when (value) {
        is JsonObject -> value.toSortedMap().entries.joinToString(",", "{", "}") { (key, child) ->
            JsonPrimitive(key).toString() + ":" + canonical(child)
        }
        is JsonArray -> value.joinToString(",", "[", "]", transform = ::canonical)
        else -> value.toString()
    }
    private fun config(groups: Int = 1, choices: Int = 1): String {
        val root = JSONObject(ManagedAdaptiveRoutesFairnessTest().config(choices = choices, groupCount = groups, publicExit = true))
        val wire = root.getJSONObject("adaptive_routes")
        val graph = JSONObject(Base64.getUrlDecoder().decode(wire.getString("graphB64")).toString(Charsets.UTF_8))
        val hops = graph.getJSONArray("hops")
        for (index in 0 until hops.length()) hops.getJSONObject(index)
            .put("entryModes", JSONArray(NetworkMode.policyModes.map { it.name }))
        wire.put("graphB64", Base64.getUrlEncoder().withoutPadding()
            .encodeToString(canonical(Json.parseToJsonElement(graph.toString())).toByteArray(Charsets.UTF_8)))
        return root.toString()
    }

    private class Harness(val raw: String, initialRevision: Long = 1, until: Long = 1_000_000) : Closeable {
        val budget = AdaptiveProbeBudget()
        val controller = checkNotNull(ManagedAdaptiveRoutes.read(raw, budget))
        val continuity = PhysicalPathContinuity()
        var physical = PhysicalProbeContext(PhysicalCandidate(31, PhysicalTransport.WIFI, true, false, false), "synthetic-link-a")
        var pathToken = checkNotNull(continuity.observe(physical))
        var scope = RouteScope(1, 2, 3, "synthetic-path-owner", Policy.hash(raw))
        var mode = NetworkMode.WIFI
        var revision = initialRevision
        var authority = Policy.hash("synthetic-path-authority")
        var boot = 1
        var leaseUntil = until
        var epoch = 1L
        var nativeScope = Policy.hash("synthetic-path-native-a")
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
            controller.bind(scope, mode, binding(), 1_000, pathToken)
        }
        fun binding(revision: Long = this.revision, authority: String = this.authority,
            until: Long = leaseUntil, boot: Int = this.boot) =
            AdaptivePolicyBinding(revision, scope.config, authority, until, boot)
        fun status() = JSONObject().put("request", "").put("running", false).put("nativeEpoch", epoch)
            .put("scope", nativeScope).put("policyScope", policyScope).put("ready", true)
            .put("group", "").put("hops", JSONArray()).put("code", "idle").put("elapsedMs", 0)
            .put("probeMs", 0).put("receipt", "").put("groupSelected", false).put("workAgeMs", 0)
        private var displayTime = 0L
        fun report(value: JSONObject, now: Long) {
            displayTime = now
            controller.report(value, now, dispatch)
        }
        fun ready(now: Long) = report(status(), now)
        fun tick(now: Long): JSONObject? {
            displayTime = now
            val before = commands.size
            controller.tick(now, false, false, dispatch)
            val probe = commands.drop(before).singleOrNull { it.getString("command") == "start" }
            if (probe != null) {
                if (starts.isNotEmpty()) assertTrue(now - starts.last().first >= 5_000)
                starts += now to probe
                assertTrue(starts.count { now - it.first < 60_000 } <= 8)
                assertTrue(starts.count { now - it.first < 3_600_000 } <= 128)
            }
            return probe
        }
        fun result(probe: JSONObject, code: String, latency: Long = 37) = status()
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
            report(result(probe, "selected", latency).put("groupSelected", true)
                .put("receipt", commit.getString("receipt")), now)
        }
        fun failed(probe: JSONObject, now: Long) = report(result(probe, "exit_mismatch"), now)
        fun quarantine() {
            ready(1_000)
            failed(checkNotNull(tick(1_000)), 1_000)
            failed(checkNotNull(tick(6_000)), 6_000)
        }
        fun rebind(now: Long, nextScope: RouteScope = scope.copy(network = scope.network + 1),
            nextMode: NetworkMode = mode, nextToken: PhysicalPathToken? = pathToken,
            nextBinding: AdaptivePolicyBinding = binding(revision = revision + 1), handshake: Boolean = true) {
            scope = nextScope
            mode = nextMode
            RouteSnapshot.owner(scope)
            controller.bind(scope, mode, nextBinding, now, nextToken)
            revision = nextBinding.revision
            authority = nextBinding.semanticAuthority
            boot = nextBinding.boot
            leaseUntil = nextBinding.leaseDeadlineElapsed
            if (nextToken != null) pathToken = nextToken
            if (handshake) {
                epoch++
                nativeScope = Policy.hash("synthetic-path-native-$epoch-$now")
                ready(now)
            }
        }
        fun metadata(now: Long) {
            physical = physical.copy(network = physical.network.copy(validated = !physical.network.validated, metered = !physical.network.metered))
            val same = checkNotNull(continuity.observe(physical))
            assertSame(pathToken, same)
            rebind(now, nextToken = same)
        }
        fun view() = RouteSnapshot.readAt(true, true, scope, displayTime)
        fun assertNoPositive() {
            val view = view()
            assertFalse(view.getBoolean("requiredReady"))
            val rows = view.getJSONArray("routes")
            for (index in 0 until rows.length()) {
                val row = rows.getJSONObject(index)
                assertNotEquals("working", row.getString("state"))
                assertEquals(0, row.getJSONArray("measuredPath").length())
                assertTrue(row.isNull("latencyMs"))
            }
        }
        override fun close() { RouteSnapshot.owner(null); RouteSnapshot.configure(null, "") }
    }

    @Test fun metadataChangesRetainOpaqueTokenButLossPathAndTransportRotateIt() {
        val continuity = PhysicalPathContinuity()
        val original = physical()
        val first = checkNotNull(continuity.observe(original))
        assertSame(first, continuity.currentToken)
        assertSame(first, continuity.observe(physical(validated = false, metered = true)))
        continuity.lost(99)
        assertSame(first, continuity.currentToken)
        assertSame(first, continuity.observe(original))
        var previous = first
        for (context in listOf(
            original.copy(linkSignature = "synthetic-link-b"),
            original.copy(network = original.network.copy(handle = 32)),
            original.copy(network = original.network.copy(transport = PhysicalTransport.CELLULAR)),
            original,
        )) {
            val next = checkNotNull(continuity.observe(context))
            assertNotSame(previous, next)
            previous = next
        }
        continuity.lost(original.network.handle)
        assertNull(continuity.currentToken)
        val reentered = checkNotNull(continuity.observe(original))
        assertNotSame(first, reentered)
        for (invalid in listOf(null, original.copy(network = original.network.copy(captive = true)),
            original.copy(network = original.network.copy(handle = 0)),
            original.copy(network = original.network.copy(handle = -1)))) {
            val old = checkNotNull(continuity.currentToken)
            assertNull(continuity.observe(invalid))
            assertNull(continuity.currentToken)
            assertNotSame(old, continuity.observe(original))
        }
        assertNotSame(continuity.currentToken, PhysicalPathContinuity().observe(original))
        assertEquals("PhysicalPathToken([redacted])", first.toString())
        assertEquals("PhysicalPathContinuity([redacted])", continuity.toString())
    }

    @Test fun compatibleMetadataRebindKeepsCooldownWithoutReadinessOrOldNativeProof() {
        Harness(config(groups = 2)).use { h ->
            h.ready(1_000)
            h.failed(checkNotNull(h.tick(1_000)), 1_000)
            val healthy = checkNotNull(h.tick(6_000))
            h.selected(healthy, 6_000)
            val oldAck = h.result(healthy, "selected").put("groupSelected", true)
            h.failed(checkNotNull(h.tick(11_000)), 11_000)
            val token = h.pathToken
            h.metadata(12_000)
            assertSame(token, h.pathToken)
            h.assertNoPositive()
            h.report(oldAck, 13_000)
            h.assertNoPositive()
            assertNull(h.tick(16_000)) // Carried group-00 quarantine yields a CPU quantum.
            val fresh = checkNotNull(h.tick(17_000))
            assertEquals("group-01", fresh.getString("group"))
            assertFalse(h.view().getBoolean("requiredReady"))
            h.selected(fresh, 17_000)
            assertFalse(h.view().getBoolean("requiredReady"))
            assertNull(h.tick(26_000))
            assertFalse(h.controller.requiresRetirement())
        }
    }

    @Test fun repeatedMetadataRebindsNeverExtendCooldownOrHalfOpenDebt() {
        val raw = config()
        var originalRetry = 0L
        Harness(raw).use { reference ->
            reference.quarantine()
            for (now in 11_000L..60_000L step 1_000) if (reference.tick(now) != null) {
                originalRetry = now
                break
            }
            assertTrue(originalRetry >= 36_000)
        }
        Harness(raw).use { h ->
            h.quarantine()
            for (now in listOf(11_000L, 16_000L, 21_000L, 26_000L, 31_000L)) {
                h.metadata(now)
                assertNull(h.tick(now))
                h.assertNoPositive()
            }
            assertNull(h.tick(originalRetry - 1_000))
            val oldTrial = checkNotNull(h.tick(originalRetry))
            assertEquals(3, h.starts.size) // Rebinding did not refresh the original cooldown.
            val late = h.result(oldTrial, "selected").put("groupSelected", true)
            h.metadata(originalRetry + 100)
            h.report(late, originalRetry + 200)
            h.assertNoPositive()
            assertNull(h.tick(originalRetry + 5_000))
            h.metadata(originalRetry + 10_000)
            assertNull(h.tick(originalRetry + 14_000))
            val retry = checkNotNull(h.tick(originalRetry + 15_000))
            h.selected(retry, originalRetry + 15_100)
            assertTrue(h.view().getBoolean("requiredReady"))
            assertEquals(4, h.starts.size)
            assertFalse(h.controller.requiresRetirement())
        }
    }

    @Test fun changedTokenOwnerModeAndPolicyRejectNegativeCarry() {
        for (change in listOf("token", "null-token", "owner", "mode", "policy", "intent", "activation", "config", "content")) Harness(config()).use { h ->
            h.quarantine()
            val token = if (change == "token") checkNotNull(PhysicalPathContinuity().observe(physical()))
                else if (change == "null-token") null else h.pathToken
            val next = when (change) {
                "token", "null-token" -> h.scope // Exact Java scope must still reset on token identity change.
                "owner" -> h.scope.copy(network = h.scope.network + 1, engine = "synthetic-different-engine")
                "intent" -> h.scope.copy(network = h.scope.network + 1, intent = h.scope.intent + 1)
                "activation" -> h.scope.copy(network = h.scope.network + 1, activation = h.scope.activation + 1)
                "config" -> h.scope.copy(network = h.scope.network + 1, config = Policy.hash("synthetic-different-config"))
                else -> h.scope.copy(network = h.scope.network + 1)
            }
            // Defensive internal-API mismatches, not signed-policy admission:
            // vary config and content independently to exercise each guard.
            val binding = if (change == "content") AdaptivePolicyBinding(2,
                Policy.hash("synthetic-different-content"), h.authority, h.leaseUntil, h.boot)
                else h.binding(revision = 2,
                    authority = if (change == "policy") Policy.hash("synthetic-changed-authority") else h.authority)
            if (change == "config") RouteSnapshot.configure(h.raw, next.config)
            h.rebind(7_000, nextScope = next, nextToken = token,
                nextMode = if (change == "mode") NetworkMode.CELLULAR else h.mode,
                nextBinding = binding)
            h.assertNoPositive()
            val probe = checkNotNull(h.tick(11_000)) // Old compatible-history deadline was at least36_000.
            assertEquals("hop-000", probe.getJSONArray("hops").getString(0))
            h.selected(probe, 11_000)
            assertTrue("incompatible $change kept a foreign fence", h.view().getBoolean("requiredReady"))
            assertFalse(h.controller.requiresRetirement())
        }
    }

    @Test fun expiredLeaseBootAndClockCannotReviveCarriedHistory() {
        for (change in listOf("old-lease", "new-lease", "boot", "clock", "revision")) Harness(config(), initialRevision = 2, until = 20_000).use { h ->
            h.quarantine()
            val now = when (change) { "old-lease" -> 20_000L; "clock" -> 5_999L; else -> 11_000L }
            h.rebind(now, nextBinding = h.binding(
                revision = if (change == "revision") 1 else 3,
                until = if (change == "new-lease") now else 100_000,
                boot = if (change == "boot") 2 else 1), handshake = false)
            assertTrue("invalid $change revived the owner", h.controller.requiresRetirement())
            h.ready(30_000)
            h.controller.force()
            assertNull(h.tick(100_000))
            assertEquals(2, h.starts.size)
            h.assertNoPositive()
        }
        Harness(config()).use { h ->
            h.quarantine()
            val originalControl = h.controller.controlFrame()
            h.rebind(7_000, nextScope = h.scope.copy(network = h.scope.network - 1), handshake = false)
            assertEquals(originalControl, h.controller.controlFrame())
            assertFalse(h.controller.requiresRetirement())
            assertNull(h.tick(11_000)) // Compatible stale epoch did not replace the current cooldown.
            assertEquals(2, h.starts.size)
            // The deliberately stale caller changed Snapshot.owner; this case
            // makes no readiness claim for that external invalid projection.
        }
        Harness(config(), until = Decision.MAX_TIME).use { h ->
            h.quarantine()
            val originalControl = h.controller.controlFrame()
            // Managed admits through MAX_TIME-600000. The pure memory owns a
            // stricter MAX_TIME-720000 ceiling, so this real eligible fork fails.
            val rejectedForkAt = Decision.MAX_TIME - 719_999
            h.rebind(rejectedForkAt, nextBinding = h.binding(revision = 2, until = Decision.MAX_TIME), handshake = false)
            assertTrue(h.controller.requiresRetirement())
            assertEquals(originalControl, h.controller.controlFrame())
            h.ready(rejectedForkAt + 1_000)
            h.controller.force()
            assertNull(h.tick(rejectedForkAt + 1_000))
            assertEquals(2, h.starts.size)
            h.assertNoPositive()
        }
    }

    private fun Harness.selectSecondPath(): JSONObject {
        ready(1_000)
        val first = checkNotNull(tick(1_000))
        assertEquals("hop-000", first.getJSONArray("hops").getString(0))
        failed(first, 1_000)
        val second = checkNotNull(tick(6_000))
        assertEquals("hop-001", second.getJSONArray("hops").getString(0))
        selected(second, 6_050)
        assertTrue(view().getBoolean("requiredReady"))
        return second
    }

    @Test fun recentWorkingRouteIsRecheckedOnceBeforeResumingColdSearch() {
        for (restartNative in listOf(false, true)) {
            Harness(config(choices = 2)).use { h ->
                val old = h.selectSecondPath()
                if (restartNative) {
                    h.epoch++
                    h.nativeScope = Policy.hash("synthetic-restarted-native")
                    h.ready(7_000)
                } else {
                    h.metadata(7_000)
                    h.metadata(7_100)
                }
                h.assertNoPositive()
                val retry = checkNotNull(h.tick(11_000))
                assertEquals("hop-001", retry.getJSONArray("hops").getString(0))
                assertNotEquals(old.getString("request"), retry.getString("request"))
                h.assertNoPositive()
                h.failed(retry, 11_000)
                val alternative = checkNotNull(h.tick(16_000))
                assertEquals("hop-000", alternative.getJSONArray("hops").getString(0))
                h.selected(alternative, 16_050)
                assertTrue(h.view().getBoolean("requiredReady"))
            }
        }
    }

    @Test fun expiredForeignOrSuspectWorkingPathsCannotLeadTheNewSearch() {
        for (reason in listOf("expired", "changed-link", "changed-policy", "suspect")) {
            Harness(config(choices = 2)).use { h ->
                h.selectSecondPath()
                var next = 11_000L
                when (reason) {
                    "expired" -> {
                        h.metadata(7_000)
                        next = 127_000
                    }
                    "changed-link" -> h.rebind(7_000, nextToken = PhysicalPathToken())
                    "changed-policy" -> h.rebind(7_000, nextBinding = h.binding(2, Policy.hash("other-program")))
                    "suspect" -> {
                        // A failed live recheck is sufficient to rule out warming this selection.
                        val recheck = checkNotNull(h.tick(80_000))
                        h.failed(recheck, 80_000)
                        h.metadata(81_000)
                        next = 86_000
                    }
                }
                h.assertNoPositive()
                assertEquals("hop-000", checkNotNull(h.tick(next)).getJSONArray("hops").getString(0))
            }
        }
    }

    @Test fun physicalContextRoundTripRequiresFreshAckAndKeepsAdmissionDebt() {
        Harness(config()).use { h ->
            h.ready(1_000)
            h.selected(checkNotNull(h.tick(1_000)), 1_000, 37)
            h.controller.force()
            val old = checkNotNull(h.tick(6_000))
            val oldCommit = h.measured(old, 6_000, 5)
            val oldAck = h.result(old, "selected", 5).put("groupSelected", true)
                .put("receipt", oldCommit.getString("receipt"))
            val token = h.pathToken
            h.metadata(6_100)
            h.metadata(6_200) // Validation/metering have returned; the Java network epoch has not.
            assertSame(token, h.pathToken)
            h.assertNoPositive()
            h.report(oldAck, 6_300)
            h.assertNoPositive()
            assertNull(h.tick(10_999))
            assertEquals(2, h.starts.size)
            val fresh = checkNotNull(h.tick(11_000))
            assertNotEquals(old.getString("request"), fresh.getString("request"))
            val commit = h.measured(fresh, 11_000, 91)
            assertFalse(h.view().getBoolean("requiredReady"))
            h.report(h.result(fresh, "selected", 5).put("groupSelected", true)
                .put("receipt", oldCommit.getString("receipt")), 11_100)
            assertFalse(h.view().getBoolean("requiredReady"))
            h.report(h.result(fresh, "selected", 91).put("groupSelected", true)
                .put("receipt", commit.getString("receipt")), 11_200)
            assertTrue(h.view().getBoolean("requiredReady"))
            assertEquals(91L, h.view().getJSONArray("routes").getJSONObject(0).getLong("latencyMs"))
            assertEquals(3, h.starts.size)
            assertFalse(h.controller.requiresRetirement())
        }
    }
}
