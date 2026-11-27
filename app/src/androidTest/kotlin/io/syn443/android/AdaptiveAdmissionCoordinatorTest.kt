package io.syn443.android

import io.syn443.android.vpn.AdaptivePolicyBinding
import io.syn443.android.vpn.AdaptiveHandoff
import io.syn443.android.vpn.AdaptiveStartAdmission
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

/** Virtual-clock admission/coordinator tests. Reports below are synthetic and
 * establish no native, physical-network, storage-durability or route proof. */
class AdaptiveAdmissionCoordinatorTest {
    private class AsyncAdmission : AdaptiveStartAdmission {
        private data class Waiting(val allowed: Boolean, val latest: Long,
            val callback: (AdaptiveStartAdmission.Result) -> Unit)
        val budget = AdaptiveProbeBudget()
        val reservations = mutableListOf<Pair<Long, Boolean>>()
        private var waiting: Waiting? = null
        var ownerBusy = false
        var denyNext = false
        var requests = 0
        var now = 0L
        var beforeClockRead: (() -> Unit)? = null
        val hasPending: Boolean get() = waiting != null

        override fun canStart(nowMs: Long, routine: Boolean) = budget.canStart(nowMs, routine)
        override fun currentTimeMs(): Long {
            beforeClockRead?.invoke()
            return now
        }
        override fun invalidated() = budget.invalidated()
        override fun routineCadence(groupCount: Int) = budget.routineCadence(groupCount)
        override fun request(nowMs: Long, routine: Boolean,
            callback: (AdaptiveStartAdmission.Result) -> Unit): Boolean {
            if (ownerBusy || waiting != null) return false
            val latest = nowMs + AdaptiveProbeBudget.MAX_HANDOFF_MS
            val denied = denyNext
            denyNext = false
            val allowed = !denied && budget.reserve(nowMs, routine, latest)
            if (allowed) reservations += nowMs to routine
            waiting = Waiting(allowed, latest, callback)
            requests++
            return true
        }
        fun complete(now: Long) {
            val work = checkNotNull(waiting)
            // This represents actual completion of the single storage owner.
            waiting = null
            work.callback(AdaptiveStartAdmission.Result(work.allowed, now, work.latest))
        }
    }

    private class Harness(val raw: String, val admission: AsyncAdmission = AsyncAdmission(),
        binding: AdaptivePolicyBinding? = null) : Closeable {
        val controller = checkNotNull(ManagedAdaptiveRoutes.read(raw) { admission })
        var scope = RouteScope(1, 2, 3, "synthetic-admission-owner", Policy.hash(raw))
        var epoch = 1L
        var nativeScope = Policy.hash("synthetic-admission-native")
        val commands = mutableListOf<JSONObject>()
        val starts = mutableListOf<Pair<Long, JSONObject>>()
        val handoffFrames = mutableListOf<JSONObject>()
        var acceptHandoff = true
        private fun record(envelope: JSONObject, budgeted: Boolean) {
            assertEquals("adaptive", envelope.getString("kind"))
            val command = JSONObject(envelope.getString("commandJson"))
            commands += command
            if (command.getString("command") == "start") {
                assertTrue("unbudgeted start", budgeted)
                val clock = admission.now
                if (starts.isNotEmpty()) assertTrue("actual starts compressed", clock - starts.last().first >= 5_000)
                starts += clock to command
                assertTrue("minute budget exceeded", starts.count { clock - it.first < 60_000 } <= 8)
                assertTrue("hour budget exceeded", starts.count { clock - it.first < 3_600_000 } <= 128)
            }
        }
        private val dispatch: (String) -> Unit = { raw ->
            val envelope = JSONObject(raw)
            assertEquals(setOf("kind", "commandJson"), envelope.keys().asSequence().toSet())
            record(envelope, false)
        }
        private val handoff: (String, Long) -> Boolean = { raw, latest ->
            val envelope = JSONObject(raw)
            assertEquals(setOf("kind", "commandJson", AdaptiveHandoff.DEADLINE), envelope.keys().asSequence().toSet())
            assertEquals(latest, envelope.getLong(AdaptiveHandoff.DEADLINE))
            handoffFrames += JSONObject(envelope.toString())
            if (!acceptHandoff || !AdaptiveHandoff.allowed(envelope, admission.now)) false
            else { record(envelope, true); true }
        }
        val policyScope: String get() = JSONObject(controller.controlFrame()).getString("scope")
        init {
            RouteSnapshot.configure(raw, scope.config)
            RouteSnapshot.owner(scope)
            if (binding == null) controller.bind(scope, NetworkMode.WIFI, 1)
            else controller.bind(scope, NetworkMode.WIFI, binding, 1_000)
        }
        fun status() = JSONObject().put("request", "").put("running", false)
            .put("nativeEpoch", epoch).put("scope", nativeScope).put("policyScope", policyScope)
            .put("ready", true).put("group", "").put("hops", JSONArray()).put("code", "idle")
            .put("elapsedMs", 0).put("probeMs", 0).put("receipt", "")
            .put("groupSelected", false).put("workAgeMs", 0)
        fun report(value: JSONObject, now: Long) {
            admission.now = now
            controller.report(value, now, dispatch)
        }
        fun ready(now: Long) = report(status(), now)
        fun tick(now: Long, current: (() -> Boolean)? = null) {
            admission.now = now
            controller.tickBudgeted(now, false, false, current ?: { true }, handoff)
        }
        fun complete(now: Long): JSONObject? {
            val before = starts.size
            admission.now = now
            admission.complete(now)
            return starts.drop(before).singleOrNull()?.second
        }
        fun begin(now: Long): JSONObject {
            tick(now)
            assertTrue("admission was not queued", admission.hasPending)
            return checkNotNull(complete(now + 100))
        }
        fun result(probe: JSONObject, code: String) = status().put("request", probe.getString("request"))
            .put("group", probe.getString("group")).put("hops", JSONArray(probe.getJSONArray("hops").toString()))
            .put("code", code)
        fun verified(probe: JSONObject, now: Long): JSONObject {
            val before = commands.size
            report(result(probe, "verified").put("probeMs", 20)
                .put("receipt", Policy.hash(probe.getString("request"))), now)
            return commands.drop(before).single()
        }
        fun selected(probe: JSONObject, now: Long) {
            val commit = verified(probe, now)
            assertEquals("commit", commit.getString("command"))
            report(result(probe, "selected").put("probeMs", 20).put("receipt", commit.getString("receipt"))
                .put("groupSelected", true).put("selectionToken", starts.size.toLong()), now)
        }
        fun failed(probe: JSONObject, now: Long) = report(result(probe, "exit_mismatch"), now)
        fun rebind(next: RouteScope, revision: Long, now: Long) {
            scope = next
            RouteSnapshot.owner(scope)
            controller.bind(scope, NetworkMode.WIFI, revision)
            ready(now)
        }
        fun bind(binding: AdaptivePolicyBinding, now: Long) {
            admission.now = now
            controller.bind(scope, NetworkMode.WIFI, binding, now)
        }
        fun reject(rejection: AdaptiveHandoff.Rejection, now: Long) {
            admission.now = now
            controller.rejectAdmission(rejection, now)
        }
        fun view() = RouteSnapshot.readAt(true, true, scope, admission.now)
        override fun close() { RouteSnapshot.owner(null); RouteSnapshot.configure(null, "") }
    }

    private fun config(groups: Int = 1, publicExit: Boolean = false, choices: Int = 1) =
        ManagedAdaptiveRoutesFairnessTest().config(choices = choices, groupCount = groups, publicExit = publicExit)
    private fun binding(raw: String, revision: Long, until: Long) =
        AdaptivePolicyBinding(revision, Policy.hash(raw), Policy.hash("synthetic-admission-authority"), until, 1)

    @Test fun asyncGrantNeedsMatchingNativeSelectionBeforeReadiness() {
        Harness(config()).use { h ->
            h.ready(1_000)
            h.tick(1_000)
            assertTrue(h.admission.hasPending)
            assertTrue(h.commands.isEmpty())
            assertFalse(h.view().getBoolean("requiredReady"))
            repeat(3) { h.tick(1_100L + it * 100) }
            assertEquals(1, h.admission.requests)
            assertTrue(h.commands.isEmpty())
            val probe = checkNotNull(h.complete(1_500))
            assertEquals(1, h.starts.size)
            assertFalse(h.view().getBoolean("requiredReady"))
            val envelope = h.handoffFrames.single()
            assertTrue(AdaptiveHandoff.allowed(envelope, 1_000))
            assertTrue(AdaptiveHandoff.allowed(envelope, 2_000))
            assertFalse(AdaptiveHandoff.allowed(envelope, 2_001))
            assertFalse(AdaptiveHandoff.allowed(envelope, 999)) // More than the original 1s lead.
            assertFalse(AdaptiveHandoff.allowed(envelope, -1))
            val invalidFrames = listOf<(JSONObject) -> Unit>(
                { it.remove(AdaptiveHandoff.DEADLINE) },
                { it.put("extra", true) },
                { it.put(AdaptiveHandoff.DEADLINE, 2_000.5) },
                { it.put(AdaptiveHandoff.DEADLINE, "2000") },
                { it.put(AdaptiveHandoff.DEADLINE, JSONObject.NULL) },
                { it.put("kind", "foreign") },
                { it.put("commandJson", JSONObject()) },
                { it.put("commandJson", "") },
            )
            for (mutate in invalidFrames) {
                val invalid = JSONObject(envelope.toString())
                mutate(invalid)
                assertFalse(AdaptiveHandoff.allowed(invalid, 1_500))
            }
            val rejectionWire = checkNotNull(AdaptiveHandoff.rejection(probe))
            val rejection = checkNotNull(AdaptiveHandoff.parseRejection(JSONObject(rejectionWire)))
            assertEquals(probe.getString("request"), rejection.request)
            assertEquals(h.epoch, rejection.nativeEpoch)
            assertEquals(h.nativeScope, rejection.scope)
            assertEquals("AdaptiveHandoff.Rejection([redacted])", rejection.toString())
            val invalidRejections = listOf<(JSONObject) -> Unit>(
                { it.put("extra", true) },
                { it.getJSONObject("admissionRejected").put("extra", true) },
                { it.getJSONObject("admissionRejected").remove("nativeEpoch") },
                { it.getJSONObject("admissionRejected").put("nativeEpoch", 1.5) },
                { it.getJSONObject("admissionRejected").put("nativeEpoch", "1") },
                { it.getJSONObject("admissionRejected").put("nativeEpoch", JSONObject.NULL) },
                { it.getJSONObject("admissionRejected").put("request", 1) },
                { it.getJSONObject("admissionRejected").put("request", "x".repeat(81)) },
                { it.getJSONObject("admissionRejected").put("scope", "foreign") },
            )
            for (mutate in invalidRejections) {
                val invalid = JSONObject(rejectionWire)
                mutate(invalid)
                assertNull(AdaptiveHandoff.parseRejection(invalid))
            }
            assertNull(AdaptiveHandoff.rejection(JSONObject(probe.toString()).put("command", "commit")))
            val commit = h.verified(probe, 1_600)
            assertEquals("commit", commit.getString("command"))
            assertFalse(h.view().getBoolean("requiredReady"))
            h.report(h.result(probe, "selected").put("receipt", Policy.hash("foreign-receipt"))
                .put("groupSelected", true), 1_700)
            assertFalse(h.view().getBoolean("requiredReady"))
            h.report(h.result(probe, "selected").put("receipt", commit.getString("receipt"))
                .put("groupSelected", true), 1_800)
            assertTrue(h.view().getBoolean("requiredReady"))
            assertFalse(h.controller.requiresRetirement())
        }
    }

    @Test fun busyDeniedAndLateGrantsLeaveCandidateEligibleWithoutCommands() {
        Harness(config(choices = 2)).use { h ->
            h.ready(1_000)
            h.admission.ownerBusy = true
            h.tick(1_000)
            assertFalse(h.admission.hasPending)
            assertEquals(0, h.admission.requests)
            h.admission.ownerBusy = false
            h.admission.denyNext = true
            h.tick(2_000)
            assertNull(h.complete(2_100))
            h.tick(3_000)
            assertTrue(h.admission.hasPending)
            assertNull(h.complete(4_001)) // One millisecond after the prepaid handoff.
            assertTrue(h.starts.isEmpty())
            assertTrue(h.commands.isEmpty())
            assertFalse(h.view().getBoolean("requiredReady"))
            assertEquals("not_checked", h.view().getJSONArray("routes").getJSONObject(0).getString("reason"))
            assertFalse(h.controller.requiresRetirement())
            h.tick(8_999)
            assertFalse(h.admission.hasPending)
            val probe = h.begin(9_000)
            assertEquals("hop-000", probe.getJSONArray("hops").getString(0))
            h.selected(probe, 9_100)
            assertTrue(h.view().getBoolean("requiredReady"))
        }
        Harness(config()).use { h ->
            h.ready(1_000)
            h.tick(1_000)
            // Coordinator timeout can discard its request, but cannot create a
            // replacement storage owner while the original callback is held.
            h.tick(14_000)
            assertEquals(1, h.admission.requests)
            assertTrue(h.admission.hasPending)
            assertTrue(h.starts.isEmpty())
            assertNull(h.complete(14_001))
            assertTrue(h.starts.isEmpty())
            h.selected(h.begin(15_000), 15_100)
            assertEquals(2, h.admission.requests)
            assertTrue(h.view().getBoolean("requiredReady"))
            assertFalse(h.controller.requiresRetirement())
        }
        Harness(config()).use { h ->
            h.ready(1_000)
            h.selected(h.begin(1_000), 1_100)
            h.acceptHandoff = false
            h.controller.force()
            h.tick(7_000)
            assertNull(h.complete(7_100))
            assertEquals(1, h.starts.size)
            assertTrue(h.view().getBoolean("requiredReady"))
            assertEquals("ok", h.view().getJSONArray("routes").getJSONObject(0).getString("reason"))
            h.acceptHandoff = true
            h.controller.force()
            h.selected(h.begin(13_000), 13_100) // No unstarted 35s native pending remains.
            h.controller.force()
            val queued = h.begin(19_000)
            val hostFrame = h.handoffFrames.last()
            assertFalse(AdaptiveHandoff.allowed(hostFrame, 20_001))
            val matching = checkNotNull(AdaptiveHandoff.parseRejection(JSONObject(checkNotNull(AdaptiveHandoff.rejection(queued)))))
            for (foreign in listOf(
                matching.copy(request = "synthetic-foreign-request"),
                matching.copy(nativeEpoch = matching.nativeEpoch + 1),
                matching.copy(scope = Policy.hash("synthetic-foreign-scope")),
            )) h.reject(foreign, 20_001)
            h.controller.force()
            h.tick(25_000) // Prepaid spacing has elapsed, so only exact native pending can block admission.
            assertFalse(h.admission.hasPending) // Foreign rejection did not release the exact probe.
            assertEquals(3, h.starts.size)
            assertTrue(h.view().getBoolean("requiredReady"))
            h.reject(matching, 25_001)
            assertTrue(h.view().getBoolean("requiredReady"))
            h.tick(30_000)
            assertFalse(h.admission.hasPending)
            h.selected(h.begin(30_001), 30_101)
            assertEquals(4, h.starts.size)
            assertEquals(5, h.admission.reservations.size) // Rejected handoff was charged, never refunded.
            assertTrue(h.view().getBoolean("requiredReady"))
            assertFalse(h.controller.requiresRetirement())
        }
    }

    @Test fun deniedFrontierCandidateKeepsItsPlaceWithoutBlockingAnotherGroup() {
        Harness(config(groups = 2, choices = 2)).use { h ->
            h.ready(1_000)
            h.admission.denyNext = true
            h.tick(1_000)
            assertNull(h.complete(1_100))
            assertTrue(h.handoffFrames.isEmpty())

            val other = h.begin(2_000)
            assertEquals("group-01", other.getString("group"))
            assertEquals("hop-000", other.getJSONArray("hops").getString(0))
            h.selected(other, 2_100)

            h.tick(7_999)
            assertFalse(h.admission.hasPending)
            val retry = h.begin(8_000)
            assertEquals("group-00", retry.getString("group"))
            assertEquals("hop-000", retry.getJSONArray("hops").getString(0))
            assertEquals(listOf(2_000L, 8_000L), h.admission.reservations.map { it.first })
        }
    }

    @Test fun onlyNativeOutcomeAdvancesFrontierAfterHandoffRefusals() {
        Harness(config(choices = 2)).use { h ->
            h.ready(1_000)
            h.acceptHandoff = false
            h.tick(1_000)
            assertNull(h.complete(1_100))
            assertEquals(1, h.handoffFrames.size)
            h.acceptHandoff = true

            val handedOff = h.begin(7_000)
            assertEquals("hop-000", handedOff.getJSONArray("hops").getString(0))
            val rejection = checkNotNull(AdaptiveHandoff.parseRejection(
                JSONObject(checkNotNull(AdaptiveHandoff.rejection(handedOff)))))
            h.reject(rejection, 8_001)
            assertEquals("not_checked", h.view().getJSONArray("routes").getJSONObject(0).getString("reason"))

            val retry = h.begin(13_001)
            assertEquals("hop-000", retry.getJSONArray("hops").getString(0))
            assertNotEquals(handedOff.getString("request"), retry.getString("request"))
            h.failed(retry, 13_101)
            val next = h.begin(19_001)
            assertEquals("hop-001", next.getJSONArray("hops").getString(0))
            assertEquals(listOf(1_000L, 7_000L, 13_001L, 19_001L), h.admission.reservations.map { it.first })
        }
    }

    @Test fun newNetworkScopeRestartsFrontierInsteadOfBorrowingHeldCandidate() {
        Harness(config(choices = 2)).use { h ->
            h.ready(1_000)
            val first = h.begin(1_000)
            assertEquals("hop-000", first.getJSONArray("hops").getString(0))
            h.failed(first, 1_100)

            h.acceptHandoff = false
            h.tick(7_000)
            assertNull(h.complete(7_100))
            val refused = JSONObject(h.handoffFrames.last().getString("commandJson"))
            assertEquals("hop-001", refused.getJSONArray("hops").getString(0))

            h.rebind(h.scope.copy(network = h.scope.network + 1), 1, 7_200)
            h.acceptHandoff = true
            h.tick(12_999)
            assertFalse(h.admission.hasPending)
            val fresh = h.begin(13_000)
            assertEquals("hop-000", fresh.getJSONArray("hops").getString(0))
            assertEquals(listOf(1_000L, 7_000L, 13_000L), h.admission.reservations.map { it.first })
        }
    }

    @Test fun networkPolicyAndOwnerRebindsRejectDelayedAdmission() {
        for (change in listOf("network", "policy", "owner")) Harness(config()).use { h ->
            h.ready(1_000)
            h.tick(1_000)
            val next = when (change) {
                "network" -> h.scope.copy(network = h.scope.network + 1)
                "owner" -> h.scope.copy(intent = 2, engine = "synthetic-replacement-owner")
                else -> h.scope
            }
            h.rebind(next, if (change == "policy") 2 else 1, 1_100)
            assertNull(h.complete(1_200))
            assertTrue("old $change grant dispatched", h.starts.isEmpty())
            assertFalse(h.view().getBoolean("requiredReady"))
            val probe = h.begin(7_000)
            h.selected(probe, 7_100)
            assertEquals(1, h.starts.size)
            assertTrue(h.view().getBoolean("requiredReady"))
            assertFalse(h.controller.requiresRetirement())
        }
    }

    @Test fun nativeEpochScopeAndReadinessChangesRejectDelayedAdmission() {
        for (change in listOf("epoch", "scope", "readiness", "running")) Harness(config()).use { h ->
            h.ready(1_000)
            h.tick(1_000)
            if (change == "epoch") h.epoch++
            if (change == "scope") h.nativeScope = Policy.hash("synthetic-changed-native")
            val changed = h.status()
            if (change == "readiness") changed.put("ready", false)
            if (change == "running") changed.put("running", true)
            h.report(changed, 1_100)
            assertNull(h.complete(1_200))
            assertTrue("old $change grant dispatched", h.starts.isEmpty())
            assertFalse(h.controller.requiresRetirement())
            h.ready(7_000)
            val probe = h.begin(7_000)
            h.selected(probe, 7_100)
            assertTrue(h.view().getBoolean("requiredReady"))
        }
    }

    @Test fun originalAndCurrentLeaseDeadlinesFenceWaitingGrant() {
        val raw = config()
        Harness(raw, binding = binding(raw, 1, 1_800)).use { h ->
            h.ready(1_000)
            val probe = h.begin(1_000)
            val envelope = h.handoffFrames.single()
            assertEquals(1_799L, envelope.getLong(AdaptiveHandoff.DEADLINE))
            assertTrue(AdaptiveHandoff.allowed(envelope, 1_799))
            assertFalse(AdaptiveHandoff.allowed(envelope, 1_800))
            h.selected(probe, 1_100)
            assertTrue(h.view().getBoolean("requiredReady"))
        }
        Harness(raw, binding = binding(raw, 1, 7_500)).use { h ->
            h.ready(1_000)
            h.selected(h.begin(1_000), 1_100)
            assertTrue(h.view().getBoolean("requiredReady"))
            h.controller.force()
            var crossOriginalLease = false
            h.tick(7_000) { if (crossOriginalLease) h.admission.now = 7_600; true }
            assertTrue(h.admission.hasPending)
            val oldPolicyScope = h.policyScope
            h.bind(binding(raw, 2, 20_000), 7_100)
            assertEquals(oldPolicyScope, h.policyScope)
            crossOriginalLease = true
            assertNull(h.complete(7_200)) // Guard returns true after crossing the captured original lease.
            assertEquals(1, h.starts.size)
            assertTrue(h.view().getBoolean("requiredReady"))
            assertFalse(h.controller.requiresRetirement())
            h.controller.force()
            val probe = h.begin(13_000)
            h.selected(probe, 13_100)
            assertTrue(h.view().getBoolean("requiredReady"))
        }
        Harness(raw, binding = binding(raw, 1, 1_500)).use { h ->
            h.ready(1_000)
            var crossCurrentLease = false
            h.tick(1_000) { if (crossCurrentLease) h.admission.now = 1_500; true }
            crossCurrentLease = true
            assertNull(h.complete(1_100))
            assertTrue(h.starts.isEmpty())
            assertTrue(h.controller.requiresRetirement())
            assertFalse(h.view().getBoolean("requiredReady"))
        }
    }

    @Test fun externalAuthorityFenceRejectsCompletionWithoutStrandingNextAttempt() {
        Harness(config()).use { h ->
            h.ready(1_000)
            var current = false
            val guard = { current }
            h.tick(1_000, guard)
            assertEquals(0, h.admission.requests)
            current = true
            h.tick(1_100, guard)
            assertTrue(h.admission.hasPending)
            current = false
            assertNull(h.complete(1_200))
            assertTrue(h.starts.isEmpty())
            assertFalse(h.view().getBoolean("requiredReady"))
            assertFalse(h.controller.requiresRetirement())
            current = true
            h.tick(7_100, guard)
            val probe = checkNotNull(h.complete(7_200))
            assertEquals(2, h.admission.requests)
            h.selected(probe, 7_200)
            assertTrue(h.view().getBoolean("requiredReady"))
        }
        Harness(config()).use { h ->
            h.ready(1_000)
            var delayedGuard = false
            val guard = { if (delayedGuard) h.admission.now = 2_001; true }
            h.tick(1_000, guard)
            delayedGuard = true
            assertNull(h.complete(1_100)) // Fresh post-guard sample passed the original 2_000 deadline.
            assertTrue(h.starts.isEmpty())
            assertTrue(h.handoffFrames.isEmpty())
            assertFalse(h.controller.requiresRetirement())
            delayedGuard = false
            h.tick(7_000, guard)
            val probe = checkNotNull(h.complete(7_100))
            h.selected(probe, 7_100)
            assertEquals(2, h.admission.reservations.size)
            assertTrue(h.view().getBoolean("requiredReady"))
        }
        Harness(config()).use { h ->
            h.ready(1_000)
            h.tick(1_000)
            var reads = 0
            h.admission.beforeClockRead = {
                reads++
                if (reads == 2) h.admission.now = 2_001
            }
            assertNull(h.complete(1_100)) // Time advances after the first sample, before effect creation.
            assertEquals(2, reads)
            assertTrue(h.starts.isEmpty())
            assertTrue(h.handoffFrames.isEmpty())
            h.admission.beforeClockRead = null
            h.selected(h.begin(7_000), 7_100)
            assertTrue(h.view().getBoolean("requiredReady"))
            assertFalse(h.controller.requiresRetirement())
        }
    }

    @Test fun deniedHalfOpenAdmissionDoesNotAcquireRetryOwnership() {
        Harness(config(publicExit = true)).use { h ->
            h.ready(1_000)
            h.failed(h.begin(1_000), 1_100)
            h.failed(h.begin(7_000), 7_100) // Two finite synthetic failures produce quarantine.
            h.admission.denyNext = true
            var retryAt = 0L
            for (now in 13_000L..90_000L step 1_000) {
                h.tick(now)
                if (h.admission.hasPending) { retryAt = now; break }
            }
            assertTrue("no half-open retry became eligible", retryAt > 0)
            assertEquals(2, h.starts.size)
            assertNull(h.complete(retryAt + 100))
            // Denied storage admission must not occupy the fifteen-second trial.
            h.tick(retryAt + 1_100)
            assertTrue("denial stranded half-open ownership", h.admission.hasPending)
            h.acceptHandoff = false
            assertNull(h.complete(retryAt + 1_200))
            assertEquals(2, h.starts.size)
            h.acceptHandoff = true
            h.tick(retryAt + 7_200)
            assertFalse("handoff rejection refunded an acquired trial", h.admission.hasPending)
            h.tick(retryAt + 16_200)
            assertTrue("bounded half-open trial never expired", h.admission.hasPending)
            val probe = checkNotNull(h.complete(retryAt + 16_300))
            assertEquals("hop-000", probe.getJSONArray("hops").getString(0))
            h.selected(probe, retryAt + 16_300)
            assertEquals(3, h.starts.size)
            assertTrue(h.view().getBoolean("requiredReady"))
            assertFalse(h.controller.requiresRetirement())
        }
    }

    @Test fun preJniRejectionKeepsHalfOpenFrontierCandidateUntilItsTrialExpires() {
        Harness(config(publicExit = true, choices = 2)).use { h ->
            h.ready(1_000)
            fun failFirst(now: Long) {
                val probe = h.begin(now)
                assertEquals("hop-000", probe.getJSONArray("hops").getString(0))
                h.failed(probe, now + 100)
            }
            fun leaveAlternativeEligible(now: Long) {
                val probe = h.begin(now)
                assertEquals("hop-001", probe.getJSONArray("hops").getString(0))
                h.report(h.result(probe, "probe_unavailable"), now + 100)
            }
            failFirst(1_000)
            leaveAlternativeEligible(7_000)
            failFirst(13_000)
            leaveAlternativeEligible(19_000)

            val trial = h.begin(50_000)
            assertEquals("hop-000", trial.getJSONArray("hops").getString(0))
            val deadline = trial.getLong("retryUntilBootMs")
            assertEquals(65_100L, deadline)
            val rejection = checkNotNull(AdaptiveHandoff.parseRejection(
                JSONObject(checkNotNull(AdaptiveHandoff.rejection(trial)))))
            h.reject(rejection, 51_001)

            val charged = h.admission.reservations.toList()
            for (now in listOf(57_001L, 58_001L, deadline - 1)) {
                h.controller.force()
                h.tick(now)
                assertFalse(h.admission.hasPending)
                assertEquals(charged, h.admission.reservations)
                assertFalse(h.view().getBoolean("requiredReady"))
            }
            val retried = h.begin(deadline)
            assertEquals("hop-000", retried.getJSONArray("hops").getString(0))
            assertNotEquals(trial.getString("request"), retried.getString("request"))
            assertEquals(deadline + 15_100, retried.getLong("retryUntilBootMs"))
            assertEquals(listOf(1_000L, 7_000L, 13_000L, 19_000L, 50_000L, deadline),
                h.admission.reservations.map { it.first })
            h.selected(retried, deadline + 100)
            assertTrue(h.view().getBoolean("requiredReady"))
        }
    }

    @Test fun sixteenGroupsRetainFairProgressRoutineReserveAndHourlyDebtAcrossRebind() {
        Harness(config(groups = 16)).use { h ->
            h.ready(1_000)
            var now = 1_000L
            fun step(force: Boolean = false): JSONObject? {
                if (force) h.controller.force()
                h.tick(now)
                val probe = if (h.admission.hasPending) h.complete(now + 100) else null
                if (probe != null) h.selected(probe, now + 100)
                now += 1_000
                return probe
            }
            val initialGroups = mutableSetOf<String>()
            while (h.starts.size < 16 && now < 300_000) step()?.let { initialGroups += it.getString("group") }
            assertEquals((0 until 16).map { "group-%02d".format(it) }.toSet(), initialGroups)
            assertTrue(h.view().getBoolean("requiredReady"))
            while (h.starts.size < 112 && now < 2_000_000) step(force = true)
            assertEquals(112, h.starts.size)
            assertEquals(96, h.admission.reservations.count { it.second })
            now += 65_000
            assertNull(step(force = true)) // Routine capacity is exhausted; recovery reserve remains.
            assertEquals(112, h.starts.size)
            h.rebind(h.scope.copy(network = h.scope.network + 1), 1, now)
            val recoveredGroups = mutableSetOf<String>()
            while (h.starts.size < 128 && now < 3_000_000) step()?.let { recoveredGroups += it.getString("group") }
            assertEquals(initialGroups, recoveredGroups)
            assertEquals(128, h.starts.size)
            assertTrue(h.view().getBoolean("requiredReady"))
            now += 65_000
            h.rebind(h.scope.copy(network = h.scope.network + 1), 1, now)
            assertNull(step(force = true))
            assertEquals(128, h.starts.size)
            assertFalse(h.view().getBoolean("requiredReady"))
            assertTrue(now < 3_601_999)
            h.tick(3_601_999)
            assertFalse(h.admission.hasPending)
            val resumed = h.begin(3_602_000) // First prepaid latest-start stamp was 2_000.
            h.selected(resumed, 3_602_100)
            assertEquals(129, h.starts.size)
            assertEquals(32, h.admission.reservations.take(128).count { !it.second })
            assertFalse(h.controller.requiresRetirement())
        }
    }
}
