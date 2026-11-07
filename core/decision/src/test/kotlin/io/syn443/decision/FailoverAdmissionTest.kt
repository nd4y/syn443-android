package io.syn443.decision

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class FailoverAdmissionTest {
    private val context = Context(1, 2, "config", "policy", 3, "a".repeat(64))
    private val members = setOf("primary", "reserve-a", "reserve-b")
    private fun make() = FailoverAdmission(context, ExitClass.privateRoute, members, "comparison")
    private fun sample(id: String, n: Int, verdict: ProbeVerdict, latency: Long = 10, exit: ExitClass = ExitClass.privateRoute) =
        VerifiedPathSample(id, exit, "probe-$n", "comparison", n * 1_000L, verdict, latency)

    @Test fun independentFailuresAndCurrentVerifiedReservePermitOneSwitch() {
        val d = make()
        fun decide(n: Int) = d.decide(context, n.toLong(), "probe-$n", n * 1_000L, "primary",
            sample("primary", n, ProbeVerdict.CONFIRMED_PATH_FAILURE),
            listOf(sample("reserve-b", n, ProbeVerdict.VERIFIED, 20), sample("reserve-a", n, ProbeVerdict.VERIFIED, 10)))
        assertNull(decide(1))
        assertNull(decide(1))
        assertEquals(FailoverChoice("primary", "reserve-a", "probe-2"), decide(2))
        assertNull(decide(3))
        assertNull(decide(4))
    }

    @Test fun targetFailureAndWrongScopeDoNotCountTowardFailover() {
        val d = make()
        fun decide(n: Int, verdict: ProbeVerdict, current: Context = context, candidate: String = "reserve-a") =
            d.decide(current, n.toLong(), "probe-$n", n * 1_000L, "primary",
                sample("primary", n, verdict), listOf(sample(candidate, n, ProbeVerdict.VERIFIED)))
        assertNull(decide(1, ProbeVerdict.CONFIRMED_PATH_FAILURE))
        assertNull(decide(2, ProbeVerdict.TARGET_FAILURE))
        assertNull(decide(3, ProbeVerdict.CONFIRMED_PATH_FAILURE, context.copy(networkEpoch = 2)))
        assertNull(decide(4, ProbeVerdict.CONFIRMED_PATH_FAILURE, candidate = "direct"))
        assertNull(decide(5, ProbeVerdict.CONFIRMED_PATH_FAILURE))
        assertEquals(FailoverChoice("primary", "reserve-a", "probe-6"), decide(6, ProbeVerdict.CONFIRMED_PATH_FAILURE))
    }

    @Test fun staleOrDifferentCheckGroupCannotAuthorizeReplacement() {
        val d = make()
        assertNull(d.decide(context, 1, "probe-1", 16_000, "primary",
            sample("primary", 1, ProbeVerdict.CONFIRMED_PATH_FAILURE).copy(sampledAtMs = 16_000),
            listOf(sample("reserve-a", 1, ProbeVerdict.VERIFIED))))
        assertNull(d.decide(context, 2, "probe-2", 16_001, "primary",
            sample("primary", 2, ProbeVerdict.CONFIRMED_PATH_FAILURE).copy(sampledAtMs = 16_001),
            listOf(sample("reserve-a", 2, ProbeVerdict.VERIFIED).copy(metricGroup = "another"))))
    }

    @Test fun stabilityThenEnergyTakePriorityOverLatency() {
        val energy = mapOf("reserve-a" to 0, "reserve-b" to 2)
        fun choose(history: Boolean): String? {
            val d = FailoverAdmission(context, ExitClass.privateRoute, members, "comparison", energy)
            fun step(n: Int, active: ProbeVerdict, a: ProbeVerdict) =
                d.decide(context, n.toLong(), "probe-$n", n * 1_000L, "primary", sample("primary", n, active),
                    listOf(sample("reserve-a", n, a, 300), sample("reserve-b", n, ProbeVerdict.VERIFIED, 10)))
            if (history) step(1, ProbeVerdict.VERIFIED, ProbeVerdict.UNKNOWN)
            step(2, ProbeVerdict.CONFIRMED_PATH_FAILURE, ProbeVerdict.VERIFIED)
            return step(3, ProbeVerdict.CONFIRMED_PATH_FAILURE, ProbeVerdict.VERIFIED)?.candidate
        }
        assertEquals("reserve-b", choose(history = true))
        assertEquals("reserve-a", choose(history = false))
    }

    @Test fun evidenceFromAnotherExitCannotAuthorizeAReplacementOrAdvanceFailureCount() {
        for ((required, wrong) in listOf(ExitClass.RU to ExitClass.NON_RU, ExitClass.NON_RU to ExitClass.RU)) {
            val d = FailoverAdmission(context, required, members, "comparison")
            fun step(n: Int, activeExit: ExitClass, reserveExit: ExitClass, latency: Long) =
                d.decide(context, n.toLong(), "probe-$n", n * 1_000L, "primary",
                    sample("primary", n, ProbeVerdict.CONFIRMED_PATH_FAILURE, exit = activeExit),
                    listOf(sample("reserve-a", n, ProbeVerdict.VERIFIED, latency, reserveExit)))
            assertNull(step(1, required, wrong, 1))
            assertNull(step(2, wrong, required, 1))
            assertNull(step(3, required, required, 120))
            assertEquals(FailoverChoice("primary", "reserve-a", "probe-4"), step(4, required, required, 120))
        }
    }

    @Test fun failedMemberCannotReturnUsingEvidenceFromBeforeCooldown() {
        val decision = make()
        fun batch(n: Long, now: Long, active: String, reserve: String, sampled: Long = now): FailoverChoice? {
            val receipt = "probe-$n"
            return decision.decide(context, n, receipt, now, active,
                VerifiedPathSample(active, ExitClass.privateRoute, receipt, "comparison", now, ProbeVerdict.CONFIRMED_PATH_FAILURE, 30),
                listOf(VerifiedPathSample(reserve, ExitClass.privateRoute, receipt, "comparison", sampled, ProbeVerdict.VERIFIED, 5)))
        }
        assertNull(batch(1, 1_000, "primary", "reserve-a"))
        assertEquals(FailoverChoice("primary", "reserve-a", "probe-2"),
            batch(2, 2_000, "primary", "reserve-a"))
        // These are recent enough for the generic 15s freshness window, but
        // were sampled before the earliest possible quarantine expiry (32s).
        assertNull(batch(3, 32_000, "reserve-a", "primary", sampled = 30_000))
        assertNull(batch(4, 39_000, "reserve-a", "primary", sampled = 30_000))
        assertNull(batch(5, 40_000, "reserve-a", "primary"))
        assertEquals(FailoverChoice("reserve-a", "primary", "probe-6"),
            batch(6, 41_000, "reserve-a", "primary"))
    }

    @Test fun optionalReserveIsDeferredOnlyAfterIndependentFailuresAgainstHealthyComparator() {
        val d = make()
        fun batch(n: Int, active: ProbeVerdict, reserve: ProbeVerdict) =
            d.decide(context, n.toLong(), "probe-$n", n * 1_000L, "primary", sample("primary", n, active),
                listOf(sample("reserve-a", n, reserve)))
        val fail = ProbeVerdict.CONFIRMED_PATH_FAILURE
        assertNull(batch(1, fail, fail))
        assertNull(batch(2, fail, fail))
        assertFalse(d.deferReserveProbe(context, "reserve-a", 2_000))
        assertNull(batch(3, ProbeVerdict.VERIFIED, fail))
        assertNull(batch(3, ProbeVerdict.VERIFIED, fail))
        assertFalse(d.deferReserveProbe(context, "reserve-a", 3_000))
        assertNull(batch(4, ProbeVerdict.VERIFIED, fail))
        val retry = checkNotNull(d.cooldown("reserve-a", 4_000)?.retryAtMs)
        assertTrue(d.deferReserveProbe(context, "reserve-a", retry - 1))
        assertFalse(d.deferReserveProbe(context.copy(networkEpoch = 2), "reserve-a", retry - 1))
        assertFalse(d.deferReserveProbe(context, "primary", retry - 1))
        assertFalse(d.deferReserveProbe(context, "reserve-a", retry))
    }
}
