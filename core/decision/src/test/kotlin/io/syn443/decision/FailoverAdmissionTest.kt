package io.syn443.decision

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class FailoverAdmissionTest {
    private val context = Context(1, 2, "config", "policy", 3, "a".repeat(64))
    private val members = setOf("primary", "reserve-a", "reserve-b")
    private fun make() = FailoverAdmission(context, members, "comparison")
    private fun sample(id: String, n: Int, verdict: ProbeVerdict, latency: Long = 10) =
        VerifiedPathSample(id, "probe-$n", "comparison", n * 1_000L, verdict, latency)

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
            val d = FailoverAdmission(context, members, "comparison", energy)
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
}
