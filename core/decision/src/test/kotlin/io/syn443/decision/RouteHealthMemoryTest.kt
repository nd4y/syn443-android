package io.syn443.decision

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RouteHealthMemoryTest {
    private val context = Context(1, 2, "cfg", "alg", 3, "a".repeat(64))
    private val path = PathHealthKey("path-a", ExitClass.NON_RU, "https")

    @Test fun pathFailuresQuarantineThenDemandFreshEvidence() {
        val memory = RouteHealthMemory(context)
        assertTrue(memory.record(context, path, 1, 10, ProbeVerdict.CONFIRMED_PATH_FAILURE))
        assertEquals(PathReadiness.SUSPECT, memory.view(context, path, 10).readiness)
        assertFalse(memory.record(context, path, 1, 11, ProbeVerdict.CONFIRMED_PATH_FAILURE))
        assertTrue(memory.record(context, path, 2, 12, ProbeVerdict.CONFIRMED_PATH_FAILURE))
        val quarantined = memory.view(context, path, 100)
        assertEquals(PathReadiness.QUARANTINED, quarantined.readiness)
        val retry = checkNotNull(quarantined.retryAtMs)
        assertTrue(retry - 12 in 30_000..36_000)
        assertFalse(memory.record(context, path, 3, 101, ProbeVerdict.VERIFIED))
        assertEquals(PathReadiness.REVALIDATE, memory.view(context, path, retry).readiness)
        assertFalse(memory.record(context, path, 4, retry, ProbeVerdict.VERIFIED))
        assertTrue(memory.beginRetry(context, path, 4, retry))
        assertFalse(memory.beginRetry(context, path, 5, retry))
        assertEquals(PathReadiness.HALF_OPEN, memory.view(context, path, retry).readiness)
        assertTrue(memory.record(context, path, 4, retry + 1, ProbeVerdict.CONFIRMED_PATH_FAILURE))
        val second = memory.view(context, path, retry + 1)
        assertEquals(PathReadiness.QUARANTINED, second.readiness)
        val retryAgain = checkNotNull(second.retryAtMs)
        assertTrue(retryAgain - retry - 1 in 48_000..72_000)
        assertTrue(memory.beginRetry(context, path, 5, retryAgain))
        assertFalse(memory.record(context, path, 5, retryAgain + 15_000, ProbeVerdict.VERIFIED))
        assertTrue(memory.beginRetry(context, path, 6, retryAgain + 15_000))
        assertTrue(memory.record(context, path, 6, retryAgain + 15_001, ProbeVerdict.VERIFIED))
        assertEquals(PathReadiness.VERIFIED, memory.view(context, path, retryAgain + 15_001).readiness)
        assertEquals(PathReadiness.REVALIDATE, memory.view(context, path, retryAgain + 135_001).readiness)
    }

    @Test fun commonFailuresAndAnotherTrafficClassCannotPoisonPath() {
        val memory = RouteHealthMemory(context)
        for ((index, verdict) in listOf(ProbeVerdict.TARGET_FAILURE, ProbeVerdict.COMMON_NETWORK_FAILURE,
            ProbeVerdict.BUDGET_EXHAUSTED, ProbeVerdict.CANCELLED, ProbeVerdict.UNKNOWN).withIndex()) {
            assertFalse(memory.record(context, path, index + 1L, index + 1L, verdict))
        }
        assertEquals(PathReadiness.NO_EVIDENCE, memory.view(context, path, 5).readiness)
        assertTrue(memory.record(context, path, 6, 6, ProbeVerdict.VERIFIED))
        assertEquals(PathReadiness.NO_EVIDENCE, memory.view(context, path.copy(intent = ExitClass.RU), 7).readiness)
        assertEquals(PathReadiness.NO_EVIDENCE, memory.view(context, path.copy(metricGroup = "other"), 7).readiness)
        assertFalse(memory.record(context, path, 5, 8, ProbeVerdict.CONFIRMED_PATH_FAILURE))
        assertEquals(PathReadiness.VERIFIED, memory.view(context, path, 8).readiness)
    }

    @Test fun authorizationFailureWaitsForContextAndRejectsLateCompletion() {
        val memory = RouteHealthMemory(context)
        assertTrue(memory.record(context, path, 1, 1, ProbeVerdict.PATH_AUTH_OR_CONFIGURATION))
        assertFalse(memory.record(context, path, 2, 100, ProbeVerdict.VERIFIED))
        assertEquals(PathReadiness.CONFIG_CHANGE_REQUIRED, memory.view(context, path, 1_000_000).readiness)
        val next = context.copy(configRevision = "replacement")
        memory.reset(next)
        assertFalse(memory.record(context, path, 3, 1_000_001, ProbeVerdict.VERIFIED))
        assertEquals(PathReadiness.NO_EVIDENCE, memory.view(next, path, 1_000_001).readiness)
        assertFalse(memory.record(next, path, 1, 1_000_000, ProbeVerdict.VERIFIED))
        assertTrue(memory.record(next, path, 1, 1_000_002, ProbeVerdict.VERIFIED))
    }

    @Test fun capacityCannotEvictAnActiveQuarantineOrConfigurationFence() {
        val memory = RouteHealthMemory(context)
        repeat(63) { i ->
            assertTrue(memory.record(context, path.copy(pathId = "fence-$i"), 1, 10, ProbeVerdict.PATH_AUTH_OR_CONFIGURATION))
        }
        assertTrue(memory.record(context, path, 1, 10, ProbeVerdict.CONFIRMED_PATH_FAILURE))
        assertTrue(memory.record(context, path, 2, 11, ProbeVerdict.CONFIRMED_PATH_FAILURE))
        val new = path.copy(pathId = "new")
        assertFalse(memory.record(context, new, 1, 12, ProbeVerdict.VERIFIED))
        val fenced = memory.view(context, path, 12)
        assertEquals(PathReadiness.QUARANTINED, fenced.readiness)
        val retry = checkNotNull(fenced.retryAtMs)
        assertTrue(memory.record(context, new, 2, retry, ProbeVerdict.VERIFIED))
        assertEquals(PathReadiness.VERIFIED, memory.view(context, new, retry).readiness)
    }
}
