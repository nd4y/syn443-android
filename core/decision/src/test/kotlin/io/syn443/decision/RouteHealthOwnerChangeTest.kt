package io.syn443.decision

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RouteHealthOwnerChangeTest {
    private val context = Context(1, 2, "cfg", "alg", 3, "a".repeat(64))
    private val path = PathHealthKey("path-a", ExitClass.NON_RU, "https")

    @Test fun ownerChangeRetractsOnlyPositiveEvidenceWithoutResettingFailureFences() {
        val memory = RouteHealthMemory(context)
        val verified = path.copy(pathId = "verified")
        val suspect = path.copy(pathId = "suspect")
        val quarantined = path.copy(pathId = "quarantined")
        val configuration = path.copy(pathId = "configuration")
        assertTrue(memory.record(context, verified, 10, 1_000, ProbeVerdict.VERIFIED))
        assertTrue(memory.record(context, suspect, 20, 1_000, ProbeVerdict.CONFIRMED_PATH_FAILURE))
        assertTrue(memory.record(context, quarantined, 30, 1_000, ProbeVerdict.CONFIRMED_PATH_FAILURE))
        assertTrue(memory.record(context, quarantined, 31, 1_001, ProbeVerdict.CONFIRMED_PATH_FAILURE))
        assertTrue(memory.record(context, configuration, 40, 1_001, ProbeVerdict.PATH_AUTH_OR_CONFIGURATION))
        val beforeSuspect = memory.view(context, suspect, 1_001)
        val beforeQuarantine = memory.view(context, quarantined, 1_001)
        val beforeConfiguration = memory.view(context, configuration, 1_001)
        assertEquals(PathReadiness.VERIFIED, memory.view(context, verified, 1_001).readiness)
        assertEquals(PathReadiness.SUSPECT, beforeSuspect.readiness)
        assertEquals(PathReadiness.QUARANTINED, beforeQuarantine.readiness)
        assertEquals(PathReadiness.CONFIG_CHANGE_REQUIRED, beforeConfiguration.readiness)

        assertTrue(memory.revokeVerified(context, 1_002))
        assertEquals(PathReadiness.NO_EVIDENCE, memory.view(context, verified, 1_002).readiness)
        assertEquals(beforeSuspect, memory.view(context, suspect, 1_002))
        assertEquals(beforeQuarantine, memory.view(context, quarantined, 1_002))
        assertEquals(beforeConfiguration, memory.view(context, configuration, 1_002))
        assertFalse(memory.record(context, suspect, 20, 1_002, ProbeVerdict.CONFIRMED_PATH_FAILURE))
        assertFalse(memory.record(context, quarantined, 31, 1_002, ProbeVerdict.VERIFIED))
        assertFalse(memory.record(context, configuration, 41, 1_002, ProbeVerdict.VERIFIED))
        assertTrue(memory.revokeVerified(context, 1_002))
        assertEquals(beforeQuarantine, memory.view(context, quarantined, 1_002))
        assertTrue(memory.record(context, verified, 11, 1_002, ProbeVerdict.VERIFIED))
        assertEquals(PathReadiness.VERIFIED, memory.view(context, verified, 1_002).readiness)
        assertEquals(PathReadiness.VERIFIED, memory.view(context, verified, 121_001).readiness)
        assertEquals(PathReadiness.REVALIDATE, memory.view(context, verified, 121_002).readiness)
        assertTrue(memory.revokeVerified(context, 121_002))
        assertEquals(PathReadiness.NO_EVIDENCE, memory.view(context, verified, 121_002).readiness)
        assertEquals(beforeConfiguration, memory.view(context, configuration, 121_002))
    }

    @Test fun repeatedOwnerChangesPreserveOriginalCooldownAndHalfOpenDebt() {
        val memory = RouteHealthMemory(context)
        assertTrue(memory.record(context, path, 1, 1_000, ProbeVerdict.CONFIRMED_PATH_FAILURE))
        assertTrue(memory.record(context, path, 2, 1_001, ProbeVerdict.CONFIRMED_PATH_FAILURE))
        val originalRetry = checkNotNull(memory.view(context, path, 1_001).retryAtMs)
        assertTrue(memory.revokeVerified(context, 1_002))
        assertTrue(memory.revokeVerified(context, originalRetry - 1))
        assertEquals(PathHealth(PathReadiness.QUARANTINED, originalRetry), memory.view(context, path, originalRetry - 1))
        assertFalse(memory.beginRetry(context, path, 3, originalRetry - 1))
        assertTrue(memory.revokeVerified(context, originalRetry))
        assertEquals(PathHealth(PathReadiness.REVALIDATE, originalRetry), memory.view(context, path, originalRetry))
        assertTrue(memory.beginRetry(context, path, 3, originalRetry))
        val trialUntil = originalRetry + 15_000
        assertTrue(memory.revokeVerified(context, originalRetry + 1))
        assertEquals(PathHealth(PathReadiness.HALF_OPEN, trialUntil), memory.view(context, path, originalRetry + 1))
        assertFalse(memory.beginRetry(context, path, 4, trialUntil - 1))
        assertTrue(memory.revokeVerified(context, trialUntil - 1))
        assertEquals(PathHealth(PathReadiness.HALF_OPEN, trialUntil), memory.view(context, path, trialUntil - 1))
        assertFalse(memory.record(context, path, 3, trialUntil, ProbeVerdict.VERIFIED))
        assertTrue(memory.revokeVerified(context, trialUntil))
        assertEquals(PathHealth(PathReadiness.REVALIDATE, originalRetry), memory.view(context, path, trialUntil))
        assertFalse(memory.beginRetry(context, path, 3, trialUntil))
        assertTrue(memory.beginRetry(context, path, 4, trialUntil))
        assertTrue(memory.record(context, path, 4, trialUntil + 1, ProbeVerdict.CONFIRMED_PATH_FAILURE))
        val thirdRetry = checkNotNull(memory.view(context, path, trialUntil + 1).retryAtMs)
        // The third failure keeps its ordinal: a reset would produce SUSPECT or a 30-second fence.
        assertTrue(thirdRetry - trialUntil - 1 in 48_000L..72_000L)
        assertTrue(memory.revokeVerified(context, thirdRetry - 1))
        assertEquals(PathHealth(PathReadiness.QUARANTINED, thirdRetry), memory.view(context, path, thirdRetry - 1))
        assertTrue(memory.revokeVerified(context, thirdRetry))
        assertEquals(PathHealth(PathReadiness.REVALIDATE, thirdRetry), memory.view(context, path, thirdRetry))
        assertTrue(memory.beginRetry(context, path, 5, thirdRetry))
        assertTrue(memory.record(context, path, 5, thirdRetry + 1, ProbeVerdict.VERIFIED))
        assertEquals(PathReadiness.VERIFIED, memory.view(context, path, thirdRetry + 1).readiness)
        assertTrue(memory.revokeVerified(context, thirdRetry + 2))
        assertEquals(PathReadiness.NO_EVIDENCE, memory.view(context, path, thirdRetry + 2).readiness)
    }

    @Test fun foreignContextRollbackAndBoundsNeverEraseCompatibleHistory() {
        val memory = RouteHealthMemory(context)
        val verified = path.copy(pathId = "verified")
        assertTrue(memory.record(context, verified, 1, 100, ProbeVerdict.VERIFIED))
        assertTrue(memory.record(context, path, 1, 100, ProbeVerdict.CONFIRMED_PATH_FAILURE))
        assertTrue(memory.record(context, path, 2, 101, ProbeVerdict.CONFIRMED_PATH_FAILURE))
        val quarantine = memory.view(context, path, 200)
        val foreignContexts = listOf(
            context.copy(networkEpoch = 2),
            context.copy(activationGeneration = 3),
            context.copy(configRevision = "other-cfg"),
            context.copy(algorithmRevision = "other-alg"),
            context.copy(engineGeneration = 4),
            context.copy(dependencyHash = "b".repeat(64)),
            context.copy(networkEpoch = -1),
        )
        for (foreign in foreignContexts) {
            assertFalse(memory.revokeVerified(foreign, 201))
            assertEquals(PathReadiness.VERIFIED, memory.view(context, verified, 200).readiness)
            assertEquals(quarantine, memory.view(context, path, 200))
        }
        val upper = Decision.MAX_TIME - 720_000
        for (invalidTime in listOf(-1L, 199L, upper + 1, Decision.MAX_TIME + 1, Long.MAX_VALUE)) {
            assertFalse(memory.revokeVerified(context, invalidTime))
            assertEquals(PathReadiness.VERIFIED, memory.view(context, verified, 200).readiness)
            assertEquals(quarantine, memory.view(context, path, 200))
        }
        assertTrue(memory.revokeVerified(context, 201))
        assertEquals(PathReadiness.NO_EVIDENCE, memory.view(context, verified, 201).readiness)
        assertEquals(quarantine, memory.view(context, path, 201))
        assertTrue(memory.revokeVerified(context, upper))
        assertEquals(PathHealth(PathReadiness.REVALIDATE, quarantine.retryAtMs), memory.view(context, path, upper))
        assertFalse(memory.revokeVerified(context, upper + 1))

        val full = RouteHealthMemory(context)
        val fences = List(64) { path.copy(pathId = "configuration-$it") }
        for (key in fences) assertTrue(full.record(context, key, 1, 100, ProbeVerdict.PATH_AUTH_OR_CONFIGURATION))
        assertTrue(full.revokeVerified(context, 200))
        assertFalse(full.record(context, path, 1, 200, ProbeVerdict.VERIFIED))
        assertEquals(PathReadiness.NO_EVIDENCE, full.view(context, path, 200).readiness)
        for (key in fences) {
            assertEquals(PathReadiness.CONFIG_CHANGE_REQUIRED, full.view(context, key, 200).readiness)
            assertFalse(full.record(context, key, 2, 200, ProbeVerdict.VERIFIED))
        }
    }
}
