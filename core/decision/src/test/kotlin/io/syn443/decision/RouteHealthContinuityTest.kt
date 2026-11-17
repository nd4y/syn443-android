package io.syn443.decision

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class RouteHealthContinuityTest {
    private val context = Context(1, 2, "cfg", "alg", 3, "a".repeat(64))
    private val next = context.copy(networkEpoch = 2, engineGeneration = 4)
    private val path = PathHealthKey("path-a", ExitClass.NON_RU, "https")

    @Test fun samePathForkRetainsOnlyNegativeEntriesAndOriginalDeadlines() {
        val original = RouteHealthMemory(context)
        val positive = path.copy(pathId = "positive")
        val suspect = path.copy(pathId = "suspect")
        val configuration = path.copy(pathId = "configuration")
        assertTrue(original.record(context, positive, 50, 1_000, ProbeVerdict.VERIFIED))
        assertTrue(original.record(context, suspect, 60, 1_000, ProbeVerdict.CONFIRMED_PATH_FAILURE))
        assertTrue(original.record(context, path, 70, 1_000, ProbeVerdict.CONFIRMED_PATH_FAILURE))
        assertTrue(original.record(context, path, 71, 1_001, ProbeVerdict.CONFIRMED_PATH_FAILURE))
        assertTrue(original.record(context, configuration, 80, 1_001, ProbeVerdict.PATH_AUTH_OR_CONFIGURATION))
        val retry = checkNotNull(original.view(context, path, 1_001).retryAtMs)

        val fork = checkNotNull(original.forkFailureFences(context, next, 1_002))
        assertEquals(PathReadiness.NO_EVIDENCE, fork.view(next, positive, 1_002).readiness)
        assertEquals(PathReadiness.VERIFIED, original.view(context, positive, 1_002).readiness)
        assertEquals(PathReadiness.SUSPECT, fork.view(next, suspect, 1_002).readiness)
        assertEquals(PathHealth(PathReadiness.QUARANTINED, retry), fork.view(next, path, 1_002))
        assertEquals(PathReadiness.CONFIG_CHANGE_REQUIRED, fork.view(next, configuration, 1_002).readiness)
        assertFalse(fork.record(next, configuration, 1, 1_002, ProbeVerdict.VERIFIED))
        assertEquals(PathReadiness.NO_EVIDENCE, fork.view(context, path, 1_002).readiness)

        assertEquals(PathHealth(PathReadiness.QUARANTINED, retry), fork.view(next, path, retry - 1))
        assertFalse(fork.beginRetry(next, path, 1, retry - 1))
        assertEquals(PathHealth(PathReadiness.REVALIDATE, retry), fork.view(next, path, retry))
        assertFalse(fork.record(next, path, 1, retry, ProbeVerdict.VERIFIED))
        assertTrue(fork.beginRetry(next, path, 1, retry))
        assertEquals(PathHealth(PathReadiness.REVALIDATE, retry), original.view(context, path, retry))
        assertTrue(fork.record(next, path, 1, retry + 1, ProbeVerdict.VERIFIED))
        assertEquals(PathReadiness.VERIFIED, fork.view(next, path, retry + 1).readiness)
        assertEquals(PathHealth(PathReadiness.REVALIDATE, retry), original.view(context, path, retry + 1))
        assertFalse(original.record(context, path, 72, retry + 1, ProbeVerdict.VERIFIED))

        // The original observation time is retained rather than refreshed by the fork.
        assertEquals(PathReadiness.SUSPECT, fork.view(next, suspect, 120_999).readiness)
        assertEquals(PathReadiness.REVALIDATE, fork.view(next, suspect, 121_000).readiness)
        original.reset(context.copy(configRevision = "replaced"))
        assertEquals(PathReadiness.CONFIG_CHANGE_REQUIRED, fork.view(next, configuration, 121_000).readiness)
    }

    @Test fun repeatedForksRetainHalfOpenDebtAndRejectOldContextResults() {
        val original = RouteHealthMemory(context)
        assertTrue(original.record(context, path, 10, 100, ProbeVerdict.CONFIRMED_PATH_FAILURE))
        assertTrue(original.record(context, path, 20, 101, ProbeVerdict.CONFIRMED_PATH_FAILURE))
        val retry = checkNotNull(original.view(context, path, 101).retryAtMs)
        assertTrue(original.beginRetry(context, path, 30, retry))
        val until = retry + 15_000
        val first = checkNotNull(original.forkFailureFences(context, next, retry + 1))
        assertEquals(PathHealth(PathReadiness.HALF_OPEN, until), first.view(next, path, retry + 1))
        assertFalse(first.record(context, path, 30, retry + 2, ProbeVerdict.VERIFIED))
        assertFalse(first.record(next, path, 30, retry + 2, ProbeVerdict.VERIFIED))
        assertFalse(first.beginRetry(next, path, 1, retry + 2))
        val thirdContext = next.copy(networkEpoch = 3)
        val second = checkNotNull(first.forkFailureFences(next, thirdContext, retry + 2))
        assertEquals(PathHealth(PathReadiness.HALF_OPEN, until), second.view(thirdContext, path, retry + 2))
        assertFalse(second.record(next, path, 1, retry + 3, ProbeVerdict.VERIFIED))
        val fourthContext = thirdContext.copy(networkEpoch = 4)
        val third = checkNotNull(second.forkFailureFences(thirdContext, fourthContext, until - 1))
        assertEquals(PathHealth(PathReadiness.HALF_OPEN, until), third.view(fourthContext, path, until - 1))
        assertFalse(third.beginRetry(fourthContext, path, 1, until - 1))
        assertFalse(third.record(fourthContext, path, 0, until - 1, ProbeVerdict.VERIFIED))
        assertFalse(third.record(fourthContext, path, 1, until - 1, ProbeVerdict.VERIFIED))

        assertEquals(PathHealth(PathReadiness.REVALIDATE, retry), third.view(fourthContext, path, until))
        assertTrue(third.beginRetry(fourthContext, path, 1, until))
        assertTrue(third.record(fourthContext, path, 1, until + 1, ProbeVerdict.CONFIRMED_PATH_FAILURE))
        val thirdRetry = checkNotNull(third.view(fourthContext, path, until + 1).retryAtMs)
        assertTrue(thirdRetry - until - 1 in 48_000L..72_000L)
        assertFalse(third.record(fourthContext, path, 1, until + 2, ProbeVerdict.VERIFIED))
        val fifthContext = fourthContext.copy(networkEpoch = 5)
        val fourth = checkNotNull(third.forkFailureFences(fourthContext, fifthContext, until + 2))
        assertEquals(PathHealth(PathReadiness.QUARANTINED, thirdRetry), fourth.view(fifthContext, path, until + 2))
        assertEquals(PathHealth(PathReadiness.REVALIDATE, retry), original.view(context, path, until + 2))
        assertFalse(original.record(context, path, 30, until + 2, ProbeVerdict.VERIFIED))
    }

    @Test fun invalidForkContextClockAndCapacityCannotCreateFreshEvidence() {
        val original = RouteHealthMemory(context)
        val positive = path.copy(pathId = "positive")
        assertTrue(original.record(context, positive, 1, 100, ProbeVerdict.VERIFIED))
        assertTrue(original.record(context, path, 1, 100, ProbeVerdict.CONFIRMED_PATH_FAILURE))
        assertTrue(original.record(context, path, 2, 101, ProbeVerdict.CONFIRMED_PATH_FAILURE))
        val quarantine = original.view(context, path, 200)
        val invalidNext = listOf(
            next.copy(networkEpoch = -1), next.copy(activationGeneration = -1),
            next.copy(engineGeneration = Decision.MAX_GENERATION + 1),
            next.copy(configRevision = ""), next.copy(algorithmRevision = "invalid revision"),
            next.copy(dependencyHash = "invalid"),
        )
        for (invalid in invalidNext) {
            assertNull(original.forkFailureFences(context, invalid, 201))
            assertEquals(PathReadiness.VERIFIED, original.view(context, positive, 200).readiness)
            assertEquals(quarantine, original.view(context, path, 200))
        }
        assertNull(original.forkFailureFences(context.copy(networkEpoch = 7), next, 201))
        val upper = Decision.MAX_TIME - 720_000
        for (invalidTime in listOf(-1L, 199L, upper + 1, Decision.MAX_TIME + 1, Long.MAX_VALUE)) {
            assertNull(original.forkFailureFences(context, next, invalidTime))
            assertEquals(PathReadiness.VERIFIED, original.view(context, positive, 200).readiness)
            assertEquals(quarantine, original.view(context, path, 200))
        }
        val valid = checkNotNull(original.forkFailureFences(context, next, 201))
        assertEquals(PathReadiness.NO_EVIDENCE, valid.view(next, positive, 201).readiness)
        assertEquals(quarantine, valid.view(next, path, 201))
        assertEquals(PathReadiness.NO_EVIDENCE, valid.view(next, path, 200).readiness)
        assertEquals(quarantine, valid.view(next, path, 201))
        val boundary = checkNotNull(original.forkFailureFences(context, next, upper))
        assertEquals(PathHealth(PathReadiness.REVALIDATE, quarantine.retryAtMs), boundary.view(next, path, upper))
        assertNull(original.forkFailureFences(context, next, upper + 1))

        val ordered = RouteHealthMemory(context)
        val oldest = path.copy(pathId = "oldest")
        val newer = path.copy(pathId = "newer")
        assertTrue(ordered.record(context, oldest, 10, 100, ProbeVerdict.CONFIRMED_PATH_FAILURE))
        assertTrue(ordered.record(context, newer, 20, 100, ProbeVerdict.CONFIRMED_PATH_FAILURE))
        val permanent = List(62) { path.copy(pathId = "permanent-$it") }
        for (key in permanent) assertTrue(ordered.record(context, key, 1, 100, ProbeVerdict.PATH_AUTH_OR_CONFIGURATION))
        val owned = checkNotNull(ordered.forkFailureFences(context, next, 102))
        assertTrue(owned.record(next, path.copy(pathId = "new-a"), 1, 103, ProbeVerdict.VERIFIED))
        assertEquals(PathReadiness.NO_EVIDENCE, owned.view(next, oldest, 103).readiness)
        assertEquals(PathReadiness.SUSPECT, owned.view(next, newer, 103).readiness)
        assertTrue(owned.record(next, path.copy(pathId = "new-b"), 1, 104, ProbeVerdict.VERIFIED))
        assertEquals(PathReadiness.NO_EVIDENCE, owned.view(next, newer, 104).readiness)
        assertEquals(PathReadiness.SUSPECT, ordered.view(context, oldest, 104).readiness)
        assertEquals(PathReadiness.SUSPECT, ordered.view(context, newer, 104).readiness)
        for (key in permanent) assertEquals(PathReadiness.CONFIG_CHANGE_REQUIRED, owned.view(next, key, 104).readiness)

        val full = RouteHealthMemory(context)
        val fences = List(64) { path.copy(pathId = "fence-$it") }
        for (key in fences) assertTrue(full.record(context, key, 1, 100, ProbeVerdict.PATH_AUTH_OR_CONFIGURATION))
        val fullFork = checkNotNull(full.forkFailureFences(context, next, 200))
        assertFalse(fullFork.record(next, path, 1, 200, ProbeVerdict.VERIFIED))
        assertEquals(PathReadiness.NO_EVIDENCE, fullFork.view(next, path, 200).readiness)
        for (key in fences) {
            assertEquals(PathReadiness.CONFIG_CHANGE_REQUIRED, fullFork.view(next, key, 200).readiness)
            assertFalse(fullFork.record(next, key, 1, 200, ProbeVerdict.VERIFIED))
        }
    }
}
