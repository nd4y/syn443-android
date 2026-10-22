package io.syn443.recovery

import org.junit.Assert.*
import org.junit.Test

class RecoveryTest {
    @Test fun stopRejectsLateEffectsAndReconnectDoesNotEraseBudget() {
        val started = Recovery.command(Checkpoint(), true)
        val failed = Recovery.failed(started, 10_000, 0.5)
        val stopped = Recovery.command(failed, false)
        assertFalse(Recovery.current(stopped, started.generation))
        val again = Recovery.command(stopped, true)
        assertEquals(failed.attempt, again.attempt)
        assertEquals(failed.nextWallMs, again.nextWallMs)
        assertFalse(Recovery.current(again, started.generation))
    }
    @Test fun jitterExponentialCapAndStableReset() {
        assertEquals(1_000L, Recovery.delay(0, 0.0))
        assertEquals(2_000L, Recovery.delay(1, 0.5))
        assertEquals(60_000L, Recovery.delay(30, 1.0))
        val s = Checkpoint(true, 1, 10, 20_000)
        assertEquals(s, Recovery.stable(s, 29_999, 20))
        assertEquals(s, Recovery.stable(s, 30_000, 2))
        assertEquals(0, Recovery.stable(s, 30_000, 3).attempt)
    }
    @Test fun flappingAndRollingBudgetSurviveReconstruction() {
        val s = Checkpoint(true, 2, 4, 20_000, 10_000, listOf(9_000, 9_500, 10_000))
        val early = Recovery.networkOpportunity(s, 15_000)
        assertEquals(15_000L, early.nextWallMs)
        assertEquals(early, Recovery.networkOpportunity(early.copy(), 15_001))
        val (blocked, allowed) = Recovery.heavyAdmission(early.copy(), 15_000)
        assertFalse(allowed)
        assertEquals(609_000L, blocked.nextWallMs)
        assertTrue(Recovery.heavyAdmission(blocked, 609_000).second)
    }
    @Test fun rollbackOverflowAndStopAdmissionAreBounded() {
        val s = Checkpoint(true, 1, heavyWallMs = listOf(50_000, 51_000, 52_000))
        val (blocked, allowed) = Recovery.heavyAdmission(s, 1_000)
        assertFalse(allowed)
        assertEquals(601_000L, blocked.nextWallMs)
        assertTrue(Recovery.heavyAdmission(blocked, 601_000).second)
        assertFalse(Recovery.heavyAdmission(Recovery.command(s, false), 1_000).second)
        assertEquals(Long.MAX_VALUE, Recovery.failed(s, Long.MAX_VALUE - 1, 1.0).nextWallMs)
    }
    @Test(expected = IllegalArgumentException::class) fun rejectsNonFiniteJitter() { Recovery.delay(0, Double.NaN) }
    @Test(expected = IllegalStateException::class) fun generationNeverWraps() { Recovery.command(Checkpoint(generation = Long.MAX_VALUE), true) }
}
