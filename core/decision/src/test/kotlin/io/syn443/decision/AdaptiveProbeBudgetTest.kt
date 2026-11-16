package io.syn443.decision

import org.junit.Assert.*
import org.junit.Test

class AdaptiveProbeBudgetTest {
    @Test fun routineSixLeavesTwoRecoveryStartsAndMinuteBoundaryRemainsStrict() {
        val budget = AdaptiveProbeBudget()
        repeat(6) { assertTrue(budget.start(it * 5_000L, routine = true)) }
        assertFalse(budget.canStart(30_000, routine = true))
        assertFalse(budget.start(30_000, routine = true))
        assertTrue(budget.start(30_000, routine = false))
        assertTrue(budget.start(35_000, routine = false))
        assertFalse(budget.canStart(40_000, routine = false))
        assertFalse(budget.canStart(59_999, routine = false))
        // Exactly 60 seconds expires the first start, not the entire window.
        assertTrue(budget.start(60_000, routine = true))
        assertFalse(budget.canStart(64_999, routine = false))
        assertTrue(budget.start(65_000, routine = false))
        assertFalse(budget.invalidated())
    }

    @Test fun repeatedReadinessAndCpuQuantaDoNotChargeOrRelaxFiveSecondSpacing() {
        val budget = AdaptiveProbeBudget()
        repeat(1_000) { assertTrue(budget.canStart(0, routine = true)) }
        assertTrue(budget.start(0, routine = true))
        assertFalse(budget.start(0, routine = false))
        assertFalse(budget.canStart(4_999, routine = false))
        assertTrue(budget.start(5_000, routine = false))
        repeat(1_000) { assertTrue(budget.canStart(10_000, routine = true)) }
        for (now in 10_000L..30_000L step 5_000L) assertTrue(budget.start(now, routine = true))
        assertFalse(budget.start(35_000, routine = true))
        assertTrue(budget.start(35_000, routine = false))
        assertFalse(budget.start(40_000, routine = false))
    }

    @Test fun routineNinetySixReservesHourCapacityButTotalOneTwentyEightStillCapsAllWork() {
        val budget = AdaptiveProbeBudget()
        // Six maintenance starts per minute reach 96 without any recovery.
        repeat(16) { minute ->
            repeat(6) { slot -> assertTrue(budget.start(minute * 60_000L + slot * 5_000L, routine = true)) }
        }
        assertTrue(budget.start(930_000, routine = false))
        assertTrue(budget.start(935_000, routine = false))
        // The minute now has room, yet the independent routine hour cap holds.
        assertFalse(budget.canStart(960_000, routine = true))
        assertTrue(budget.canStart(960_000, routine = false))
        var recovery = 2
        for (minute in 16..19) {
            repeat(minOf(8, 32 - recovery)) { slot ->
                assertTrue(budget.start(minute * 60_000L + slot * 5_000L, routine = false))
                recovery++
            }
        }
        assertEquals(32, recovery)
        assertFalse(budget.canStart(1_170_000, routine = false))
        assertFalse(budget.canStart(3_599_999, routine = false))
        // Both rolling hour limits release only the exact expired record.
        assertTrue(budget.start(3_600_000, routine = true))
        assertFalse(budget.canStart(3_604_999, routine = false))
        assertTrue(budget.start(3_605_000, routine = false))
        assertFalse(budget.invalidated())
    }

    @Test fun sixteenGroupsCanMaintainContinuouslyAndRecoverAtOldFifteenMinuteThirtySixSecondExhaustion() {
        val maintenance = AdaptiveProbeBudget()
        val cadence = maintenance.routineCadence(16)
        assertEquals(600_000L, cadence)
        val stagger = cadence / 16
        // Twelve complete rounds are two hours. Routine maintenance alone
        // never consumes recovery reserve or hits a permanent hourly dead end.
        repeat(16 * 12) { index -> assertTrue(maintenance.start(index * stagger, routine = true)) }
        val recovering = AdaptiveProbeBudget()
        var now = 0L
        while (now <= 900_000) {
            assertTrue(recovering.start(now, routine = true))
            now += stagger
        }
        // The old eager maintenance loop could already have used all128 starts.
        // Paced16-group maintenance has capacity for actual no-route/recovery.
        assertTrue(recovering.canStart(936_000, routine = false))
        assertTrue(recovering.start(936_000, routine = false))
        assertFalse(recovering.canStart(940_999, routine = true))
        assertTrue(recovering.start(941_000, routine = true))
    }

    @Test fun invalidOrBackwardBootTimePermanentlySealsWithoutRefillingHistory() {
        for (invalid in listOf(-1L, 9_999L, Decision.MAX_TIME + 1, Long.MIN_VALUE, Long.MAX_VALUE)) {
            val budget = AdaptiveProbeBudget()
            assertTrue(budget.start(10_000, routine = true))
            assertFalse(budget.canStart(invalid, routine = false))
            assertTrue(budget.invalidated())
            assertFalse(budget.start(3_610_000, routine = false))
            assertFalse(budget.canStart(Decision.MAX_TIME, routine = false))
        }
        val boundary = AdaptiveProbeBudget()
        assertTrue(boundary.start(0, routine = false))
        assertTrue(boundary.start(Decision.MAX_TIME, routine = false))
        assertFalse(boundary.invalidated())
        assertFalse(boundary.start(Decision.MAX_TIME + 1, routine = false))
        assertTrue(boundary.invalidated())
    }

    @Test fun cadenceIsBoundedAndDiagnosticsNeverExposeAdmissionHistory() {
        val budget = AdaptiveProbeBudget()
        for (groups in 1..16) {
            val expected = maxOf(60_000L, (groups * 3_600_000L + 95) / 96)
            assertEquals(expected, budget.routineCadence(groups))
        }
        for (groups in listOf(Int.MIN_VALUE, -1, 0, 17, Int.MAX_VALUE)) {
            assertThrows(IllegalArgumentException::class.java) { budget.routineCadence(groups) }
        }
        val before = budget.toString()
        assertTrue(budget.start(123_456, routine = true))
        assertEquals("AdaptiveProbeBudget([redacted])", before)
        assertEquals(before, budget.toString())
        assertFalse(budget.toString().contains("123456"))
        // There is intentionally no snapshot, mutable collection getter or
        // reset API: context changes cannot wipe these starts or mint authority.
    }
}
