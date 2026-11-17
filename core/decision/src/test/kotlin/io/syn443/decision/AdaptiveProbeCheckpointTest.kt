package io.syn443.decision

import io.syn443.decision.AdaptiveProbeBudget.Checkpoint
import io.syn443.decision.AdaptiveProbeBudget.Entry
import org.junit.Assert.*
import org.junit.Test

class AdaptiveProbeCheckpointTest {
    private fun fullHour(): AdaptiveProbeBudget = AdaptiveProbeBudget().apply {
        repeat(16) { minute ->
            repeat(8) { slot -> assertTrue(start(minute * 60_000L + slot * 5_000L, routine = slot < 6)) }
        }
    }

    @Test fun checkpointOwnsEntriesAndExportDoesNotObserveSpendOrExposeHistory() {
        val budget = AdaptiveProbeBudget()
        assertTrue(budget.start(123_456, routine = true))
        assertTrue(budget.canStart(130_000, routine = false))
        val saved = budget.checkpoint()
        assertEquals(130_000L, saved.observedAtMs)
        assertFalse(saved.clockSealed)
        assertEquals(listOf(Entry(6_544, true)), saved.entries)
        assertEquals(saved, budget.checkpoint())
        val supplied = arrayListOf(Entry(10_000, true), Entry(0, false))
        val owned = Checkpoint(20_000, false, supplied)
        supplied[0] = Entry(15_000, false)
        supplied.clear()
        assertEquals(listOf(Entry(10_000, true), Entry(0, false)), owned.entries)
        assertThrows(UnsupportedOperationException::class.java) { (owned.entries as MutableList<Entry>).clear() }
        assertEquals(Checkpoint(20_000, false, listOf(Entry(10_000, true), Entry(0, false))), owned)
        assertEquals(Checkpoint(20_000, false, owned.entries).hashCode(), owned.hashCode())
        assertNotEquals(owned, Checkpoint(20_000, true, owned.entries))
        assertNotEquals(owned, saved)
        assertNotEquals(owned, null)
        assertEquals("AdaptiveProbeBudget([redacted])", budget.toString())
        assertEquals("AdaptiveProbeBudget.Checkpoint([redacted])", saved.toString())
        assertEquals("AdaptiveProbeBudget.Entry([redacted])", saved.entries.single().toString())
        assertEquals(saved, budget.checkpoint())
        assertEquals(1, budget.checkpoint().entries.size)
    }

    @Test fun sameBootRestorationExpiresOnlyActualElapsedDebtAtExactBoundaries() {
        val spacing = AdaptiveProbeBudget()
        assertTrue(spacing.start(10_000, routine = false))
        assertFalse(spacing.canStart(12_000, routine = false))
        val restored = AdaptiveProbeBudget.restore(spacing.checkpoint(), 14_000, sameBoot = true)
        assertEquals(14_000L, restored.checkpoint().observedAtMs)
        assertEquals(listOf(Entry(4_000, false)), restored.checkpoint().entries)
        assertFalse(restored.start(14_999, routine = false))
        assertTrue(restored.start(15_000, routine = false))
        val minute = AdaptiveProbeBudget()
        repeat(8) { assertTrue(minute.start(it * 5_000L, routine = false)) }
        val limited = AdaptiveProbeBudget.restore(minute.checkpoint(), 59_999, sameBoot = true)
        assertFalse(limited.start(59_999, routine = false))
        assertTrue(limited.start(60_000, routine = false))
        val hour = AdaptiveProbeBudget()
        assertTrue(hour.start(0, routine = false))
        assertTrue(hour.start(5_000, routine = true))
        val saved = hour.checkpoint()
        assertEquals(2, AdaptiveProbeBudget.restore(saved, 3_599_999, true).checkpoint().entries.size)
        assertEquals(listOf(Entry(3_595_000, true)), AdaptiveProbeBudget.restore(saved, 3_600_000, true).checkpoint().entries)
        assertTrue(AdaptiveProbeBudget.restore(saved, 3_605_000, true).checkpoint().entries.isEmpty())
        assertEquals(saved, hour.checkpoint())
    }

    @Test fun newBootRetainsSpacingMinuteHourAndRoutineRecoveryReserves() {
        val spacing = AdaptiveProbeBudget()
        assertTrue(spacing.start(100_000, routine = true))
        assertFalse(spacing.canStart(103_000, routine = false))
        val saved = spacing.checkpoint()
        val rebooted = AdaptiveProbeBudget.restore(saved, 0, sameBoot = false)
        assertEquals(0L, rebooted.checkpoint().observedAtMs)
        assertEquals(saved.entries, rebooted.checkpoint().entries)
        assertFalse(rebooted.start(1_999, routine = false))
        assertTrue(rebooted.start(2_000, routine = false))
        val minute = AdaptiveProbeBudget()
        repeat(6) { assertTrue(minute.start(it * 5_000L, routine = true)) }
        val reserves = AdaptiveProbeBudget.restore(minute.checkpoint(), 0, sameBoot = false)
        assertFalse(reserves.start(4_999, routine = false))
        assertTrue(reserves.start(5_000, routine = false))
        assertTrue(reserves.start(10_000, routine = false))
        assertFalse(reserves.start(34_999, routine = true))
        assertTrue(reserves.start(35_000, routine = true))
        val routineHour = AdaptiveProbeBudget()
        repeat(16) { minuteIndex ->
            repeat(6) { slot -> assertTrue(routineHour.start(minuteIndex * 60_000L + slot * 5_000L, routine = true)) }
        }
        val routineDebt = AdaptiveProbeBudget.restore(routineHour.checkpoint(), 0, sameBoot = false)
        assertTrue(routineDebt.start(5_000, routine = false))
        assertFalse(routineDebt.start(60_000, routine = true))
        assertTrue(routineDebt.start(60_000, routine = false))
        val full = fullHour().checkpoint()
        assertEquals(128, full.entries.size)
        assertEquals(96, full.entries.count { it.routine })
        val hourDebt = AdaptiveProbeBudget.restore(full, 0, sameBoot = false)
        assertFalse(hourDebt.start(2_664_999, routine = false))
        assertTrue(hourDebt.start(2_665_000, routine = true))
        assertFalse(hourDebt.start(2_669_999, routine = false))
        assertTrue(hourDebt.start(2_670_000, routine = false))
        assertFalse(hourDebt.invalidated())
    }

    @Test fun onlyANewValidBootClearsClockSealWithoutClearingSavedStarts() {
        val budget = AdaptiveProbeBudget()
        assertTrue(budget.start(10_000, routine = true))
        assertFalse(budget.canStart(9_999, routine = false))
        val sealed = budget.checkpoint()
        assertTrue(sealed.clockSealed)
        assertEquals(10_000L, sealed.observedAtMs)
        val same = AdaptiveProbeBudget.restore(sealed, 20_000, sameBoot = true)
        assertTrue(same.invalidated())
        assertEquals(listOf(Entry(10_000, true)), same.checkpoint().entries)
        assertFalse(same.start(3_620_000, routine = false))
        assertEquals(20_000L, same.checkpoint().observedAtMs)
        val newBoot = AdaptiveProbeBudget.restore(sealed, 0, sameBoot = false)
        assertFalse(newBoot.invalidated())
        assertEquals(sealed.entries, newBoot.checkpoint().entries)
        assertFalse(newBoot.start(0, routine = false))
        assertTrue(newBoot.start(5_000, routine = false))
        val plain = Checkpoint(10_000, false, listOf(Entry(0, true)))
        val backwards = AdaptiveProbeBudget.restore(plain, 9_999, sameBoot = true)
        assertTrue(backwards.invalidated())
        assertEquals(Checkpoint(10_000, true, plain.entries), backwards.checkpoint())
        for (now in listOf(-1L, Decision.MAX_TIME + 1, Long.MIN_VALUE, Long.MAX_VALUE)) {
            for (sameBoot in listOf(false, true)) {
                val invalid = AdaptiveProbeBudget.restore(plain, now, sameBoot)
                assertTrue(invalid.invalidated())
                assertEquals(Checkpoint(plain.observedAtMs, true, plain.entries), invalid.checkpoint())
                assertFalse(invalid.start(Decision.MAX_TIME, routine = false))
            }
        }
        val upper = AdaptiveProbeBudget.restore(Checkpoint(Decision.MAX_TIME, false, emptyList()), Decision.MAX_TIME, true)
        assertTrue(upper.start(Decision.MAX_TIME, routine = false))
        assertFalse(upper.start(Decision.MAX_TIME + 1, routine = false))
    }

    @Test fun malformedCheckpointsRejectImpossibleCountsAgesOrderingAndTime() {
        for (observed in listOf(-1L, Decision.MAX_TIME + 1, Long.MIN_VALUE, Long.MAX_VALUE)) {
            assertThrows(IllegalArgumentException::class.java) { Checkpoint(observed, false, emptyList()) }
        }
        for (age in listOf(-1_001L, 3_600_000L, Long.MIN_VALUE, Long.MAX_VALUE)) {
            assertThrows(IllegalArgumentException::class.java) { Checkpoint(0, false, listOf(Entry(age, false))) }
        }
        for (entries in listOf(
            List(129) { Entry(0, false) },
            listOf(Entry(0, false), Entry(5_000, false)),
            listOf(Entry(0, false), Entry(0, false)),
            listOf(Entry(5_000, false), Entry(1, false)),
            List(9) { Entry((8 - it) * 5_000L, false) },
            List(7) { Entry((6 - it) * 5_000L, true) },
            List(97) { Entry((96 - it) * 30_000L, true) }
        )) assertThrows(IllegalArgumentException::class.java) { Checkpoint(0, false, entries) }
        assertThrows(IllegalArgumentException::class.java) { Checkpoint(Decision.MAX_TIME, false, listOf(Entry(-1, false))) }
        assertEquals(listOf(Entry(-1_000, false)), Checkpoint(0, false, listOf(Entry(-1_000, false))).entries)
        assertEquals(2, Checkpoint(0, true, listOf(Entry(3_599_999, true), Entry(0, false))).entries.size)
        assertEquals(7, Checkpoint(0, false, List(7) { Entry((6 - it) * 5_000L, false) }).entries.size)
        assertEquals(128, Checkpoint(0, false, fullHour().checkpoint().entries).entries.size)
    }

    @Test fun sequentialProcessAndRebootCheckpointsNeverReplenishAdmissionDebt() {
        val original = fullHour().checkpoint()
        val denied = AdaptiveProbeBudget.restore(original, original.observedAtMs, sameBoot = true)
        assertFalse(denied.reserve(original.observedAtMs + 1_000, routine = false, latestStartMs = original.observedAtMs + 2_000))
        val highWater = denied.checkpoint()
        assertEquals(original.observedAtMs + 1_000, highWater.observedAtMs)
        assertEquals(original.entries.map { Entry(it.ageMs + 1_000, it.routine) }, highWater.entries)
        assertFalse(highWater.clockSealed)
        assertFalse(denied.canStart(highWater.observedAtMs - 1, routine = false))
        assertEquals(Checkpoint(highWater.observedAtMs, true, highWater.entries), denied.checkpoint())
        var saved = original
        repeat(12) {
            val sameBoot = AdaptiveProbeBudget.restore(saved, saved.observedAtMs, sameBoot = true)
            assertFalse(sameBoot.start(saved.observedAtMs, routine = false))
            assertEquals(saved, sameBoot.checkpoint())
            val newBoot = AdaptiveProbeBudget.restore(sameBoot.checkpoint(), 0, sameBoot = false)
            assertFalse(newBoot.start(0, routine = false))
            saved = newBoot.checkpoint()
            assertEquals(original.entries, saved.entries)
            assertEquals(128, saved.entries.size)
            assertEquals(96, saved.entries.count { it.routine })
        }
        val running = AdaptiveProbeBudget()
        assertTrue(running.start(0, routine = true))
        val first = running.checkpoint()
        val secondOwner = AdaptiveProbeBudget.restore(first, 5_000, sameBoot = true)
        assertTrue(secondOwner.start(5_000, routine = false))
        val second = secondOwner.checkpoint()
        repeat(20) {
            val owner = AdaptiveProbeBudget.restore(second, 5_000, sameBoot = true)
            assertFalse(owner.start(5_000, routine = false))
            assertEquals(second, owner.checkpoint())
        }
        assertEquals(listOf(Entry(5_000, true), Entry(0, false)), second.entries)
        assertEquals(listOf(Entry(0, true)), first.entries)
    }

    @Test fun reservedLatestHandoffPreservesActualSpacingAcrossDelayProcessAndBoot() {
        assertEquals(1_000L, AdaptiveProbeBudget.MAX_HANDOFF_MS)
        val budget = AdaptiveProbeBudget()
        assertTrue(budget.reserve(10_000, routine = false, latestStartMs = 11_000))
        val saved = budget.checkpoint()
        assertEquals(10_000L, saved.observedAtMs)
        assertEquals(listOf(Entry(-1_000, false)), saved.entries)
        assertFalse(budget.start(15_000, routine = false))
        assertFalse(budget.start(15_999, routine = false))
        assertTrue(budget.reserve(16_000, routine = false, latestStartMs = 17_000))
        assertEquals(listOf(Entry(5_000, false), Entry(-1_000, false)), budget.checkpoint().entries)
        val process = AdaptiveProbeBudget.restore(saved, 10_500, sameBoot = true)
        assertEquals(listOf(Entry(-500, false)), process.checkpoint().entries)
        assertFalse(process.start(15_999, routine = false))
        assertTrue(process.start(16_000, routine = false))
        val reboot = AdaptiveProbeBudget.restore(saved, 0, sameBoot = false)
        assertEquals(saved.entries, reboot.checkpoint().entries)
        assertFalse(reboot.start(5_999, routine = false))
        assertTrue(reboot.start(6_000, routine = false))
        val sealedFuture = AdaptiveProbeBudget.restore(saved, 9_999, sameBoot = true)
        assertTrue(sealedFuture.invalidated())
        assertEquals(saved.entries, sealedFuture.checkpoint().entries)
        val nextBoot = AdaptiveProbeBudget.restore(sealedFuture.checkpoint(), 0, sameBoot = false)
        assertFalse(nextBoot.invalidated())
        assertEquals(saved.entries, nextBoot.checkpoint().entries)
        assertFalse(nextBoot.start(5_999, routine = false))
        assertTrue(nextBoot.start(6_000, routine = false))
        val impossibleRebase = AdaptiveProbeBudget.restore(saved, Decision.MAX_TIME, sameBoot = false)
        assertTrue(impossibleRebase.invalidated())
        assertEquals(Checkpoint(saved.observedAtMs, true, saved.entries), impossibleRebase.checkpoint())
        for (latest in listOf(9_999L, 11_001L, Decision.MAX_TIME + 1, Long.MIN_VALUE, Long.MAX_VALUE)) {
            val rejected = AdaptiveProbeBudget()
            assertFalse(rejected.reserve(10_000, routine = false, latestStartMs = latest))
            assertEquals(Checkpoint(10_000, false, emptyList()), rejected.checkpoint())
        }
        val late = AdaptiveProbeBudget()
        assertFalse(late.reserve(11_001, routine = false, latestStartMs = 11_000))
        assertTrue(late.checkpoint().entries.isEmpty())
        val old = AdaptiveProbeBudget()
        val immediate = AdaptiveProbeBudget()
        assertTrue(old.start(10_000, routine = true))
        assertTrue(immediate.reserve(10_000, routine = true, latestStartMs = 10_000))
        assertEquals(old.checkpoint(), immediate.checkpoint())
        assertTrue(old.start(15_000, routine = false))
        val reservedMinute = AdaptiveProbeBudget()
        repeat(6) { index -> assertTrue(reservedMinute.reserve(index * 6_000L, routine = true, latestStartMs = index * 6_000L + 1_000)) }
        assertFalse(reservedMinute.reserve(36_000, routine = true, latestStartMs = 37_000))
        assertTrue(reservedMinute.reserve(36_000, routine = false, latestStartMs = 37_000))
        assertTrue(reservedMinute.reserve(42_000, routine = false, latestStartMs = 43_000))
        assertFalse(reservedMinute.reserve(48_000, routine = false, latestStartMs = 49_000))
        assertEquals(8, reservedMinute.checkpoint().entries.size)
        assertEquals(6, reservedMinute.checkpoint().entries.count { it.routine })
        val maximum = AdaptiveProbeBudget()
        assertTrue(maximum.reserve(Decision.MAX_TIME - 500, routine = true, latestStartMs = Decision.MAX_TIME))
        assertEquals(listOf(Entry(-500, true)), maximum.checkpoint().entries)
        assertFalse(maximum.reserve(Decision.MAX_TIME, routine = false, latestStartMs = Decision.MAX_TIME))
    }
}
