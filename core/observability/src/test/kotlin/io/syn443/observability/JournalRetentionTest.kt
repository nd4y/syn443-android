package io.syn443.observability

import org.junit.Assert.*
import org.junit.Test

class JournalRetentionTest {
    private fun clock(elapsed: Long, boot: Int = 4, wall: Long = 1_000 + elapsed) = EventClock(boot, wall, elapsed)
    private fun segment(id: Long, elapsed: Long = id, boot: Int = 4, bytes: Long = 40) =
        JournalSegment(id, bytes, clock(elapsed, boot), clock(elapsed, boot))
    private fun plan(previous: EventClock?, now: EventClock, segments: List<JournalSegment>, reserve: Long = JournalRetention.MAX_FRAME_BYTES) =
        requireNotNull(JournalRetention.plan(previous, now, segments, reserve))
    private fun rejected(block: () -> Unit) {
        try { block(); fail("Invalid segment metadata accepted") } catch (_: IllegalArgumentException) { }
    }

    @Test fun sameBootExpiryUsesElapsedAndHonoursExactSevenDayBoundary() {
        val first = clock(100)
        val record = JournalSegment(1, 40, first, clock(200))
        val before = plan(record.committed, clock(first.elapsedMs + JournalRetention.MAX_AGE_MS - 1), listOf(record))
        assertEquals(JournalClockState.CURRENT_EPOCH, before.clockState)
        assertEquals(listOf(1L), before.exportable)
        assertTrue(before.expired.isEmpty())
        assertTrue(before.appendAllowed)
        val exact = plan(record.committed, clock(first.elapsedMs + JournalRetention.MAX_AGE_MS), listOf(record))
        assertTrue(exact.expired.isEmpty())
        assertEquals(listOf(1L), exact.retained)
        assertEquals(record.bytes, exact.retainedBytes)
        assertTrue(exact.exportable.isEmpty())
        assertTrue(exact.reset.isEmpty())
        assertTrue(exact.appendAllowed)
        assertTrue(exact.pruningIncomplete)
        // A failed pre-write attempt leaves the original inventory/floor intact.
        val afterFailedWrite = listOf(record).filter { it.id in exact.retained }
        assertEquals(record, afterFailedWrite.single())
        val rollback = plan(afterFailedWrite.single().committed,
            clock(first.elapsedMs + JournalRetention.MAX_AGE_MS + 1, wall = record.committed.wallMs - 1), afterFailedWrite)
        assertEquals(JournalClockState.CLOCK_UNCERTAIN, rollback.clockState)
        assertFalse(rollback.appendAllowed)
        assertTrue(rollback.exportable.isEmpty())
        assertEquals(listOf(1L), rollback.retained)
        val newer = segment(2, first.elapsedMs + JournalRetention.MAX_AGE_MS + 1)
        val committed = plan(newer.committed, newer.committed, listOf(record, newer))
        assertEquals(listOf(1L), committed.expired)
        assertEquals(listOf(2L), committed.retained)
        assertEquals(listOf(2L), committed.exportable)
        assertFalse(committed.pruningIncomplete)
        val wallJump = plan(record.committed, clock(201, wall = StructuredEvent.MAX_SAFE), listOf(record))
        assertEquals(listOf(1L), wallJump.exportable)
        val distant = JournalSegment(2, 1, EventClock(4, 0, 0), EventClock(4, 0, 0))
        val oldest = plan(distant.committed, EventClock(4, StructuredEvent.MAX_SAFE, StructuredEvent.MAX_SAFE), listOf(distant))
        assertEquals(listOf(2L), oldest.retained)
        assertTrue(oldest.expired.isEmpty())
        assertTrue(oldest.exportable.isEmpty())
    }

    @Test fun rebootNeverComparesElapsedAcrossDifferentBootsWithNewEpoch() {
        val old = segment(1, JournalRetention.MAX_AGE_MS * 2)
        val restarted = plan(old.committed, EventClock(5, 0, 0), listOf(old))
        assertEquals(JournalClockState.NEW_EPOCH, restarted.clockState)
        assertEquals(listOf(1L), restarted.reset)
        assertTrue(restarted.expired.isEmpty())
        assertTrue(restarted.exportable.isEmpty())
        assertTrue(restarted.appendAllowed)
        val fresh = segment(2, 2, boot = 5)
        val current = plan(fresh.committed, clock(3, boot = 5), listOf(old, fresh))
        assertEquals(JournalClockState.CURRENT_EPOCH, current.clockState)
        assertEquals(listOf(1L), current.reset)
        assertEquals(listOf(2L), current.exportable)
        val first = plan(null, clock(0, boot = 0), emptyList())
        assertEquals(JournalClockState.NEW_EPOCH, first.clockState)
        assertTrue(first.appendAllowed)
        assertTrue(first.reset.isEmpty())
    }

    @Test fun rollbackFutureAndMissingFloorPreserveWitnessesAndDenyReadOrAppend() {
        val record = segment(1, 100)
        val sources = listOf(record)
        val cases = listOf(
            record.committed to clock(99, wall = record.committed.wallMs),
            record.committed to clock(101, wall = record.committed.wallMs - 1),
            record.committed to clock(101, boot = 3),
            null to clock(101),
            clock(99) to clock(101),
            clock(99, wall = record.committed.wallMs) to clock(101),
            clock(100, wall = record.committed.wallMs - 1) to clock(101),
        )
        for ((previous, now) in cases) {
            val result = plan(previous, now, sources)
            assertEquals(JournalClockState.CLOCK_UNCERTAIN, result.clockState)
            assertEquals(listOf(1L), result.retained)
            assertEquals(40L, result.retainedBytes)
            assertFalse(result.appendAllowed)
            assertTrue(result.exportable.isEmpty())
            assertTrue(result.expired.isEmpty())
            assertTrue(result.reset.isEmpty())
            assertTrue(result.evicted.isEmpty())
        }
        val alreadyNew = segment(2, 1, boot = 5)
        val wrongAnchor = plan(record.committed, clock(2, boot = 5), listOf(record, alreadyNew))
        assertEquals(JournalClockState.CLOCK_UNCERTAIN, wrongAnchor.clockState)
        assertEquals(listOf(1L, 2L), wrongAnchor.retained)
        assertTrue(wrongAnchor.reset.isEmpty())
        assertEquals(listOf(1L), plan(record.committed, clock(101), sources).exportable)
        assertEquals(record.committed, sources.single().committed)
    }

    @Test fun capacityEvictsOldestOwnedSegmentsIncludingPendingWholeFrameAndSlot() {
        val full = (1..JournalRetention.MAX_SEALED_SEGMENTS).map { segment(it.toLong(), bytes = JournalRetention.MAX_FRAME_BYTES) }
        val previous = full.last().committed
        val now = clock(2_000)
        val read = plan(previous, now, full, 0)
        assertEquals(1023, read.retained.size)
        assertTrue(read.evicted.isEmpty())
        assertFalse(read.appendAllowed)
        val writing = plan(previous, now, full)
        assertEquals(listOf(1L), writing.evicted)
        assertEquals(1022, writing.retained.size)
        assertTrue(writing.appendAllowed)
        assertTrue(writing.retainedBytes + writing.reservedBytes <= JournalRetention.MAX_BYTES)
        assertEquals(JournalRetention.MAX_FRAME_BYTES, writing.reservedBytes)
        assertEquals(1023, full.size)
        val anchored = (1..1022).map { segment(it.toLong(), JournalRetention.MAX_AGE_MS + it, bytes = JournalRetention.MAX_FRAME_BYTES) } +
            JournalSegment(1023, JournalRetention.MAX_FRAME_BYTES, clock(0), clock(JournalRetention.MAX_AGE_MS + 1023))
        val protectedPlan = plan(anchored.last().committed, clock(JournalRetention.MAX_AGE_MS + 2_000), anchored)
        assertEquals(listOf(1L), protectedPlan.evicted)
        assertTrue(1023L in protectedPlan.retained)
        assertFalse(1023L in protectedPlan.exportable)
        assertTrue(protectedPlan.expired.isEmpty())
        assertTrue(protectedPlan.pruningIncomplete)
        assertEquals(1022 * JournalRetention.MAX_FRAME_BYTES, protectedPlan.retainedBytes)
        assertTrue(protectedPlan.appendAllowed)
        val newEpoch = plan(previous, clock(0, boot = 5), full)
        assertEquals((1L..8L).toList(), newEpoch.reset)
        assertTrue(newEpoch.expired.isEmpty())
        assertTrue(newEpoch.exportable.isEmpty())
        assertTrue(newEpoch.appendAllowed)
        assertTrue(newEpoch.pruningIncomplete)
        val mixed = (1L..4L).map { segment(it, boot = 3) } + (5L..12L).map { segment(it) }
        val expired = plan(mixed.last().committed, clock(JournalRetention.MAX_AGE_MS + 20), mixed)
        assertEquals((1L..4L).toList(), expired.reset)
        assertEquals((5L..8L).toList(), expired.expired)
        assertEquals(8, expired.reset.size + expired.expired.size + expired.evicted.size)
        assertTrue(expired.pruningIncomplete)
        assertTrue(expired.exportable.isEmpty())
        val remaining = mixed.filter { it.id in expired.retained }
        val next = plan(mixed.last().committed, clock(JournalRetention.MAX_AGE_MS + 20), remaining)
        assertEquals((9L..11L).toList(), next.expired)
        assertTrue(next.pruningIncomplete)
        assertEquals(listOf(12L), next.retained)
        assertTrue(next.exportable.isEmpty())
        val fresh = segment(13, JournalRetention.MAX_AGE_MS + 21)
        val afterCommit = plan(fresh.committed, fresh.committed, listOf(mixed.last(), fresh))
        assertEquals(listOf(12L), afterCommit.expired)
        assertEquals(listOf(13L), afterCommit.retained)
        assertFalse(afterCommit.pruningIncomplete)
    }

    @Test fun invalidDuplicateUnorderedAndOverflowMetadataProducesNoDeletionPlan() {
        val first = segment(1)
        val second = segment(2)
        val previous = second.committed
        val now = clock(3)
        for (rows in listOf(listOf(first, first), listOf(second, first),
            listOf(first, segment(2, 0)), listOf(segment(1, boot = 5), segment(2, boot = 4)),
            listOf(first, JournalSegment(2, 40, EventClock(4, 0, 2), EventClock(4, 1_000, 2))))) {
            assertNull(JournalRetention.plan(previous, now, rows, 0))
        }
        val tooMany = (1..1024).map { segment(it.toLong()) }
        assertNull(JournalRetention.plan(tooMany.last().committed, clock(2_000), tooMany, 0))
        for (reserve in listOf(-1L, 1L, 65_535L, 65_537L, Long.MAX_VALUE)) {
            assertNull(JournalRetention.plan(previous, now, listOf(first, second), reserve))
        }
        rejected { first.copy(id = 0) }
        rejected { first.copy(id = StructuredEvent.MAX_SAFE + 1) }
        rejected { first.copy(bytes = 0) }
        rejected { first.copy(bytes = JournalRetention.MAX_FRAME_BYTES + 1) }
        rejected { first.copy(bytes = Long.MAX_VALUE) }
        rejected { first.copy(committed = clock(2, boot = 5)) }
        rejected { first.copy(first = clock(2)) }
        rejected { first.copy(first = clock(0, wall = first.committed.wallMs + 1)) }
        assertEquals(40L, first.bytes)
        assertEquals(1L, first.id)
    }

    @Test fun retentionPlansAreOwnedAndRepeatedPlanningCannotExtendOriginalAge() {
        val record = segment(1, 100)
        val input = mutableListOf(record)
        val initial = plan(record.committed, clock(101), input)
        input.clear()
        assertEquals(listOf(1L), initial.retained)
        assertEquals(listOf(1L), initial.exportable)
        for (view in listOf(initial.retained, initial.expired, initial.reset, initial.evicted, initial.exportable)) {
            try { (view as MutableList<Long>).add(99); fail("Mutable retention result") } catch (_: UnsupportedOperationException) { }
        }
        assertEquals("JournalRetentionPlan([redacted])", initial.toString())
        assertEquals("JournalSegment([redacted])", record.toString())
        val before = plan(record.committed, clock(100 + JournalRetention.MAX_AGE_MS - 1), listOf(record))
        assertEquals(listOf(1L), before.exportable)
        val exact = plan(record.committed, clock(100 + JournalRetention.MAX_AGE_MS), listOf(record))
        assertEquals(listOf(1L), exact.retained)
        assertTrue(exact.expired.isEmpty())
        assertTrue(exact.exportable.isEmpty())
        assertTrue(exact.pruningIncomplete)
        assertEquals(record.first, EventClock(4, 1_100, 100))
        val again = plan(record.committed, clock(100 + JournalRetention.MAX_AGE_MS + 1), listOf(record))
        assertEquals(exact.expired, again.expired)
        assertEquals(exact.retained, again.retained)
        assertTrue(again.exportable.isEmpty())
        assertEquals(listOf(1L), initial.exportable)
        for (boot in 5..7) {
            val reboot = plan(record.committed, clock(0, boot = boot), listOf(record))
            assertEquals(listOf(1L), reboot.reset)
            assertTrue(reboot.exportable.isEmpty())
        }
    }
}
