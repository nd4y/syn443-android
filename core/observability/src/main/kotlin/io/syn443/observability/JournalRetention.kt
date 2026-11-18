package io.syn443.observability

import java.util.Collections

/** The Android owner authenticates both clocks and ownership before admission. */
data class JournalSegment(val id: Long, val bytes: Long, val first: EventClock, val committed: EventClock) {
    init {
        require(id in 1..StructuredEvent.MAX_SAFE && bytes in 1..JournalRetention.MAX_FRAME_BYTES &&
            first.boot == committed.boot && first.elapsedMs <= committed.elapsedMs && first.wallMs <= committed.wallMs) { "invalid_journal_segment" }
    }
    override fun toString() = "JournalSegment([redacted])"
}

enum class JournalClockState { CURRENT_EPOCH, NEW_EPOCH, CLOCK_UNCERTAIN }

/** Recommendations for authenticated IDs only, not file deletion authority. */
class JournalRetentionPlan internal constructor(
    val clockState: JournalClockState,
    retained: List<Long>, expired: List<Long>, reset: List<Long>, evicted: List<Long>, exportable: List<Long>,
    val retainedBytes: Long, val reservedBytes: Long, val appendAllowed: Boolean, val pruningIncomplete: Boolean,
) {
    val retained: List<Long> = owned(retained)
    val expired: List<Long> = owned(expired)
    val reset: List<Long> = owned(reset)
    val evicted: List<Long> = owned(evicted)
    val exportable: List<Long> = owned(exportable)
    private fun owned(values: List<Long>): List<Long> = Collections.unmodifiableList(ArrayList(values))
    override fun toString() = "JournalRetentionPlan([redacted])"
}

/** Pure bounded planning. No clock reads, files, timers, mutation or reset API. */
object JournalRetention {
    const val MAX_FRAME_BYTES = 65_536L
    const val MAX_SEALED_SEGMENTS = 1023
    const val MAX_BYTES = 67_108_864L
    const val MAX_AGE_MS = 604_800_000L
    const val MAX_PRUNE = 8

    fun plan(previousCommitted: EventClock?, now: EventClock, segments: List<JournalSegment>, reservedWriteBytes: Long): JournalRetentionPlan? {
        if (segments.size > MAX_SEALED_SEGMENTS || reservedWriteBytes != 0L && reservedWriteBytes != MAX_FRAME_BYTES) return null
        val owned = segments.toList()
        for (index in owned.indices) {
            if (index == 0) continue
            val previous = owned[index - 1]
            val current = owned[index]
            if (current.id <= previous.id || current.committed.boot < previous.committed.boot ||
                current.committed.boot == previous.committed.boot &&
                (current.committed.elapsedMs < previous.committed.elapsedMs || current.committed.wallMs < previous.committed.wallMs)) return null
        }
        val state = clockState(previousCommitted, now, owned)
        if (state == JournalClockState.CLOCK_UNCERTAIN) {
            // Keep every durable floor witness. Never turn missing/rolled-back
            // observation authority into permission to wipe or restamp history.
            return JournalRetentionPlan(state, owned.map { it.id }, emptyList(), emptyList(), emptyList(), emptyList(),
                owned.sumOf { it.bytes }, reservedWriteBytes, false, false)
        }
        // Pre-write retirement must leave a durable current-boot high-water
        // witness. A failed write cannot turn restart into an empty first epoch.
        val protectedFloor = if (state == JournalClockState.CURRENT_EPOCH)
            owned.lastOrNull { it.committed.boot == now.boot }?.id else null
        val expired = ArrayList<Long>()
        val reset = ArrayList<Long>()
        val evicted = ArrayList<Long>()
        val retained = ArrayList<JournalSegment>(owned.size)
        var budget = MAX_PRUNE
        var incomplete = false
        for (segment in owned) {
            val oldEpoch = segment.committed.boot != now.boot
            val tooOld = !oldEpoch && now.elapsedMs - segment.first.elapsedMs >= MAX_AGE_MS
            if (oldEpoch || tooOld) {
                if (segment.id != protectedFloor && budget > 0) {
                    if (oldEpoch) reset += segment.id else expired += segment.id
                    budget--
                    continue
                }
                incomplete = true
            }
            retained += segment
        }
        var retainedBytes = retained.sumOf { it.bytes }
        val slots = if (reservedWriteBytes == 0L) 0 else 1
        fun fits() = retained.size + slots <= MAX_SEALED_SEGMENTS && retainedBytes <= MAX_BYTES - reservedWriteBytes
        while (!fits() && budget > 0 && retained.isNotEmpty()) {
            val index = retained.indexOfFirst { it.id != protectedFloor }
            if (index < 0) break
            val victim = retained.removeAt(index)
            retainedBytes -= victim.bytes
            evicted += victim.id
            budget--
        }
        if (!fits()) incomplete = true
        val exportable = retained.filter { it.committed.boot == now.boot && now.elapsedMs - it.first.elapsedMs < MAX_AGE_MS }.map { it.id }
        return JournalRetentionPlan(state, retained.map { it.id }, expired, reset, evicted, exportable,
            retainedBytes, reservedWriteBytes, reservedWriteBytes == MAX_FRAME_BYTES && fits(), incomplete)
    }

    private fun clockState(previous: EventClock?, now: EventClock, segments: List<JournalSegment>): JournalClockState {
        if (previous == null) return if (segments.isEmpty()) JournalClockState.NEW_EPOCH else JournalClockState.CLOCK_UNCERTAIN
        if (now.boot < previous.boot || segments.any { it.committed.boot > previous.boot ||
                it.committed.boot == previous.boot && (it.committed.elapsedMs > previous.elapsedMs || it.committed.wallMs > previous.wallMs) }) {
            return JournalClockState.CLOCK_UNCERTAIN
        }
        if (now.boot != previous.boot) return JournalClockState.NEW_EPOCH
        if (now.elapsedMs < previous.elapsedMs || now.wallMs < previous.wallMs) return JournalClockState.CLOCK_UNCERTAIN
        return JournalClockState.CURRENT_EPOCH
    }
}
