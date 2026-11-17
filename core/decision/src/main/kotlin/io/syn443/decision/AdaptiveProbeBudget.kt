package io.syn443.decision

/** Local start admission only. This class grants no route/proxy authority and
 * does not coordinate SDK work. Keep one instance for the actual owner; force,
 * policy and network transitions must not replace it to erase admission debt. */
class AdaptiveProbeBudget {
    /** Oldest-to-newest starts are represented by decreasing ages. No identity
     * or route evidence belongs in an admission checkpoint. */
    data class Entry(val ageMs: Long, val routine: Boolean) {
        override fun toString() = "AdaptiveProbeBudget.Entry([redacted])"
    }

    /** An owned value, not a live view of the budget or the caller's list.
     * Validation admits only histories possible under the existing hard limits. */
    class Checkpoint(val observedAtMs: Long, val clockSealed: Boolean, entries: List<Entry>) {
        private val ownedEntries: List<Entry>
        val entries: List<Entry> get() = ownedEntries

        init {
            require(observedAtMs in 0..Decision.MAX_TIME)
            val count = entries.size
            require(count in 0..128)
            val copied = ArrayList<Entry>(count)
            for (index in 0 until count) {
                val entry = requireNotNull(entries[index])
                require(entry.ageMs in -MAX_HANDOFF_MS..3_599_999L)
                require(observedAtMs - entry.ageMs <= Decision.MAX_TIME)
                if (copied.isNotEmpty()) require(copied.last().ageMs - entry.ageMs >= 5_000)
                copied.add(Entry(entry.ageMs, entry.routine))
            }
            require(copied.count { it.routine } <= 96)
            for (index in copied.indices) {
                val at = copied[index].ageMs
                var minute = 0
                var routineMinute = 0
                for (previous in 0..index) if (copied[previous].ageMs - at < 60_000) {
                    minute++
                    if (copied[previous].routine) routineMinute++
                }
                require(minute <= 8 && routineMinute <= 6)
            }
            ownedEntries = java.util.Collections.unmodifiableList(copied)
        }

        override fun equals(other: Any?): Boolean = other is Checkpoint && observedAtMs == other.observedAtMs &&
            clockSealed == other.clockSealed && ownedEntries == other.ownedEntries
        override fun hashCode(): Int = 31 * (31 * observedAtMs.hashCode() + clockSealed.hashCode()) + ownedEntries.hashCode()
        override fun toString() = "AdaptiveProbeBudget.Checkpoint([redacted])"
    }

    private data class Start(val atMs: Long, val routine: Boolean)
    private val starts = java.util.ArrayDeque<Start>(128)
    private var lastNow = 0L
    private var invalid = false

    private fun observe(nowMs: Long): Boolean {
        // Reject before trimming. Neither an invalid clock nor a later valid
        // timestamp can erase admission history and reopen a sealed owner.
        if (invalid) return false
        if (nowMs !in lastNow..Decision.MAX_TIME) {
            invalid = true
            return false
        }
        lastNow = nowMs
        while (starts.isNotEmpty() && nowMs - starts.first.atMs >= 3_600_000) starts.removeFirst()
        return true
    }

    /** May expire old records, but never registers work or spends a quantum. */
    @Synchronized
    fun canStart(nowMs: Long, routine: Boolean): Boolean {
        if (!observe(nowMs)) return false
        if (starts.size >= 128 || starts.lastOrNull()?.let { nowMs - it.atMs < 5_000 } == true) return false
        if (starts.count { nowMs - it.atMs < 60_000 } >= 8) return false
        if (routine && (starts.count { it.routine } >= 96 || starts.count { it.routine && nowMs - it.atMs < 60_000 } >= 6)) return false
        return true
    }

    /** Record exactly one actual admitted start; failed admission records none. */
    @Synchronized
    fun start(nowMs: Long, routine: Boolean): Boolean {
        if (!canStart(nowMs, routine)) return false
        starts.addLast(Start(nowMs, routine))
        return true
    }

    /** Prepay at the latest permitted dispatch, not the beginning of storage.
     * The caller must still fence dispatch against this original handoff bound.
     * Delayed or cancelled work burns its quantum; it never compresses spacing. */
    @Synchronized
    fun reserve(nowMs: Long, routine: Boolean, latestStartMs: Long): Boolean {
        if (!canStart(nowMs, routine)) return false
        if (latestStartMs < nowMs || latestStartMs > Decision.MAX_TIME || latestStartMs - nowMs > MAX_HANDOFF_MS) return false
        starts.addLast(Start(latestStartMs, routine))
        return true
    }

    @Synchronized
    fun invalidated(): Boolean = invalid

    /** Export at the last accepted observation, without observing a caller's
     * clock, spending a start, expiring debt or exposing the mutable deque. */
    @Synchronized
    fun checkpoint(): Checkpoint = Checkpoint(lastNow, invalid,
        starts.map { Entry(lastNow - it.atMs, it.routine) })

    /** Shared maintenance pacing, independent of route evidence or authority. */
    fun routineCadence(groupCount: Int): Long {
        require(groupCount in 1..16)
        return maxOf(60_000L, (groupCount * 3_600_000L + 95) / 96)
    }

    override fun toString() = "AdaptiveProbeBudget([redacted])"

    companion object {
        const val MAX_HANDOFF_MS = 1_000L

        /** The Android owner supplies actual BOOTTIME and independently compares
         * BOOT_COUNT. Wall time and policy/context changes cannot forgive debt.
         * A new boot rebases saved ages, including starts before its time zero. */
        fun restore(checkpoint: Checkpoint, nowMs: Long, sameBoot: Boolean): AdaptiveProbeBudget {
            val currentTimeValid = nowMs in 0..Decision.MAX_TIME
            val backwards = sameBoot && nowMs < checkpoint.observedAtMs
            val invalidRebase = !sameBoot && currentTimeValid && checkpoint.entries.any {
                it.ageMs < 0 && nowMs > Decision.MAX_TIME + it.ageMs
            }
            val anchor = if (currentTimeValid && !backwards && !invalidRebase) nowMs else checkpoint.observedAtMs
            val elapsed = if (sameBoot && currentTimeValid && !backwards) nowMs - checkpoint.observedAtMs else 0
            return AdaptiveProbeBudget().apply {
                lastNow = anchor
                invalid = !currentTimeValid || backwards || invalidRebase || sameBoot && checkpoint.clockSealed
                for (entry in checkpoint.entries) {
                    // Both operands are bounded by MAX_TIME and one hour, far
                    // below Long overflow. An expired record is never rebased.
                    val age = entry.ageMs + elapsed
                    if (age < 3_600_000) starts.addLast(Start(anchor - age, entry.routine))
                }
            }
        }
    }
}
