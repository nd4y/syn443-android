package io.syn443.decision

/** Local start admission only. This class grants no route/proxy authority and
 * does not coordinate SDK work. Keep one instance for the actual owner; force,
 * policy and network transitions must not replace it to erase admission debt. */
class AdaptiveProbeBudget {
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

    @Synchronized
    fun invalidated(): Boolean = invalid

    /** Shared maintenance pacing, independent of route evidence or authority. */
    fun routineCadence(groupCount: Int): Long {
        require(groupCount in 1..16)
        return maxOf(60_000L, (groupCount * 3_600_000L + 95) / 96)
    }

    override fun toString() = "AdaptiveProbeBudget([redacted])"
}
