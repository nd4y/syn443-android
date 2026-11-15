package io.syn443.identity

/** UI scheduling advice only: grants no session, route or transmission authority. */
class ChatRefreshGate {
    enum class Result { SUCCESS, TRANSIENT_FAILURE, THROTTLED, BUSY, AUTHORITY_REQUIRED, CANCELLED }
    private var clock = 0L
    private var serial = 0L
    private var active: Long? = null
    private var automaticAt = 0L
    private var manualAt = 0L
    private var failures = 0
    private fun valid(now: Long) = now in clock..(MAX_TIME - 300_000)

    @Synchronized fun manualReady(now: Long): Boolean = valid(now) && active == null && now >= manualAt

    @Synchronized fun begin(now: Long, manual: Boolean = false): Long? {
        if (!valid(now) || active != null || serial == MAX_TIME ||
            now < (if (manual) manualAt else automaticAt)) return null
        clock = now
        manualAt = now + 30_000
        serial++
        active = serial
        return serial
    }

    /** A stale/cancelled worker cannot replace the current retry schedule. */
    @Synchronized fun complete(ticket: Long, result: Result, now: Long): Boolean {
        if (active != ticket || !valid(now)) return false
        clock = now
        active = null
        when (result) {
            Result.SUCCESS -> { failures = 0; automaticAt = now + 10_000 }
            Result.BUSY -> automaticAt = now + 10_000
            Result.AUTHORITY_REQUIRED -> automaticAt = MAX_TIME
            Result.CANCELLED -> automaticAt = maxOf(automaticAt, now + 10_000)
            Result.TRANSIENT_FAILURE, Result.THROTTLED -> {
                failures = (failures + 1).coerceAtMost(4)
                automaticAt = now + minOf(60_000L shl (failures - 1), 300_000L)
                if (result == Result.THROTTLED) manualAt = maxOf(manualAt, now + 60_000)
            }
        }
        return true
    }

    companion object { private const val MAX_TIME = 9_007_199_254_740_991L }
}
