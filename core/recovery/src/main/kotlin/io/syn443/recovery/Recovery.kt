package io.syn443.recovery

import kotlin.math.min

/** Pure recovery admission; the Android adapter persists every returned checkpoint before effects. */
data class Checkpoint(
    val desiredOn: Boolean = false,
    val generation: Long = 0,
    val attempt: Int = 0,
    val nextWallMs: Long = 0,
    val lastEarlyWallMs: Long = 0,
    val heavyWallMs: List<Long> = emptyList(),
) {
    init {
        require(generation >= 0 && attempt in 0..30)
        require(nextWallMs >= 0 && lastEarlyWallMs >= 0)
        require(heavyWallMs.size <= 3 && heavyWallMs.all { it >= 0 })
    }
}

object Recovery {
    private const val WINDOW = 600_000L
    private fun add(a: Long, b: Long) = if (a > Long.MAX_VALUE - b) Long.MAX_VALUE else a + b

    fun command(state: Checkpoint, on: Boolean): Checkpoint {
        check(state.generation < Long.MAX_VALUE) { "intent generation exhausted" }
        // Repeated Connect must not bypass the outage/heavy-restart budget.
        return state.copy(desiredOn = on, generation = state.generation + 1)
    }

    fun delay(attempt: Int, jitter: Double): Long {
        require(attempt in 0..30 && jitter.isFinite() && jitter in 0.0..1.0)
        val base = min(60_000L, 1_000L shl min(attempt, 6))
        return (base * (0.8 + 0.4 * jitter)).toLong().coerceIn(1_000, 60_000)
    }

    fun failed(state: Checkpoint, now: Long, jitter: Double): Checkpoint {
        require(now >= 0)
        return state.copy(attempt = min(30, state.attempt + 1), nextWallMs = add(now, delay(state.attempt, jitter)))
    }

    fun stable(state: Checkpoint, durationMs: Long, successfulChecks: Int): Checkpoint =
        if (durationMs >= 30_000 && successfulChecks >= 3) state.copy(attempt = 0, nextWallMs = 0) else state

    fun normalizeClock(state: Checkpoint, now: Long): Checkpoint {
        require(now >= 0)
        // Rebase once after clock rollback; a previously valid wall deadline
        // must never postpone recovery for hours or slide forward on each poll.
        val horizon = if (state.heavyWallMs.size >= 3) WINDOW else 60_000L
        return state.copy(nextWallMs = min(state.nextWallMs, add(now, horizon)),
            lastEarlyWallMs = min(state.lastEarlyWallMs, now), heavyWallMs = state.heavyWallMs.map { min(it, now) })
    }

    fun networkOpportunity(state: Checkpoint, now: Long): Checkpoint {
        require(now >= 0)
        if (!state.desiredOn || now < state.lastEarlyWallMs || now - state.lastEarlyWallMs < 5_000) return state
        return state.copy(nextWallMs = min(state.nextWallMs, now), lastEarlyWallMs = now)
    }

    fun heavyAdmission(state: Checkpoint, now: Long): Pair<Checkpoint, Boolean> {
        require(now >= 0)
        // Clock rollback retains a conservative bounded window, never an unlimited ban.
        val history = state.heavyWallMs.map { min(it, now) }.filter { now - it < WINDOW }.sorted()
        if (!state.desiredOn) return state.copy(heavyWallMs = history) to false
        if (history.size >= 3) return state.copy(heavyWallMs = history, nextWallMs = maxOf(state.nextWallMs.coerceAtMost(add(now, WINDOW)), add(history.first(), WINDOW))) to false
        if (now < state.nextWallMs.coerceAtMost(add(now, WINDOW))) return state.copy(heavyWallMs = history, nextWallMs = min(state.nextWallMs, add(now, WINDOW))) to false
        return state.copy(heavyWallMs = history + now) to true
    }

    /** Read-only reservation check. A waiting policy must not consume native starts. */
    fun replacementReady(state: Checkpoint, now: Long, slots: Int = 2): Boolean {
        require(now >= 0 && slots in 1..3)
        val recent = state.heavyWallMs.count { now - min(it, now) < WINDOW }
        return state.desiredOn && now >= state.nextWallMs && recent + slots <= 3
    }

    fun current(state: Checkpoint, generation: Long) = state.desiredOn && state.generation == generation
}
