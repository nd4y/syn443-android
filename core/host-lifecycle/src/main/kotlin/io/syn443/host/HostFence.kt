package io.syn443.host

/** An in-process ownership fence. Effects must be executed by the Android supervisor. */
class HostFence(
    private val supervisorId: String,
    private val startTimeoutMs: Long = 10_000,
    private val stopTimeoutMs: Long = 5_000,
    initialGeneration: Int = 0,
) {
    enum class Phase { IDLE, STARTING, RUNNING, STOPPING, AWAITING_DEATH, AWAITING_RELEASE }
    enum class Reason { START_TIMEOUT, STOP_TIMEOUT, HANG, CLOCK_EXHAUSTED, CLOCK_INVALID }
    enum class Rejection { BUSY, GENERATION_EXHAUSTED, CLOCK_EXHAUSTED, STALE_OR_OUT_OF_ORDER }
    data class Token(val supervisorId: String, val generation: Int)
    data class Snapshot(val phase: Phase, val token: Token?, val deadlineMs: Long?)
    sealed interface Effect {
        val token: Token
        data class Launch(override val token: Token) : Effect
        data class GracefulStop(override val token: Token) : Effect
        data class TerminateOwned(override val token: Token, val reason: Reason) : Effect
    }
    data class Transition(
        val snapshot: Snapshot,
        val effects: List<Effect> = emptyList(),
        val rejection: Rejection? = null,
    )

    private var generation = initialGeneration
    private var lastTimeMs = 0L
    private var state = Snapshot(Phase.IDLE, null, null)

    init {
        require(supervisorId.matches(Regex("[a-f0-9]{32}")))
        require(startTimeoutMs in 1..60_000 && stopTimeoutMs in 1..60_000)
        require(initialGeneration >= 0)
    }

    @Synchronized fun snapshot(): Snapshot = state

    private fun time(nowMs: Long) {
        require(nowMs >= 0 && nowMs >= lastTimeMs) { "monotonic processing time required" }
        lastTimeMs = nowMs
    }

    private fun deadline(nowMs: Long, timeoutMs: Long): Long? =
        if (nowMs > Long.MAX_VALUE - timeoutMs) null else nowMs + timeoutMs

    private fun reject(reason: Rejection) = Transition(state, rejection = reason)

    private fun liveHost() = state.phase == Phase.STARTING || state.phase == Phase.RUNNING || state.phase == Phase.STOPPING

    private fun terminate(reason: Reason): Transition {
        val token = checkNotNull(state.token)
        state = Snapshot(Phase.AWAITING_DEATH, token, null)
        return Transition(state, listOf(Effect.TerminateOwned(token, reason)))
    }

    @Synchronized fun reserveStart(nowMs: Long): Transition {
        time(nowMs)
        if (state.phase != Phase.IDLE) return reject(Rejection.BUSY)
        if (generation == Int.MAX_VALUE) return reject(Rejection.GENERATION_EXHAUSTED)
        val until = deadline(nowMs, startTimeoutMs) ?: return reject(Rejection.CLOCK_EXHAUSTED)
        val token = Token(supervisorId, ++generation)
        state = Snapshot(Phase.STARTING, token, until)
        return Transition(state, listOf(Effect.Launch(token)))
    }

    @Synchronized fun started(token: Token, nowMs: Long): Transition {
        time(nowMs)
        if (token != state.token || state.phase != Phase.STARTING) {
            return reject(Rejection.STALE_OR_OUT_OF_ORDER)
        }
        if (nowMs >= checkNotNull(state.deadlineMs)) return terminate(Reason.START_TIMEOUT)
        state = Snapshot(Phase.RUNNING, token, null)
        return Transition(state)
    }

    @Synchronized fun requestStop(nowMs: Long): Transition {
        if (nowMs < 0 || nowMs < lastTimeMs) {
            return if (liveHost()) terminate(Reason.CLOCK_INVALID) else Transition(state)
        }
        time(nowMs)
        if (state.phase != Phase.STARTING && state.phase != Phase.RUNNING) return Transition(state)
        if (state.phase == Phase.STARTING && nowMs >= checkNotNull(state.deadlineMs)) {
            return terminate(Reason.START_TIMEOUT)
        }
        val until = deadline(nowMs, stopTimeoutMs) ?: return terminate(Reason.CLOCK_EXHAUSTED)
        val token = checkNotNull(state.token)
        state = Snapshot(Phase.STOPPING, token, until)
        return Transition(state, listOf(Effect.GracefulStop(token)))
    }

    @Synchronized fun tick(nowMs: Long): Transition {
        time(nowMs)
        if ((state.phase == Phase.STARTING || state.phase == Phase.STOPPING) && nowMs >= checkNotNull(state.deadlineMs)) {
            return terminate(if (state.phase == Phase.STARTING) Reason.START_TIMEOUT else Reason.STOP_TIMEOUT)
        }
        return Transition(state)
    }

    @Synchronized fun terminateForHang(token: Token, nowMs: Long): Transition {
        time(nowMs)
        if (token != state.token || !liveHost()) {
            return reject(Rejection.STALE_OR_OUT_OF_ORDER)
        }
        return terminate(Reason.HANG)
    }

    /** Only the trusted supervisor can supply this proof, never a native stop ACK alone. */
    @Synchronized fun confirmedExit(token: Token, identityReleased: Boolean, nowMs: Long): Transition {
        time(nowMs)
        if (token != state.token) return reject(Rejection.STALE_OR_OUT_OF_ORDER)
        state = if (identityReleased) Snapshot(Phase.IDLE, null, null)
        else Snapshot(Phase.AWAITING_RELEASE, token, null)
        return Transition(state)
    }

    /** Confirm release of the old host identity/descriptor ownership after its death. */
    @Synchronized fun confirmedRelease(token: Token, nowMs: Long): Transition {
        time(nowMs)
        if (token != state.token || state.phase != Phase.AWAITING_RELEASE) {
            return reject(Rejection.STALE_OR_OUT_OF_ORDER)
        }
        state = Snapshot(Phase.IDLE, null, null)
        return Transition(state)
    }
}
