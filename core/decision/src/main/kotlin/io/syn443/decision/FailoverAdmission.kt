package io.syn443.decision

data class VerifiedPathSample(
    val pathId: String,
    val exitClass: ExitClass,
    val receipt: String,
    val metricGroup: String,
    val sampledAtMs: Long,
    val verdict: ProbeVerdict,
    val latencyMs: Long,
)

data class FailoverChoice(val previous: String, val candidate: String, val receipt: String)

/**
 * Decides whether to ask the engine for a make-before-break switch.
 * Every route is already authorized for one intent and this comparison group.
 * This policy never expands the set of authorized routes.
 */
class FailoverAdmission(
    private val context: Context,
    private val exitClass: ExitClass,
    authorized: Set<String>,
    private val metricGroup: String,
    energyClasses: Map<String, Int> = emptyMap(),
) {
    private val members = authorized.toSet()
    private val energy = energyClasses.toMap()
    private data class Success(val at: Long, val streak: Int)
    private val success = mutableMapOf<String, Success>()
    private val health = RouteHealthMemory(context)
    private var lastSequence = 0L
    private var lastClock = 0L
    private var lastFailureAt = 0L
    private var lastFailureMember: String? = null
    private var failureStreak = 0
    private var nextSwitch = 0L

    init {
        require(Decision.validContext(context) && Decision.validId(metricGroup))
        require(members.size in 2..8 && members.all(Decision::validId))
        require(energy.all { (path, cost) -> path in members && cost in 0..2 })
    }

    private fun valid(sample: VerifiedPathSample, receipt: String, nowMs: Long) =
        sample.pathId in members && sample.exitClass == exitClass && sample.receipt == receipt && sample.metricGroup == metricGroup &&
            sample.sampledAtMs in 0..nowMs && nowMs - sample.sampledAtMs < 15_000 && sample.latencyMs in 0..30_000

    private fun clearFailure() {
        lastFailureMember = null
        failureStreak = 0
    }

    private fun track(sample: VerifiedPathSample, sequence: Long, nowMs: Long): Boolean {
        val key = PathHealthKey(sample.pathId, exitClass, metricGroup)
        val before = health.view(context, key, nowMs)
        when (before.readiness) {
            PathReadiness.CONFIG_CHANGE_REQUIRED, PathReadiness.QUARANTINED, PathReadiness.HALF_OPEN -> return false
            PathReadiness.REVALIDATE -> before.retryAtMs?.let { retryAt ->
                if (sample.sampledAtMs < retryAt || !health.beginRetry(context, key, sequence, nowMs)) return false
            }
            else -> Unit
        }
        return health.record(context, key, sequence, nowMs, sample.verdict)
    }

    @Synchronized
    fun cooldown(pathId: String, nowMs: Long): PathHealth? {
        if (pathId !in members) return null
        return health.view(context, PathHealthKey(pathId, exitClass, metricGroup), nowMs)
            .takeIf { it.retryAtMs != null }
    }

    /** Optional measurement only. The caller must keep measuring the active selector. */
    @Synchronized
    fun deferReserveProbe(current: Context, pathId: String, nowMs: Long): Boolean {
        if (current != context || pathId !in members) return false
        return when (health.view(context, PathHealthKey(pathId, exitClass, metricGroup), nowMs).readiness) {
            PathReadiness.QUARANTINED, PathReadiness.HALF_OPEN, PathReadiness.CONFIG_CHANGE_REQUIRED -> true
            else -> false
        }
    }

    /** A repeated heartbeat cannot count the same batch as two failures. */
    @Synchronized
    fun decide(
        current: Context,
        sequence: Long,
        receipt: String,
        nowMs: Long,
        selected: String,
        active: VerifiedPathSample,
        reserves: List<VerifiedPathSample>,
    ): FailoverChoice? {
        if (current != context || sequence !in 1..Decision.MAX_TIME || sequence <= lastSequence ||
            nowMs !in lastClock..(Decision.MAX_TIME - 720_000) || !Decision.validId(receipt) ||
            active.pathId != selected || !valid(active, receipt, nowMs) || reserves.size > 7 ||
            reserves.any { it.pathId == selected || !valid(it, receipt, nowMs) } ||
            reserves.map { it.pathId }.toSet().size != reserves.size) return null
        lastSequence = sequence
        lastClock = nowMs
        val verified = mutableListOf<VerifiedPathSample>()
        val observedReserve = reserves.any { it.verdict == ProbeVerdict.VERIFIED }
        for (sample in listOf(active) + reserves) {
            if (sample.verdict !in setOf(ProbeVerdict.VERIFIED, ProbeVerdict.CONFIRMED_PATH_FAILURE,
                    ProbeVerdict.PATH_AUTH_OR_CONFIGURATION)) continue
            // A successful comparator must be a different member in this
            // batch. When every route fails, preserve the existing memory.
            if (sample.verdict == ProbeVerdict.CONFIRMED_PATH_FAILURE &&
                !observedReserve && (sample.pathId == selected || active.verdict != ProbeVerdict.VERIFIED)) continue
            if (!track(sample, sequence, nowMs)) continue
            when (sample.verdict) {
                ProbeVerdict.VERIFIED -> {
                    val old = success[sample.pathId]
                    val streak = if (old != null && nowMs - old.at < 120_000) (old.streak + 1).coerceAtMost(5) else 1
                    success[sample.pathId] = Success(nowMs, streak)
                    if (sample.pathId != selected) verified += sample
                }
                ProbeVerdict.CONFIRMED_PATH_FAILURE, ProbeVerdict.PATH_AUTH_OR_CONFIGURATION -> success.remove(sample.pathId)
                else -> Unit
            }
        }
        if (active.verdict != ProbeVerdict.CONFIRMED_PATH_FAILURE || verified.isEmpty()) {
            // No evidence that one specific path failed and an eligible
            // replacement works and is eligible. Keep the current selection.
            clearFailure()
            return null
        }
        failureStreak = if (lastFailureMember == selected && nowMs - lastFailureAt < 120_000)
            (failureStreak + 1).coerceAtMost(2) else 1
        lastFailureMember = selected
        lastFailureAt = nowMs
        if (failureStreak < 2 || nowMs < nextSwitch) return null
        val best = verified.minWith(compareBy<VerifiedPathSample>(
            { -(success[it.pathId]?.streak ?: 0) }, { energy[it.pathId] ?: 2 }, { it.latencyMs }, { it.pathId },
        ))
        clearFailure()
        nextSwitch = nowMs + 30_000
        return FailoverChoice(selected, best.pathId, receipt)
    }
}
