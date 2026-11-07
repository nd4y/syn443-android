package io.syn443.decision

data class VerifiedPathSample(
    val pathId: String,
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
        sample.pathId in members && sample.receipt == receipt && sample.metricGroup == metricGroup &&
            sample.sampledAtMs in 0..nowMs && nowMs - sample.sampledAtMs < 15_000 && sample.latencyMs in 0..30_000

    private fun clearFailure() {
        lastFailureMember = null
        failureStreak = 0
    }

    private fun track(sample: VerifiedPathSample, sequence: Long, nowMs: Long): Boolean {
        val key = PathHealthKey(sample.pathId, ExitClass.privateRoute, metricGroup)
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
            // For this pilot, a path failure is attributable only when another
            // member successfully ran the identical checks in this batch.
            if (sample.verdict == ProbeVerdict.CONFIRMED_PATH_FAILURE && !observedReserve) continue
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
