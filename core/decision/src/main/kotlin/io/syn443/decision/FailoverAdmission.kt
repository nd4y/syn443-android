package io.syn443.decision

data class VerifiedPathSample(
    val pathId: String,
    val exitClass: ExitClass,
    val receipt: String,
    val metricGroup: String,
    val sampledAtMs: Long,
    val verdict: ProbeVerdict,
    val latencyMs: Long,
    val transientTransportFailure: Boolean = false,
)

data class FailoverChoice(val previous: String, val candidate: String, val receipt: String)

/** Immutable local algorithms selected by the verified policy revision. */
enum class FailoverAlgorithm(val revision: String, val confirmations: Int, val switchIntervalMs: Long) {
    BASELINE("m1-local-v1", 2, 30_000),
    CONFIRMED("m4-confirmed-v1", 3, 60_000);

    companion object {
        fun fromRevision(revision: String): FailoverAlgorithm? = entries.firstOrNull { it.revision == revision }
    }
}

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
    private val algorithm: FailoverAlgorithm = FailoverAlgorithm.BASELINE,
) {
    private val members = authorized.toSet()
    private val energy = energyClasses.toMap()
    private data class Success(val at: Long, val streak: Int)
    private val success = mutableMapOf<String, Success>()
    private val health = RouteHealthMemory(context)
    private data class TransientFailures(val observedAt: Long, val count: Int)
    private val transient = mutableMapOf<String, TransientFailures>()
    private var nextEarlyTrial = 0L
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
            PathReadiness.CONFIG_CHANGE_REQUIRED, PathReadiness.QUARANTINED -> return false
            PathReadiness.HALF_OPEN -> if (!health.ownsEarlySample(context, key, sequence, sample.sampledAtMs, nowMs)) return false
            PathReadiness.REVALIDATE -> before.retryAtMs?.let { retryAt ->
                if (sample.sampledAtMs < retryAt || !health.beginRetry(context, key, sequence, nowMs)) return false
            }
            else -> Unit
        }
        if (!health.record(context, key, sequence, nowMs, sample.verdict)) return false
        if (sample.verdict == ProbeVerdict.CONFIRMED_PATH_FAILURE && sample.transientTransportFailure) {
            val previous = transient[sample.pathId]
            val count = if (previous != null && nowMs - previous.observedAt < 120_000) 2 else 1
            transient[sample.pathId] = TransientFailures(nowMs, count)
        } else {
            transient.remove(sample.pathId)
        }
        return true
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

    /** A trial is a diagnostic opportunity on an authorized reserve, never a switch choice.
     * An ordinary or unknown reserve always receives its normal probe first. */
    @Synchronized
    fun earlyReserve(current: Context, selected: String, nowMs: Long): String? {
        if (current != context || selected !in members || nowMs < nextEarlyTrial || nowMs < lastClock) return null
        val candidates = mutableListOf<Pair<String, Long>>()
        for (id in members - selected) {
            val key = PathHealthKey(id, exitClass, metricGroup)
            val state = health.view(context, key, nowMs)
            when (state.readiness) {
                PathReadiness.CONFIG_CHANGE_REQUIRED -> continue
                PathReadiness.HALF_OPEN -> return null
                PathReadiness.QUARANTINED -> {
                    val failures = transient[id] ?: continue
                    if (failures.count >= 2 && nowMs - failures.observedAt >= 10_000)
                        candidates += id to checkNotNull(state.retryAtMs)
                }
                else -> return null
            }
        }
        return candidates.minWithOrNull(compareBy({ it.second }, { energy[it.first] ?: 2 }, { it.first }))?.first
    }

    @Synchronized
    fun beginEarlyReserve(current: Context, selected: String, sequence: Long, nowMs: Long): String? {
        if (sequence != lastSequence + 1) return null
        val id = earlyReserve(current, selected, nowMs) ?: return null
        if (!health.beginEarlyRetry(context, PathHealthKey(id, exitClass, metricGroup), sequence, nowMs)) return null
        nextEarlyTrial = nowMs + 300_000
        return id
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
        val samples = listOf(active) + reserves
        val accepted = samples.filter { it.verdict == ProbeVerdict.VERIFIED && track(it, sequence, nowMs) }
        for (sample in accepted) {
            val old = success[sample.pathId]
            val streak = if (old != null && nowMs - old.at < 120_000) (old.streak + 1).coerceAtMost(5) else 1
            success[sample.pathId] = Success(nowMs, streak)
        }
        for (sample in samples) {
            // Only a fresh, admitted success on a different member attributes
            // a transient failure. An old half-open sample cannot penalize the incumbent.
            if (sample.verdict == ProbeVerdict.CONFIRMED_PATH_FAILURE && accepted.isEmpty()) continue
            if (sample.verdict !in setOf(ProbeVerdict.CONFIRMED_PATH_FAILURE, ProbeVerdict.PATH_AUTH_OR_CONFIGURATION)) continue
            if (track(sample, sequence, nowMs)) success.remove(sample.pathId)
        }
        val verified = accepted.filter { it.pathId != selected }
        if (active.verdict != ProbeVerdict.CONFIRMED_PATH_FAILURE || verified.isEmpty()) {
            // No evidence that one specific path failed and an eligible
            // replacement works and is eligible. Keep the current selection.
            clearFailure()
            return null
        }
        failureStreak = if (lastFailureMember == selected && nowMs - lastFailureAt < 120_000)
            (failureStreak + 1).coerceAtMost(algorithm.confirmations) else 1
        lastFailureMember = selected
        lastFailureAt = nowMs
        if (failureStreak < algorithm.confirmations || nowMs < nextSwitch) return null
        val best = verified.minWith(compareBy<VerifiedPathSample>(
            { -(success[it.pathId]?.streak ?: 0) }, { energy[it.pathId] ?: 2 }, { it.latencyMs }, { it.pathId },
        ))
        clearFailure()
        nextSwitch = nowMs + algorithm.switchIntervalMs
        return FailoverChoice(selected, best.pathId, receipt)
    }
}
