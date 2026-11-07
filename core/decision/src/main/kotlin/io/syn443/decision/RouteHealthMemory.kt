package io.syn443.decision

enum class ProbeVerdict {
    VERIFIED, CONFIRMED_PATH_FAILURE, PATH_AUTH_OR_CONFIGURATION,
    TARGET_FAILURE, COMMON_NETWORK_FAILURE, BUDGET_EXHAUSTED, CANCELLED, UNKNOWN,
}

data class PathHealthKey(val pathId: String, val intent: ExitClass, val metricGroup: String)
enum class PathReadiness { NO_EVIDENCE, VERIFIED, SUSPECT, QUARANTINED, REVALIDATE, HALF_OPEN, CONFIG_CHANGE_REQUIRED }
data class PathHealth(val readiness: PathReadiness, val retryAtMs: Long? = null)

/**
 * Local evidence scoped to an exact runtime context and comparison group.
 * The caller attributes a failure before recording it. A timeout at an
 * arbitrary destination, for example, is not a confirmed path failure.
 */
class RouteHealthMemory(private var context: Context) {
    private data class Trial(val attempt: Long, val untilMs: Long)
    private data class Entry(
        val attempt: Long,
        val observedAtMs: Long,
        val failures: Int,
        val retryAtMs: Long?,
        val requiresChange: Boolean,
        val trial: Trial? = null,
    )

    private val table = LinkedHashMap<PathHealthKey, Entry>(64)
    private var clock = 0L

    init { require(Decision.validContext(context)) }

    @Synchronized
    fun reset(next: Context) {
        require(Decision.validContext(next))
        if (context != next) {
            table.clear()
            context = next
        }
    }

    private fun validKey(key: PathHealthKey) = Decision.validId(key.pathId) && Decision.validId(key.metricGroup)

    private fun advanceClock(nowMs: Long): Boolean {
        if (nowMs !in clock..(Decision.MAX_TIME - 720_000)) return false
        clock = nowMs
        return true
    }

    /** One half-open probe at a time. A late completion cannot open the fence. */
    @Synchronized
    fun beginRetry(current: Context, key: PathHealthKey, attempt: Long, nowMs: Long): Boolean {
        if (current != context || !validKey(key) || attempt !in 1..Decision.MAX_TIME || !advanceClock(nowMs)) return false
        val old = table[key] ?: return false
        val retry = old.retryAtMs ?: return false
        if (nowMs < retry || attempt <= old.attempt || old.trial?.let { attempt <= it.attempt || nowMs < it.untilMs } == true) return false
        table[key] = old.copy(trial = Trial(attempt, nowMs + 15_000))
        return true
    }

    /** False means the result was not admitted and must not affect ranking. */
    @Synchronized
    fun record(current: Context, key: PathHealthKey, attempt: Long, nowMs: Long, verdict: ProbeVerdict): Boolean {
        if (current != context || !validKey(key) || attempt !in 1..Decision.MAX_TIME || !advanceClock(nowMs)) return false
        val old = table[key]
        if (old != null && (attempt <= old.attempt || old.requiresChange || old.retryAtMs != null &&
                old.trial?.let { attempt == it.attempt && nowMs < it.untilMs } != true)) return false
        val entry = when (verdict) {
            ProbeVerdict.VERIFIED -> Entry(attempt, nowMs, 0, null, false)
            ProbeVerdict.PATH_AUTH_OR_CONFIGURATION -> Entry(attempt, nowMs, 0, null, true)
            ProbeVerdict.CONFIRMED_PATH_FAILURE -> {
                val prior = if (old != null && nowMs - (old.retryAtMs ?: old.observedAtMs) < 120_000) old.failures else 0
                val failures = (prior + 1).coerceAtMost(7)
                val cooldownMs = when (failures) {
                    1 -> null
                    2 -> 30_000L
                    3 -> 60_000L
                    4 -> 120_000L
                    5 -> 240_000L
                    6 -> 480_000L
                    else -> 600_000L
                }
                val factor = 80 + ((key.pathId.hashCode().toLong() xor attempt xor current.networkEpoch) and Long.MAX_VALUE) % 41
                Entry(attempt, nowMs, failures, cooldownMs?.let { nowMs + (it * factor / 100).coerceIn(30_000, 600_000) }, false)
            }
            else -> return false
        }
        if (old == null && table.size == 64) {
            // Never evict an active fence to fit a new path.
            val oldest = table.entries.firstOrNull { (_, value) ->
                !value.requiresChange && value.retryAtMs?.let { nowMs < it } != true && value.trial?.let { nowMs < it.untilMs } != true
            } ?: return false
            table.remove(oldest.key)
        }
        table.remove(key)
        table[key] = entry
        return true
    }

    @Synchronized
    fun view(current: Context, key: PathHealthKey, nowMs: Long): PathHealth {
        if (current != context || !validKey(key) || !advanceClock(nowMs)) return PathHealth(PathReadiness.NO_EVIDENCE)
        val entry = table[key] ?: return PathHealth(PathReadiness.NO_EVIDENCE)
        if (entry.requiresChange) return PathHealth(PathReadiness.CONFIG_CHANGE_REQUIRED)
        val retry = entry.retryAtMs
        val trial = entry.trial
        return when {
            retry != null && nowMs < retry -> PathHealth(PathReadiness.QUARANTINED, retry)
            trial != null && nowMs < trial.untilMs -> PathHealth(PathReadiness.HALF_OPEN, trial.untilMs)
            retry != null || nowMs - entry.observedAtMs >= 120_000 -> PathHealth(PathReadiness.REVALIDATE)
            entry.failures > 0 -> PathHealth(PathReadiness.SUSPECT)
            else -> PathHealth(PathReadiness.VERIFIED)
        }
    }
}
