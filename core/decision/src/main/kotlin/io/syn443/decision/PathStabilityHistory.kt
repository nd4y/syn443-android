package io.syn443.decision

/** Recent, attributable checks within one live route coordinator and native owner. */
class PathStabilityHistory {
    enum class Quality { INSUFFICIENT, STEADY, DEGRADED }

    private data class Sample(val at: Long, val success: Boolean)
    private class Window {
        val samples = ArrayDeque<Sample>(5)
        var lastAttempt = 0L
        var degradedAt: Long? = null

        fun expire(now: Long) {
            while (samples.isNotEmpty() && now - samples.first().at >= WINDOW_MS) samples.removeFirst()
            if (degradedAt?.let { now - it >= WINDOW_MS } == true) degradedAt = null
        }

        fun quality(): Quality = when {
            degradedAt != null -> Quality.DEGRADED
            samples.takeLast(3).let { it.size == 3 && it.all(Sample::success) } -> Quality.STEADY
            else -> Quality.INSUFFICIENT
        }
    }

    private val windows = LinkedHashMap<PathHealthKey, Window>()
    private var clock = 0L

    fun clear() {
        windows.clear()
        clock = 0
    }

    fun observe(key: PathHealthKey, attempt: Long, sampledAt: Long, now: Long, verdict: ProbeVerdict): Boolean {
        val success = when (verdict) {
            ProbeVerdict.VERIFIED -> true
            ProbeVerdict.CONFIRMED_PATH_FAILURE -> false
            else -> return false
        }
        if (now !in clock..Decision.MAX_TIME || sampledAt !in 0..now || now - sampledAt > 30_000 ||
            attempt !in 1..Decision.MAX_TIME) return false
        clock = now
        val previous = windows[key]
        if (previous != null && (attempt <= previous.lastAttempt ||
                previous.samples.lastOrNull()?.let { sampledAt < it.at } == true)) return false
        val window = previous ?: Window()
        if (previous == null && windows.size >= 64) {
            val oldest = windows.entries.firstOrNull { (_, entry) ->
                entry.expire(now)
                entry.degradedAt == null
            } ?: return false
            windows.remove(oldest.key)
        }
        window.expire(now)
        if (window.samples.size == 5) window.samples.removeFirst()
        window.samples.addLast(Sample(sampledAt, success))
        window.lastAttempt = attempt
        if (!success && window.samples.count { !it.success } >= 3) window.degradedAt = sampledAt
        if (success && window.samples.size >= 3 && window.samples.takeLast(3).all(Sample::success)) {
            window.degradedAt = null
        }
        windows.remove(key)
        windows[key] = window
        return true
    }

    fun quality(key: PathHealthKey, now: Long): Quality {
        if (now !in clock..Decision.MAX_TIME) return Quality.INSUFFICIENT
        clock = now
        val window = windows[key] ?: return Quality.INSUFFICIENT
        window.expire(now)
        return window.quality()
    }

    private companion object { const val WINDOW_MS = 600_000L }
}
