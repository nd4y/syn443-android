package io.syn443.android.vpn

import org.json.JSONObject

/** Recent successful application probes for one concrete path and one route owner. */
internal class RouteProbeDurations private constructor(
    private val path: List<String>,
    private val samples: List<Sample>,
) {
    private data class Sample(val receipt: String, val at: Long, val durationMs: Long)

    private val ordered = samples.sortedBy { it.durationMs }

    companion object {
        private const val WINDOW_MS = 15 * 60_000L
        private const val MAX_SAMPLES = 20

        fun append(previous: RouteProbeDurations?, path: List<String>, receipt: String, at: Long, durationMs: Long): RouteProbeDurations {
            val same = previous?.takeIf { it.path == path && at >= it.samples.last().at }
            if (same != null && same.samples.any { it.receipt == receipt }) return same
            val recent = same?.samples.orEmpty().filter { at - it.at < WINDOW_MS }.takeLast(MAX_SAMPLES - 1)
            return RouteProbeDurations(path.toList(), recent + Sample(receipt, at, durationMs))
        }
    }

    fun summary(now: Long): JSONObject? {
        if (now < samples.last().at) return null
        val sorted = if (now - samples.first().at < WINDOW_MS) ordered
            else ordered.filter { now - it.at < WINDOW_MS }
        if (sorted.size < 2) return null
        fun percentile(percent: Int) = sorted[(sorted.size * percent + 99) / 100 - 1].durationMs
        return JSONObject().put("samples", sorted.size).put("p50Ms", percentile(50)).put("p95Ms", percentile(95))
    }
}
