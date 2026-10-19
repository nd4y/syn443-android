package io.syn443.decision

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

@Serializable
data class Context(
    val networkEpoch: Long,
    val activationGeneration: Long,
    val configRevision: String,
    val algorithmRevision: String,
    val engineGeneration: Long,
    val dependencyHash: String,
)

@Serializable
data class Candidate(
    val id: String,
    val context: Context,
    val allowed: Boolean,
    val exitClass: String,
    val requiredHealthy: Boolean,
    val optionalDegraded: Boolean,
    val hardFailure: Boolean,
    val observedAtMs: Long,
    val samples: Long,
    val failures: Long,
    val trailingSuccesses: Long,
    val bytesPerMinute: Long?,
    val handshakesPerMinute: Long?,
    val activeBackups: Long?,
    val latencyMs: Long?,
    val metricGroup: String,
)

@Serializable
data class Request(
    val schemaVersion: Int,
    val context: Context,
    val nowMs: Long,
    val evidenceTtlMs: Long,
    val intent: String,
    val metricGroup: String,
    val candidates: List<Candidate>,
)

@Serializable
data class Rejection(val pathId: String, val reason: String)

@Serializable
data class Result(
    val selectedPathId: String?,
    val orderedPathIds: List<String>,
    val rejected: List<Rejection>,
)

object Decision {
    val json = Json { ignoreUnknownKeys = false; isLenient = false; coerceInputValues = false }
    private val id = Regex("^[a-z0-9][a-z0-9._-]{0,63}$")
    private val hash = Regex("^[a-f0-9]{64}$")
    const val MAX_GENERATION = 2147483647L
    const val MAX_TIME = 9007199254740991L

    fun validId(value: String): Boolean = id.matches(value)

    fun validContext(c: Context): Boolean =
        c.networkEpoch in 0..MAX_GENERATION &&
            c.activationGeneration in 0..MAX_GENERATION &&
            c.engineGeneration in 0..MAX_GENERATION &&
            validId(c.configRevision) && validId(c.algorithmRevision) &&
            hash.matches(c.dependencyHash)

    fun decode(raw: String): Request {
        StrictJson.validate(raw)
        return json.decodeFromString<Request>(raw).also(::validate)
    }

    fun validate(r: Request) {
        require(r.schemaVersion == 1 && validContext(r.context))
        require(r.nowMs in 0..MAX_TIME && r.evidenceTtlMs in 1..600000)
        require(r.intent in setOf("RU", "NON_RU", "INTERNAL") && validId(r.metricGroup))
        require(r.candidates.size <= 4096)
        val ids = HashSet<String>()
        for (c in r.candidates) {
            require(validId(c.id) && ids.add(c.id) && validContext(c.context))
            require(c.exitClass in setOf("RU", "NON_RU", "INTERNAL"))
            require(c.observedAtMs in 0..MAX_TIME && validId(c.metricGroup))
            require(c.samples in 0..20 && c.failures in 0..c.samples)
            require(c.trailingSuccesses in 0..(c.samples - c.failures))
            require(c.bytesPerMinute == null || c.bytesPerMinute in 0..2147483647L)
            require(c.handshakesPerMinute == null || c.handshakesPerMinute in 0..1000000L)
            require(c.activeBackups == null || c.activeBackups in 0..64L)
            require(c.latencyMs == null || c.latencyMs in 0..600000L)
        }
    }

    private fun rejection(r: Request, c: Candidate): String? = when {
        c.context != r.context -> "context_mismatch"
        !c.allowed -> "disallowed"
        c.exitClass != r.intent -> "wrong_exit"
        !c.requiredHealthy -> "required_check_failed"
        c.hardFailure -> "hard_failure"
        c.observedAtMs > r.nowMs || r.nowMs - c.observedAtMs >= r.evidenceTtlMs -> "stale_evidence"
        else -> null
    }

    private fun band(value: Long?, low: Long, medium: Long): Int = when {
        value == null -> 2
        value <= low -> 0
        value <= medium -> 1
        else -> 2
    }

    private fun rank(r: Request, c: Candidate): List<Long> {
        val stability = when {
            c.optionalDegraded -> 2
            c.samples >= 5 && c.trailingSuccesses >= 3 && c.failures * 100 <= c.samples * 5 -> 0
            c.samples >= 5 -> 2
            else -> 1
        }
        val energy = maxOf(
            band(c.bytesPerMinute, 2048, 8192),
            band(c.handshakesPerMinute, 1, 4),
            band(c.activeBackups, 1, 2),
        )
        val latency = if (c.latencyMs != null && c.metricGroup == r.metricGroup) c.latencyMs / 25 else 24001L
        val confidence = when { c.samples >= 10 -> 0; c.samples >= 5 -> 1; else -> 2 }
        return listOf(stability.toLong(), energy.toLong(), latency, confidence.toLong())
    }

    fun select(r: Request): Result {
        validate(r)
        val rejected = r.candidates.mapNotNull { c -> rejection(r, c)?.let { Rejection(c.id, it) } }.sortedBy { it.pathId }
        val eligible = r.candidates.filter { rejection(r, it) == null }
        val ordered = eligible.sortedWith { a, b ->
            val ra = rank(r, a)
            val rb = rank(r, b)
            var comparison = 0
            for (i in ra.indices) {
                comparison = ra[i].compareTo(rb[i])
                if (comparison != 0) break
            }
            if (comparison == 0) a.id.compareTo(b.id) else comparison
        }.map { it.id }
        return Result(ordered.firstOrNull(), ordered, rejected)
    }
}

