package io.syn443.decision

import java.security.MessageDigest
import java.nio.ByteBuffer

enum class NetworkMode { HOME_WIFI, WIFI, CELLULAR_RESTRICTED, CELLULAR }
enum class ExitClass {
    RU, NON_RU, INTERNAL;

    companion object {
        internal val privateRoute = INTERNAL
    }
}
enum class PathFeature { TCP, UDP, IPV4, IPV6, ICMP }

data class RouteHop(
    val id: String,
    val entryModes: Set<NetworkMode>,
    val exit: ExitClass?,
    val features: Set<PathFeature>,
    val publicCandidate: Boolean = false,
) {
    init { require(!publicCandidate || exit == null) }

    /** Candidate eligibility only; a public declaration is never exit proof. */
    internal fun declaresExit(intent: ExitClass): Boolean =
        exit == intent || publicCandidate && (intent == ExitClass.RU || intent == ExitClass.NON_RU)
}

/** Directed transition in traffic order, from physical entry toward the exit. */
data class RouteEdge(val from: String, val to: String, val features: Set<PathFeature>)
data class RouteTemplate(val id: String, val slots: List<Set<String>>)
data class PlannedPath(val id: String, val hops: List<String>)
data class FrontierBatch(
    val paths: List<PlannedPath>,
    val examined: Int,
    val upperBound: Int,
    val exhausted: Boolean,
    val invalidated: Boolean,
)

/**
 * One bounded scan of the signed graph for one intent. Its output is a probe
 * candidate, never permission to use an unverified path. A warm hint goes
 * through the same eligibility checks and needs fresh evidence on this network.
 */
class RouteFrontier(
    private val context: Context,
    private val mode: NetworkMode,
    private val intent: ExitClass,
    requirements: Set<PathFeature>,
    hops: List<RouteHop>,
    edges: List<RouteEdge>,
    templates: List<RouteTemplate>,
    warmHints: List<List<String>>,
    createdAtMs: Long,
    ttlMs: Long,
) {
    /** RAM traversal hint only. It contains no path, metric, lease or receipt.
     * There is no decoder, public constructor, copy method or field accessor. */
    class Position private constructor(
        private val owner: Any,
        private val binding: String,
        private val ordinal: Int,
        private val hints: Int,
        private val observedAtMs: Long,
    ) {
        internal fun read(expectedOwner: Any, expectedBinding: String, maximum: Int, hintCount: Int, createdAtMs: Long): Pair<Int, Int>? {
            if (owner !== expectedOwner || binding != expectedBinding || ordinal !in 0..maximum || hints !in 0..hintCount ||
                ordinal > 0 && hints != hintCount || createdAtMs < observedAtMs ||
                createdAtMs !in 0..(Decision.MAX_TIME - 600_000)) return null
            return ordinal to hints
        }

        override fun toString() = "FrontierPosition([redacted])"

        companion object {
            internal fun capture(owner: Any, binding: String, ordinal: Int, hints: Int, nowMs: Long) =
                Position(owner, binding, ordinal, hints, nowMs)
        }
    }

    private enum class Invalidation { NONE, EXPIRED, UNSAFE }
    private val required = requirements.toSet()
    private val byId: Map<String, RouteHop>
    private val byEdge: Map<Pair<String, String>, Set<PathFeature>>
    private val slots: List<List<List<String>>>
    private val hints: List<List<String>>
    private val deadline: Long
    private val maximum: Int
    private var hintOffset = 0
    private var templateOffset = 0
    private var digits = IntArray(0)
    private var examined = 0
    private var lastNow = createdAtMs
    private var invalidation = Invalidation.NONE
    private var owner: Any? = null
    private var ownerBinding: String? = null
    private var pristine = true

    init {
        require(Decision.validContext(context))
        require(createdAtMs in 0..(Decision.MAX_TIME - 600_000) && ttlMs in 1..600_000)
        require(required.isNotEmpty() && hops.size in 1..500 && edges.size <= 4_096 && templates.size in 1..64)
        require(warmHints.size <= 2 && warmHints.all { it.size in 1..4 })
        require(hops.all { Decision.validId(it.id) && it.features.isNotEmpty() })
        byId = hops.associate { it.id to it.copy(entryModes = it.entryModes.toSet(), features = it.features.toSet()) }
        require(byId.size == hops.size)
        require(edges.all { it.from in byId && it.to in byId && it.from != it.to && it.features.isNotEmpty() })
        byEdge = edges.associate { (it.from to it.to) to it.features.toSet() }
        require(byEdge.size == edges.size)
        require(templates.map { it.id }.toSet().size == templates.size && templates.all {
            Decision.validId(it.id) && it.slots.size in 1..4 &&
                it.slots.all { slot -> slot.isNotEmpty() && slot.size <= 500 && slot.all(byId::containsKey) }
        })
        val sorted = templates.sortedWith(compareBy<RouteTemplate>({ it.slots.size }, { it.id }))
        var total = 0L
        slots = sorted.map { template ->
            val row = template.slots.map { slot -> slot.sorted() }
            val size = row.fold(1L) { product, slot -> product * slot.size }
            total += size
            require(total <= 4_096) { "route candidate bound exceeded" }
            row
        }
        maximum = total.toInt()
        hints = warmHints.map { it.toList() }.distinct().filter { path -> eligible(path) && slots.any { matches(it, path) } }
        digits = IntArray(slots.first().size)
        deadline = createdAtMs + ttlMs
    }

    /** Attach only before the graph factory exposes the cursor. Graph identity
     * and its immutable raw-metadata hash both participate in every restore. */
    @Synchronized
    internal fun ownedBy(graphOwner: Any, groupID: String, graphStamp: String): RouteFrontier {
        check(pristine && owner == null)
        owner = graphOwner
        val digest = MessageDigest.getInstance("SHA-256")
        fun put(value: String) {
            val raw = value.toByteArray(Charsets.UTF_8)
            digest.update(ByteBuffer.allocate(4).putInt(raw.size).array())
            digest.update(raw)
        }
        listOf("route-frontier-mixed-radix-v1", graphStamp, groupID, mode.name, intent.name,
            context.networkEpoch.toString(), context.activationGeneration.toString(), context.configRevision,
            context.algorithmRevision, context.engineGeneration.toString(), context.dependencyHash).forEach(::put)
        put(required.size.toString())
        required.map { it.name }.sorted().forEach(::put)
        // Only effective hints can affect enumeration. Their IDs are already
        // present in this bounded graph; never encode arbitrary rejected hints.
        put(hints.size.toString())
        hints.forEach { hint -> put(hint.size.toString()); hint.forEach(::put) }
        ownerBinding = digest.digest().joinToString("") { "%02x".format(it) }
        return this
    }

    private fun observe(current: Context, nowMs: Long): Boolean {
        if (current != context || nowMs < lastNow || nowMs !in 0..Decision.MAX_TIME) {
            invalidation = Invalidation.UNSAFE
        } else {
            lastNow = nowMs
            if (invalidation == Invalidation.NONE && nowMs >= deadline) invalidation = Invalidation.EXPIRED
        }
        return invalidation == Invalidation.NONE
    }

    /** Expiry may renew a metadata scan; context/clock invalidation may not.
     * Capturing or restoring a hint cannot authorize a native operation. */
    @Synchronized
    fun checkpoint(current: Context, nowMs: Long): Position? {
        observe(current, nowMs)
        pristine = false
        val graphOwner = owner ?: return null
        val binding = ownerBinding ?: return null
        if (invalidation == Invalidation.UNSAFE || nowMs !in 0..(Decision.MAX_TIME - 600_000)) return null
        return Position.capture(graphOwner, binding, examined, hintOffset, nowMs)
    }

    /** One bounded integer position replaces a potentially large visited set.
     * Decode at most 64 template bounds and four mixed-radix digits. */
    @Synchronized
    internal fun restore(position: Position, createdAtMs: Long): Boolean {
        if (!pristine || invalidation != Invalidation.NONE) return false
        val graphOwner = owner ?: return false
        val binding = ownerBinding ?: return false
        val state = position.read(graphOwner, binding, maximum, hints.size, createdAtMs) ?: return false
        var remaining = state.first
        var index = 0
        while (index < slots.size) {
            val bound = slots[index].fold(1) { size, ids -> size * ids.size }
            if (remaining < bound) break
            remaining -= bound
            index++
        }
        if (index == slots.size && remaining != 0) return false
        val restored = if (index == slots.size) IntArray(0) else IntArray(slots[index].size)
        if (index < slots.size) {
            for (digit in restored.lastIndex downTo 0) {
                restored[digit] = remaining % slots[index][digit].size
                remaining /= slots[index][digit].size
            }
            if (remaining != 0) return false
        }
        templateOffset = index
        digits = restored
        examined = state.first
        hintOffset = state.second
        pristine = false
        return true
    }

    private fun matches(template: List<List<String>>, path: List<String>): Boolean =
        template.size == path.size && path.indices.all { template[it].binarySearch(path[it]) >= 0 }

    private fun eligible(path: List<String>): Boolean {
        if (path.toSet().size != path.size) return false
        val head = byId[path.first()] ?: return false
        if (mode !in head.entryModes || byId[path.last()]?.declaresExit(intent) != true) return false
        return path.all { byId[it]?.features?.containsAll(required) == true } &&
            path.zipWithNext().all { byEdge[it]?.containsAll(required) == true }
    }

    private fun advance() {
        val row = slots[templateOffset]
        for (i in digits.lastIndex downTo 0) {
            digits[i]++
            if (digits[i] < row[i].size) return
            digits[i] = 0
        }
        templateOffset++
        if (templateOffset < slots.size) digits = IntArray(slots[templateOffset].size)
    }

    private fun path(hops: List<String>): PlannedPath {
        val raw = MessageDigest.getInstance("SHA-256").digest(hops.joinToString("/").toByteArray(Charsets.US_ASCII))
        val hex = "0123456789abcdef"
        return PlannedPath(buildString(64) {
            raw.forEach {
                val v = it.toInt() and 255
                append(hex[v ushr 4])
                append(hex[v and 15])
            }
        }, hops)
    }

    /** Stop/reschedule after the requested work quantum even if no path was eligible. */
    @Synchronized
    fun next(current: Context, nowMs: Long, resultLimit: Int, scanLimit: Int): FrontierBatch {
        require(resultLimit in 1..16 && scanLimit in 1..256)
        pristine = false
        if (!observe(current, nowMs)) {
            return FrontierBatch(emptyList(), examined, maximum, false, true)
        }
        val result = ArrayList<PlannedPath>(resultLimit)
        while (hintOffset < hints.size && result.size < resultLimit) {
            result += path(hints[hintOffset++])
        }
        var scanned = 0
        while (templateOffset < slots.size && scanned < scanLimit && result.size < resultLimit) {
            val index = templateOffset
            val candidate = slots[index].mapIndexed { slot, ids -> ids[digits[slot]] }
            advance()
            scanned++
            examined++
            if (candidate !in hints && eligible(candidate) && (0 until index).none { matches(slots[it], candidate) }) {
                result += path(candidate)
            }
        }
        return FrontierBatch(result, examined, maximum, templateOffset == slots.size && hintOffset == hints.size, false)
    }
}
