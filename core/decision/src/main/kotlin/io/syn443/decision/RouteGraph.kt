package io.syn443.decision

import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.decodeFromJsonElement

@Serializable private data class GraphWire(
    val schemaVersion: Int,
    val hops: List<HopWire>,
    val edges: List<EdgeWire>,
    val templates: List<TemplateWire>,
    val groups: List<GroupWire>,
)
@Serializable private data class HopWire(
    val id: String, val entryModes: List<String>, val exitClass: String?, val features: List<String>,
)
@Serializable private data class EdgeWire(val from: String, val to: String, val features: List<String>)
@Serializable private data class TemplateWire(val id: String, val slots: List<List<String>>)
@Serializable private data class GroupWire(
    val id: String, val intent: String, val features: List<String>, val templates: List<String>,
)

/** Owned declaration summary; never route-selection authority. */
data class RouteGroupInfo(val intent: ExitClass, val features: Set<PathFeature>, val upperBound: Int, val maxHops: Int) {
    override fun toString()="RouteGroupInfo([redacted])"
}

/** Immutable declarations bound to a separately authorized profile catalogue.
 * Eligibility, bounds and warm hints are not route-selection authority.
 */
class RouteGraph private constructor(
    private val hops: List<RouteHop>,
    private val edges: List<RouteEdge>,
    private val templates: Map<String, RouteTemplate>,
    private val groups: Map<String, Group>,
    private val intentBounds: Map<ExitClass, Int>,
    private val graphStamp: String,
) {
    private data class Group(
        val intent: ExitClass, val features: Set<PathFeature>, val templates: List<String>, val upperBound: Int,
    )
    private val hopByID = hops.associateBy { it.id }
    private val edgeByPair = edges.associate { (it.from to it.to) to it.features }
    private val frontierOwner = Any()

    fun groupIDs(): List<String> = groups.keys.sorted()
    fun upperBound(groupID: String): Int? = groups[groupID]?.upperBound
    fun intentUpperBound(intent: ExitClass): Int? = intentBounds[intent]
    fun groupInfo(groupID: String): RouteGroupInfo? = groups[groupID]?.let { group ->
        RouteGroupInfo(group.intent,group.features.toSet(),group.upperBound,group.templates.maxOf {templates.getValue(it).slots.size})
    }

    /** Static metadata only. A caller still needs native evidence for selection. */
    fun isDeclaredPath(groupID: String, mode: NetworkMode, path: List<String>): Boolean {
        val group = groups[groupID] ?: return false
        if (path.size !in 1..4 || path.toSet().size != path.size) return false
        val head = hopByID[path.first()] ?: return false
        if (mode !in head.entryModes || hopByID[path.last()]?.declaresExit(group.intent) != true) return false
        if (path.any { hopByID[it]?.features?.containsAll(group.features) != true } ||
            path.zipWithNext().any { edgeByPair[it]?.containsAll(group.features) != true }) return false
        return group.templates.any { id ->
            val slots = templates.getValue(id).slots
            slots.size == path.size && slots.indices.all { path[it] in slots[it] }
        }
    }

    fun frontier(
        groupID: String, context: Context, mode: NetworkMode, warmHints: List<List<String>>,
        createdAtMs: Long, ttlMs: Long,
    ): RouteFrontier {
        val group = groups[groupID] ?: error("unknown_route_group")
        return RouteFrontier(context, mode, group.intent, group.features, hops, edges,
            group.templates.map(templates::getValue), warmHints, createdAtMs, ttlMs).ownedBy(frontierOwner, groupID, graphStamp)
    }

    /** Local RAM hint, not a wire token or selection proof. Reject rather than
     * clamp/reinterpret a foreign position; ordinary cold construction remains
     * separate and unchanged. No native resources or I/O are acquired here. */
    fun resumeFrontier(
        groupID: String, context: Context, mode: NetworkMode, warmHints: List<List<String>>,
        createdAtMs: Long, ttlMs: Long, position: RouteFrontier.Position,
    ): RouteFrontier? {
        if (groupID !in groups || !Decision.validContext(context) ||
            createdAtMs !in 0..(Decision.MAX_TIME - 600_000) || ttlMs !in 1..600_000 ||
            warmHints.size > 2 || warmHints.any { it.size !in 1..4 || it.any { id -> !Decision.validId(id) } }) return null
        val next = frontier(groupID, context, mode, warmHints, createdAtMs, ttlMs)
        return next.takeIf { it.restore(position, createdAtMs) }
    }

    override fun toString(): String = "RouteGraph(hops=${hops.size},groups=${groups.size})"

    companion object {
        const val MAX_BYTES = 262144

        /** Catalogue IDs must come from verified source resolution, never this document. */
        fun decode(raw: ByteArray, catalogue: List<String>): RouteGraph {
            try {
                require(raw.size in 1..MAX_BYTES && catalogue.size in 1..500)
                val authorized = catalogue.toList()
                require(authorized.all(Decision::validId) && authorized.toSet().size == authorized.size)
                val text = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(raw)).toString()
                StrictJson.validate(text)
                val tree = Decision.json.parseToJsonElement(text)
                require(tree is JsonObject)
                // kotlinx.serialization accepts quoted integer tokens even in
                // strict mode. Version is a JSON number, exactly literal 1.
                val version = tree["schemaVersion"]
                require(version is JsonPrimitive && !version.isString && version.content == "1")
                val wire = Decision.json.decodeFromJsonElement<GraphWire>(tree)
                require(wire.schemaVersion == 1 && wire.hops.size in 1..500 && wire.hops.size == authorized.size)
                require(wire.edges.size <= 4096 && wire.templates.size in 1..64 && wire.groups.size in 1..16)

                fun ids(values: List<String>, maximum: Int): List<String> {
                    require(values.size in 1..maximum && values.all(Decision::validId) && values.toSet().size == values.size)
                    return values.toList()
                }
                fun features(values: List<String>): Set<PathFeature> {
                    require(values.size in 1..5 && values.toSet().size == values.size)
                    return values.map(PathFeature::valueOf).toSet()
                }
                val hopIDs = ids(wire.hops.map { it.id }, 500)
                require(hopIDs.toSet() == authorized.toSet())
                val hops = wire.hops.map { hop ->
                    require(hop.entryModes.size <= 4 && hop.entryModes.toSet().size == hop.entryModes.size)
                    val publicCandidate = hop.exitClass == "PUBLIC"
                    RouteHop(hop.id, hop.entryModes.map(NetworkMode::valueOf).toSet(),
                        if (publicCandidate) null else hop.exitClass?.let(ExitClass::valueOf),
                        features(hop.features), publicCandidate)
                }
                val byID = hops.associateBy { it.id }
                require(wire.edges.map { it.from to it.to }.toSet().size == wire.edges.size)
                val edges = wire.edges.map { edge ->
                    require(edge.from != edge.to && edge.from in byID && edge.to in byID)
                    val capabilities = features(edge.features)
                    require(byID.getValue(edge.from).features.containsAll(capabilities) &&
                        byID.getValue(edge.to).features.containsAll(capabilities))
                    RouteEdge(edge.from, edge.to, capabilities)
                }
                ids(wire.templates.map { it.id }, 64)
                val templateBounds = mutableMapOf<String, Int>()
                val templates = wire.templates.associate { template ->
                    require(template.slots.size in 1..4)
                    var bound = 1
                    val slots = template.slots.map { slot ->
                        val choices = ids(slot, 500)
                        require(choices.all(byID::containsKey) && choices.size <= 4096 / bound)
                        bound *= choices.size
                        choices.toSet()
                    }
                    templateBounds[template.id] = bound
                    template.id to RouteTemplate(template.id, slots)
                }
                ids(wire.groups.map { it.id }, 16)
                val referenced = mutableMapOf<ExitClass, MutableSet<String>>()
                val groups = wire.groups.associate { group ->
                    val intent = ExitClass.valueOf(group.intent)
                    val required = features(group.features)
                    val references = ids(group.templates, 64)
                    var bound = 0
                    for (reference in references) {
                        val size = templateBounds[reference] ?: error("unknown_route_template")
                        require(size <= 4096 - bound)
                        bound += size
                    }
                    referenced.getOrPut(intent) { mutableSetOf() }.addAll(references)
                    group.id to Group(intent, required, references.sorted(), bound)
                }
                val intentBounds = referenced.mapValues { (_, references) ->
                    var sum = 0
                    for (reference in references) {
                        val size = templateBounds.getValue(reference)
                        require(size <= 4096 - sum)
                        sum += size
                    }
                    sum
                }
                val stamp = MessageDigest.getInstance("SHA-256").digest(text.toByteArray(StandardCharsets.UTF_8)).joinToString("") { "%02x".format(it) }
                return RouteGraph(hops, edges, templates, groups, intentBounds, stamp)
            } catch (_: Exception) {
                // Do not retain parser exceptions containing private identifiers.
                throw IllegalArgumentException("invalid_route_graph")
            }
        }
    }
}
