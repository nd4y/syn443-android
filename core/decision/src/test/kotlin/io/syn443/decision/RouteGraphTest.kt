package io.syn443.decision

import kotlinx.serialization.json.*
import org.junit.Assert.*
import org.junit.Test

class RouteGraphTest {
    @Test fun publicCandidatePreservesGroupIntentAndCapabilityFences() {
        val vector = fixture().getValue("validCases").jsonArray.map { it.jsonObject }
            .first { it.getValue("name").jsonPrimitive.content == "public-candidate-shared-exit-class" }
        val graph = graph(vector)
        assertEquals(listOf("foreign", "inside", "ru"), graph.groupIDs())
        assertEquals(ExitClass.RU, graph.groupInfo("ru")?.intent)
        assertEquals(ExitClass.NON_RU, graph.groupInfo("foreign")?.intent)
        assertEquals(ExitClass.privateRoute, graph.groupInfo("inside")?.intent)
        for (mode in NetworkMode.entries) {
            assertTrue(graph.isDeclaredPath("ru", mode, listOf("public")))
            assertTrue(graph.isDeclaredPath("foreign", mode, listOf("public")))
            assertFalse(graph.isDeclaredPath("inside", mode, listOf("public")))
        }
        assertEquals(3, ExitClass.entries.size)
        val raw = vector.getValue("graph").toString()
        val unknownIntent = raw.replace("\"intent\":\"RU\"", "\"intent\":\"PUBLIC\"")
        rejected(unknownIntent.toByteArray(), listOf("public"))
        val nullExit = RouteGraph.decode(raw.replace("\"exitClass\":\"PUBLIC\"", "\"exitClass\":null").toByteArray(), listOf("public"))
        for (group in graph.groupIDs()) assertFalse(nullExit.isDeclaredPath(group, NetworkMode.WIFI, listOf("public")))
    }

    @Test fun groupInfoReturnsOwnedBoundedDeclarations() {
        val raw="""{"schemaVersion":1,"hops":[{"id":"entry","entryModes":["WIFI"],"exitClass":null,"features":["TCP","IPV4"]},{"id":"exit","entryModes":["WIFI"],"exitClass":"INTERNAL","features":["TCP","IPV4"]}],"edges":[{"from":"entry","to":"exit","features":["TCP","IPV4"]}],"templates":[{"id":"two","slots":[["entry"],["exit"]]},{"id":"one","slots":[["exit"]]}],"groups":[{"id":"inside","intent":"INTERNAL","features":["TCP","IPV4"],"templates":["two","one"]}]}"""
        val graph=RouteGraph.decode(raw.toByteArray(),listOf("entry","exit"))
        val info=checkNotNull(graph.groupInfo("inside"))
        assertEquals(ExitClass.valueOf("INTERNAL"),info.intent)
        assertEquals(2,info.upperBound);assertEquals(2,info.maxHops)
        assertEquals(setOf(PathFeature.TCP,PathFeature.IPV4),info.features)
        try {(info.features as MutableSet<PathFeature>).clear()}
        catch (_:UnsupportedOperationException) {} catch (_:ClassCastException) {}
        assertEquals(setOf(PathFeature.TCP,PathFeature.IPV4),checkNotNull(graph.groupInfo("inside")).features)
        assertTrue(graph.isDeclaredPath("inside",NetworkMode.WIFI,listOf("entry","exit")))
        assertTrue(graph.isDeclaredPath("inside",NetworkMode.WIFI,listOf("exit")))
        assertNull(graph.groupInfo("unknown"))
        assertEquals("RouteGroupInfo([redacted])",info.toString())
    }
    private val context = Context(1, 2, "policy", "algorithm", 3, "a".repeat(64))
    private fun fixture(): JsonObject = Decision.json.parseToJsonElement(
        requireNotNull(javaClass.getResourceAsStream("/route-graph-vectors.json")).use {
            it.readBytes().toString(Charsets.UTF_8)
        }
    ).jsonObject
    private fun JsonElement.strings() = jsonArray.map { it.jsonPrimitive.content }
    private fun graph(value: JsonObject): RouteGraph = RouteGraph.decode(
        value.getValue("graph").toString().toByteArray(), value.getValue("catalogue").strings()
    )
    private fun rejected(raw: ByteArray, ids: List<String>, label: String = "invalid graph") {
        val failure = assertThrows(label, IllegalArgumentException::class.java) { RouteGraph.decode(raw, ids) }
        assertEquals("invalid_route_graph", failure.message)
        assertNull(failure.cause)
    }

    @Test fun sharedGraphQueriesAndBoundsAgreeWithGo() {
        val cases = fixture().getValue("validCases").jsonArray
        assertTrue(cases.isNotEmpty())
        for (element in cases) {
            val vector = element.jsonObject
            val graph = graph(vector)
            for ((id, bound) in vector.getValue("groupBounds").jsonObject) {
                assertEquals(bound.jsonPrimitive.int, graph.upperBound(id))
            }
            for ((intent, bound) in vector.getValue("intentBounds").jsonObject) {
                assertEquals(bound.jsonPrimitive.int, graph.intentUpperBound(ExitClass.valueOf(intent)))
            }
            for (query in vector.getValue("queries").jsonArray) {
                val q = query.jsonObject
                assertEquals(q.getValue("name").jsonPrimitive.content, q.getValue("allowed").jsonPrimitive.boolean,
                    graph.isDeclaredPath(q.getValue("group").jsonPrimitive.content,
                        NetworkMode.valueOf(q.getValue("mode").jsonPrimitive.content), q.getValue("path").strings()))
            }
            assertNull(graph.upperBound("missing"))
        }
    }

    @Test fun sharedMalformedGraphsNeverAcquirePartialAuthority() {
        val cases = fixture().getValue("invalidCases").jsonArray
        assertTrue(cases.size >= 60)
        for (element in cases) {
            val v = element.jsonObject
            rejected(v.getValue("raw").jsonPrimitive.content.toByteArray(), v.getValue("catalogue").strings(),
                v.getValue("name").jsonPrimitive.content)
        }
    }

    private fun enumerate(frontier: RouteFrontier): List<PlannedPath> {
        val result = mutableListOf<PlannedPath>()
        var examined = 0
        repeat(5000) {
            val batch = frontier.next(context, 100L + it, 1, 1)
            assertFalse(batch.invalidated)
            assertTrue(batch.examined - examined in 0..1)
            examined = batch.examined
            result.addAll(batch.paths)
            if (batch.exhausted) {
                assertEquals(batch.upperBound, batch.examined)
                assertEquals(result.size, result.map { it.id }.toSet().size)
                return result
            }
        }
        error("finite graph scan did not finish")
    }

    @Test fun graphFrontierEnumeratesOnlyBoundGroupPathsWithStableIDs() {
        for (element in fixture().getValue("validCases").jsonArray) {
            val v = element.jsonObject
            val graph = graph(v)
            for (enumeration in v.getValue("enumerations").jsonArray) {
                val row = enumeration.jsonObject
                val group = row.getValue("group").jsonPrimitive.content
                val mode = NetworkMode.valueOf(row.getValue("mode").jsonPrimitive.content)
                val paths = enumerate(graph.frontier(group, context, mode, emptyList(), 100, 600_000))
                assertEquals(row.getValue("paths").jsonArray.map { it.strings() }, paths.map { it.hops })
                for (path in paths) {
                    assertTrue(graph.isDeclaredPath(group, mode, path.hops))
                    val query = v.getValue("queries").jsonArray.map { it.jsonObject }.first {
                        it.getValue("allowed").jsonPrimitive.boolean && it.getValue("group").jsonPrimitive.content == group &&
                            it.getValue("mode").jsonPrimitive.content == mode.name && it.getValue("path").strings() == path.hops
                    }
                    assertEquals(query.getValue("pathId").jsonPrimitive.content, path.id)
                }
            }
        }
    }

    @Test fun graphWarmHintDoesNotBypassModeTemplateExpiryOrContext() {
        val g = graph(fixture().getValue("validCases").jsonArray.first().jsonObject)
        val long = listOf("entry", "transit", "exit-a")
        val f = g.frontier("foreign", context, NetworkMode.CELLULAR_RESTRICTED,
            listOf(listOf("home"), long), 100, 1000)
        assertEquals(listOf(long), f.next(context, 100, 1, 1).paths.map { it.hops })
        assertEquals(listOf(listOf("entry", "exit-b")), enumerate(f).map { it.hops })
        val restricted = g.frontier("foreign-three", context, NetworkMode.CELLULAR_RESTRICTED,
            listOf(listOf("entry", "exit-b")), 100, 1000)
        assertEquals(listOf(long), enumerate(restricted).map { it.hops })
        val expired = g.frontier("foreign", context, NetworkMode.WIFI, emptyList(), 100, 10)
        assertTrue(expired.next(context, 110, 1, 1).invalidated)
        val changed = g.frontier("foreign", context, NetworkMode.WIFI, emptyList(), 100, 10)
        assertTrue(changed.next(context.copy(networkEpoch = 2), 100, 1, 1).invalidated)
        assertTrue(changed.next(context, 101, 1, 1).invalidated)
        assertThrows(IllegalStateException::class.java) {
            g.frontier("missing", context, NetworkMode.WIFI, emptyList(), 100, 10)
        }
    }

    private fun synthetic(count: Int, widths: List<Int>): Pair<JsonObject, List<String>> {
        val ids = (0 until count).map { "node-%03d".format(it) }
        fun strings(values: List<String>) = JsonArray(values.map(::JsonPrimitive))
        val raw = buildJsonObject {
            put("schemaVersion", 1)
            put("hops", JsonArray(ids.map { id -> buildJsonObject {
                put("id", id); put("entryModes", strings(listOf("WIFI")))
                put("exitClass", "NON_RU"); put("features", strings(listOf("TCP", "IPV4")))
            } }))
            put("edges", JsonArray(emptyList()))
            put("templates", JsonArray(listOf(buildJsonObject {
                put("id", "wide"); put("slots", JsonArray(widths.map { strings(ids.take(it)) }))
            })))
            put("groups", JsonArray(listOf(buildJsonObject {
                put("id", "foreign"); put("intent", "NON_RU")
                put("features", strings(listOf("TCP", "IPV4"))); put("templates", strings(listOf("wide")))
            })))
        }
        return raw to ids
    }

    @Test fun exactCatalogueAndCandidateBoundaryCannotBeTruncated() {
        val (raw, ids) = synthetic(500, listOf(16, 16, 16))
        val g = RouteGraph.decode(raw.toString().toByteArray(), ids)
        assertEquals(4096, g.upperBound("foreign"))
        assertEquals(4096, g.intentUpperBound(ExitClass.NON_RU))
        for (widths in listOf(listOf(17, 16, 16), listOf(500, 500, 500, 500))) {
            rejected(synthetic(500, widths).first.toString().toByteArray(), ids)
        }
        val over = synthetic(501, listOf(1))
        rejected(over.first.toString().toByteArray(), over.second)
        val one = synthetic(1, listOf(1))
        assertTrue(RouteGraph.decode(one.first.toString().toByteArray(), one.second)
            .isDeclaredPath("foreign", NetworkMode.WIFI, one.second))
    }

    @Test fun perIntentBoundDeduplicatesSharedTemplatesAndRejectsSplitOverflow() {
        val (base, ids) = synthetic(16, listOf(16, 16, 16))
        val group = base.getValue("groups").jsonArray.first().jsonObject
        val second = JsonObject(group + ("id" to JsonPrimitive("second")))
        val same = JsonObject(base + ("groups" to JsonArray(listOf(group, second))))
        assertEquals(4096, RouteGraph.decode(same.toString().toByteArray(), ids).intentUpperBound(ExitClass.NON_RU))
        val extra = buildJsonObject {
            put("id", "extra"); put("slots", JsonArray(listOf(JsonArray(listOf(JsonPrimitive(ids.first()))))))
        }
        val templates = JsonArray(base.getValue("templates").jsonArray + extra)
        for (singleGroup in listOf(true, false)) {
            val extraGroup = JsonObject(second + ("templates" to JsonArray(listOf(JsonPrimitive("extra")))))
            val combinedRefs = JsonArray(listOf(JsonPrimitive("wide"), JsonPrimitive("extra")))
            val combinedGroup = JsonObject(group + ("templates" to combinedRefs))
            val groups = JsonArray(if (singleGroup) listOf(combinedGroup) else listOf(group, extraGroup))
            rejected(JsonObject(base + ("templates" to templates) + ("groups" to groups)).toString().toByteArray(), ids)
        }
    }

    @Test fun utf8ByteLimitsAndOwnedMetadataSurviveCallerMutation() {
        val v = fixture().getValue("validCases").jsonArray.first().jsonObject
        val ids = v.getValue("catalogue").strings().toMutableList()
        val raw = v.getValue("graph").toString().toByteArray()
        val padded = raw + ByteArray(RouteGraph.MAX_BYTES - raw.size) { 32 }
        val g = RouteGraph.decode(padded, ids)
        rejected(padded + byteArrayOf(32), ids)
        rejected(byteArrayOf(0xff.toByte()), ids)
        rejected(byteArrayOf(), ids)
        val original = g.groupIDs()
        val exposed = g.groupIDs()
        if (exposed is MutableList) exposed[0] = "changed"
        padded.fill(0); ids.fill("changed")
        assertEquals(original, g.groupIDs())
        assertTrue(g.isDeclaredPath("foreign", NetworkMode.WIFI, listOf("exit-b")))
        assertEquals("RouteGraph(hops=5,groups=5)", g.toString())
    }
}
