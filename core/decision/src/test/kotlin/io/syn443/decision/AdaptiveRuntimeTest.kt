package io.syn443.decision

import java.security.MessageDigest
import java.util.Base64
import kotlinx.serialization.json.*
import org.junit.Assert.*
import org.junit.Test

class AdaptiveRuntimeTest {
    private data class Input(val graph: String, val catalogue: String, val groups: String = "{\"inside\":\"managed-inside\"}")
    private fun canonical(value: JsonElement): String = when (value) {
        is JsonObject -> value.toSortedMap().entries.joinToString(",", "{", "}") { (key, child) -> JsonPrimitive(key).toString() + ":" + canonical(child) }
        is JsonArray -> value.joinToString(",", "[", "]", transform = ::canonical)
        else -> value.toString()
    }
    private fun canon(raw: String): String = canonical(Decision.json.parseToJsonElement(raw))
    private fun b64(raw: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(raw)
    private fun wire(input: Input): ByteArray = wireB64(b64(input.graph.toByteArray()), b64(input.catalogue.toByteArray()), input.groups)
    private fun wireB64(graph: String, catalogue: String, groups: String): ByteArray =
        "{\"catalogueB64\":\"$catalogue\",\"graphB64\":\"$graph\",\"groups\":$groups,\"schemaVersion\":1}".toByteArray()
    private fun digest(raw: ByteArray) = MessageDigest.getInstance("SHA-256").digest(raw).joinToString("") { "%02x".format(it.toInt() and 255) }
    private fun profile(id: String = "hop-000", port: Int = 2000, type: String = "http", fields: String = ""): String =
        canon("{\"server\":\"192.0.2.1\",\"server_port\":$port,\"tag\":\"$id\",\"type\":\"$type\"$fields}")
    private fun fixture(count: Int = 1): Input {
        val ids = (0 until count).map { "hop-%03d".format(it) }
        val catalogue = ids.mapIndexed { i, id -> JsonPrimitive(id).toString() + ":" + profile(id, 2000 + i) }.joinToString(",", "{", "}")
        val graph = buildJsonObject {
            put("schemaVersion", 1)
            put("hops", JsonArray(ids.map { id -> buildJsonObject {
                put("id", id); put("entryModes", JsonArray(listOf(JsonPrimitive("WIFI"))))
                put("exitClass", "INTERNAL"); put("features", JsonArray(listOf(JsonPrimitive("TCP"), JsonPrimitive("IPV4"))))
            } }))
            put("edges", JsonArray(emptyList()))
            put("templates", JsonArray(listOf(buildJsonObject {
                put("id", "single"); put("slots", JsonArray(listOf(JsonArray(ids.map(::JsonPrimitive)))))
            })))
            put("groups", JsonArray(listOf(buildJsonObject {
                put("id", "inside"); put("intent", "INTERNAL")
                put("features", JsonArray(listOf(JsonPrimitive("TCP"), JsonPrimitive("IPV4"))))
                put("templates", JsonArray(listOf(JsonPrimitive("single"))))
            })))
        }
        return Input(canonical(graph), catalogue)
    }
    private fun withProfile(input: Input, raw: String): Input = input.copy(catalogue = "{\"hop-000\":$raw}")
    private fun reject(raw: ByteArray) {
        val failure = assertThrows(IllegalArgumentException::class.java) { AdaptiveRuntime.decode(raw) }
        assertEquals("invalid_adaptive_runtime", failure.message)
        assertNull(failure.cause)
    }

    @Test fun closedWireOwnsCanonicalProfilesMappingsAndHash() {
        val input = fixture(2)
        val raw = wire(input)
        val expected = raw.copyOf()
        val value = AdaptiveRuntime.decode(raw)
        assertEquals(digest(expected), value.hash)
        assertArrayEquals(expected, value.canonicalWire())
        assertArrayEquals(input.graph.toByteArray(), value.graphBytes())
        assertEquals(listOf("hop-000", "hop-001"), value.catalogueIDs())
        assertEquals(mapOf("inside" to "managed-inside"), value.groupTags())
        assertTrue(value.graph.isDeclaredPath("inside", NetworkMode.WIFI, listOf("hop-001")))
        raw.fill(33); value.canonicalWire().fill(33); value.graphBytes().fill(33)
        value.catalogueProfiles().getValue("hop-000").fill(33)
        try { (value.groupTags() as MutableMap<String, String>)["inside"] = "changed" } catch (_: UnsupportedOperationException) { }
        assertArrayEquals(expected, value.canonicalWire())
        assertArrayEquals(profile().toByteArray(), value.catalogueProfiles().getValue("hop-000"))
        assertEquals("managed-inside", value.groupTags()["inside"])
        assertEquals("AdaptiveRuntime([redacted])", value.toString())
        assertFalse(value.toString().contains(value.hash))
        val formatted = input.copy(graph = input.graph.replace(",", ",\n").replace("{", "{\n"))
        val other = AdaptiveRuntime.decode(" \n".toByteArray() + wire(formatted) + "\t\r\n".toByteArray())
        assertEquals(value.hash, other.hash)
        assertArrayEquals(expected, other.canonicalWire())
    }

    @Test fun strictShapeAndCanonicalBase64CannotBeCoerced() {
        val input = fixture()
        val text = wire(input).toString(Charsets.UTF_8)
        for (raw in listOf(byteArrayOf(), "null".toByteArray(), "[]".toByteArray(), "{}".toByteArray(),
            (text + "null").toByteArray(), (text + ",").toByteArray(), byteArrayOf(0xff.toByte()) + text.toByteArray(),
            text.replace("\"schemaVersion\":1", "\"schemaVersion\":1,\"schemaVersion\":1").toByteArray(),
            text.replace("\"schemaVersion\":1", "\"schemaVersion\":1,\"\\u0073chemaVersion\":1").toByteArray(),
            text.replace("\"graphB64\"", "\"GraphB64\"").toByteArray(),
        )) reject(raw)
        val root = Decision.json.parseToJsonElement(text).jsonObject
        for (key in listOf("schemaVersion", "graphB64", "catalogueB64", "groups")) {
            reject(canonical(JsonObject(root - key)).toByteArray())
            for (wrong in listOf(JsonNull, JsonPrimitive(true), JsonPrimitive("1"), Decision.json.parseToJsonElement("1.0"), JsonArray(emptyList()))) {
                reject(canonical(JsonObject(root + (key to wrong))).toByteArray())
            }
        }
        reject(canonical(JsonObject(root + ("extra" to JsonPrimitive("field")))).toByteArray())
        for (bad in listOf("", "!", "Zg==", "Zg\n", "Zh", "Zg+", "Zg/")) {
            for (key in listOf("graphB64", "catalogueB64")) reject(canonical(JsonObject(root + (key to JsonPrimitive(bad)))).toByteArray())
        }
        reject(wireB64(b64(byteArrayOf(0xff.toByte())), b64(input.catalogue.toByteArray()), input.groups))
        reject(wireB64(b64(input.graph.toByteArray()), b64(byteArrayOf(0xff.toByte())), input.groups))
        for (number in listOf("1e0", "1E+0", "01", "1.", "1e", "+1", "-1")) {
            reject(text.replace("\"schemaVersion\":1", "\"schemaVersion\":$number").toByteArray())
        }
        reject(wire(input.copy(graph = input.graph.replace("\"schemaVersion\":1", "\"schemaVersion\":1,\"\\u0073chemaVersion\":1"))))
        reject(wire(input.copy(graph = input.graph.replace("\"schemaVersion\"", "\"SchemaVersion\""))))
    }

    @Test fun catalogueAndGroupGuardsRejectUnsafeOrUnboundInputs() {
        val input = fixture(2)
        val nullable = Decision.json.parseToJsonElement(input.graph).jsonObject.toMutableMap()
        val hops = nullable.getValue("hops").jsonArray.toMutableList()
        hops[0] = JsonObject(hops[0].jsonObject + ("exitClass" to JsonNull))
        nullable["hops"] = JsonArray(hops)
        nullable["edges"] = Decision.json.parseToJsonElement("[{\"from\":\"hop-000\",\"to\":\"hop-001\",\"features\":[\"TCP\",\"IPV4\"]}]")
        nullable["templates"] = Decision.json.parseToJsonElement("[{\"id\":\"single\",\"slots\":[[\"hop-000\"],[\"hop-001\"]]}]")
        assertTrue(AdaptiveRuntime.decode(wire(input.copy(graph = canonical(JsonObject(nullable))))).graph
            .isDeclaredPath("inside", NetworkMode.WIFI, listOf("hop-000", "hop-001")))
        for (mutation in listOf("tag", "type", "port-string", "port-zero", "port-high", "server-empty", "detour", "unknown", "case", "null", "tls-insecure", "tls-disabled", "tls-file", "utls-file", "reality-file", "ssh-no-pin", "ssh-file", "alias")) {
            val catalogue = Decision.json.parseToJsonElement(input.catalogue).jsonObject.toMutableMap()
            val node = catalogue.getValue("hop-000").jsonObject.toMutableMap()
            when (mutation) {
                "tag" -> node["tag"] = JsonPrimitive("wrong")
                "type" -> node["type"] = JsonPrimitive("direct")
                "port-string" -> node["server_port"] = JsonPrimitive("443")
                "port-zero" -> node["server_port"] = JsonPrimitive(0)
                "port-high" -> node["server_port"] = JsonPrimitive(65536)
                "server-empty" -> node["server"] = JsonPrimitive("")
                "detour" -> node["detour"] = JsonPrimitive("direct")
                "unknown" -> node["unexpected"] = JsonPrimitive("value")
                "case" -> node["Type"] = JsonPrimitive("http")
                "null" -> node["password"] = JsonNull
                "tls-insecure" -> node["tls"] = Decision.json.parseToJsonElement("{\"enabled\":true,\"insecure\":true}")
                "tls-disabled" -> node["tls"] = Decision.json.parseToJsonElement("{\"enabled\":false}")
                "tls-file" -> node["tls"] = Decision.json.parseToJsonElement("{\"enabled\":true,\"certificate_path\":\"/fixture/file\"}")
                "utls-file" -> node["tls"] = Decision.json.parseToJsonElement("{\"enabled\":true,\"utls\":{\"enabled\":true,\"path\":\"/fixture/file\"}}")
                "reality-file" -> node["tls"] = Decision.json.parseToJsonElement("{\"enabled\":true,\"reality\":{\"enabled\":true,\"private_key_path\":\"/fixture/file\"}}")
                "ssh-no-pin" -> node["type"] = JsonPrimitive("ssh")
                "ssh-file" -> { node["type"] = JsonPrimitive("ssh"); node["host_key"] = JsonArray(listOf(JsonPrimitive("fixture-key"))); node["private_key_path"] = JsonPrimitive("/fixture/file") }
                "alias" -> catalogue["hop-001"] = JsonObject(catalogue.getValue("hop-001").jsonObject + ("server_port" to node.getValue("server_port")))
            }
            catalogue["hop-000"] = JsonObject(node)
            reject(wire(input.copy(catalogue = canonical(JsonObject(catalogue)))))
        }
        reject(wire(input.copy(catalogue = " " + input.catalogue)))
        val single = fixture()
        val rawProfile = profile()
        reject(wire(single.copy(catalogue = "{\"hop-000\":$rawProfile,\"\\u0068op-000\":$rawProfile}")))
        reject(wire(input.copy(catalogue = single.catalogue)))
        reject(wire(input.copy(graph = input.graph.replace("\"id\":\"hop-001\"", "\"id\":\"missing\""))))
        for (groups in listOf("{}", "{\"other\":\"managed-inside\"}", "{\"inside\":\"managed-inside\",\"extra\":\"managed-extra\"}")) reject(wire(input.copy(groups = groups)))
        for (tag in listOf("direct", "syn443_control", "", "Uppercase", "dot.tag", "has space", "-invalid", "x".repeat(65))) {
            reject(wire(input.copy(groups = "{\"inside\":${JsonPrimitive(tag)}}")))
        }
        assertEquals("managed_inside", AdaptiveRuntime.decode(wire(single.copy(groups = "{\"inside\":\"managed_inside\"}"))).groupTags()["inside"])
        // These are basic normalized shapes, not acceptance of an actual SDK,
        // transport, certificate or SSH handshake.
        for (raw in listOf(
            profile(type = "socks", fields = ",\"version\":\"5\""),
            profile(type = "ssh", fields = ",\"host_key\":[\"fixture-key\"],\"user\":\"fixture\""),
            profile(fields = ",\"tls\":{\"enabled\":true,\"insecure\":false,\"utls\":{\"enabled\":true,\"fingerprint\":\"chrome\"}}"),
            profile(type = "vless", fields = ",\"tls\":{\"enabled\":true,\"reality\":{\"enabled\":true,\"public_key\":\"fixture-public\",\"short_id\":\"00\"}}"),
        )) assertEquals(1, AdaptiveRuntime.decode(wire(withProfile(single, raw))).catalogueIDs().size)
    }

    @Test fun goCanonicalStringsAndNumberLexemesArePreserved() {
        val input = fixture()
        val escaped = "\\u003c\\u003e\\u0026\\u2028\\u2029\\b\\f\\n\\r\\t\\u0000\\\"\\\\/"
        val goProfile = profile().dropLast(1) + ",\"username\":\"$escaped\"}"
        val value = AdaptiveRuntime.decode(wire(withProfile(input, goProfile)))
        assertArrayEquals(goProfile.toByteArray(), value.catalogueProfiles().getValue("hop-000"))
        reject(wire(withProfile(input, goProfile.replace("\\u003c", "<"))))
        reject(wire(withProfile(input, goProfile.replace("\\u2028", "\u2028"))))
        reject(wire(withProfile(input, profile().dropLast(1) + ",\"username\":\"\\ud800\"}")))
        // Only wire shape is asserted here; transport-specific engine validation
        // remains mandatory before any adapter can be constructed.
        val unicodeKeys = "{\"\ue000\":1e0,\"\ud800\udc00\":-0.0}"
        val numbers = "{\"server\":\"192.0.2.1\",\"server_port\":2000,\"tag\":\"hop-000\",\"transport\":{\"data\":$unicodeKeys,\"type\":\"ws\"},\"type\":\"vless\"}"
        val numeric = AdaptiveRuntime.decode(wire(withProfile(input, numbers)))
        assertArrayEquals(numbers.toByteArray(), numeric.catalogueProfiles().getValue("hop-000"))
        val changed = AdaptiveRuntime.decode(wire(withProfile(input, numbers.replace("1e0", "1.0"))))
        assertNotEquals(numeric.hash, changed.hash)
    }

    @Test fun fiveHundredProfilesFitWithoutTruncation() {
        val input = fixture(500)
        val raw = wire(input)
        assertTrue(raw.size <= AdaptiveRuntime.MAX_WIRE_BYTES)
        val value = AdaptiveRuntime.decode(raw)
        assertEquals(500, value.catalogueIDs().size)
        assertEquals(500, value.graph.upperBound("inside"))
        assertTrue(value.graph.isDeclaredPath("inside", NetworkMode.WIFI, listOf("hop-499")))
        reject(wire(fixture(501)))
    }

    @Test fun wholeWireAndPerProfileByteBoundariesRemainExact() {
        val input = fixture()
        val raw = wire(input)
        val exact = raw + ByteArray(AdaptiveRuntime.MAX_WIRE_BYTES - raw.size) { 32 }
        assertArrayEquals(raw, AdaptiveRuntime.decode(exact).canonicalWire())
        reject(exact + byteArrayOf(32))
        val empty = profile(fields = ",\"username\":\"\"")
        val count = 65536 - empty.toByteArray().size
        val maxProfile = empty.replace("\"username\":\"\"", "\"username\":\"${"p".repeat(count)}\"")
        assertEquals(65536, maxProfile.toByteArray().size)
        assertEquals(65536, AdaptiveRuntime.decode(wire(withProfile(input, maxProfile))).catalogueProfiles().getValue("hop-000").size)
        reject(wire(withProfile(input, maxProfile.replace("\"username\":\"p", "\"username\":\"pp"))))
    }

    @Test fun dedicatedParserBoundsDepthArraysObjectsAndSharedTokens() {
        val input = fixture()
        fun transport(data: String): ByteArray = wire(withProfile(input,
            "{\"server\":\"192.0.2.1\",\"server_port\":2000,\"tag\":\"hop-000\",\"transport\":{\"data\":$data,\"type\":\"ws\"},\"type\":\"vless\"}"))
        AdaptiveRuntime.decode(transport("[".repeat(13) + "0" + "]".repeat(13)))
        reject(transport("[".repeat(14) + "0" + "]".repeat(14)))
        AdaptiveRuntime.decode(transport(List(256) { "0" }.joinToString(",", "[", "]")))
        reject(transport(List(257) { "0" }.joinToString(",", "[", "]")))
        fun members(count: Int) = (0 until count).joinToString(",", "{", "}") { "\"key-%03d\":0".format(it) }
        AdaptiveRuntime.decode(transport(members(128)))
        reject(transport(members(129)))
        fun wide(width: Int): String {
            val row = List(width) { "0" }.joinToString(",", "[", "]")
            return List(256) { row }.joinToString(",", "[", "]")
        }
        AdaptiveRuntime.decode(transport(wide(125)))
        reject(transport(wide(126)))
        reject(transport("{\"key\":1,\"\\u006bey\":2}"))
        reject(transport("null"))
    }

    @Test fun publicGraphKeepsSeparateGroupMappingsAndNoObservedExitAuthority() {
        val shared = requireNotNull(javaClass.getResourceAsStream("/route-graph-vectors.json")).use {
            Decision.json.parseToJsonElement(it.readBytes().toString(Charsets.UTF_8)).jsonObject
        }
        val graph = shared.getValue("validCases").jsonArray.map { it.jsonObject }
            .first { it.getValue("name").jsonPrimitive.content == "public-candidate-shared-exit-class" }.getValue("graph")
        val input = Input(canonical(graph), "{\"public\":${profile(id = "public")}}", "{\"foreign\":\"managed-foreign\",\"inside\":\"managed-inside\",\"ru\":\"managed-ru\"}")
        val value = AdaptiveRuntime.decode(wire(input))
        for (mode in NetworkMode.entries) {
            assertTrue(value.graph.isDeclaredPath("ru", mode, listOf("public")))
            assertTrue(value.graph.isDeclaredPath("foreign", mode, listOf("public")))
            assertFalse(value.graph.isDeclaredPath("inside", mode, listOf("public")))
        }
        assertEquals(3, ExitClass.entries.size)
        reject(wire(input.copy(groups = "{\"foreign\":\"managed-ru\",\"inside\":\"managed-inside\",\"ru\":\"managed-ru\"}")))
        val single = fixture()
        val tree = Decision.json.parseToJsonElement(single.graph).jsonObject
        fun groups(count: Int): Input {
            val rows = (0 until count).map { i -> JsonObject(tree.getValue("groups").jsonArray.single().jsonObject + ("id" to JsonPrimitive("group-%02d".format(i)))) }
            val tags = (0 until count).associate { "group-%02d".format(it) to JsonPrimitive("managed_group_%02d".format(it)) }
            return single.copy(graph = canonical(JsonObject(tree + ("groups" to JsonArray(rows)))), groups = canonical(JsonObject(tags)))
        }
        assertEquals(16, AdaptiveRuntime.decode(wire(groups(16))).groupTags().size)
        reject(wire(groups(17)))
    }
}
