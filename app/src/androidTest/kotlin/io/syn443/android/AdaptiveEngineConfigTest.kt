package io.syn443.android

import io.syn443.android.vpn.EngineConfig
import io.syn443.decision.AdaptiveRuntime
import java.io.File
import java.util.Base64
import kotlinx.serialization.json.*
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

/** In-memory validation/rendering only: no SDK, phone settings, enrollment or
 * provider traffic. A validated shape is not a successful TLS/SSH handshake. */
class AdaptiveEngineConfigTest {
    private val uuid = "00000000-0000-4000-8000-000000000001"
    private fun canonical(value: JsonElement): String = when (value) {
        is JsonObject -> value.toSortedMap().entries.joinToString(",", "{", "}") { (key, child) -> JsonPrimitive(key).toString() + ":" + canonical(child) }
        is JsonArray -> value.joinToString(",", "[", "]", transform = ::canonical)
        else -> value.toString()
    }
    private fun canonical(value: JSONObject): String = canonical(Json.parseToJsonElement(value.toString()))
    private fun b64(raw: String) = Base64.getUrlEncoder().withoutPadding().encodeToString(raw.toByteArray(Charsets.UTF_8))
    private fun profile(id: String, port: Int): JSONObject = JSONObject().put("type", "http").put("tag", id).put("server", "192.0.2.1").put("server_port", port)
    private fun setting(count: Int = 1, intent: String = "INTERNAL", chain: Boolean = false): JSONObject {
        val ids = (0 until count).map { "hop-%03d".format(it) }
        val catalogue = JSONObject()
        val hops = JSONArray()
        for ((i, id) in ids.withIndex()) {
            catalogue.put(id, profile(id, 2000 + i))
            hops.put(JSONObject().put("id", id).put("entryModes", JSONArray().put("WIFI"))
                .put("exitClass", if (chain && i < ids.lastIndex) JSONObject.NULL else intent)
                .put("features", JSONArray().put("TCP").put("IPV4")))
        }
        val edges = JSONArray()
        if (chain) for ((from, to) in ids.zipWithNext()) edges.put(JSONObject().put("from", from).put("to", to).put("features", JSONArray().put("TCP").put("IPV4")))
        val slots = if (chain) JSONArray(ids.map { JSONArray().put(it) }) else JSONArray().put(JSONArray(ids))
        val graph = JSONObject().put("schemaVersion", 1).put("hops", hops).put("edges", edges)
            .put("templates", JSONArray().put(JSONObject().put("id", "one").put("slots", slots)))
            .put("groups", JSONArray().put(JSONObject().put("id", "inside").put("intent", intent)
                .put("features", JSONArray().put("TCP").put("IPV4")).put("templates", JSONArray().put("one"))))
        val wire = JSONObject().put("schemaVersion", 1).put("graphB64", b64(canonical(graph))).put("catalogueB64", b64(canonical(catalogue)))
            .put("groups", JSONObject().put("inside", "managed-inside"))
        val check = if (intent == "INTERNAL") JSONObject().put("method", "tcp").put("target", "192.0.2.7:22")
            else JSONObject().put("method", "https_exit_country").put("target", "https://country.example.invalid/").put("expected_exit_class", intent)
        return JSONObject().put("outbounds", JSONArray().put(JSONObject().put("type", "syn443-adaptive").put("tag", "managed-inside").put("group", "inside"))
            .put(JSONObject().put("type", "direct").put("tag", "direct")))
            .put("route", JSONObject().put("final", "managed-inside"))
            .put("route_checks", JSONArray().put(JSONObject().put("outbound", "managed-inside").put("required", true).put("checks", JSONArray().put(check))))
            .put("adaptive_routes", wire)
    }
    private fun payload(config: JSONObject, field: String): JSONObject = JSONObject(String(Base64.getUrlDecoder().decode(config.getJSONObject("adaptive_routes").getString(field)), Charsets.UTF_8))
    private fun payload(config: JSONObject, field: String, value: JSONObject) { config.getJSONObject("adaptive_routes").put(field, b64(canonical(value))) }
    private fun reject(raw: String) {
        val failure = assertThrows(IllegalArgumentException::class.java) { EngineConfig.validate(raw) }
        assertEquals("invalid_adaptive_engine_config", failure.message)
        assertNull(failure.cause)
    }
    private fun reject(config: JSONObject) = reject(config.toString())

    @Test fun managedCatalogueValidatesEveryProtocolAndRetainsNativeExtractionMetadata() {
        val config = setting(4)
        val catalogue = payload(config, "catalogueB64")
        catalogue.getJSONObject("hop-001").put("type", "socks").put("version", "5")
        catalogue.getJSONObject("hop-002").put("type", "vless").put("uuid", uuid).put("network", "tcp")
            .put("tls", JSONObject().put("enabled", true).put("server_name", "cover.example.invalid").put("insecure", false)
                .put("utls", JSONObject().put("enabled", true).put("fingerprint", "chrome"))
                .put("reality", JSONObject().put("enabled", true).put("public_key", "A".repeat(43)).put("short_id", "00aA")))
            .put("transport", JSONObject().put("type", "xhttp").put("host", "cover.example.invalid").put("path", "/transport").put("mode", "packet-up")
                .put("headers", JSONObject().put("X-Fixture", "bounded")))
        catalogue.getJSONObject("hop-003").put("type", "ssh").put("user", "fixture").put("password", "synthetic-pass")
            .put("host_key", JSONArray().put("ssh-ed25519 synthetic-public-host-key"))
        payload(config, "catalogueB64", catalogue)
        EngineConfig.validate(config.toString())
        EngineConfig.validateAssigned(config.toString())
        val raw = config.toString()
        val decoded = AdaptiveRuntime.decode(config.getJSONObject("adaptive_routes").toString().toByteArray())
        val rendered = JSONObject(EngineConfig.render(raw, File("/synthetic/state")))
        assertTrue(rendered.has("adaptive_routes")); assertTrue(rendered.has("route_checks"))
        assertEquals(decoded.hash, AdaptiveRuntime.decode(rendered.getJSONObject("adaptive_routes").toString().toByteArray()).hash)
        assertEquals(4, decoded.catalogueIDs().size)
        assertEquals(1, rendered.getJSONArray("inbounds").length())
        assertTrue(rendered.getJSONObject("log").getBoolean("disabled"))
        assertEquals(raw, config.toString())
    }

    @Test fun managedMappingsChecksAndEnvelopeTypesFailClosed() {
        for (change in listOf<(JSONObject) -> Unit>(
            { it.remove("route_checks") },
            { it.getJSONArray("route_checks").getJSONObject(0).put("checks", JSONArray()) },
            { it.getJSONArray("route_checks").getJSONObject(0).put("checks", JSONArray(List(5) { JSONObject().put("method", "tcp").put("target", "192.0.2.7:22") })) },
            { it.getJSONArray("route_checks").getJSONObject(0).put("outbound", "direct") },
            { it.getJSONArray("route_checks").put(JSONObject(it.getJSONArray("route_checks").getJSONObject(0).toString())) },
            { it.getJSONArray("outbounds").getJSONObject(0).put("group", "other") },
            { it.getJSONArray("outbounds").getJSONObject(0).put("group", JSONObject.NULL) },
            { it.getJSONArray("outbounds").getJSONObject(0).put("Group", "inside") },
            { it.getJSONArray("outbounds").getJSONObject(0).put("detour", "direct") },
            { it.getJSONArray("outbounds").getJSONObject(0).put("default", "direct") },
            { it.getJSONArray("outbounds").getJSONObject(0).put("network", "udp") },
            { it.getJSONObject("adaptive_routes").put("groups", JSONObject().put("inside", "direct")) },
            { it.getJSONObject("adaptive_routes").put("groups", JSONObject().put("inside", "syn443_control")) },
            { it.getJSONObject("adaptive_routes").put("extra", "field") },
            { it.put("adaptive_routes", JSONObject.NULL) },
            { it.put("route_failover", JSONObject()) },
            { it.getJSONArray("outbounds").put(JSONObject().put("type", "urltest").put("tag", "legacy-test")) },
        )) reject(setting().also(change))
        val raw = setting().toString()
        reject(raw.replace("\"adaptive_routes\":", "\"Adaptive_routes\":"))
        reject(raw.replace("\"adaptive_routes\":", "\"adaptive_routes\":{},\"adaptive_routes\":"))
        reject(raw.replace("\"schemaVersion\":1", "\"schemaVersion\":1.0"))
        reject(raw.replace("\"schemaVersion\":1", "\"schemaVersion\":\"1\""))
        reject(raw.replace("\"schemaVersion\":1", "\"schemaVersion\":null"))
        val duplicateMember = raw.replace("\"group\":\"inside\"", "\"group\":\"inside\",\"\\u0067roup\":\"inside\"")
        val duplicate = assertThrows(Exception::class.java) { EngineConfig.validate(duplicateMember) }
        assertFalse(duplicate.message.orEmpty().contains("192.0.2.1"))
        for (intent in listOf("RU", "NON_RU")) {
            EngineConfig.validate(setting(intent = intent).toString())
            reject(setting(intent = intent).also { it.getJSONArray("route_checks").getJSONObject(0).getJSONArray("checks").getJSONObject(0).put("expected_exit_class", if (intent == "RU") "NON_RU" else "RU") })
            reject(setting(intent = intent).also { it.getJSONArray("route_checks").getJSONObject(0).put("checks", JSONArray().put(JSONObject().put("method", "https_204").put("target", "https://check.example.invalid/generate_204"))) })
        }
        reject(setting().also { it.getJSONArray("route_checks").getJSONObject(0).put("checks", JSONArray().put(JSONObject().put("method", "https_exit_country").put("target", "https://country.example.invalid/").put("expected_exit_class", "RU"))) })
        for (feature in listOf("UDP", "ICMP")) reject(setting().also { config ->
            val graph = payload(config, "graphB64")
            graph.getJSONArray("groups").getJSONObject(0).getJSONArray("features").put(feature)
            graph.getJSONArray("hops").getJSONObject(0).getJSONArray("features").put(feature)
            payload(config, "graphB64", graph)
        })
        reject(setting().also { config ->
            val graph = payload(config, "graphB64")
            graph.getJSONArray("groups").getJSONObject(0).put("features", JSONArray().put("IPV4"))
            payload(config, "graphB64", graph)
        })
    }

    @Test fun unsafeNormalizedCredentialsTlsSshAndTransportsCannotEnterAdaptiveCatalogue() {
        val mutations: List<(JSONObject) -> Unit> = listOf(
            { it.put("username", true) }, { it.put("password", 123) }, { it.put("password", "line\nbreak") },
            { it.put("server", "invalid host") }, { it.put("server_port", "443") },
            { it.put("detour", "direct") }, { it.put("private_key_path", "/fixture/key") },
            { it.put("tls", JSONObject().put("enabled", true).put("client_certificate_path", "/fixture/client.pem")) },
            { it.put("tls", JSONObject().put("enabled", true).put("certificate_path", "/fixture/cert.pem")) },
            { it.put("tls", JSONObject().put("enabled", true).put("insecure", true)) },
            { it.put("tls", JSONObject().put("enabled", true).put("utls", JSONObject().put("enabled", true).put("fingerprint", ""))) },
            { it.put("tls", JSONObject().put("enabled", true).put("reality", JSONObject().put("enabled", true).put("public_key", "invalid"))) },
            { it.put("tls", JSONObject().put("enabled", true).put("reality", JSONObject().put("enabled", true).put("public_key", "A".repeat(43)).put("short_id", "a"))) },
            { it.put("type", "vless").put("uuid", "invalid") },
            { it.put("type", "vless").put("uuid", uuid).put("network", "udp") },
            { it.put("type", "vless").put("uuid", uuid).put("transport", JSONObject().put("type", "xhttp").put("mode", "unsupported")) },
            { it.put("type", "vless").put("uuid", uuid).put("transport", JSONObject().put("type", "xhttp").put("headers", JSONObject().put("X-Fixture", "line\nbreak"))) },
            { it.put("type", "vless").put("uuid", uuid).put("transport", JSONObject().put("type", "ws").put("max_early_data", 1.5)) },
            { it.put("type", "socks").put("version", "6") },
            { it.put("type", "ssh").put("user", "fixture").put("password", "synthetic-pass").put("host_key", JSONArray().put(" ")) },
            { it.put("type", "ssh").put("user", "fixture").put("password", "synthetic-pass").put("host_key", JSONArray().put(123)) },
            { it.put("type", "ssh").put("user", "fixture").put("host_key", JSONArray().put("fixture-pin")) },
            { it.put("type", "netbird") },
        )
        for (change in mutations) reject(setting().also { config ->
            val catalogue = payload(config, "catalogueB64")
            change(catalogue.getJSONObject("hop-000")); payload(config, "catalogueB64", catalogue)
        })
        reject(setting(2).also { config ->
            val catalogue = payload(config, "catalogueB64")
            catalogue.getJSONObject("hop-001").put("server_port", 2000); payload(config, "catalogueB64", catalogue)
        })
    }

    @Test fun ordinaryDependenciesAndNetBirdKeepOwnedBoundedPaths() {
        fun extra(config: JSONObject, tag: String, detour: String): JSONObject {
            val node = profile(tag, 2443).put("type", "vless").put("uuid", uuid).put("detour", detour)
            config.getJSONArray("outbounds").put(node); return node
        }
        val prefix = setting(2, chain = true)
        extra(prefix, "after-one", "managed-inside"); extra(prefix, "after-two", "after-one")
        prefix.getJSONObject("route").put("final", "after-two")
        EngineConfig.validate(prefix.toString())
        reject(JSONObject(prefix.toString()).also { extra(it, "after-three", "after-two") })
        reject(setting().also { extra(it, "cycle", "cycle") })
        reject(setting().also { extra(it, "missing", "unknown") })
        val selector = setting().also { it.getJSONArray("outbounds").put(JSONObject().put("type", "selector").put("tag", "manual").put("outbounds", JSONArray().put("managed-inside")).put("default", "managed-inside")) }
        EngineConfig.validate(selector.toString())
        fun overlay(mode: String = "direct", detour: String? = null) = JSONObject().put("type", "netbird").put("tag", "overlay")
            .put("management_url", "https://control.example.invalid").put("connection_mode", mode).also { if (detour != null) it.put("detour", detour) }
        val direct = setting().also { it.getJSONArray("outbounds").put(overlay()) }
        EngineConfig.validate(direct.toString())
        val rendered = JSONObject(EngineConfig.render(direct.toString(), File("/synthetic/state")))
        assertEquals("direct", rendered.getJSONArray("outbounds").getJSONObject(2).getString("connection_mode"))
        assertTrue(rendered.getJSONArray("outbounds").getJSONObject(2).has("state_directory"))
        assertFalse(direct.getJSONArray("outbounds").getJSONObject(2).has("state_directory"))
        reject(setting().also { it.getJSONArray("outbounds").put(overlay("vless", "managed-inside")) })
        reject(setting().also { extra(it, "bridge", "managed-inside"); it.getJSONArray("outbounds").put(overlay("vless", "bridge")) })
        reject(JSONObject(selector.toString()).also { it.getJSONArray("outbounds").put(overlay("vless", "manual")) })
        reject(setting().also { it.getJSONArray("outbounds").put(overlay(detour = "direct")) })
        reject(setting().also { it.put("dns", JSONObject().put("servers", JSONArray().put(JSONObject().put("type", "https").put("detour", "managed-inside")))) })
    }

    @Test fun fiveHundredProfilesAndUtf8BoundsRemainExplicit() {
        val fiveHundred = setting(500).toString()
        assertTrue(fiveHundred.toByteArray().size <= 262144)
        EngineConfig.validateAssigned(fiveHundred)
        reject(setting(501))
        val raw = setting().toString()
        EngineConfig.validateAssigned(raw + " ".repeat(262144 - raw.toByteArray().size))
        reject(raw + " ".repeat(262145 - raw.toByteArray().size))
        reject(raw.replace("192.0.2.7:22", "bad\ud800"))
        val oversizedRegular = setting()
        repeat(62) { oversizedRegular.getJSONArray("outbounds").put(JSONObject().put("type", "direct").put("tag", "direct-$it")) }
        EngineConfig.validate(oversizedRegular.toString())
        oversizedRegular.getJSONArray("outbounds").put(JSONObject().put("type", "direct").put("tag", "overflow"))
        reject(oversizedRegular)
    }

    @Test fun renderCopiesAndLegacyBehaviorRemainUnchanged() {
        val raw = setting().toString()
        val original = JSONObject(raw)
        val first = JSONObject(EngineConfig.render(raw, File("/synthetic/state")))
        first.getJSONObject("adaptive_routes").getJSONObject("groups").put("inside", "changed")
        val next = JSONObject(EngineConfig.render(raw, File("/synthetic/state")))
        assertEquals("managed-inside", next.getJSONObject("adaptive_routes").getJSONObject("groups").getString("inside"))
        assertEquals(raw, original.toString())
        val legacy = """{"outbounds":[{"type":"http","tag":"ordinary"}],"route":{"final":"ordinary"},"route_checks":[{"outbound":"ordinary","checks":[{"method":"tcp","target":"192.0.2.7:22"}]}]}"""
        EngineConfig.validate(legacy)
        assertFalse(JSONObject(EngineConfig.render(legacy, File("/synthetic/state"))).has("route_checks"))
        assertFalse(JSONObject(EngineConfig.render(null, File("/synthetic/state"))).has("adaptive_routes"))
        val netbird = setting().also { it.getJSONArray("outbounds").put(JSONObject().put("type", "netbird").put("tag", "overlay").put("management_url", "https://control.example.invalid")) }
        val failure = assertThrows(IllegalArgumentException::class.java) { EngineConfig.render(netbird.toString(), File("/synthetic/" + "x".repeat(524288))) }
        assertEquals("invalid_adaptive_engine_config", failure.message)
    }
}
