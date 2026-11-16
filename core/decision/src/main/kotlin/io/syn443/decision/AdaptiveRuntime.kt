package io.syn443.decision

import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Base64

/** Protected, owned metadata only. Full engine validation and native ownership
 * are still required; decoding does not activate a capability or a data path. */
class AdaptiveRuntime private constructor(
    val graph: RouteGraph,
    private val graphRaw: ByteArray,
    private val profiles: Map<String, ByteArray>,
    private val tags: Map<String, String>,
    private val wire: ByteArray,
    val hash: String,
) {
    fun graphBytes(): ByteArray = graphRaw.copyOf()
    fun catalogueProfiles(): Map<String, ByteArray> = profiles.mapValues { it.value.copyOf() }
    fun catalogueIDs(): List<String> = profiles.keys.sorted()
    fun groupTags(): Map<String, String> = tags.toMap()
    /** Contains credentials. Keep this buffer out of logs, telemetry and public DTOs. */
    fun canonicalWire(): ByteArray = wire.copyOf()
    override fun toString(): String = "AdaptiveRuntime([redacted])"

    companion object {
        const val MAX_WIRE_BYTES = 196608
        const val MAX_DECODED_BYTES = 262144
        private val hopID = Regex("^[a-z0-9][a-z0-9._-]{0,63}$")
        private val managedTag = Regex("^[a-z0-9][a-z0-9_-]{0,63}$")
        private val rawURL = Regex("^[A-Za-z0-9_-]+$")

        fun decode(raw: ByteArray): AdaptiveRuntime {
            try {
                require(raw.size in 1..MAX_WIRE_BYTES)
                val budget = AdaptiveBudget()
                val root = AdaptiveParser(raw, budget, 4, 256, false).parse().objectValue()
                require(root.keys == setOf("schemaVersion", "graphB64", "catalogueB64", "groups"))
                require((root["schemaVersion"] as? AdaptiveNumber)?.literal == "1")
                val graphInput = unbase64(root.getValue("graphB64"))
                val catalogueInput = unbase64(root.getValue("catalogueB64"))
                val catalogue = AdaptiveParser(catalogueInput, budget, 500, 256, false).parse().objectValue()
                require(catalogue.size in 1..500 && catalogueInput.contentEquals(AdaptiveCanonical.bytes(AdaptiveObject(catalogue))))
                val owned = linkedMapOf<String, ByteArray>()
                val identities = mutableSetOf<String>()
                var size = 0
                for ((id, value) in catalogue.toSortedMap()) {
                    require(hopID.matches(id))
                    val node = value.objectValue()
                    validateProfile(id, node)
                    val profile = AdaptiveCanonical.bytes(AdaptiveObject(node))
                    require(profile.size in 1..65536)
                    size += id.length + profile.size
                    require(size <= MAX_DECODED_BYTES)
                    val identity = AdaptiveObject(node.filterKeys { it != "tag" })
                    require(identities.add(digest(AdaptiveCanonical.bytes(identity))))
                    owned[id] = profile
                }
                val graphTree = AdaptiveParser(graphInput, budget, 128, 4096, true).parse()
                val graph = RouteGraph.decode(graphInput, owned.keys.toList())
                val mappings = root.getValue("groups").objectValue()
                require(mappings.keys == graph.groupIDs().toSet() && mappings.size in 1..16)
                val tags = mappings.mapValues { (_, value) -> value.stringValue() }
                require(tags.values.toSet().size == tags.size && tags.values.all {
                    managedTag.matches(it) && it != "direct" && !it.startsWith("syn443_")
                })
                val canonicalGraph = AdaptiveCanonical.bytes(graphTree)
                val canonicalCatalogue = AdaptiveCanonical.bytes(AdaptiveObject(catalogue))
                val canonical = AdaptiveCanonical.bytes(AdaptiveObject(mapOf(
                    "schemaVersion" to AdaptiveNumber("1"),
                    "graphB64" to AdaptiveString(base64(canonicalGraph)),
                    "catalogueB64" to AdaptiveString(base64(canonicalCatalogue)),
                    "groups" to AdaptiveObject(tags.mapValues { AdaptiveString(it.value) }),
                )))
                require(canonical.size <= MAX_WIRE_BYTES)
                return AdaptiveRuntime(graph, canonicalGraph, owned, tags.toMap(), canonical, digest(canonical))
            } catch (_: Exception) {
                throw IllegalArgumentException("invalid_adaptive_runtime")
            }
        }

        private fun unbase64(value: AdaptiveValue): ByteArray {
            val text = value.stringValue()
            require(text.isNotEmpty() && rawURL.matches(text) && text.length.toLong() * 3 / 4 <= MAX_DECODED_BYTES)
            val bytes = Base64.getUrlDecoder().decode(text)
            require(bytes.size in 1..MAX_DECODED_BYTES && base64(bytes) == text)
            return bytes
        }

        private fun base64(raw: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(raw)
        private fun digest(raw: ByteArray): String = buildString(64) {
            val hex = "0123456789abcdef"
            for (byte in MessageDigest.getInstance("SHA-256").digest(raw)) {
                val value = byte.toInt() and 255
                append(hex[value ushr 4]); append(hex[value and 15])
            }
        }

        private fun validateProfile(id: String, node: Map<String, AdaptiveValue>) {
            val type = node["type"]?.stringValue()
            val fields = "type tag server server_port " + when (type) {
                "http" -> "username password tls"
                "socks" -> "username password version"
                "vless" -> "uuid flow encryption packet_encoding network tls transport"
                "ssh" -> "user password private_key private_key_passphrase host_key host_key_algorithms client_version"
                else -> error("invalid_profile")
            }
            require(node.keys.all { it in fields.split(' ') } && node["tag"]?.stringValue() == id)
            val server = node.getValue("server").stringValue().toByteArray(Charsets.UTF_8)
            val port = (node["server_port"] as? AdaptiveNumber)?.literal?.toLongOrNull()
            require(server.size in 1..253 && port != null && port in 1..65535)
            node["tls"]?.let { value ->
                val tls = value.objectValue()
                require(tls.keys.all { it in setOf("enabled", "server_name", "insecure", "alpn", "utls", "reality", "min_version", "max_version", "certificate") })
                require((tls["enabled"] as? AdaptiveBoolean)?.value == true)
                require("insecure" !in tls || (tls["insecure"] as? AdaptiveBoolean)?.value == false)
                for ((key, allowed) in mapOf("utls" to setOf("enabled", "fingerprint"), "reality" to setOf("enabled", "public_key", "short_id"))) {
                    tls[key]?.let {
                        val child = it.objectValue()
                        require(child.keys.all { field -> field in allowed } && (child["enabled"] as? AdaptiveBoolean)?.value == true)
                    }
                }
            }
            if (type == "ssh") require((node["host_key"] as? AdaptiveArray)?.values?.isNotEmpty() == true)
        }
    }
}

private sealed interface AdaptiveValue
private class AdaptiveObject(val values: Map<String, AdaptiveValue>) : AdaptiveValue
private class AdaptiveArray(val values: List<AdaptiveValue>) : AdaptiveValue
private class AdaptiveString(val value: String) : AdaptiveValue
private class AdaptiveNumber(val literal: String) : AdaptiveValue
private class AdaptiveBoolean(val value: Boolean) : AdaptiveValue
private data object AdaptiveNull : AdaptiveValue
private fun AdaptiveValue.objectValue(): Map<String, AdaptiveValue> = (this as AdaptiveObject).values
private fun AdaptiveValue.stringValue(): String = (this as AdaptiveString).value

private class AdaptiveBudget(var remaining: Int = 32768) {
    fun token() { require(remaining > 0); remaining-- }
}

/** Dedicated limits do not relax StrictJson or other policy JSON boundaries. */
private class AdaptiveParser(
    raw: ByteArray, private val budget: AdaptiveBudget, private val rootMembers: Int,
    private val arrayItems: Int, private val allowNull: Boolean,
) {
    private val text: String
    private var index = 0
    init {
        require(raw.size in 1..AdaptiveRuntime.MAX_DECODED_BYTES)
        text = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(raw)).toString()
    }
    fun parse(): AdaptiveValue {
        val value = value(0)
        whitespace()
        require(index == text.length)
        return value
    }
    private fun whitespace() { while (index < text.length && text[index] in " \r\n\t") index++ }
    private fun peek(): Char { whitespace(); require(index < text.length); return text[index] }
    private fun take(c: Char) { require(peek() == c); index++ }
    private fun string(): String {
        val start = index
        take('"')
        while (index < text.length) {
            val c = text[index++]
            require(c >= ' ')
            if (c == '"') {
                val decoded = Decision.json.decodeFromString<String>(text.substring(start, index))
                var offset = 0
                while (offset < decoded.length) {
                    val current = decoded[offset++]
                    if (current.isHighSurrogate()) require(offset < decoded.length && decoded[offset++].isLowSurrogate())
                    else require(!current.isLowSurrogate())
                }
                return decoded
            }
            if (c == '\\') { require(index < text.length); index++ }
        }
        error("invalid_json_string")
    }
    private fun number(): AdaptiveNumber {
        val start = index
        if (text[index] == '-') { index++; require(index < text.length) }
        if (text[index] == '0') index++ else {
            require(text[index] in '1'..'9')
            while (index < text.length && text[index] in '0'..'9') index++
        }
        if (index < text.length && text[index] == '.') {
            index++; val decimal = index
            while (index < text.length && text[index] in '0'..'9') index++
            require(index > decimal)
        }
        if (index < text.length && text[index] in "eE") {
            index++
            if (index < text.length && text[index] in "+-") index++
            val exponent = index
            while (index < text.length && text[index] in '0'..'9') index++
            require(index > exponent)
        }
        return AdaptiveNumber(text.substring(start, index))
    }
    private fun literal(value: String) { require(text.startsWith(value, index)); index += value.length }
    private fun value(depth: Int): AdaptiveValue {
        require(depth <= 16)
        val next = peek()
        budget.token()
        return when (next) {
            '{' -> {
                take('{'); val fields = linkedMapOf<String, AdaptiveValue>()
                if (peek() != '}') while (true) {
                    require(fields.size < (if (depth == 0) rootMembers else 128))
                    budget.token(); val key = string()
                    require(key !in fields); take(':'); fields[key] = value(depth + 1)
                    if (peek() == '}') break
                    take(',')
                }
                take('}'); budget.token(); AdaptiveObject(fields)
            }
            '[' -> {
                take('['); val entries = mutableListOf<AdaptiveValue>()
                if (peek() != ']') while (true) {
                    require(entries.size < arrayItems); entries += value(depth + 1)
                    if (peek() == ']') break
                    take(',')
                }
                take(']'); budget.token(); AdaptiveArray(entries)
            }
            '"' -> AdaptiveString(string())
            't' -> { literal("true"); AdaptiveBoolean(true) }
            'f' -> { literal("false"); AdaptiveBoolean(false) }
            'n' -> { require(allowNull); literal("null"); AdaptiveNull }
            '-', in '0'..'9' -> number()
            else -> error("invalid_json_value")
        }
    }
}

/** encoding/json.Marshal compatibility, including HTML-safe strings and number lexemes. */
private object AdaptiveCanonical {
    fun bytes(value: AdaptiveValue): ByteArray = buildString { appendValue(value) }.toByteArray(Charsets.UTF_8)
    private fun compareKeys(a: String, b: String): Int {
        var left = 0; var right = 0
        while (left < a.length && right < b.length) {
            val x = Character.codePointAt(a, left); val y = Character.codePointAt(b, right)
            if (x != y) return x.compareTo(y)
            left += Character.charCount(x); right += Character.charCount(y)
        }
        return (a.length - left).compareTo(b.length - right)
    }
    private fun StringBuilder.appendString(value: String) {
        append('"')
        for (c in value) when (c) {
            '"' -> append("\\\""); '\\' -> append("\\\\")
            '\b' -> append("\\b"); '\u000c' -> append("\\f")
            '\n' -> append("\\n"); '\r' -> append("\\r"); '\t' -> append("\\t")
            '<' -> append("\\u003c"); '>' -> append("\\u003e"); '&' -> append("\\u0026")
            '\u2028' -> append("\\u2028"); '\u2029' -> append("\\u2029")
            else -> if (c < ' ') {
                val hex = "0123456789abcdef"
                append("\\u00"); append(hex[c.code ushr 4]); append(hex[c.code and 15])
            } else append(c)
        }
        append('"')
    }
    private fun StringBuilder.appendValue(value: AdaptiveValue) {
        when (value) {
            is AdaptiveObject -> {
                append('{')
                value.values.keys.sortedWith(Comparator(::compareKeys)).forEachIndexed { index, key ->
                    if (index != 0) append(',')
                    appendString(key); append(':'); appendValue(value.values.getValue(key))
                }
                append('}')
            }
            is AdaptiveArray -> { append('['); value.values.forEachIndexed { index, child -> if (index != 0) append(','); appendValue(child) }; append(']') }
            is AdaptiveString -> appendString(value.value)
            is AdaptiveNumber -> append(value.literal)
            is AdaptiveBoolean -> append(if (value.value) "true" else "false")
            AdaptiveNull -> append("null")
        }
    }
}
