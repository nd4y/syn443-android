package io.syn443.policy

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*
import java.math.BigInteger
import java.net.URI
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

@Serializable data class Check(val id: String, val type: String, val target: String, val port: Int = 0,
    val expected: String = "", val required: Boolean = true)
@Serializable data class Gate(val timeoutSeconds: Int, val allowDegraded: Boolean, val checks: List<Check>)
@Serializable data class Payload(val schemaVersion: Int, val revision: Long, val securityEpoch: Long,
    val revocationFloor: Long, val targetDevice: String, val audience: String, val issuedAtMs: Long,
    val notBeforeMs: Long, val refreshAfterMs: Long, val offlineUntilMs: Long,
    val requiredCapabilities: List<String>, val algorithmRevision: String,
    val engineConfigB64: String, val contentHash: String, val activation: Gate)
data class Verified(val envelope: String, val payload: Payload, val engineConfig: String)
@Serializable data class Journal(val phase: String = "idle", val desired: String? = null,
    val active: String? = null, val lastGood: String? = null, val candidate: String? = null,
    val maxRevision: Long = 0, val epoch: Long = 0, val floor: Long = 0,
    val activationGeneration: Long = 0, val failedRevisions: List<Long> = emptyList(),
    val failedSnapshots: List<String> = emptyList(),
    val baseline: List<Boolean> = emptyList(), val reason: String = "")

/** JCS subset: safe integers only; engine JSON is an opaque, hashed UTF-8 string. */
object Canonical {
    val json = Json { encodeDefaults = true; explicitNulls = true }
    fun parse(text: String): JsonElement {
        require(text.toByteArray(Charsets.UTF_8).size <= 524_288)
        class Parser {
            var i = 0
            fun ws() { while (i < text.length && text[i] in " \t\r\n") i++ }
            fun take(c: Char) { ws(); require(i < text.length && text[i++] == c) }
            fun peek(): Char { ws(); require(i < text.length); return text[i] }
            fun string(): String {
                ws(); val start = i; take('"')
                while (i < text.length) {
                    val c = text[i++]; require(c >= ' ')
                    if (c == '"') {
                        val s = json.decodeFromString<String>(text.substring(start, i))
                        var k = 0
                        while (k < s.length) {
                            if (s[k].isHighSurrogate()) { require(k + 1 < s.length && s[k+1].isLowSurrogate()); k++ }
                            else require(!s[k].isLowSurrogate())
                            k++
                        }
                        return s
                    }
                    if (c == '\\') { require(i < text.length); i++ }
                }
                error("json_string")
            }
            fun value(depth: Int): JsonElement {
                require(depth <= 24)
                return when (peek()) {
                    '{' -> { take('{'); val map = linkedMapOf<String, JsonElement>()
                        if (peek() != '}') while (true) {
                            require(map.size < 64); val key = string(); require(!map.containsKey(key)); take(':')
                            map[key] = value(depth + 1); if (peek() == '}') break; take(',')
                        }; take('}'); JsonObject(map) }
                    '[' -> { take('['); val list = arrayListOf<JsonElement>()
                        if (peek() != ']') while (true) { require(list.size < 128); list.add(value(depth + 1)); if (peek() == ']') break; take(',') }
                        take(']'); JsonArray(list) }
                    '"' -> JsonPrimitive(string())
                    't', 'f', 'n' -> { val word = when (peek()) { 't' -> "true"; 'f' -> "false"; else -> "null" }
                        require(text.startsWith(word, i)); i += word.length
                        when (word) { "true" -> JsonPrimitive(true); "false" -> JsonPrimitive(false); else -> JsonNull } }
                    else -> { val start = i; if (text[i] == '-') i++
                        require(i < text.length && text[i] in '0'..'9')
                        if (text[i] == '0') i++ else while (i < text.length && text[i] in '0'..'9') i++
                        val n = text.substring(start, i).toLong(); require(n in -9_007_199_254_740_991L..9_007_199_254_740_991L)
                        JsonPrimitive(n) }
                }
            }
        }
        val parser = Parser(); val value = parser.value(0); parser.ws(); require(parser.i == text.length); return value
    }
    fun encode(value: JsonElement): String = when (value) {
        is JsonObject -> value.keys.sorted().joinToString(",", "{", "}") { json.encodeToString(JsonPrimitive.serializer(), JsonPrimitive(it)) + ":" + encode(value.getValue(it)) }
        is JsonArray -> value.joinToString(",", "[", "]") { encode(it) }
        else -> value.toString()
    }
}

object Policy {
    val json = Canonical.json
    val capabilities = setOf("engine-config.v1", "policy.es256.v1", "netbird.direct", "netbird.vless")
    fun hash(raw: String): String = MessageDigest.getInstance("SHA-256").digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    fun decode64(value: String): ByteArray {
        require(value.matches(Regex("[A-Za-z0-9_-]+")))
        val bytes = Base64.getUrlDecoder().decode(value)
        require(Base64.getUrlEncoder().withoutPadding().encodeToString(bytes) == value)
        return bytes
    }
    fun utf8(bytes: ByteArray): String = Charsets.UTF_8.newDecoder().decode(java.nio.ByteBuffer.wrap(bytes)).toString()
    fun verify(raw: String, keys: Map<String, String>, device: String, now: Long): Verified {
        require(raw.length in 1..524_288 && raw.all { it.code < 128 })
        val parts = raw.split('.'); require(parts.size == 3 && parts[0].length <= 1024)
        val headerText = utf8(decode64(parts[0])); val header = Canonical.parse(headerText).jsonObject
        require(header.keys == setOf("alg", "kid", "typ") && headerText == Canonical.encode(header))
        require(header.values.all { it is JsonPrimitive && it.isString })
        require(header.getValue("alg").jsonPrimitive.content == "ES256" && header.getValue("typ").jsonPrimitive.content == "syn443-policy+jws")
        val kid = header.getValue("kid").jsonPrimitive.content; require(kid.matches(Regex("[a-zA-Z0-9_-]{1,64}")))
        val key = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(Base64.getDecoder().decode(keys.getValue(kid)))) as ECPublicKey
        require(key.params.order == BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16) && key.params.cofactor == 1 && key.params.curve.field.fieldSize == 256)
        val signature = decode64(parts[2]); require(signature.size == 64)
        fun integer(bytes: ByteArray): ByteArray {
            val n = BigInteger(1, bytes); require(n.signum() > 0 && n < key.params.order)
            val v = n.toByteArray(); return byteArrayOf(2, v.size.toByte()) + v
        }
        val integers = integer(signature.copyOfRange(0, 32)) + integer(signature.copyOfRange(32, 64))
        val der = byteArrayOf(0x30, integers.size.toByte()) + integers
        require(Signature.getInstance("SHA256withECDSA").run { initVerify(key); update((parts[0] + "." + parts[1]).toByteArray(Charsets.US_ASCII)); verify(der) })
        val text = utf8(decode64(parts[1])); val element = Canonical.parse(text); require(Canonical.encode(element) == text)
        element.jsonObject.getValue("activation").jsonObject.getValue("checks").jsonArray.forEach {
            require(it.jsonObject.keys == setOf("id", "type", "target", "port", "expected", "required"))
        }
        val p = json.decodeFromJsonElement<Payload>(element)
        require(p.schemaVersion == 1 && p.audience == "syn443-device" && p.targetDevice == device)
        require(p.targetDevice.matches(Regex("[a-zA-Z0-9_-]{8,64}")))
        require(p.revision in 1..9_007_199_254_740_991L && p.securityEpoch in 0..9_007_199_254_740_991L && p.revocationFloor in 0..p.revision)
        require(p.issuedAtMs in 1..now + 300_000 && p.notBeforeMs >= p.issuedAtMs && p.notBeforeMs <= now)
        require(p.refreshAfterMs in p.notBeforeMs..p.offlineUntilMs && p.offlineUntilMs > now && p.offlineUntilMs - p.issuedAtMs <= 604_800_000)
        require(p.algorithmRevision == "m1-local-v1" && p.requiredCapabilities.isNotEmpty() && p.requiredCapabilities.size <= 16 && p.requiredCapabilities.toSet().size == p.requiredCapabilities.size && capabilities.containsAll(p.requiredCapabilities))
        val engine = utf8(decode64(p.engineConfigB64)); require(engine.toByteArray().size in 1..262_144 && hash(engine) == p.contentHash)
        val g = p.activation; require(g.timeoutSeconds in 30..120 && g.checks.size in 1..8 && g.checks.map { it.id }.toSet().size == g.checks.size)
        require(g.checks.any { it.required && it.type == "https_204" })
        g.checks.forEach { c ->
            require(c.id.matches(Regex("[a-zA-Z0-9_-]{1,48}")))
            when (c.type) {
                "https_204" -> { val uri = URI(c.target); require(c.target.length <= 2048 && c.target.all { it.code in 32..126 } && uri.scheme == "https" && !uri.host.isNullOrEmpty() && uri.userInfo == null && uri.fragment == null && c.port == 0 && c.expected == "") }
                "tcp_banner" -> { require(c.target.matches(Regex("[a-zA-Z0-9.:-]{1,253}")) && c.port in 1..65535 && c.expected.length in 1..64 && c.expected.all { it.code in 32..126 }) }
                else -> error("unsupported_check")
            }
        }
        return Verified(raw, p, engine)
    }
    fun stage(j: Journal, v: Verified): Journal {
        val p = v.payload
        require(j.phase !in setOf("prepared", "applying"))
        require(p.revision > j.maxRevision && p.securityEpoch >= j.epoch && p.revocationFloor >= j.floor)
        require(snapshot(p) !in j.failedSnapshots)
        return j.copy(phase = "prepared", desired = v.envelope, candidate = v.envelope, maxRevision = p.revision,
            epoch = p.securityEpoch, floor = p.revocationFloor, activationGeneration = j.activationGeneration + 1,
            baseline = emptyList(), reason = "candidate_prepared")
    }
    fun begin(j: Journal, baseline: List<Boolean>): Journal {
        require(j.phase == "prepared" && j.candidate != null); return j.copy(phase = "applying", baseline = baseline, reason = "candidate_applying")
    }
    fun finish(j: Journal, v: Verified, actual: List<Boolean>, engineStarted: Boolean): Journal {
        require(j.phase == "applying" && j.candidate == v.envelope && j.baseline.size == v.payload.activation.checks.size && actual.size == j.baseline.size)
        val checks = v.payload.activation.checks
        val failed = checks.indices.filter { checks[it].required && !actual[it] }
        val regression = failed.any { j.baseline[it] }
        if (!engineStarted || regression || (failed.isNotEmpty() && !v.payload.activation.allowDegraded)) return rollback(j, v.payload.revision, "activation_failed")
        return j.copy(phase = if (failed.isEmpty()) "committed" else "degraded", active = v.envelope,
            lastGood = if (failed.isEmpty()) v.envelope else j.lastGood, candidate = null, baseline = emptyList(), reason = if (failed.isEmpty()) "checks_passed" else "baseline_also_unavailable")
    }
    fun snapshot(p: Payload) = hash(p.contentHash + ":" + p.algorithmRevision + ":" + Canonical.encode(json.encodeToJsonElement(p.activation)))
    fun rollback(j: Journal, revision: Long, reason: String): Journal {
        val fingerprint = j.candidate?.let { snapshot(json.decodeFromString<Payload>(utf8(decode64(it.split('.')[1])))) }
        return j.copy(phase = "rolled_back", candidate = null, active = j.lastGood,
            failedRevisions = (j.failedRevisions + revision).takeLast(16), failedSnapshots = (j.failedSnapshots + listOfNotNull(fingerprint)).distinct().takeLast(16), baseline = emptyList(), reason = reason)
    }
}
