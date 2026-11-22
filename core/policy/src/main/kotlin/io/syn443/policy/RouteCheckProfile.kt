package io.syn443.policy

import kotlinx.serialization.json.*
import java.net.Inet6Address
import java.net.InetAddress
import java.net.URI

/** Value-only compiled metadata. Native alone evaluates probes and owns proof hashes. */
class RouteCheckProfile private constructor(
    val id: String, val revision: Long, val deadlineMs: Long,
    private val encoded: String, private val leaves: List<Leaf>, private val gates: Set<String>,
) {
    private data class Leaf(val id: String, val method: String, val exit: String, val check: String)
    fun wireJson(): String = encoded
    fun leafIDs(): List<String> = leaves.map { it.id }
    fun confirmedExitClass(passed: Set<String>): String? = leaves
        .filter { it.method == "https_exit_country" && it.id in passed }
        .map { it.exit }.distinct().singleOrNull()
    fun methods(): Set<String> = leaves.map { it.method }.toSet()
    fun requireIntent(intent: String) {
        require(intent in setOf("RU", "NON_RU", "INTERNAL"))
        val countries = leaves.filter { it.method == "https_exit_country" }
        require(countries.all { intent != "INTERNAL" && it.exit == intent && it.id in gates })
        require(intent == "INTERNAL" || countries.any { it.id in gates && it.exit == intent })
    }
    override fun toString(): String = "RouteCheckProfile([redacted])"

    companion object {
        private val identifier = Regex("[a-z][a-z0-9._-]{0,63}")
        private val methods = setOf("tcp", "tls", "https_204", "ssh_banner", "https_exit_ip", "https_exit_country", "https_status")
        private val mandatory = setOf("tls", "https_exit_ip", "https_exit_country")
        private fun obj(value: JsonElement, keys: Set<String>): JsonObject =
            (value as? JsonObject).also { require(it != null && it.keys == keys) }!!
        private fun text(value: JsonElement?): String =
            (value as? JsonPrimitive).also { require(it != null && it.isString) }!!.content
        private fun integer(value: JsonElement?, range: LongRange): Long {
            val primitive = value as? JsonPrimitive
            require(primitive != null && !primitive.isString && Regex("0|[1-9][0-9]*").matches(primitive.content))
            return primitive.content.toLong().also { require(it in range) }
        }
        private fun array(value: JsonElement?, range: IntRange): JsonArray =
            (value as? JsonArray).also { require(it != null && it.size in range) }!!
        private fun ip(value: String): Boolean {
            if (':' !in value) {
                val pieces = value.split('.')
                return pieces.size == 4 && pieces.all { Regex("0|[1-9][0-9]{0,2}").matches(it) && it.toInt() in 0..255 }
            }
            if (value.length !in 2..45 || !Regex("[0-9a-fA-F:.]+").matches(value)) return false
            // The alphabet and mandatory colon restrict this to a numeric literal.
            return try { InetAddress.getByName(value) is Inet6Address } catch (_: Exception) { false }
        }
        private fun host(raw: String): Boolean {
            val value = raw.removeSurrounding("[", "]")
            if (':' in value) {
                if (value.length !in 2..45 || !Regex("[0-9a-fA-F:.]+").matches(value)) return false
                return try { InetAddress.getByName(value); true } catch (_: Exception) { false }
            }
            return value.length in 1..253 && value == value.lowercase(java.util.Locale.ROOT) &&
                !value.endsWith('.') && value.split('.').all {
                    it.length in 1..63 && Regex("[a-z0-9](?:[a-z0-9-]*[a-z0-9])?").matches(it)
                }
        }
        private fun primitive(value: JsonElement): Leaf {
            val raw = value as? JsonObject ?: error("invalid_check_profile")
            val method = text(raw["method"])
            require(method in methods)
            val keys = setOf("method", "target") + when (method) {
                "https_exit_ip" -> setOf("expected_ip")
                "https_exit_country" -> setOf("expected_exit_class")
                "https_status" -> setOf("http_method", "expected_status")
                else -> emptySet()
            }
            require(raw.keys == keys)
            val target = text(raw["target"])
            require(target.length in 1..2048 && target.all { it.code in 33..126 } && '\\' !in target && '#' !in target)
            val secure = method in setOf("tls", "https_204", "https_exit_ip", "https_exit_country", "https_status")
            val uri = URI(if (secure) target else "tcp://$target")
            require(uri.host != null && host(uri.host) && uri.userInfo == null && uri.rawFragment == null && !uri.rawAuthority.endsWith(":"))
            val authority = uri.rawAuthority
            val explicitPort = if (authority.startsWith('[')) authority.substringAfter(']').takeIf { it.isNotEmpty() }?.removePrefix(":")
                else authority.substringAfter(':', "").takeIf { ':' in authority }
            if (explicitPort != null) require(Regex("[0-9]{1,5}").matches(explicitPort) && explicitPort.toInt() in 1..65535)
            require(if (secure) uri.scheme == "https" && (uri.port == -1 || uri.port in 1..65535)
                else uri.port in 1..65535 && uri.rawPath.isNullOrEmpty() && uri.rawQuery == null)
            if (method == "https_exit_ip") require(ip(text(raw["expected_ip"])))
            if (method == "https_status") {
                require(text(raw["http_method"]) in setOf("GET", "HEAD"))
                integer(raw["expected_status"], 200L..599L)
            }
            val exit = if (method == "https_exit_country") text(raw["expected_exit_class"]) else ""
            if (method == "https_exit_country") require(exit in setOf("RU", "NON_RU") &&
                (uri.rawPath.isNullOrEmpty() || uri.rawPath == "/") && uri.rawQuery == null)
            return Leaf("", method, exit, Canonical.encode(raw))
        }
        internal fun validateHTTPSStatus(check: JsonElement) {
            require(primitive(check).method == "https_status")
        }
        fun decode(raw: String): RouteCheckProfile = try { decodeValue(raw) }
            catch (_: Exception) { throw IllegalArgumentException("invalid_check_profile") }
        private fun decodeValue(raw: String): RouteCheckProfile {
            require(raw.toByteArray(Charsets.UTF_8).size in 1..24000)
            val value = obj(Canonical.parse(raw), setOf("schemaVersion", "id", "revision", "deadlineMs", "leaves", "gates", "stages"))
            require(integer(value["schemaVersion"], 2L..2L) == 2L)
            val id = text(value["id"]).also { require(identifier.matches(it)) }
            val revision = integer(value["revision"], 1L..9_007_199_254_740_991L)
            val deadline = integer(value["deadlineMs"], 1L..12000L)
            val leaves = array(value["leaves"], 1..4).map { leaf ->
                val item = obj(leaf, setOf("id", "check"))
                val leafID = text(item["id"]).also { require(identifier.matches(it)) }
                primitive(item.getValue("check")).copy(id = leafID)
            }.sortedBy { it.id }
            require(leaves.map { it.id }.toSet().size == leaves.size && leaves.map { it.check }.toSet().size == leaves.size)
            val names = leaves.map { it.id }.toSet()
            val refs = mutableSetOf<String>()
            fun reference(value: JsonElement?): String = text(value).also { require(it in names && refs.add(it)) }
            val gates = array(value["gates"], 0..4).map(::reference).toSet()
            val stages = array(value["stages"], 0..4)
            require(gates.isNotEmpty() || stages.isNotEmpty())
            var nodes = 0
            fun expression(rawExpression: JsonElement, depth: Int) {
                require(++nodes <= 7 && depth <= 4)
                val node = rawExpression as? JsonObject ?: error("invalid_check_profile")
                require(node.size == 1)
                when (val operation = node.keys.single()) {
                    "leaf" -> reference(node[operation])
                    "all", "any" -> array(node[operation], 2..4).forEach { expression(it, depth + 1) }
                    "quorum" -> {
                        val quorum = obj(node.getValue(operation), setOf("k", "of"))
                        val children = array(quorum["of"], 2..4)
                        integer(quorum["k"], 1L..children.size.toLong())
                        children.forEach { expression(it, depth + 1) }
                    }
                    else -> error("invalid_check_profile")
                }
            }
            stages.forEach { expression(it, 1) }
            require(refs == names && leaves.filter { it.method in mandatory }.all { it.id in gates })
            val owned = JsonObject(value.toMutableMap().apply {
                put("leaves", JsonArray(leaves.map { leaf -> JsonObject(linkedMapOf(
                    "id" to JsonPrimitive(leaf.id), "check" to Canonical.parse(leaf.check))) }))
            })
            return RouteCheckProfile(id, revision, deadline, Canonical.encode(owned), leaves.toList(), gates.toSet())
        }
    }
}

/** Strict, scoped extraction avoids normalizing numeric lexemes or duplicate keys.
 * It does not widen Canonical's global limits or validate other engine features. */
object RouteCheckProfiles {
    private val number = Regex("-?(?:0|[1-9][0-9]*)(?:\\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
    class Inspection internal constructor(val profileCount: Int, private val names: Set<String>) {
        fun hasMethod(method: String): Boolean = method in names
        override fun toString(): String = "RouteCheckInspection([redacted])"
    }
    fun inspectEngine(raw: String): Inspection {
        require(raw.toByteArray(Charsets.UTF_8).size <= 262144)
        val field = extract(raw) ?: return Inspection(0, emptySet())
        val rows = Canonical.parse(field) as? JsonArray ?: error("invalid_check_profile")
        require(rows.size <= 16)
        var profiles = 0
        val methods = mutableSetOf<String>()
        for (value in rows) {
            val row = value as? JsonObject ?: continue // Legacy admission remains EngineConfig's responsibility.
            require(row.keys.none { it.equals("profile", ignoreCase = true) && it != "profile" })
            if ("profile" in row) {
                require(row.keys == setOf("outbound", "required", "profile"))
                val outbound = row["outbound"] as? JsonPrimitive
                require(outbound != null && outbound.isString && outbound.content.length in 1..256)
                val required = row["required"] as? JsonPrimitive
                require(required != null && !required.isString && required.content in setOf("true", "false"))
                val profile = RouteCheckProfile.decode(row.getValue("profile").toString())
                profiles++; methods.addAll(profile.methods())
            } else for (check in row["checks"] as? JsonArray ?: JsonArray(emptyList())) {
                val method = ((check as? JsonObject)?.get("method") as? JsonPrimitive)?.takeIf { it.isString }?.content
                if (method == "https_status") RouteCheckProfile.validateHTTPSStatus(check)
                if (method != null) methods.add(method)
            }
        }
        if (profiles > 0) {
            require(field.toByteArray(Charsets.UTF_8).size <= 24000)
            requireJsonAtoms(raw)
        }
        return Inspection(profiles, methods.toSet())
    }
    /** JsonElement's tree reader can retain unquoted unknown atoms. Validate
     * their grammar without canonicalizing or imposing envelope array limits. */
    private fun requireJsonAtoms(raw: String) {
        val pending = java.util.ArrayDeque<Pair<JsonElement, Int>>()
        pending.addLast(Canonical.json.parseToJsonElement(raw) to 0)
        while (pending.isNotEmpty()) {
            val (value, depth) = pending.removeLast()
            require(depth <= 32)
            when (value) {
                is JsonObject -> value.values.forEach { pending.addLast(it to depth + 1) }
                is JsonArray -> value.forEach { pending.addLast(it to depth + 1) }
                is JsonPrimitive -> if (!value.isString) require(value === JsonNull ||
                    value.content in setOf("true", "false") || number.matches(value.content))
            }
        }
    }
    private fun extract(raw: String): String? {
        var i = 0
        fun ws() { while (i < raw.length && raw[i] in " \r\n\t") i++ }
        fun stringEnd(): Int {
            require(i < raw.length && raw[i++] == '"')
            while (i < raw.length) when (raw[i++]) {
                '"' -> return i
                '\\' -> { require(i < raw.length); i++ }
            }
            error("invalid_check_profile")
        }
        fun end(): Int {
            ws(); require(i < raw.length)
            if (raw[i] == '"') return stringEnd()
            if (raw[i] != '{' && raw[i] != '[') {
                while (i < raw.length && raw[i] !in ",} \r\n\t") i++
                return i
            }
            val stack = java.util.ArrayDeque<Char>(); stack.addLast(raw[i++])
            while (i < raw.length && stack.isNotEmpty()) when (val c = raw[i]) {
                '"' -> stringEnd()
                '{', '[' -> { require(stack.size < 32); stack.addLast(c); i++ }
                '}', ']' -> { require(stack.removeLast() == if (c == '}') '{' else '['); i++ }
                else -> i++
            }
            require(stack.isEmpty()); return i
        }
        ws(); require(i < raw.length && raw[i++] == '{'); ws()
        val keys = mutableSetOf<String>(); var result: String? = null
        while (i < raw.length && raw[i] != '}') {
            val start = i; val keyEnd = stringEnd()
            val key = (Canonical.parse(raw.substring(start, keyEnd)) as JsonPrimitive).content
            require(keys.size < 64 && keys.add(key)); ws(); require(i < raw.length && raw[i++] == ':'); ws()
            val valueStart = i; val valueEnd = end()
            if (key == "route_checks") result = raw.substring(valueStart, valueEnd)
            ws(); require(i < raw.length)
            if (raw[i] == '}') break
            require(raw[i++] == ','); ws()
        }
        require(i < raw.length && raw[i++] == '}'); ws(); require(i == raw.length)
        return result
    }
}
