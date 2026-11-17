package io.syn443.android.vpn

import android.net.InetAddresses
import io.syn443.decision.AdaptiveRuntime
import io.syn443.decision.Decision
import io.syn443.decision.ExitClass
import io.syn443.decision.PathFeature
import kotlinx.serialization.json.jsonObject
import org.json.JSONArray
import org.json.JSONObject

object EngineConfig {
    private val supported = setOf("direct", "http", "socks", "vless", "ssh", "selector", "urltest", "netbird")
    fun validate(raw: String) {
        var adaptive = false
        try { validateInternal(raw) { adaptive = true } }
        catch (failure: Exception) {
            if (adaptive) throw IllegalArgumentException("invalid_adaptive_engine_config")
            throw failure
        }
    }
    private fun validateInternal(raw: String, adaptiveSeen: () -> Unit) {
        // JSONObject alone silently drops duplicate keys; preserve their rejection.
        android.util.JsonReader(java.io.StringReader(raw)).use { reader ->
            fun value(depth: Int, tlsOptions: Boolean = false) {
                require(depth <= 32)
                when (reader.peek()) {
                    android.util.JsonToken.BEGIN_OBJECT -> {
                        reader.beginObject(); val keys = mutableSetOf<String>()
                        while (reader.hasNext()) {
                            val key = reader.nextName()
                            if (depth == 0 && key.equals("adaptive_routes", ignoreCase = true)) adaptiveSeen()
                            require(keys.size < 256 && keys.add(key))
                            if (tlsOptions && key.equals("insecure", ignoreCase = true)) {
                                require(depth < 32 && reader.peek() == android.util.JsonToken.BOOLEAN && !reader.nextBoolean()) {
                                    "tls_verification_required"
                                }
                            } else value(depth + 1, tlsOptions = key.equals("tls", ignoreCase = true))
                        }
                        reader.endObject()
                    }
                    android.util.JsonToken.BEGIN_ARRAY -> { reader.beginArray(); var n = 0
                        while (reader.hasNext()) { require(++n <= 4096); value(depth + 1) }; reader.endArray() }
                    android.util.JsonToken.NUMBER -> require(reader.nextString().toDouble().isFinite())
                    android.util.JsonToken.STRING -> reader.nextString()
                    android.util.JsonToken.BOOLEAN -> reader.nextBoolean()
                    android.util.JsonToken.NULL -> reader.nextNull()
                    else -> error("invalid_json")
                }
            }
            value(0); require(reader.peek() == android.util.JsonToken.END_DOCUMENT)
        }
        val value = JSONObject(raw)
        if (RouteCheckPlans.hasProfiles(value)) io.syn443.policy.RouteCheckProfiles.inspectEngine(raw)
        require(value.keys().asSequence().all { it in setOf("outbounds", "dns", "route", "route_checks", "route_failover", "adaptive_routes") }) { "unsupported root field" }
        val adaptive = if (value.has("adaptive_routes")) {
            require(utf8Bytes(raw) <= 262144)
            require(value.get("adaptive_routes") is JSONObject)
            // JSONObject can turn numeric 1.0 into 1. Preserve original number
            // lexemes after duplicate preflight, before any typed coercion.
            Decision.json.parseToJsonElement(raw).jsonObject.getValue("adaptive_routes")
            AdaptiveRuntime.decode(checkNotNull(protectedAdaptiveWire(raw)))
        } else null
        val outbounds = value.getJSONArray("outbounds")
        require(outbounds.length() in 1..64)
        val tags = mutableSetOf<String>()
        var overlays = 0
        for (i in 0 until outbounds.length()) {
            val item = outbounds.getJSONObject(i)
            require(!item.has("credential_pending") && !item.has("recover_existing")) { "local overlay state cannot be imported" }
            require(item.keys().asSequence().none { it != "type" && it.equals("type", ignoreCase = true) }) { "ambiguous_outbound_type" }
            val type = item.getString("type")
            require(type in supported || adaptive != null && type == "syn443-adaptive")
            require(item.getString("tag").toByteArray(Charsets.UTF_8).size in 1..256 && tags.add(item.getString("tag")))
            if (type == "ssh") {
                // The embedded SSH engine accepts any server key when no pin is supplied.
                // It parses the actual public key before dialing. Do not accept a missing or
                // empty list here, regardless of whether the config was imported or assigned.
                val pins = item.opt("host_key")
                require(item.keys().asSequence().none { it != "host_key" && it.equals("host_key", ignoreCase = true) } && when (pins) {
                    is String -> validSshPin(pins)
                    is JSONArray -> pins.length() in 1..16 &&
                        (0 until pins.length()).all { validSshPin(pins.opt(it)) }
                    else -> false
                }) { "ssh_host_key_required" }
            }
            if (type == "netbird") {
                require(++overlays <= 1) { "one NetBird identity per native process" }
                require(item.optString("connection_mode", "direct") in setOf("direct", "vless"))
            }
        }
        val final = value.optJSONObject("route")?.optString("final").orEmpty()
        require(final.isEmpty() || final in tags)
        RouteSnapshot.validate(value)
        if (adaptive != null) validateAdaptive(value, adaptive)
        ManagedFailoverPlan.read(value)
    }
    private fun utf8Bytes(value: String): Int = java.nio.charset.StandardCharsets.UTF_8.newEncoder()
        .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT).onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
        .encode(java.nio.CharBuffer.wrap(value)).remaining()

    private fun validateAdaptive(config: JSONObject, runtime: AdaptiveRuntime) {
        require(!config.has("route_failover"))
        val tags = runtime.groupTags()
        val byTag = (0 until config.getJSONArray("outbounds").length()).map {
            config.getJSONArray("outbounds").getJSONObject(it)
        }.associateBy { require(it.get("tag") is String); it.getString("tag") }
        val managed = byTag.filterValues { it.get("type") == "syn443-adaptive" }
        require(managed.keys == tags.values.toSet())
        for ((group, tag) in tags) {
            val node = managed.getValue(tag)
            require(node.keys().asSequence().toSet() == setOf("type", "tag", "group") && node.get("group") is String && node.getString("group") == group)
            val info = requireNotNull(runtime.graph.groupInfo(group))
            require(PathFeature.TCP in info.features && PathFeature.UDP !in info.features && PathFeature.ICMP !in info.features)
        }
        require(byTag.values.none { it.getString("type") == "urltest" })
        // This stricter normalized-source guard is scoped to adaptive private
        // profiles. Legacy imported ordinary configurations keep their existing
        // validation behavior. Native typed construction is still mandatory.
        for ((id, bytes) in runtime.catalogueProfiles()) {
            val node = JSONObject(bytes.toString(Charsets.UTF_8))
            validateAdaptiveProfile(node)
            val ordinary = JSONObject().put("outbounds", JSONArray().put(node)).put("route", JSONObject().put("final", id))
            validate(ordinary.toString())
        }
        val rows = config.getJSONArray("route_checks")
        for ((group, tag) in tags) {
            val plans = (0 until rows.length()).map(rows::getJSONObject).filter {
                require(it.get("outbound") is String); it.getString("outbound") == tag
            }
            val row = plans.single()
            val profile = RouteCheckPlans.profile(row)
            if (profile != null) {
                profile.requireIntent(requireNotNull(runtime.graph.groupInfo(group)).intent.name)
                continue
            }
            val checks = row.getJSONArray("checks")
            require(checks.length() in 1..4)
            val intent = requireNotNull(runtime.graph.groupInfo(group)).intent
            var country = false
            for (i in 0 until checks.length()) {
                val check = checks.getJSONObject(i)
                require(check.get("method") is String && check.get("target") is String)
                if (check.getString("method") == "https_exit_country") {
                    require(intent.name != "INTERNAL" && check.get("expected_exit_class") == intent.name)
                    country = true
                }
            }
            require(intent.name == "INTERNAL" || country)
        }
        data class Span(val hops: Int, val managed: Boolean, val levels: Int)
        val visiting = mutableSetOf<String>()
        val known = mutableMapOf<String, Span>()
        val maxPrivate = tags.map { (group, tag) -> tag to requireNotNull(runtime.graph.groupInfo(group)).maxHops }.toMap()
        fun dependencies(node: JSONObject): List<String> {
            val result = mutableListOf<String>()
            if (node.has("detour")) {
                require(node.get("detour") is String)
                node.getString("detour").takeIf(String::isNotEmpty)?.let(result::add)
            }
            if (node.has("outbounds")) {
                require(node.getString("type") == "selector")
                val members = node.getJSONArray("outbounds")
                require(members.length() in 1..16)
                val values = (0 until members.length()).map { require(members.get(it) is String); members.getString(it) }
                require(values.toSet().size == values.size)
                if (node.has("default")) require(node.get("default") is String && node.getString("default") in values)
                result += values
            }
            return result
        }
        fun visit(tag: String, depth: Int): Span {
            require(depth <= 16)
            known[tag]?.let { require(depth + it.levels <= 16); return it }
            require(visiting.add(tag))
            val node = byTag.getValue(tag)
            val type = node.getString("type")
            val children = dependencies(node).map { visit(it, depth + 1) }
            val touchesManaged = tag in maxPrivate || children.any { it.managed }
            if (type == "netbird") {
                require(!touchesManaged)
                val mode = if (node.has("connection_mode")) node.get("connection_mode") else "direct"
                require(mode is String && mode in setOf("direct", "vless"))
                if (mode == "direct") require(!node.has("detour") || node.get("detour") == "")
            }
            val before = children.maxOfOrNull { it.hops } ?: 0
            val hops = maxPrivate[tag] ?: (before + if (type in setOf("http", "socks", "vless", "ssh", "netbird")) 1 else 0)
            require(hops <= 4)
            val levels = if (children.isEmpty()) 0 else children.maxOf { it.levels } + 1
            require(depth + levels <= 16)
            val span = Span(hops, touchesManaged, levels)
            visiting.remove(tag); known[tag] = span
            return span
        }
        byTag.keys.forEach { visit(it, 0) }
        // Bootstrap DNS cannot depend on an unverified adaptive TCP prefix.
        config.optJSONObject("dns")?.optJSONArray("servers")?.let { servers ->
            for (i in 0 until servers.length()) {
                val server = servers.getJSONObject(i)
                for (key in listOf("detour", "outbound")) if (server.has(key)) {
                    require(server.get(key) is String)
                    val tag = server.getString(key)
                    require(tag.isEmpty() || !visit(tag, 0).managed)
                }
            }
        }
    }

    private fun text(node: JSONObject, key: String, maximum: Int, required: Boolean = false): String {
        if (!node.has(key)) { require(!required); return "" }
        val value = node.get(key)
        require(value is String && utf8Bytes(value) <= maximum && (!required || value.isNotEmpty()) && value.none { it == '\u0000' || it == '\r' || it == '\n' })
        return value
    }
    private fun strings(value: Any, maximum: Int): List<String> {
        val values = when (value) {
            is String -> listOf(value)
            is JSONArray -> { require(value.length() in 1..16); (0 until value.length()).map { value.get(it) as String } }
            else -> error("invalid_profile_strings")
        }
        require(values.all { it.isNotEmpty() && utf8Bytes(it) <= maximum && '\u0000' !in it })
        return values
    }
    private fun only(node: JSONObject, fields: String) {
        val allowed = fields.split(' ').toSet()
        require(node.keys().asSequence().all(allowed::contains))
    }
    private fun integer(node: JSONObject, key: String, minimum: Long, maximum: Long): Long {
        val value = node.get(key)
        require(value is Int || value is Long)
        val number = (value as Number).toLong()
        require(number in minimum..maximum)
        return number
    }
    private fun validateAdaptiveProfile(node: JSONObject) {
        val type = text(node, "type", 16, true)
        val fields = "type tag server server_port " + when (type) {
            "http" -> "username password tls"
            "socks" -> "username password version"
            "vless" -> "uuid flow encryption packet_encoding network tls transport"
            "ssh" -> "user password private_key private_key_passphrase host_key host_key_algorithms client_version"
            else -> error("invalid_profile_type")
        }
        only(node, fields)
        val server = text(node, "server", 253, true)
        require(server.all { it.code in 33..126 } && server.none { it in " /\\" } && (':' !in server || '%' !in server && InetAddresses.isNumericAddress(server)))
        integer(node, "server_port", 1, 65535)
        for (key in listOf("tag", "username", "password", "user", "flow", "encryption", "packet_encoding", "network", "version", "client_version", "private_key_passphrase")) text(node, key, 8192)
        if (type == "vless") {
            require(Regex("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}").matches(text(node, "uuid", 36, true)))
            require(text(node, "flow", 8192) in setOf("", "xtls-rprx-vision"))
            require(text(node, "network", 8192) in setOf("", "tcp"))
            require(text(node, "packet_encoding", 8192) in setOf("", "xudp", "packetaddr"))
        }
        if (type == "socks") require(text(node, "version", 8192) in setOf("", "5", "4", "4a"))
        if (type == "ssh") {
            text(node, "user", 256, true)
            require(node.get("host_key") is JSONArray)
            strings(node.get("host_key"), 8192)
            if (text(node, "password", 8192).isEmpty()) strings(node.get("private_key"), 65536)
            for (key in listOf("private_key", "host_key_algorithms")) if (node.has(key)) strings(node.get(key), 65536)
        }
        if (node.has("tls")) {
            val tls = node.getJSONObject("tls")
            only(tls, "enabled server_name insecure alpn utls reality min_version max_version certificate")
            require(tls.get("enabled") == true && (!tls.has("insecure") || tls.get("insecure") == false))
            for (key in listOf("server_name", "min_version", "max_version")) text(tls, key, 253)
            for (key in listOf("alpn", "certificate")) if (tls.has(key)) strings(tls.get(key), 65536)
            if (tls.has("utls")) {
                val utls = tls.getJSONObject("utls"); only(utls, "enabled fingerprint")
                require(utls.get("enabled") == true); text(utls, "fingerprint", 64, true)
            }
            if (tls.has("reality")) {
                val reality = tls.getJSONObject("reality"); only(reality, "enabled public_key short_id")
                require(reality.get("enabled") == true)
                val key = text(reality, "public_key", 64, true)
                require(Regex("[A-Za-z0-9_-]{43}").matches(key))
                val decoded = java.util.Base64.getUrlDecoder().decode(key)
                require(decoded.size == 32 && java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(decoded) == key)
                val short = text(reality, "short_id", 16)
                require(short.length % 2 == 0 && Regex("[0-9a-fA-F]*").matches(short))
            }
        }
        if (node.has("transport")) {
            val transport = node.getJSONObject("transport")
            val kind = text(transport, "type", 16, true)
            only(transport, "type " + when (kind) {
                "ws" -> "path headers max_early_data early_data_header_name"
                "grpc" -> "service_name"
                "xhttp" -> "host path mode headers"
                else -> error("unsupported_transport")
            })
            for (key in listOf("path", "host", "mode", "service_name", "early_data_header_name")) text(transport, key, 4096)
            if (transport.has("headers")) {
                val headers = transport.getJSONObject("headers")
                require(headers.length() <= 32)
                for (key in headers.keys().asSequence()) {
                    require(utf8Bytes(key) in 1..128 && key.none { it in "\r\n\u0000:" })
                    require(strings(headers.get(key), 4096).all { '\r' !in it && '\n' !in it })
                }
            }
            if (transport.has("max_early_data")) integer(transport, "max_early_data", 0, 65536)
            if (kind == "xhttp") require(text(transport, "mode", 4096) in setOf("", "auto", "packet-up", "stream-up", "stream-one"))
        }
    }
    private fun validSshPin(pin: Any?): Boolean = pin is String && pin.isNotBlank() &&
        '\u0000' !in pin && pin.toByteArray(Charsets.UTF_8).size <= 8192

    /** Overlay state must acquire an account namespace before managed enrollment advertises it. */
    fun validateAssigned(raw:String) = validateAssigned(raw,null)
    internal fun validateAssigned(raw:String,material:OverlayRuntimeMaterial?) {
        validate(raw)
        val outbounds=JSONObject(raw).getJSONArray("outbounds")
        for(i in 0 until outbounds.length()) {
            val item=outbounds.getJSONObject(i)
            if(item.getString("type")=="netbird") {
                val prepared=requireNotNull(material){"overlay_material_unavailable"}
                require(io.syn443.policy.Policy.hash(raw)==prepared.configHash)
                prepared.validateOutbound(item)
            }else require(!item.has("managed") && !item.has("managed_namespace"))
        }
    }
    fun render(raw: String?, stateRoot: java.io.File): String = renderInternal(raw,stateRoot,null)
    internal fun renderManaged(raw:String,stateRoot:java.io.File,material:OverlayRuntimeMaterial):String {
        require(io.syn443.policy.Policy.hash(raw)==material.configHash);material.requireCurrent()
        return renderInternal(raw,stateRoot,material).also{material.requireCurrent()}
    }
    private fun renderInternal(raw:String?,stateRoot:java.io.File,material:OverlayRuntimeMaterial?):String {
        val value = if (raw == null) JSONObject("""{"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}""") else JSONObject(raw).also { validate(raw) }
        // Native adaptive construction extracts its immutable approved checks
        // together with adaptive_routes before parsing ordinary SDK options.
        val adaptive = value.has("adaptive_routes")
        val checks = value.optJSONArray("route_checks")
        val hasProfiles = checks != null && (0 until checks.length()).any { checks.getJSONObject(it).has("profile") }
        if (!adaptive && !hasProfiles) value.remove("route_checks")
        value.remove("route_failover")
        value.put("log", JSONObject().put("disabled", true))
        val outbounds = value.getJSONArray("outbounds")
        var managedApplied=false
        for (i in 0 until outbounds.length()) {
            val item = outbounds.getJSONObject(i)
            if (item.getString("type") != "netbird") {require(!item.has("managed") && !item.has("managed_namespace"));continue}
            if(material!=null) {
                require(!managedApplied);managedApplied=true
                material.localize(item,stateRoot)
                if(!item.has("connection_mode"))item.put("connection_mode","direct")
                continue
            }
            require(!item.has("managed") && !item.has("managed_namespace"))
            // Stable across route/config edits, isolated from arbitrary imported paths.
            val identity = item.getString("tag") + "\u0000" + item.getString("management_url")
            val hash = java.security.MessageDigest.getInstance("SHA-256").digest(identity.toByteArray(Charsets.UTF_8))
                .joinToString("") { "%02x".format(it) }
            item.put("state_directory", java.io.File(stateRoot, "netbird/$hash").absolutePath)
            if (!item.has("connection_mode")) item.put("connection_mode", "direct")
        }
        require(material==null || managedApplied)
        value.put("inbounds", JSONArray().put(JSONObject().put("type", "tun").put("tag", "tun")
            .put("address", JSONArray().put("192.0.2.1/30").put("fd00:443::1/126"))
            .put("mtu", 1400).put("auto_route", false).put("stack", "gvisor")))
        if (!value.has("dns")) value.put("dns", JSONObject().put("servers", JSONArray().put(
            JSONObject().put("type", "local").put("tag", "physical-dns"))).put("final", "physical-dns"))
        val route = value.optJSONObject("route") ?: JSONObject()
        val rules = route.optJSONArray("rules") ?: JSONArray()
        val combined = JSONArray().put(JSONObject().put("port", 53).put("action", "hijack-dns"))
        for (i in 0 until rules.length()) combined.put(rules.get(i))
        route.put("rules", combined).put("auto_detect_interface", true)
        value.put("route", route)
        return value.toString().also { if (adaptive) require(utf8Bytes(it) <= 524288) { "invalid_adaptive_engine_config" } }
    }
}
