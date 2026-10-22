package io.syn443.android.vpn

import org.json.JSONArray
import org.json.JSONObject

object EngineConfig {
    private val supported = setOf("direct", "http", "socks", "vless", "ssh", "selector", "urltest", "netbird")
    fun validate(raw: String) {
        val value = JSONObject(raw)
        require(value.keys().asSequence().all { it in setOf("outbounds", "dns", "route") }) { "unsupported root field" }
        val outbounds = value.getJSONArray("outbounds")
        require(outbounds.length() in 1..64)
        val tags = mutableSetOf<String>()
        var overlays = 0
        for (i in 0 until outbounds.length()) {
            val item = outbounds.getJSONObject(i)
            require(item.getString("type") in supported)
            require(tags.add(item.getString("tag")))
            if (item.getString("type") == "netbird") {
                require(++overlays <= 1) { "one NetBird identity per native process" }
                require(item.optString("connection_mode", "direct") in setOf("direct", "vless"))
            }
        }
        val final = value.optJSONObject("route")?.optString("final").orEmpty()
        require(final.isEmpty() || final in tags)
    }
    fun render(raw: String?, stateRoot: java.io.File): String {
        val value = if (raw == null) JSONObject("""{"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}""") else JSONObject(raw).also { validate(raw) }
        value.put("log", JSONObject().put("disabled", true))
        val outbounds = value.getJSONArray("outbounds")
        for (i in 0 until outbounds.length()) {
            val item = outbounds.getJSONObject(i)
            if (item.getString("type") != "netbird") continue
            // Stable across route/config edits, isolated from arbitrary imported paths.
            val identity = item.getString("tag") + "\u0000" + item.getString("management_url")
            val hash = java.security.MessageDigest.getInstance("SHA-256").digest(identity.toByteArray(Charsets.UTF_8))
                .joinToString("") { "%02x".format(it) }
            item.put("state_directory", java.io.File(stateRoot, "netbird/$hash").absolutePath)
            if (!item.has("connection_mode")) item.put("connection_mode", "direct")
        }
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
        return value.toString()
    }
}
