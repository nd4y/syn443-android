package io.syn443.android.vpn

import org.json.JSONArray
import org.json.JSONObject

object EngineConfig {
    private val supported = setOf("direct", "http", "socks", "vless", "ssh", "selector", "urltest")
    fun validate(raw: String) {
        val value = JSONObject(raw)
        require(value.keys().asSequence().all { it in setOf("outbounds", "dns", "route") }) { "unsupported root field" }
        val outbounds = value.getJSONArray("outbounds")
        require(outbounds.length() in 1..64)
        val tags = mutableSetOf<String>()
        for (i in 0 until outbounds.length()) {
            val item = outbounds.getJSONObject(i)
            require(item.getString("type") in supported)
            require(tags.add(item.getString("tag")))
        }
        val final = value.optJSONObject("route")?.optString("final").orEmpty()
        require(final.isEmpty() || final in tags)
    }
    fun render(raw: String?, dns: String): String {
        val value = if (raw == null) JSONObject("""{"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}""") else JSONObject(raw).also { validate(raw) }
        value.put("log", JSONObject().put("disabled", true))
        value.put("inbounds", JSONArray().put(JSONObject().put("type", "tun").put("tag", "tun")
            .put("address", JSONArray().put("192.0.2.1/30").put("fd00:443::1/126"))
            .put("mtu", 1400).put("auto_route", false).put("stack", "gvisor")))
        if (!value.has("dns")) value.put("dns", JSONObject().put("servers", JSONArray().put(
            JSONObject().put("type", "udp").put("tag", "physical-dns").put("server", dns))).put("final", "physical-dns"))
        val route = value.optJSONObject("route") ?: JSONObject()
        val rules = route.optJSONArray("rules") ?: JSONArray()
        val combined = JSONArray().put(JSONObject().put("port", 53).put("action", "hijack-dns"))
        for (i in 0 until rules.length()) combined.put(rules.get(i))
        route.put("rules", combined).put("auto_detect_interface", true)
        value.put("route", route)
        return value.toString()
    }
}
