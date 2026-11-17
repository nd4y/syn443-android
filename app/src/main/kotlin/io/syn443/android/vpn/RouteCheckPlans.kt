package io.syn443.android.vpn

import io.syn443.policy.RouteCheckProfile
import org.json.JSONArray
import org.json.JSONObject

/** APP serialization only; neither this adapter nor its diagnostics authorize I/O. */
internal object RouteCheckPlans {
    private val failureCodes = setOf("dial_failed", "check_timeout", "tls_failed", "ssh_banner_mismatch",
        "request_failed", "response_failed", "http_response_mismatch", "exit_evidence_invalid", "exit_ip_mismatch", "exit_country_mismatch")
    fun hasProfiles(config: JSONObject): Boolean {
        val rows = config.optJSONArray("route_checks") ?: return false
        return (0 until rows.length()).any { index ->
            rows.optJSONObject(index)?.keys()?.asSequence()?.any { it.equals("profile", ignoreCase = true) } == true
        }
    }
    fun profile(row: JSONObject): RouteCheckProfile? {
        if (!row.has("profile")) return null
        require(row.keys().asSequence().toSet() == setOf("outbound", "required", "profile"))
        require(row.get("outbound") is String && row.getString("outbound").length in 1..256 && row.get("required") is Boolean)
        val profile = row.get("profile") as? JSONObject ?: error("invalid_check_profile")
        fun integers(value: Any?) {
            when (value) {
                is JSONObject -> value.keys().forEach { integers(value.get(it)) }
                is JSONArray -> for (i in 0 until value.length()) integers(value.get(i))
                is Number -> require(value is Int || value is Long)
            }
        }
        integers(profile)
        return RouteCheckProfile.decode(profile.toString())
    }
    fun wire(id: String, outbound: String, checks: JSONArray, profile: RouteCheckProfile?): JSONObject =
        JSONObject().put("id", id).put("outbound", outbound).also {
            if (profile == null) it.put("checks", checks) else it.put("profile", JSONObject(profile.wireJson()))
        }
    fun requireConcrete(config: JSONObject) {
        val rows = config.optJSONArray("route_checks") ?: return
        val plans = (0 until rows.length()).map { rows.getJSONObject(it) }.filter { it.has("profile") }
        if (plans.isEmpty()) return
        require(!config.has("route_failover"))
        val nodes = config.getJSONArray("outbounds")
        val byTag = (0 until nodes.length()).associate { nodes.getJSONObject(it).getString("tag") to nodes.getJSONObject(it) }
        for (plan in plans) {
            var cursor = plan.getString("outbound")
            val seen = mutableSetOf<String>()
            if (byTag.getValue(cursor).getString("type") == "syn443-adaptive") continue
            while (cursor.isNotEmpty()) {
                require(seen.size < 4 && seen.add(cursor))
                val node = byTag.getValue(cursor)
                if (node.getString("type") == "direct") {
                    require(!node.has("detour"))
                    break
                }
                require(node.getString("type") in setOf("http", "socks", "vless", "ssh"))
                cursor = node.optString("detour")
            }
        }
    }
    fun diagnostic(value: JSONObject, profile: RouteCheckProfile): JSONObject {
        require(value.toString().toByteArray(Charsets.UTF_8).size <= 4096)
        require(value.keys().asSequence().toSet() == setOf("id", "revision", "outcome", "leaves"))
        require(value.get("id") == profile.id && value.get("revision") is Number &&
            value.get("revision").let { it is Int || it is Long } && value.getLong("revision") == profile.revision)
        require(value.get("outcome") in setOf("TRUE", "FALSE", "UNKNOWN"))
        val leaves = value.getJSONArray("leaves")
        val ids = profile.leafIDs()
        require(leaves.length() == ids.size && leaves.length() in 1..4)
        for (i in 0 until leaves.length()) {
            val leaf = leaves.getJSONObject(i)
            require(leaf.keys().asSequence().toSet() == setOf("id", "outcome", "code") && leaf.get("id") == ids[i])
            val code = leaf.get("code")
            require(when (leaf.get("outcome")) {
                "TRUE" -> code == "ok"
                "FALSE" -> code in failureCodes
                "UNKNOWN" -> code in setOf("probe_unavailable", "cancelled", "check_timeout", "unsupported", "outbound_unavailable")
                "SKIPPED" -> code == "not_checked"
                else -> false
            })
        }
        return JSONObject(value.toString())
    }
    fun unknown(profile: RouteCheckProfile): JSONObject = JSONObject().put("id", profile.id).put("revision", profile.revision)
        .put("outcome", "UNKNOWN").put("leaves", JSONArray(profile.leafIDs().map {
            JSONObject().put("id", it).put("outcome", "SKIPPED").put("code", "not_checked")
        }))
    fun projection(value: JSONObject?, profile: RouteCheckProfile, expected: String): JSONObject? = try {
        value?.let { diagnostic(it, profile).takeIf { result -> result.getString("outcome") == expected } }
    } catch (_: Exception) { null }
}
