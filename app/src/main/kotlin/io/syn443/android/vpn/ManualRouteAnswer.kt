package io.syn443.android.vpn

import org.json.JSONArray
import org.json.JSONObject

/** The entered destination is never part of the retained answer. */
internal class ManualRouteAnswer(val description: String, val outbound: String? = null, private val revision: String? = null) {
    fun measurement(health: JSONObject?): String? {
        if (outbound == null || revision.isNullOrEmpty() || health == null || health.optString("measurementRevision") != revision) return null
        val rows = health.optJSONArray("routes") ?: return null
        val nodes = (0 until rows.length()).map { rows.getJSONObject(it) }
        val route = nodes.singleOrNull { it.optString("label") == outbound } ?: return null
        if (route.optString("state") != "working" || route.optBoolean("checkPending") || route.optString("reason") != "ok") return null
        val path = route.optJSONArray("measuredPath") ?: return null
        if (path.length() !in 1..64) return null
        val ids = path.strings()
        if (ids.toSet().size != ids.size) return null
        val dialOrder = if (route.optString("type") == "syn443-adaptive") {
            // The native commit acknowledged these graph node IDs in entry-to-exit order.
            if (route.optJSONObject("search")?.optString("state") != "VERIFIED") return null
            ids
        } else {
            // The ordinary probe sampled selector -> exit -> ... -> entry and checked the selection again on return.
            val byId = nodes.associateBy { it.optString("id") }
            if (ids.first() != route.optString("id")) return null
            val hops = ids.map { byId[it] ?: return null }
            if (hops.last().optString("type") in groups) return null
            val concrete = hops.filter { it.optString("type") !in groups }
            if (concrete.isEmpty() || concrete.any { it.optString("type") !in protocols }) return null
            concrete.asReversed().map { it.optString("label") }
        }
        if (!dialOrder.all(alias::matches)) return null
        return "Последняя успешная проверка · " + dialOrder.joinToString(" → ") + " · узел выхода " + dialOrder.last()
    }

    private fun JSONArray.strings() = List(length()) { optString(it) }
    private companion object {
        val alias = Regex("[A-Za-z0-9_-][A-Za-z0-9_.-]{0,63}")
        val groups = setOf("selector", "urltest")
        val protocols = setOf("direct", "http", "socks", "vless", "ssh")
    }
}
