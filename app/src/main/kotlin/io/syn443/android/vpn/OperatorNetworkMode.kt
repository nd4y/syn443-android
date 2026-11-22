package io.syn443.android.vpn

import org.json.JSONObject

/** Only the live service supplies a report. A stored link or SSID cannot authorize a mode. */
internal object OperatorNetworkMode {
    private val stampPattern = Regex("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
    private val availableModes = setOf("WIFI", "HOME_WIFI", "CELLULAR", "CELLULAR_RESTRICTED")

    fun observe(state: JSONObject, report: JSONObject?, now: Long): JSONObject {
        val result = JSONObject().put("state", "unavailable")
        for (field in listOf("generation", "networkEpoch")) {
            val value = state.optLong(field, -1)
            if (value >= 0) result.put(field, value)
        }
        if (state.opt("desiredOn") != true || report == null || !result.has("generation") || !result.has("networkEpoch")) return result
        val source = report.getString("source")
        val until = report.getLong("until")
        if (source == "manual" && until <= now) return result
        return result.put("state", "observed").put("effective", report.getString("effective"))
            .put("source", source).put("allowed", report.getJSONArray("allowed"))
            .put("maxMinutes", report.getInt("maxMinutes")).put("stamp", report.getString("stamp"))
            .also { if (source == "manual") it.put("remainingMs", until - now) }
    }

    fun request(view: JSONObject, argument: String, submit: (String, String, Int) -> Boolean): JSONObject {
        require(argument.length <= 80 && view.getString("state") == "observed")
        val parts = argument.split(':')
        require(parts.size == 3 && stampPattern.matches(parts[0]) && parts[0] == view.getString("stamp"))
        val mode = parts[1]
        val minutes = requireNotNull(parts[2].toIntOrNull())
        require(parts[2] == minutes.toString())
        if (mode == "AUTO") {
            require(minutes == 0 && view.getString("source") == "manual")
        } else {
            val allowed = view.getJSONArray("allowed")
            require(mode in availableModes && (0 until allowed.length()).any { allowed.getString(it) == mode })
            require(minutes in 1..view.getInt("maxMinutes") && minutes <= 1440)
        }
        val receipt = JSONObject().put("admitted", true).put("generation", view.getLong("generation"))
            .put("networkEpoch", view.getLong("networkEpoch"))
        require(submit(parts[0], mode, minutes))
        return receipt
    }
}
