package io.syn443.android.support

import org.json.JSONObject

/** Redacted while rendering, before any config bytes reach the diagnostic collector. */
internal class EffectiveConfig private constructor(private val json: String, val hasNetBird: Boolean) {
    fun component() = DiagnosticArchive.Component(
        DiagnosticArchive.Name.EFFECTIVE_CONFIG, json.toByteArray(Charsets.UTF_8),
        DiagnosticArchive.State.AVAILABLE, DiagnosticArchive.Reason.PROJECTION_ONLY,
    )

    companion object {
        private val protocols = setOf("direct", "http", "socks", "vless", "ssh", "selector", "urltest", "netbird", "syn443-adaptive")

        fun fromRendered(config: JSONObject): EffectiveConfig {
            val counts = JSONObject()
            val outbounds = config.getJSONArray("outbounds")
            for (index in 0 until outbounds.length()) {
                val type = outbounds.getJSONObject(index).opt("type")
                val name = if (type is String && type in protocols) type else "unknown"
                counts.put(name, counts.optInt(name) + 1)
            }
            val value = JSONObject().put("schemaVersion", 1)
                .put("outboundTypes", counts)
                .put("adaptiveRouting", config.has("adaptive_routes"))
            config.optJSONObject("dns")?.optJSONArray("servers")?.let { value.put("dnsServerCount", it.length()) }
            config.optJSONObject("route")?.optJSONArray("rules")?.let { value.put("routeRuleCount", it.length()) }
            return EffectiveConfig(value.toString(), counts.optInt("netbird") > 0)
        }
    }
}

/** Owned by the current controller process. Identity distinguishes successive engine starts. */
internal class ReadyConfig(val generation: Long, val summary: EffectiveConfig) {
    fun netBirdFor(generation: Long, desiredOn: Boolean, engineReady: Boolean): Boolean? =
        if (desiredOn && engineReady && generation == this.generation) summary.hasNetBird else null
    companion object {
        @Volatile var current: ReadyConfig? = null
            private set
        fun publish(snapshot: ReadyConfig?) { current = snapshot }
    }
}
