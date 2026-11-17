package io.syn443.android.vpn

/** A closed ASCII local command. No JSON coercion, duplicate keys or hidden payload. */
internal data class OverlayViewRequest(val section: String, val page: Int, val request: String) {
    companion object {
        private val entry = Regex("[ \\t\\r\\n]*\"(kind|section|page|request)\"[ \\t\\r\\n]*:[ \\t\\r\\n]*(?:\"([A-Za-z0-9_-]{1,64})\"|(0|[1-9][0-9]?))[ \\t\\r\\n]*")
        fun parse(raw: String?): OverlayViewRequest? {
            if (raw == null || raw.length !in 1..1024 || raw.any { it.code > 127 }) return null
            val body = raw.trim(' ', '\t', '\r', '\n')
            if (!body.startsWith('{') || !body.endsWith('}')) return null
            val fields = body.substring(1, body.lastIndex).split(',')
            if (fields.size != 4) return null
            val values = mutableMapOf<String, Pair<String, Boolean>>()
            for (field in fields) {
                val match = entry.matchEntire(field) ?: return null
                val key = match.groupValues[1]
                val quoted = match.groups[2] != null
                if (values.put(key, (if (quoted) match.groupValues[2] else match.groupValues[3]) to quoted) != null) return null
            }
            if (values["kind"] != ("overlay-view" to true)) return null
            val section = values["section"]?.takeIf { it.second && it.first in setOf("peers", "diagnostics") }?.first ?: return null
            val page = values["page"]?.takeIf { !it.second }?.first?.toIntOrNull()?.takeIf { it in 0..63 } ?: return null
            val request = values["request"]?.takeIf { it.second }?.first ?: return null
            return OverlayViewRequest(section, page, request)
        }
    }
}
