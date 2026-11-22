package io.syn443.policy

import java.util.Collections
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.intOrNull

class NetworkModePolicy private constructor(
    val preferredMode: String,
    val userModes: Set<String>,
    val maxOverrideMinutes: Int,
) {
    companion object {
        private val modes = setOf("WIFI", "HOME_WIFI", "CELLULAR", "CELLULAR_RESTRICTED")

        fun parse(input: JsonElement, hasHomeProof: Boolean): NetworkModePolicy {
            val fields = input as? JsonObject ?: throw IllegalArgumentException("invalid_mode_selection")
            require(fields.keys == setOf("preferredMode", "userModes", "maxOverrideMinutes"))
            fun text(value: JsonElement?): String =
                (value as? JsonPrimitive)?.takeIf { it.isString }?.content ?: throw IllegalArgumentException("invalid_mode")
            fun valid(mode: String) = mode in modes && (mode != "HOME_WIFI" || hasHomeProof)
            val preferred = text(fields["preferredMode"])
            require(preferred == "AUTO" || valid(preferred))
            val array = fields["userModes"] as? JsonArray ?: throw IllegalArgumentException("invalid_mode_list")
            require(array.size <= 4)
            val permitted = array.map(::text)
            require(permitted.all(::valid) && permitted.distinct().size == permitted.size)
            val limit = (fields["maxOverrideMinutes"] as? JsonPrimitive)?.takeUnless { it.isString }?.intOrNull
            require(limit != null && (if (permitted.isEmpty()) limit == 0 else limit in 1..1440))
            return NetworkModePolicy(preferred, Collections.unmodifiableSet(permitted.toSet()), limit)
        }
    }
}
