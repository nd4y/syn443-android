package io.syn443.policy

import kotlinx.serialization.json.*

data class VerifiedFailoverProgram internal constructor(
    val revision: Long,
    val confirmations: Int,
    val minSwitchIntervalMs: Long,
    val policyHash: String,
    val signer: String,
) {
    companion object {
        // Called only for previously authenticated journal entries when computing the rollback key.
        internal fun journalProgramHash(raw: String): String {
            require(raw.length in 1..8192)
            val parts = raw.split('.')
            require(parts.size == 3)
            val document = Canonical.parse(Policy.utf8(Policy.decode64(parts[1]))).jsonObject
            val digest = document.getValue("policyHash").jsonPrimitive
            require(digest.isString && Regex("[a-f0-9]{64}").matches(digest.content))
            return digest.content
        }

        internal fun verify(policy: Payload, roots: Map<String, String>, now: Long): VerifiedFailoverProgram {
            val raw = policy.decisionBundle
            val document = Policy.signedDocument(raw, roots, "syn443-decision+jws", 8192)
            require(document.keys == setOf("schemaVersion", "algorithmId", "evaluatorMin", "evaluatorMax",
                "requiredCapabilities", "targetDevice", "keyThumbprint", "configHash", "notBeforeMs",
                "expiresMs", "policyHash", "program"))
            fun number(value: JsonElement?): Long {
                require(value is JsonPrimitive && !value.isString)
                return requireNotNull(value.longOrNull)
            }
            fun matches(key: String, value: String) = document[key] == JsonPrimitive(value)
            require(number(document["schemaVersion"]) == 1L && number(document["evaluatorMin"]) == 1L &&
                number(document["evaluatorMax"]) == 1L && matches("algorithmId", Policy.CONFIRMED_ALGORITHM))
            require(document["requiredCapabilities"] == JsonArray(listOf(Policy.DECISION_BUNDLE, Policy.ROUTE_DECISION).map { JsonPrimitive(it) }))
            require(matches("targetDevice", policy.targetDevice) && matches("keyThumbprint", policy.keyThumbprint) &&
                matches("configHash", policy.contentHash))
            require(number(document["notBeforeMs"]) == policy.notBeforeMs && number(document["expiresMs"]) == policy.offlineUntilMs &&
                now >= policy.notBeforeMs && now < policy.offlineUntilMs)
            val program = document.getValue("program").jsonObject
            require(program.keys == setOf("revision", "confirmations", "minSwitchIntervalMs"))
            val revision = number(program["revision"])
            val confirmations = number(program["confirmations"])
            val interval = number(program["minSwitchIntervalMs"])
            require(revision in 1L..9007199254740991L && confirmations in 3L..6L && interval in 60_000L..300_000L)
            val hash = Policy.hash(Canonical.encode(program))
            require(matches("policyHash", hash))
            val header = Canonical.parse(Policy.utf8(Policy.decode64(raw.substringBefore('.')))).jsonObject
            return VerifiedFailoverProgram(revision, confirmations.toInt(), interval, hash, header.getValue("kid").jsonPrimitive.content)
        }
    }
}
