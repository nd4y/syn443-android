package io.syn443.policy

import kotlinx.serialization.json.*
import org.junit.Assert.*
import org.junit.Test

class HttpsStatusCheckTest {
    private fun profile(check: JsonElement) =
        """{"schemaVersion":2,"id":"availability","revision":1,"deadlineMs":4000,"leaves":[{"id":"service","check":$check}],"gates":[],"stages":[{"leaf":"service"}]}"""

    @Test fun sharedStatusPredicatesPreserveTheExactMethodAndCode() {
        val data = checkNotNull(javaClass.getResourceAsStream("/https-status-check-vectors.json")).use { it.reader().readText() }
        val vectors = Json.parseToJsonElement(data).jsonObject
        val valid = vectors.getValue("valid").jsonArray
        val invalid = vectors.getValue("invalid").jsonArray
        assertEquals(3, valid.size)
        assertEquals(12, invalid.size)
        for (check in valid) {
            val engine = """{"route_checks":[{"outbound":"direct","required":true,"checks":[$check]}]}"""
            assertTrue(RouteCheckProfiles.inspectEngine(engine).hasMethod("https_status"))
            val parsed = RouteCheckProfile.decode(profile(check))
            val leaf = Canonical.parse(parsed.wireJson()).jsonObject.getValue("leaves").jsonArray.single()
            assertEquals(check, leaf.jsonObject.getValue("check"))
            assertTrue(runCatching { parsed.requireIntent("NON_RU") }.isFailure)
        }
        for (check in invalid) {
            assertTrue(runCatching { RouteCheckProfile.decode(profile(check)) }.isFailure)
            if (check.jsonObject["method"]?.jsonPrimitive?.content == "https_status") {
                val engine = """{"route_checks":[{"outbound":"direct","required":true,"checks":[$check]}]}"""
                assertTrue(runCatching { RouteCheckProfiles.inspectEngine(engine) }.isFailure)
            }
        }
    }
}
