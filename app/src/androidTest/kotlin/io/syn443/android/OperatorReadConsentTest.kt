package io.syn443.android

import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.core.net.toUri
import androidx.test.platform.app.InstrumentationRegistry
import io.syn443.android.support.DiagnosticProjection
import io.syn443.android.support.DiagnosticsRoute
import org.json.JSONArray
import org.json.JSONObject
import io.syn443.android.vpn.OperatorReadGrant
import java.io.FileInputStream
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test

class OperatorReadConsentTest {
    @get:Rule val ui = createComposeRule()
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val app = instrumentation.targetContext
    private val privateUri = "content://io.syn443.control"
    private val readUri = "content://io.syn443.operator.read"

    private fun shell(method: String, uri: String = readUri, argument: String = ""): String {
        val command = "content call --uri $uri --method $method" + if (argument.isEmpty()) "" else " --arg $argument"
        return instrumentation.uiAutomation.executeShellCommand(command).use { descriptor ->
            FileInputStream(descriptor.fileDescriptor).use { it.readBytes().toString(Charsets.UTF_8) }
        }
    }

    private fun local(action: String) {
        assertTrue(app.contentResolver.call(privateUri.toUri(), "operator-read-access", action, null)!!.getBoolean("ok"))
    }

    @Test fun shellCanReadOnlyDuringAnExplicitLocalDiagnosticsGrant() {
        local("revoke")
        try {
            assertTrue(shell("status").contains("local_consent_required"))
            assertTrue(shell("routes-status").contains("local_consent_required"))
            assertTrue(shell("operator-read-access", privateUri, "grant").contains("ok=false"))
            assertTrue(shell("logs").contains("local_consent_required"))
            assertTrue(shell("overlay-status", argument = "netbird").contains("local_consent_required"))
            ui.setContent { DiagnosticsRoute() }
            val enable = ui.onNodeWithText("Разрешить на 15 минут")
            val revoke = ui.onNodeWithText("Отозвать доступ")
            ui.waitUntil(10000) { ui.onAllNodesWithText("Разрешить на 15 минут").fetchSemanticsNodes().isNotEmpty() }
            enable.performScrollTo().performClick()
            ui.waitUntil(10000) { ui.onAllNodesWithText("Отозвать доступ").fetchSemanticsNodes().isNotEmpty() }
            assertTrue(shell("capabilities").contains("optionalOperations"))
            assertTrue(shell("overlay-status", argument = "netbird").contains("\"controlTransport\""))
            assertTrue(shell("overlay-status", argument = "tailscale").contains("not_implemented"))
            assertTrue(shell("overlay-status", argument = "invalid").contains("ok=false"))
            assertTrue(shell("capabilities").contains("routes-status"))
            assertTrue(shell("routes-status").contains("\"routes\""))
            assertTrue(shell("routes-status", argument = "unexpected").contains("ok=false"))
            val status = shell("status")
            assertTrue(status.contains("ok=true") && status.contains("\"phase\""))
            assertFalse(status.contains("configRevision") || status.contains("targetDevice"))
            assertTrue(shell("logs").contains("\"events\""))
            assertTrue(shell("connect").contains("ok=false"))
            assertTrue(shell("status", argument = "unexpected").contains("ok=false"))
            val own = app.contentResolver.call(readUri.toUri(), "status", null, null)
            assertEquals("unauthorized", own!!.getString("error"))
            revoke.performScrollTo().performClick()
            ui.waitUntil(10000) { ui.onAllNodesWithText("Разрешить на 15 минут").fetchSemanticsNodes().isNotEmpty() }
            assertTrue(shell("status").contains("local_consent_required"))
            assertTrue(shell("routes-status").contains("local_consent_required"))
        } finally { local("revoke") }
    }

    @Test fun routeHealthProjectionPreservesOrdinalFreshnessAndDropsPrivateFields() {
        fun row(n: Int, age: Any, state: String) = JSONObject().put("id", "route-$n")
            .put("required", n == 1).put("state", state).put("ageMs", age)
            .put("label", "private-test-name").put("chain", JSONArray().put("private-test-hop"))
            .put("search", JSONObject().put("state", "VERIFIED").put("target", "private-test-target"))
        val rows = JSONArray().put(row(1, 120_000, "working")).put(row(2, 120_001, "working"))
            .put(row(3, JSONObject.NULL, "off")).put(row(4, 0, "failed"))
        val result = DiagnosticProjection.operatorRoutes(JSONObject().put("routes", rows).put("debug", "private-test"))
        assertEquals(setOf("schemaVersion", "routes"), result.keys().asSequence().toSet())
        val safe = result.getJSONArray("routes")
        assertEquals(4, safe.length())
        val first = safe.getJSONObject(0)
        assertEquals(setOf("position", "state", "required", "ageMs", "search"), first.keys().asSequence().toSet())
        assertTrue(first.getBoolean("required"))
        assertEquals(1, first.getInt("position"))
        assertEquals("working", first.getString("state"))
        assertEquals(120_000L, first.getLong("ageMs"))
        assertEquals("VERIFIED", first.getString("search"))
        assertEquals("unverified", safe.getJSONObject(1).getString("state"))
        assertEquals("SEARCH_INCOMPLETE", safe.getJSONObject(1).getString("search"))
        assertFalse(safe.getJSONObject(1).has("ageMs"))
        assertEquals("off", safe.getJSONObject(2).getString("state"))
        assertFalse(safe.getJSONObject(2).has("ageMs"))
        assertEquals("failed", safe.getJSONObject(3).getString("state"))
        assertEquals(0L, safe.getJSONObject(3).getLong("ageMs"))
        assertFalse(result.toString().contains("private-test"))
    }

    @Test fun monotonicReadWindowEndsAtItsDeadlineAndRejectsAnImpossibleClock() {
        val length = OperatorReadGrant.durationMs
        assertEquals(length, OperatorReadGrant.remaining(100, 100 + length))
        assertEquals(1L, OperatorReadGrant.remaining(99, 100))
        assertEquals(0L, OperatorReadGrant.remaining(100, 100))
        assertEquals(0L, OperatorReadGrant.remaining(101, 100))
        assertEquals(0L, OperatorReadGrant.remaining(99, 100 + length))
        assertEquals(0L, OperatorReadGrant.remaining(-1, 0))
    }
}
