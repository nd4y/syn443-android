package io.syn443.android

import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.core.net.toUri
import androidx.test.platform.app.InstrumentationRegistry
import io.syn443.android.support.DiagnosticsRoute
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
            assertTrue(shell("operator-read-access", privateUri, "grant").contains("ok=false"))
            assertTrue(shell("logs").contains("local_consent_required"))
            ui.setContent { DiagnosticsRoute() }
            val enable = ui.onNodeWithText("Разрешить на 15 минут")
            val revoke = ui.onNodeWithText("Отозвать доступ")
            ui.waitUntil(10000) { ui.onAllNodesWithText("Разрешить на 15 минут").fetchSemanticsNodes().isNotEmpty() }
            enable.performScrollTo().performClick()
            ui.waitUntil(10000) { ui.onAllNodesWithText("Отозвать доступ").fetchSemanticsNodes().isNotEmpty() }
            assertTrue(shell("capabilities").contains("ok=true"))
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
        } finally { local("revoke") }
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
