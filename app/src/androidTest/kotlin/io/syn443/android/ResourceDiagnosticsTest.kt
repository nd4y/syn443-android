package io.syn443.android

import androidx.test.platform.app.InstrumentationRegistry
import androidx.core.net.toUri
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import androidx.compose.ui.test.*

/** Safe on a configured physical phone: no imports, Connect, Stop or fault injection. */
class ResourceDiagnosticsTest {
    @get:org.junit.Rule val compose = androidx.compose.ui.test.junit4.createAndroidComposeRule<MainActivity>()
    @Test fun engineExitHistoryHasVisibleOnDemandControls() {
        compose.onNodeWithTag("exit-refresh").performScrollTo().performClick()
        compose.waitUntil(10_000) { compose.onAllNodesWithTag("exit-status").fetchSemanticsNodes().isNotEmpty() }
        compose.onNodeWithTag("exit-status").performScrollTo().assertIsDisplayed()
    }
    @Test fun resourceRequestsAreBoundedRedactedAndDoNotChangeIntent() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val uri = "content://io.syn443.control".toUri()
        fun call(method: String): JSONObject {
            val result = checkNotNull(context.contentResolver.call(uri, method, null, null))
            assertTrue(result.getBoolean("ok"))
            return JSONObject(checkNotNull(result.getString("json")))
        }
        val before = call("status")
        val first = call("resources")
        val second = call("resources")
        assertEquals(1, first.getInt("schemaVersion"))
        assertEquals(30_000L, first.getLong("minIntervalMs"))
        assertTrue(second.getBoolean("cached"))
        assertEquals(first.getLong("sampledElapsedMs"), second.getLong("sampledElapsedMs"))
        val processes = first.getJSONArray("processes")
        assertEquals(2, processes.length())
        assertEquals("controller", processes.getJSONObject(0).getString("role"))
        assertEquals("available", processes.getJSONObject(0).getString("state"))
        assertTrue(processes.getJSONObject(0).getLong("cpuTimeMs") >= 0)
        for (i in 0 until processes.length()) {
            val process = processes.getJSONObject(i)
            assertEquals(setOf("role", "state", "cpuTimeMs", "rssBytes", "threads", "fileDescriptors", "window"), process.keys().asSequence().toSet())
            assertEquals(setOf("state", "elapsedMs", "awakeMs", "cpuMs", "cpuPermille"), process.getJSONObject("window").keys().asSequence().toSet())
        }
        val after = call("status")
        for (key in listOf("generation", "desiredOn", "configRevision")) assertEquals(before.opt(key), after.opt(key))
    }
}
