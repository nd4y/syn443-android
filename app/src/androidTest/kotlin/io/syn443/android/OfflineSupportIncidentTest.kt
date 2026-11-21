package io.syn443.android

import android.content.Context
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.test.core.app.ApplicationProvider
import io.syn443.android.chat.AdminIncidentLookup
import io.syn443.android.chat.incidentResult
import io.syn443.android.chat.ChatLimits
import io.syn443.android.chat.ChatOutbox
import io.syn443.android.chat.IncidentPreview
import io.syn443.android.chat.SupportIncident
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import java.io.File

class OfflineSupportIncidentTest {
    @get:Rule val compose = createComposeRule()
    private val id = "0123456789abcdef".repeat(2)
    private fun sample() = JSONObject().put("desiredOn", true).put("phase", "Degraded")
        .put("engineStateKnown", true).put("engineActive", true).put("reason", "private-marker")
        .put("account", "private-marker").put("policy", JSONObject().put("activeRevision", 9).put("lastKnownGoodRevision", 7))
        .put("routeHealth", JSONObject().put("routes", JSONArray()
            .put(JSONObject().put("state", "working").put("label", "private-marker"))
            .put(JSONObject().put("state", "failed").put("reason", "tls_failed"))
            .put(JSONObject().put("state", "stale").put("reason", "private-marker"))))

    @Test fun snapshotOnlyContainsClosedFactsAndDropsObsoleteEngineEvidence() {
        val raw = sample()
        val message = SupportIncident.capture(raw, id).message
        for (label in listOf("SYN-0123456789ab", "частичная доступность", "работают 1, с ошибкой 1, устарели 1",
            "Слой сбоя - TLS", "Активная версия политики - 9", "Последняя рабочая версия политики - 7"))
            assertTrue(label, message.contains(label))
        assertFalse(message.contains("private-marker"))
        raw.put("engineStateKnown", false).put("phase", "Online")
        raw.getJSONObject("policy").put("activeRevision", "private-marker")
        val old = SupportIncident.capture(raw, id).message
        assertTrue(old.contains("Состояние при создании - неизвестно"))
        assertTrue(old.contains("Проверки маршрутов при создании - нет подтверждений"))
        assertTrue(old.contains("Активная версия политики - неизвестна"))
        assertFalse(old.contains("private-marker"))
        assertFalse(old.contains("TLS"))
        assertTrue(SupportIncident.capture(null, id).message.contains("Намерение VPN - неизвестно"))
    }

    @Test fun encryptedOfflineReportSurvivesReopenAndOnlyBindsOnceToSelf() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val name = "test-" + ChatLimits.id()
        val report = SupportIncident.capture(sample(), id)
        val first = "a".repeat(32)
        val other = "b".repeat(32)
        fun self(target: String) = JSONObject().put("admin", true).put("conversation", JSONObject().put("id", target))
        try {
            ChatOutbox(context, 7, name).use { store ->
                store.queueIncident(report)
                store.queueIncident(report)
                assertEquals(1, store.drafts().size)
                assertEquals("", store.draft(id)!!.getString("conversation"))
            }
            val file = File(context.noBackupFilesDir, "$name.db")
            assertFalse(file.readBytes().toString(Charsets.UTF_8).contains(report.message))
            ChatOutbox(context, 7, name).use { store ->
                assertThrows(Exception::class.java) { store.bindOwnIncidents(JSONObject().put("id", other)) }
                store.bindOwnIncidents(self(first))
                store.bindOwnIncidents(self(other))
                store.queueIncident(report)
                val saved = store.draft(id)!!
                assertEquals(first, saved.getString("conversation"))
                assertEquals(report.message, saved.getString("text"))
                assertEquals(0, saved.getJSONArray("files").length())
                val wrong = JSONObject().put("id", other).put("clientId", id).put("conversation", other)
                    .put("text", report.message).put("attachments", JSONArray()).put("sequence", 1)
                assertThrows(Exception::class.java) { store.acknowledgeSent(id, emptyList(), wrong) }
                assertNotNull(store.draft(id))
                store.acknowledgeSent(id, emptyList(), wrong.put("conversation", first))
                assertNull(store.draft(id))
                store.queueIncident(SupportIncident.capture(null))
            }
            ChatOutbox(context, 8, name).use { store -> assertTrue(store.drafts().isEmpty()) }
        } finally {
            ChatOutbox.erase(context, name)
            context.deleteDatabase(File(context.noBackupFilesDir, "$name.db").path)
        }
    }

    @Test fun administratorLookupWillNotDisplayAWrongOrLateIncident() {
        val reference = "SYN-0123456789ab"
        val deferred = kotlinx.coroutines.CompletableDeferred<JSONObject>()
        val started = java.util.concurrent.atomic.AtomicInteger()
        fun result(ref:String) = JSONObject().put("reference",ref).put("state","found")
            .put("report",JSONObject().put("text","Обращение $ref\nСлой сбоя - TLS").put("createdAt",1700000000))
        assertThrows(Exception::class.java) { incidentResult(reference, result("SYN-111111111111")) }
        assertThrows(Exception::class.java) { incidentResult(reference, result(reference).put("state","ambiguous")) }
        compose.setContent { MaterialTheme { AdminIncidentLookup { started.incrementAndGet(); deferred.await() } } }
        val field = compose.onNodeWithTag("incident-reference")
        val submit = compose.onNodeWithTag("incident-find")
        field.performTextReplacement(reference+"0")
        submit.assertIsNotEnabled()
        field.performTextReplacement(reference)
        submit.performClick()
        compose.waitUntil(5_000) { started.get() == 1 }
        field.performTextReplacement("SYN-000000000001")
        deferred.complete(result(reference))
        compose.waitForIdle()
        compose.onNodeWithTag("incident-result").assertDoesNotExist()
        field.performTextReplacement(reference)
        submit.performClick()
        compose.onNodeWithTag("incident-result").assertTextContains("Слой сбоя - TLS",substring=true)
        submit.assertIsEnabled()
    }

    @Test fun previewRequiresExplicitSubmissionAndAllowsCancelWithoutAnAccount() {
        val ownerReady = mutableStateOf(false)
        var submitted = 0
        var dismissed = 0
        val report = SupportIncident.capture(null, id)
        compose.setContent { MaterialTheme {
            IncidentPreview(report, false, null, ownerReady.value, { submitted++ }, { dismissed++ })
        } }
        compose.onNodeWithTag("incident-preview").assertTextContains("Обращение SYN-0123456789ab", substring = true)
        compose.onNodeWithTag("incident-submit").assertIsNotEnabled()
        compose.onNodeWithText("Отмена").performClick()
        compose.runOnIdle { assertEquals(1, dismissed); assertEquals(0, submitted); ownerReady.value = true }
        compose.onNodeWithTag("incident-submit").assertIsEnabled().performClick()
        compose.runOnIdle { assertEquals(1, submitted) }
    }
}
