package io.syn443.android

import androidx.test.platform.app.InstrumentationRegistry
import io.syn443.android.vpn.TechnicalTelemetryDisk
import io.syn443.android.vpn.TelemetryCapture
import io.syn443.identity.Identity
import io.syn443.identity.TechnicalTelemetry
import java.io.File
import java.util.UUID
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class TechnicalTelemetryDiskTest {
    @Test fun consentFenceDropsPriorEventsAndRawDiagnosticStrings() {
        val context=InstrumentationRegistry.getInstrumentation().targetContext
        val capture=TelemetryCapture(context,"test-consent-"+UUID.randomUUID().toString().replace("-",""))
        val owner=Identity.hash("synthetic enrollment".toByteArray())
        try {
            capture.enable(owner,1)
            val consent=checkNotNull(capture.consent(owner))
            val rows=JSONArray(listOf(1L,2L).map {sequence->JSONObject().put("sequence",sequence)
                .put("at",1_800_000_000_000).put("elapsed",10).put("networkEpoch",1)
                .put("phase","Online").put("code","synthetic endpoint.example.invalid")})
            val (entries,through)=capture.sample(JSONObject().put("events",rows),consent,52)
            assertEquals(2L,through)
            assertEquals("online",entries.single().event.code)
            assertNull(entries.single().event.path)
            assertTrue(capture.recorded(consent,through))
            assertTrue(capture.sample(JSONObject().put("events",rows),checkNotNull(capture.consent(owner)),52).first.isEmpty())
            capture.disable()
            assertFalse(capture.recorded(consent,3))
            assertNull(capture.consent(owner))
        }finally {capture.disable()}
    }
    @Test fun encryptedQueueRestartsWithoutExposingAnotherEnrollment() {
        val context=InstrumentationRegistry.getInstrumentation().targetContext
        val namespace="test-telemetry-"+UUID.randomUUID().toString().replace("-","")
        val first=TechnicalTelemetryDisk(context,namespace)
        val owner=Identity.hash("synthetic owner".toByteArray())
        val other=Identity.hash("another synthetic owner".toByteArray())
        val entry=TechnicalTelemetry.Queued(TechnicalTelemetry.Key(Identity.random(),52,1,1),
            TechnicalTelemetry.Event(Identity.random(),1_800_000_000_000,1,1,"probe","dns_timeout","wifi"))
        val queue=TechnicalTelemetry.Snapshot(1,owner,listOf(entry))
        try {
            assertTrue(first.read(owner).entries.isEmpty())
            first.write(owner,queue)
            val file=File(context.noBackupFilesDir,"$namespace.bin")
            assertFalse(file.readBytes().decodeToString().contains("dns_timeout"))
            assertFalse(file.readBytes().decodeToString().contains(entry.event.id))
            val reopened=TechnicalTelemetryDisk(context,namespace)
            assertEquals(queue,reopened.read(owner))
            assertTrue(reopened.read(other).entries.isEmpty())
            assertThrows(IllegalArgumentException::class.java){reopened.write(other,queue)}
            reopened.erase()
            assertTrue(reopened.read(owner).entries.isEmpty())
        }finally {first.erase()}
    }
}
