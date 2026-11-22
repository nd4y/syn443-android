package io.syn443.android

import androidx.test.platform.app.InstrumentationRegistry
import io.syn443.android.vpn.TechnicalTelemetryDisk
import io.syn443.android.vpn.StateStore
import io.syn443.decision.NetworkMode
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
    @Test fun adaptiveAcknowledgementKeepsLifecycleAndAttributesOnlyCurrentSignedEvents() {
        val state = JSONObject().put("desiredOn", true).put("generation", 7L).put("networkEpoch", 9L)
            .put("phase", "Online").put("reason", "required_https_ok")
        val pristine = state.toString()
        fun record(generation: Long, epoch: Long, revision: Long) =
            StateStore.recordAdaptiveReselection(state, generation, epoch, revision, NetworkMode.HOME_WIFI)
        assertFalse(record(6, 9, 43))
        assertFalse(record(7, 8, 43))
        assertFalse(record(7, 9, 0))
        assertEquals(pristine, state.toString())
        state.put("desiredOn", false)
        assertFalse(record(7, 9, 43))
        state.put("desiredOn", true)
        assertTrue(record(7, 9, 43))
        assertEquals("Online", state.getString("phase"))
        assertEquals("required_https_ok", state.getString("reason"))
        val row = state.getJSONArray("events").getJSONObject(0)
        assertEquals(setOf("sequence","at","elapsed","phase","code","intentGeneration","networkEpoch","policyRevision","algorithmRevision","networkMode"), row.keys().asSequence().toSet())
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val capture = TelemetryCapture(context, "test-consent-" + UUID.randomUUID().toString().replace("-",""))
        val owner = Identity.hash("synthetic adaptive sample".toByteArray())
        try {
            capture.enable(owner, 0)
            val consent = checkNotNull(capture.consent(owner))
            val queued = capture.sample(state, consent, 128).first.single()
            assertEquals(43L, queued.key.policyRevision)
            assertEquals(3, queued.key.algorithmRevision)
            assertEquals("route", queued.event.kind)
            assertEquals("reselected", queued.event.code)
            assertEquals("home_wifi", queued.event.mode)
            assertNull(queued.event.path)
            assertEquals(0L, capture.sample(state, consent, 127).first.single().key.policyRevision)
            row.put("policyRevision", "43")
            assertEquals(0L, capture.sample(state, consent, 128).first.single().key.policyRevision)
            row.put("policyRevision", 43).put("algorithmRevision", "synthetic-other")
            assertEquals(0L, capture.sample(state, consent, 128).first.single().key.policyRevision)
        } finally { capture.disable() }
    }

    @Test fun onlyConfirmedRouteSelectionCarriesItsPolicyAndAlgorithmRevisions() {
        val context=InstrumentationRegistry.getInstrumentation().targetContext
        val capture=TelemetryCapture(context,"test-consent-"+UUID.randomUUID().toString().replace("-",""))
        val owner=Identity.hash("synthetic enrollment".toByteArray())
        fun row(sequence:Long,code:String,revision:Long,algorithm:String)=JSONObject().put("sequence",sequence)
            .put("at",1_800_000_000_000).put("elapsed",10).put("networkEpoch",1).put("phase","Degraded")
            .put("code",code).put("policyRevision",revision).put("algorithmRevision",algorithm)
        try {
            capture.enable(owner,0)
            val consent=checkNotNull(capture.consent(owner))
            val events=JSONArray(listOf(
                row(1,"managed_route_recheck",41,"m4-confirmed-v1"),
                row(2,"other",41,"m4-confirmed-v1"),
                row(3,"managed_route_recheck",42,"m1-local-v1"),
                row(4,"managed_route_recheck",-1,"m4-confirmed-v1"),
                row(5,"managed_route_recheck",43,"unknown-local-version")))
            val (entries,through)=capture.sample(JSONObject().put("events",events),consent,62)
            assertEquals(5L,through)
            assertEquals(listOf(41L to 2, 0L to 1, 42L to 1, 0L to 1, 0L to 1),
                entries.map {it.key.policyRevision to it.key.algorithmRevision})
            assertEquals(listOf("wifi","unknown","wifi","unknown","unknown"),entries.map {it.event.mode})
            assertTrue(entries.all {it.event.path==null})
        } finally {capture.disable()}
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
