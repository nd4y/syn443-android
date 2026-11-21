package io.syn443.android

import androidx.test.platform.app.InstrumentationRegistry
import io.syn443.android.vpn.RuntimeObservationCapture
import io.syn443.android.vpn.RuntimeObservationDisk
import io.syn443.identity.Identity
import io.syn443.identity.RuntimeObservation
import java.io.File
import java.util.UUID
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class RuntimeObservationDiskTest {
    private val context get()=InstrumentationRegistry.getInstrumentation().targetContext
    private fun namespace()="test-runtime-"+UUID.randomUUID().toString().replace("-","")
    private val owner=Identity.hash("synthetic runtime key".toByteArray())
    private fun queue()=RuntimeObservation.empty(owner).offer(owner,
        RuntimeObservation.Report(1,1,75,"online",4,true,true,"wifi",1_800_000_000_000))
    @Test fun encryptedRuntimeRetrySurvivesRestartAndConsentWithdrawalRetainsOnlyItsCursor() {
        val namespace=namespace();val disk=RuntimeObservationDisk(context,namespace)
        try {
            assertEquals(RuntimeObservation.empty(owner),disk.read(owner))
            val queued=queue();disk.write(owner,queued)
            val raw=File(context.noBackupFilesDir,"$namespace.bin").readBytes()
            assertFalse(raw.decodeToString().contains("online"));assertFalse(raw.decodeToString().contains(owner))
            val restored=RuntimeObservationDisk(context,namespace);assertEquals(queued,restored.read(owner))
            restored.clearPending();val cleared=restored.read(owner)
            assertNull(cleared.pending);assertEquals(queued.cursor,cleared.cursor)
            assertTrue(cleared.offer(owner,queued.pending!!).cursor>queued.cursor)
            val other=Identity.hash("other runtime key".toByteArray())
            assertEquals(RuntimeObservation.empty(other),restored.read(other))
            assertThrows(IllegalArgumentException::class.java){restored.write(other,queued)}
        }finally {disk.erase()}
    }
    @Test fun runtimeQueueRejectsCiphertextSubstitutionTruncationAndOversizeWithoutReplacingIt() {
        val first=namespace();val second=namespace()
        val disk=RuntimeObservationDisk(context,first);val other=RuntimeObservationDisk(context,second)
        val file=File(context.noBackupFilesDir,"$first.bin");val foreign=File(context.noBackupFilesDir,"$second.bin")
        try {
            disk.write(owner,queue());other.write(owner,queue())
            val original=file.readBytes()
            for(raw in listOf(original.copyOf(12),ByteArray(4097),foreign.readBytes(),original.copyOf().also {it[it.lastIndex]=(it.last().toInt() xor 1).toByte()})) {
                file.writeBytes(raw)
                assertThrows(Exception::class.java){disk.read(owner)}
                assertArrayEquals(raw,file.readBytes())
            }
            file.writeBytes(original);assertEquals(queue(),disk.read(owner))
        }finally {disk.erase();other.erase()}
    }
    @Test fun runtimeCaptureNeverTurnsCachedOnlineOrAnUnboundEngineIntoPositiveEvidence() {
        fun state(phase:String,known:Boolean,active:Boolean)=JSONObject().put("phase",phase)
            .put("engineStateKnown",known).put("engineActive",active)
        fun sample(s:JSONObject,revision:Long=4)=RuntimeObservationCapture.sample(s,revision,"wifi",1_800_000_000_000,75)
        val cached=sample(state("Online",false,true));assertEquals("unknown",cached.phase);assertFalse(cached.engineActive)
        val unbound=sample(state("Online",true,true),0);assertEquals("unknown",unbound.phase);assertFalse(unbound.engineKnown)
        assertEquals("online",sample(state("Online",true,true)).phase)
        assertEquals("recovering",sample(state("Recovering",true,false)).phase)
        assertEquals("recovering",sample(state("Degraded",true,true)).phase)
        assertEquals("no_network",sample(state("NoNetwork",true,false)).phase)
        assertEquals("blocked",sample(state("Blocked",false,false)).phase)
        assertEquals("blocked",sample(state("BlockedByPolicy",false,false)).phase)
        assertEquals("starting",sample(state("Starting",false,false)).phase)
        assertEquals("starting",sample(state("Connecting",true,false)).phase)
        assertEquals("off",sample(state("Off",true,false)).phase)
        assertEquals("unknown",sample(state("Off",false,false)).phase)
        assertEquals("unknown",sample(state("future",false,false)).phase)
    }
    @Test fun runtimeQueueRejectsMainThreadStorageAccess() {
        val disk=RuntimeObservationDisk(context,namespace())
        InstrumentationRegistry.getInstrumentation().runOnMainSync {
            assertThrows(IllegalStateException::class.java){disk.read(owner)}
            assertThrows(IllegalStateException::class.java){disk.write(owner,queue())}
            assertThrows(IllegalStateException::class.java){disk.clearPending()}
            assertThrows(IllegalStateException::class.java){disk.erase()}
        }
    }
    @Test fun runtimeAttemptBudgetSurvivesEncryptedRestartAndCannotBeResetByConsentOrRetry() {
        val namespace=namespace();val disk=RuntimeObservationDisk(context,namespace)
        try {
            val queued=queue();val report=checkNotNull(queued.pending);val at=report.sampledAtMs
            val attempted=queued.attempted(owner,report,io.syn443.identity.TimeWindow(at,at+1000),60_000)
            disk.write(owner,attempted)
            val restarted=RuntimeObservationDisk(context,namespace)
            assertFalse(restarted.read(owner).ready(owner,at+60_999))
            restarted.clearPending();val withdrawn=restarted.read(owner)
            assertNull(withdrawn.pending);assertFalse(withdrawn.offer(owner,report).ready(owner,at+60_999))
            assertTrue(withdrawn.ready(owner,at+61_000))
            val unavailable=withdrawn.deferred(owner,io.syn443.identity.TimeWindow(at,at),3_600_000)
            restarted.write(owner,unavailable)
            val restored=RuntimeObservationDisk(context,namespace).read(owner)
            assertFalse(restored.ready(owner,at+3_599_999));assertTrue(restored.ready(owner,at+3_600_000))
        }finally {disk.erase()}
    }
}
