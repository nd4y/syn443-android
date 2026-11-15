package io.syn443.identity

import io.syn443.policy.Canonical
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.*
import org.junit.Test

class RuntimeObservationTest {
    private val owner=Identity.hash("synthetic device and key".toByteArray())
    private fun sample(at:Long=1_800_000_000_000)=RuntimeObservation.Report(1,1,75,"online",4,true,true,"wifi",at)
    @Test fun wireIsClosedSmallRedactedAndCompatibleWithAllSupportedPhases() {
        val report=sample();val obj=Identity.objectJSON(report.body().decodeToString())
        assertEquals(setOf("version","sequence","build","phase","policyRevision","engineKnown","engineActive","network","sampledAtMs"),obj.keys)
        assertEquals("wifi",obj.getValue("network").jsonPrimitive.content)
        assertTrue(report.body().size<=1024);assertFalse(report.toString().contains("online"))
        for(phase in listOf("starting","recovering","no_network","blocked","unknown"))report.copy(phase=phase).validate()
        report.copy(phase="off",engineActive=false,policyRevision=0,network="none").validate()
        report.copy(phase="unknown",engineKnown=false,engineActive=false,network="cellular").validate()
        report.copy(network="unknown").validate()
    }
    @Test fun invalidNumbersPhasesAndContradictoryEvidenceNeverProduceARequest() {
        for(bad in listOf(sample().copy(version=2),sample().copy(sequence=0),sample().copy(sequence=9_007_199_254_740_992),
            sample().copy(build=0),sample().copy(build=2_100_000_001),sample().copy(policyRevision=-1),sample().copy(policyRevision=0),
            sample().copy(sampledAtMs=0),sample().copy(phase="connected"),sample().copy(network="ethernet"),
            sample().copy(engineKnown=false),sample().copy(engineActive=false),sample().copy(phase="off")))
            assertThrows(IllegalArgumentException::class.java){bad.body()}
    }
    @Test fun exactPendingRetrySurvivesSerializationWithoutRefreshingItsTimestamp() {
        val first=RuntimeObservation.empty(owner).offer(owner,sample())
        val restored=Canonical.json.decodeFromString<RuntimeObservation.Snapshot>(Canonical.json.encodeToString(first))
        val retry=restored.offer(owner,sample(sample().sampledAtMs+89_999))
        assertEquals(first,retry);assertArrayEquals(first.pending!!.body(),retry.pending!!.body())
        assertEquals(sample().sampledAtMs,retry.cursor)
    }
    @Test fun oldOrChangedFactsReserveANewSequenceBeforeTheNextUpload() {
        val first=RuntimeObservation.empty(owner).offer(owner,sample())
        val old=first.offer(owner,sample(sample().sampledAtMs+90_000))
        assertTrue(old.cursor>first.cursor);assertEquals(sample().sampledAtMs+90_000,old.pending!!.sampledAtMs)
        val changed=first.offer(owner,sample().copy(phase="recovering"))
        assertEquals(first.cursor+1,changed.cursor);assertEquals("recovering",changed.pending!!.phase)
        val cleared=changed.discard(owner);assertNull(cleared.pending);assertEquals(changed.cursor,cleared.cursor)
    }
    @Test fun acknowledgmentAndConsentWithdrawalKeepTheCursorAndRejectSubstitution() {
        val first=RuntimeObservation.empty(owner).offer(owner,sample())
        val done=first.acknowledged(owner,first.pending!!)
        assertNull(done.pending);assertEquals(first.cursor,done.cursor)
        assertTrue(done.offer(owner,sample()).cursor>done.cursor)
        val other=Identity.hash("other key".toByteArray())
        for(action in listOf<()->Unit>({first.offer(other,sample())},{first.acknowledged(other,first.pending!!)},
            {first.discard(other)},{first.acknowledged(owner,sample())},{first.copy(cursor=0).validate()},
            {RuntimeObservation.empty("not-a-scope")},{first.copy(cursor=9_007_199_254_740_991,pending=null).offer(owner,sample())}))
            assertThrows(IllegalArgumentException::class.java,action)
    }
    @Test fun samplesUseOnlyTheTrustedTimeWindowAndRefuseUnboundedUncertainty() {
        assertEquals(1_800_000_010_000,RuntimeObservation.sampleTime(TimeWindow(1_800_000_000_000,1_800_000_020_000)))
        assertEquals(1L,RuntimeObservation.sampleTime(TimeWindow(1,1)))
        for(window in listOf(TimeWindow(0,1),TimeWindow(10,9),TimeWindow(1,50_002)))
            assertThrows(IllegalArgumentException::class.java){RuntimeObservation.sampleTime(window)}
    }
}
