package io.syn443.identity

import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.*
import org.junit.Test

class TelemetryTest {
    private val owner=Identity.hash("synthetic scope".toByteArray())
    private val other=Identity.hash("another synthetic scope".toByteArray())
    private val now=1_800_000_000_000
    private val key=TechnicalTelemetry.Key(Identity.hash("synthetic session".toByteArray()),52,1,1)
    private fun queued(n:Int,k:TechnicalTelemetry.Key=key,age:Long=0)=TechnicalTelemetry.Queued(k,
        TechnicalTelemetry.Event(Identity.hash("synthetic event $n".toByteArray()),now-age,n.toLong(),0,"vpn","online","wifi"))

    @Test fun technicalBatchOmitsOptionalFieldsAndRejectsFreeText() {
        val batch=checkNotNull(TechnicalTelemetry.Snapshot(1,owner,listOf(queued(1))).peek(owner))
        val event=Identity.objectJSON(batch.body().decodeToString()).getValue("events").jsonArray.single().jsonObject
        assertEquals(setOf("id","atMs","elapsedMs","networkEpoch","kind","code","mode"),event.keys)
        assertThrows(IllegalArgumentException::class.java){batch.copy(events=listOf(queued(1).event.copy(code="node.example.invalid"))).body()}
        assertThrows(IllegalArgumentException::class.java){batch.copy(events=listOf(queued(1).event.copy(path="node.example.invalid"))).body()}
    }

    @Test fun acknowledgmentRemovesOnlyTheOriginalPrefixAndNeverAnotherScope() {
        val initial=TechnicalTelemetry.Snapshot(1,owner,listOf(queued(1)))
        val sent=checkNotNull(initial.peek(owner))
        val appended=initial.offer(owner,queued(2))
        assertEquals(listOf(queued(2)),appended.acknowledged(owner,sent).entries)
        assertThrows(IllegalArgumentException::class.java){appended.acknowledged(other,sent)}
        assertThrows(IllegalArgumentException::class.java){appended.acknowledged(owner,sent.copy(policyRevision=2))}
        val changed=appended.offer(owner,queued(3,key.copy(policyRevision=2)))
        assertEquals(listOf(queued(1).event,queued(2).event),changed.peek(owner)?.events)
    }

    @Test fun queueCapsBatchesAndExpiresOldEvidenceWithoutReordering() {
        var state=TechnicalTelemetry.Snapshot(1,owner,emptyList())
        for(n in 1..150)state=state.offer(owner,queued(n))
        assertEquals(128,state.entries.size)
        assertEquals(queued(23),state.entries.first())
        assertEquals(32,state.peek(owner)?.events?.size)
        val old=queued(151,age=8*24*60*60*1000L)
        assertFalse(state.offer(owner,old).expired(owner,now).entries.contains(old))
    }
}
