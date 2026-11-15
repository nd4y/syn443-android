package io.syn443.android

import io.syn443.android.vpn.PolicyCheckSnapshot
import io.syn443.health.*
import org.junit.Assert.*
import org.junit.Test

/** Isolated RAM object only; never changes the phone's VPN, policy or authentication. */
class PolicyCheckSnapshotTest {
    private val observations = listOf(CheckObservation(Outcome.FAIL, Failure.DNS, Stage.RESOLVE), CheckObservation(Outcome.PASS, null, Stage.RESPONSE))
    private val batch get() = Batch(observations.map { it.outcome }, observations)
    @Test fun diagnosticsArePositionalBoundedAndReturnedAsIndependentCopies() {
        val state = PolicyCheckSnapshot { 1_000 }
        assertTrue(state.read(1,2,3,true).isNull("lastBatch"))
        state.record(batch,1,2,3)
        val first = state.read(1,2,3,true)
        assertTrue(first.getBoolean("current"));assertEquals(0L,first.getLong("ageMs"))
        val rows = first.getJSONObject("lastBatch").getJSONArray("checks")
        assertEquals(2,rows.length())
        assertEquals(setOf("index","outcome","stage","failure"),rows.getJSONObject(0).keys().asSequence().toSet())
        assertEquals("DNS",rows.getJSONObject(0).getString("failure"));assertEquals("RESOLVE",rows.getJSONObject(0).getString("stage"))
        assertTrue(rows.getJSONObject(1).isNull("failure"))
        rows.getJSONObject(0).put("outcome","PASS")
        assertEquals("FAIL",state.read(1,2,3,true).getJSONObject("lastBatch").getJSONArray("checks").getJSONObject(0).getString("outcome"))
        for (count in listOf(0,9)) assertThrows(IllegalArgumentException::class.java) {
            val values = List(count) { CheckObservation(Outcome.PASS) }
            state.record(Batch(values.map { it.outcome },values),1,2,3)
        }
        assertThrows(IllegalArgumentException::class.java) { state.record(Batch(listOf(Outcome.PASS)),1,2,3) }
        assertThrows(IllegalArgumentException::class.java) { state.record(batch,-1,2,3) }
    }
    @Test fun changedOwnerIntentNetworkActivationOrStoppedVpnCannotRelabelEvidenceAsCurrent() {
        val state = PolicyCheckSnapshot { 1_000 };state.record(batch,1,2,3)
        for (scope in listOf(Triple(9L,2L,3L),Triple(1L,9L,3L),Triple(1L,2L,9L)))
            assertFalse(state.read(scope.first,scope.second,scope.third,true).getBoolean("current"))
        assertFalse(state.read(1,2,3,false).getBoolean("current"))
        state.invalidate()
        assertFalse(state.read(1,2,3,true).getBoolean("current"))
        assertFalse(state.read(1,2,3,true).isNull("lastBatch"))
        state.record(batch,1,2,3);assertTrue(state.read(1,2,3,true).getBoolean("current"))
    }
    @Test fun staleOrBackwardClockKeepsHistoryWithoutClaimingCurrentHealth() {
        var clock = 1_000L;val state = PolicyCheckSnapshot { clock };state.record(batch,1,2,3)
        clock=31_000;assertTrue(state.read(1,2,3,true).getBoolean("current"))
        clock=31_001;assertFalse(state.read(1,2,3,true).getBoolean("current"))
        clock=999;assertFalse(state.read(1,2,3,true).getBoolean("current"));assertTrue(state.read(1,2,3,true).isNull("ageMs"))
        assertFalse(PolicyCheckSnapshot { clock }.read(1,2,3,true).getBoolean("current"))
    }
}
