package io.syn443.android

import io.syn443.android.vpn.PolicyCheckSnapshot
import io.syn443.health.Batch
import io.syn443.health.CheckObservation
import io.syn443.health.Failure
import io.syn443.health.Outcome
import io.syn443.health.Stage
import org.junit.Assert.*
import org.junit.Test

class PassivePolicyDiagnosticTest {
    @Test fun historicalExportKeepsRealBatchWithoutInventingActivationOrChangingAuthority() {
        val state = PolicyCheckSnapshot { 1_000 }
        val observation = CheckObservation(Outcome.FAIL, Failure.DNS, Stage.RESOLVE)
        state.record(Batch(listOf(Outcome.FAIL), listOf(observation)), 7, 4, 11)
        val before = state.read(7,4,11,true).toString()
        val exported = state.passiveSnapshot()
        assertTrue(exported.isNull("current"))
        assertEquals(11L, exported.getJSONObject("lastBatch").getLong("activationGeneration"))
        assertEquals("FAIL", exported.getJSONObject("lastBatch").getJSONArray("checks").getJSONObject(0).getString("outcome"))
        exported.getJSONObject("lastBatch").getJSONArray("checks").getJSONObject(0).put("outcome", "PASS")
        assertEquals(before, state.read(7,4,11,true).toString())
        assertEquals("FAIL", state.passiveSnapshot().getJSONObject("lastBatch").getJSONArray("checks").getJSONObject(0).getString("outcome"))
    }

    @Test fun expiredRetiredAndBackwardHistoryNeverBecomesCurrentOrGetsANewSampleTime() {
        var clock = 1_000L
        val state = PolicyCheckSnapshot { clock }
        assertTrue(state.passiveSnapshot().isNull("lastBatch"))
        state.record(Batch(listOf(Outcome.PASS), listOf(CheckObservation(Outcome.PASS))), 7,4,11)
        clock = 100_000
        state.invalidate()
        val retired = state.passiveSnapshot()
        assertTrue(retired.isNull("current"))
        assertEquals(99_000L, retired.getLong("ageMs"))
        assertEquals(1_000L, retired.getJSONObject("lastBatch").getLong("sampledElapsedMs"))
        clock = 999
        assertTrue(state.passiveSnapshot().isNull("ageMs"))
        assertFalse(state.read(7,4,11,true).getBoolean("current"))
    }
}
