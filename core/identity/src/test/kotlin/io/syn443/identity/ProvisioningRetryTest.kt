package io.syn443.identity

import org.junit.Assert.*
import org.junit.Test

class ProvisioningRetryTest {
    @Test fun initialPendingWaitsAndRepeatedObservationsDoNotSpendBudget() {
        val gate=ProvisioningRetry()
        repeat(100) {assertNull(gate.admit(1,4_999,0))}
        val admitted=checkNotNull(gate.admit(1,5_000,0))
        assertNull(admitted.admit(1,14_999,5_000))
        assertNotNull(admitted.admit(1,15_000,5_000))
    }
    @Test fun sixRequestsPerRollingWindowSurviveHideShowAndEventuallyRefill() {
        var gate=ProvisioningRetry();var last=0L
        for(now in listOf(5_000L,15_000L,35_000L,75_000L,135_000L,195_000L)) {
            gate=checkNotNull(gate.admit(2,now,last));last=now
        }
        assertNull(gate.admit(2,255_000,last));assertNull(gate.admit(2,304_999,last))
        gate=checkNotNull(gate.admit(2,305_000,last))
        assertNull(gate.admit(2,364_999,305_000));assertNotNull(gate.admit(2,365_000,305_000))
    }
    @Test fun generationChangesRetainTheFetchFloorAndBackwardTimeCannotAdmit() {
        val gate=checkNotNull(ProvisioningRetry().admit(1,50_000,0))
        assertNull(gate.admit(1,49_999,0));assertNull(gate.admit(1,100_000,100_001))
        assertNull(gate.admit(2,54_999,50_000));assertNotNull(gate.admit(2,55_000,50_000))
    }
    @Test fun throttlingAlwaysRequiresAtLeastOneMinute() {
        val gate=ProvisioningRetry()
        assertNull(gate.admit(3,59_999,0,true))
        assertNotNull(gate.admit(3,60_000,0,true))
    }
    @Test fun timestampsAreBoundedAndLargeElapsedValuesDoNotOverflow() {
        val gate=ProvisioningRetry()
        assertThrows(IllegalArgumentException::class.java) {gate.admit(-1,0,0)}
        assertThrows(IllegalArgumentException::class.java) {gate.admit(0,-1,0)}
        assertThrows(IllegalArgumentException::class.java) {gate.admit(0,0,-1)}
        val admitted=checkNotNull(gate.admit(4,Long.MAX_VALUE-10_000,0))
        assertNotNull(admitted.admit(4,Long.MAX_VALUE,Long.MAX_VALUE-10_000))
    }
}
