package io.syn443.recovery

import org.junit.Assert.*
import org.junit.Test

class RouteEvidenceTest {
    private val scope = RouteScope(1, 2, 3, "engine-a", "config-a")
    private val pass = RouteObservation(scope, 5_000, true, true)
    @Test fun everyGenerationAndConfigFenceRejectsOldRouteSuccess() {
        for (s in listOf(scope.copy(intent=2),scope.copy(network=3),scope.copy(activation=4),scope.copy(engine="engine-b"),scope.copy(config="config-b")))
            assertEquals(RouteState.UNVERIFIED,RouteEvidence.classify(true,true,s,pass,false,5_001))
    }
    @Test fun offAndMissingOwnerOverrideEvenAFreshPassingProbe() {
        assertEquals(RouteState.OFF,RouteEvidence.classify(false,true,scope,pass,true,5_001))
        assertEquals(RouteState.UNAVAILABLE,RouteEvidence.classify(true,false,scope,pass,true,5_001))
    }
    @Test fun futureStaleAndAbsentEvidenceCannotBecomeWorking() {
        assertEquals(RouteState.STALE,RouteEvidence.classify(true,true,scope,pass,false,4_999))
        assertEquals(RouteState.WORKING,RouteEvidence.classify(true,true,scope,pass,false,125_000))
        assertEquals(RouteState.STALE,RouteEvidence.classify(true,true,scope,pass,false,125_001))
        assertEquals(RouteState.CHECKING,RouteEvidence.classify(true,true,scope,null,true,5_001))
        assertEquals(RouteState.UNVERIFIED,RouteEvidence.classify(true,true,scope,null,false,5_001))
    }
    @Test fun incompleteAndFailedRemainDistinctWithoutPoisoningOtherRoutes() {
        assertEquals(RouteState.INCOMPLETE,RouteEvidence.classify(true,true,scope,pass.copy(complete=false),false,5_001))
        assertEquals(RouteState.FAILED,RouteEvidence.classify(true,true,scope,pass.copy(ok=false),false,5_001))
        assertEquals(RouteState.WORKING,RouteEvidence.classify(true,true,scope,pass,false,5_001))
    }
    @Test fun requiredUnknownAndStaleBlockOnlineWhileOptionalFailureDoesNot() {
        assertTrue(RouteEvidence.requiredReady(listOf(true to RouteState.WORKING,false to RouteState.FAILED)))
        for (state in RouteState.entries.filter {it!=RouteState.WORKING})
            assertFalse(RouteEvidence.requiredReady(listOf(true to state)))
    }
    @Test fun invalidTimeBoundsAreRejected() {
        for ((now,ttl) in listOf(-1L to 1_000L,1L to 999L,1L to 300_001L))
            assertThrows(IllegalArgumentException::class.java){RouteEvidence.classify(true,true,scope,pass,false,now,ttl)}
    }
    @Test fun activationRequiresEveryRequiredRouteAndIgnoresOptionalOutages() {
        assertEquals(RouteActivation.READY, RouteEvidence.activation(emptyList()))
        for (state in RouteState.entries) {
            assertEquals(RouteActivation.READY, RouteEvidence.activation(listOf(true to RouteState.WORKING, false to state)))
            assertEquals(when(state) {
                RouteState.WORKING -> RouteActivation.READY
                RouteState.FAILED -> RouteActivation.FAILED
                else -> RouteActivation.WAIT
            }, RouteEvidence.activation(listOf(true to state)))
        }
        assertEquals(RouteActivation.FAILED, RouteEvidence.activation(listOf(true to RouteState.CHECKING, true to RouteState.FAILED)))
    }
}
