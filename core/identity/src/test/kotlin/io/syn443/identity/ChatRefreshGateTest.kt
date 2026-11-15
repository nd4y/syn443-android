package io.syn443.identity

import org.junit.Assert.*
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ConcurrentLinkedQueue
import kotlin.concurrent.thread

class ChatRefreshGateTest {
    @Test fun healthyPollingAndManualActionsHaveIndependentBoundedIntervals() {
        val gate=ChatRefreshGate();val first=requireNotNull(gate.begin(0))
        assertNull(gate.begin(0,true));assertTrue(gate.complete(first,ChatRefreshGate.Result.SUCCESS,1))
        assertNull(gate.begin(10_000));val second=requireNotNull(gate.begin(10_001))
        assertTrue(gate.complete(second,ChatRefreshGate.Result.SUCCESS,10_002))
        assertFalse(gate.manualReady(30_000));assertTrue(gate.manualReady(40_001))
    }
    @Test fun repeatedOfflineFailuresBackOffWithoutPollingOrDroppingTheTail() {
        val gate=ChatRefreshGate();var now=0L
        for(delay in listOf(60_000L,120_000L,240_000L,300_000L,300_000L)) {
            val token=requireNotNull(gate.begin(now));assertTrue(gate.complete(token,ChatRefreshGate.Result.TRANSIENT_FAILURE,now))
            assertNull(gate.begin(now+delay-1));now+=delay
        }
        assertNotNull(gate.begin(now))
    }
    @Test fun authorityFailureNeedsAnExplicitRetryAndANewAccountStartsFresh() {
        val gate=ChatRefreshGate();val token=requireNotNull(gate.begin(10))
        assertTrue(gate.complete(token,ChatRefreshGate.Result.AUTHORITY_REQUIRED,20))
        assertNull(gate.begin(600_000));assertNull(gate.begin(30_009,true))
        val manual=requireNotNull(gate.begin(600_001,true))
        assertTrue(gate.complete(manual,ChatRefreshGate.Result.SUCCESS,600_002))
        assertNotNull(gate.begin(610_002));assertNotNull(ChatRefreshGate().begin(21))
    }
    @Test fun serverThrottlingCannotBeBypassedByTheRetryButton() {
        val gate=ChatRefreshGate();val token=requireNotNull(gate.begin(0))
        assertTrue(gate.complete(token,ChatRefreshGate.Result.THROTTLED,1))
        assertFalse(gate.manualReady(60_000));assertNull(gate.begin(60_000,true))
        assertNotNull(gate.begin(60_001,true))
    }
    @Test fun cancellationAndBusyDoNotInventAPathOrAccumulateFailureBackoff() {
        val gate=ChatRefreshGate();var token=requireNotNull(gate.begin(0))
        assertTrue(gate.complete(token,ChatRefreshGate.Result.CANCELLED,1));assertNull(gate.begin(10_000))
        token=requireNotNull(gate.begin(10_001));assertTrue(gate.complete(token,ChatRefreshGate.Result.BUSY,10_002))
        token=requireNotNull(gate.begin(20_002));assertTrue(gate.complete(token,ChatRefreshGate.Result.TRANSIENT_FAILURE,20_003))
        assertNull(gate.begin(80_002));assertNotNull(gate.begin(80_003))
    }
    @Test fun staleCompletionsAndInvalidClocksCannotReleaseANewerWorker() {
        val gate=ChatRefreshGate();val old=requireNotNull(gate.begin(10))
        assertFalse(gate.complete(old,ChatRefreshGate.Result.SUCCESS,9))
        assertTrue(gate.complete(old,ChatRefreshGate.Result.CANCELLED,11))
        val current=requireNotNull(gate.begin(10_011))
        assertFalse(gate.complete(old,ChatRefreshGate.Result.SUCCESS,10_012));assertNull(gate.begin(100_000,true))
        assertTrue(gate.complete(current,ChatRefreshGate.Result.SUCCESS,10_013))
        assertNull(gate.begin(-1));assertNull(gate.begin(Long.MAX_VALUE));assertFalse(gate.manualReady(Long.MAX_VALUE))
        assertFalse(gate.complete(current,ChatRefreshGate.Result.SUCCESS,20_000))
    }
    @Test fun concurrentRefreshRequestsAdmitExactlyOneOwnedAttempt() {
        val gate=ChatRefreshGate();val start=CountDownLatch(1);val tokens=ConcurrentLinkedQueue<Long>()
        val workers=(0 until 16).map {thread {start.await();gate.begin(100,true)?.let(tokens::add)}}
        start.countDown();workers.forEach {it.join()};assertEquals(1,tokens.size)
        assertTrue(gate.complete(tokens.single(),ChatRefreshGate.Result.SUCCESS,101))
    }
}
