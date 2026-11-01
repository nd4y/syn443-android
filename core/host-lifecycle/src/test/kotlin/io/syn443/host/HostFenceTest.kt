package io.syn443.host

import io.syn443.host.HostFence.Effect
import io.syn443.host.HostFence.Phase
import io.syn443.host.HostFence.Reason
import io.syn443.host.HostFence.Rejection
import org.junit.Assert.*
import org.junit.Test
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import kotlin.random.Random

class HostFenceTest {
    private val owner = "a".repeat(32)
    private fun token(result: HostFence.Transition) = checkNotNull(result.snapshot.token)

    @Test fun reservesExactlyOneHostUntilConfirmedExitAndRelease() {
        val fence = HostFence(owner)
        val first = token(fence.reserveStart(0))
        assertEquals(Rejection.BUSY, fence.reserveStart(1).rejection)
        assertEquals(Phase.RUNNING, fence.started(first, 2).snapshot.phase)
        assertEquals(Phase.AWAITING_RELEASE, fence.confirmedExit(first, false, 3).snapshot.phase)
        assertEquals(Rejection.BUSY, fence.reserveStart(4).rejection)
        assertEquals(Phase.IDLE, fence.confirmedRelease(first, 5).snapshot.phase)
        val second = token(fence.reserveStart(6))
        assertEquals(first.generation + 1, second.generation)
    }

    @Test fun stopIsIdempotentDoesNotExtendDeadlineOrAcceptLateReady() {
        val fence = HostFence(owner, stopTimeoutMs = 5)
        val active = token(fence.reserveStart(0))
        val stop = fence.requestStop(1)
        assertEquals(listOf(Effect.GracefulStop(active)), stop.effects)
        assertEquals(6L, stop.snapshot.deadlineMs)
        assertTrue(fence.requestStop(4).effects.isEmpty())
        assertEquals(6L, fence.snapshot().deadlineMs)
        assertEquals(Rejection.STALE_OR_OUT_OF_ORDER, fence.started(active, 5).rejection)
        assertEquals(listOf(Effect.TerminateOwned(active, Reason.STOP_TIMEOUT)), fence.tick(6).effects)
        assertTrue(fence.tick(7).effects.isEmpty())
        assertEquals(Rejection.BUSY, fence.reserveStart(8).rejection)
        assertTrue(fence.requestStop(9).effects.isEmpty())
        assertEquals(Phase.IDLE, fence.confirmedExit(active, true, 10).snapshot.phase)
        assertNull(fence.snapshot().token) // No implicit reconnect after an exit callback.
    }

    @Test fun lateStartAcknowledgementTriggersTerminationButNeverReleasesOwnership() {
        val fence = HostFence(owner, startTimeoutMs = 10)
        val active = token(fence.reserveStart(0))
        assertEquals(listOf(Effect.TerminateOwned(active, Reason.START_TIMEOUT)), fence.started(active, 10).effects)
        assertEquals(Phase.AWAITING_DEATH, fence.snapshot().phase)
        assertEquals(Rejection.BUSY, fence.reserveStart(11).rejection)
        assertEquals(Rejection.STALE_OR_OUT_OF_ORDER, fence.confirmedRelease(active, 12).rejection)
        fence.confirmedExit(active, false, 13)
        assertTrue(fence.requestStop(14).effects.isEmpty())
        assertEquals(Rejection.BUSY, fence.reserveStart(15).rejection)
    }

    @Test fun startupDeadlineAndExplicitStopAtDeadlineAreFailClosed() {
        val fence = HostFence(owner, startTimeoutMs = 10)
        val active = token(fence.reserveStart(5))
        assertTrue(fence.tick(14).effects.isEmpty())
        assertEquals(listOf(Effect.TerminateOwned(active, Reason.START_TIMEOUT)), fence.tick(15).effects)
        fence.confirmedExit(active, true, 16)
        val second = token(fence.reserveStart(17))
        assertEquals(listOf(Effect.TerminateOwned(second, Reason.START_TIMEOUT)), fence.requestStop(27).effects)
    }

    @Test fun foreignAndStaleCallbacksCannotKillOrReleaseTheCurrentHost() {
        val fence = HostFence(owner)
        val old = token(fence.reserveStart(0))
        fence.confirmedExit(old, true, 1)
        val current = token(fence.reserveStart(2))
        val foreign = current.copy(supervisorId = "b".repeat(32))
        for (wrong in listOf(old, foreign, current.copy(generation = 0))) {
            assertNotNull(fence.started(wrong, 3).rejection)
            assertNotNull(fence.terminateForHang(wrong, 3).rejection)
            assertNotNull(fence.confirmedExit(wrong, true, 3).rejection)
            assertNotNull(fence.confirmedRelease(wrong, 3).rejection)
            assertEquals(current, fence.snapshot().token)
        }
        assertEquals(listOf(Effect.TerminateOwned(current, Reason.HANG)), fence.terminateForHang(current, 4).effects)
        assertNotNull(fence.terminateForHang(current, 5).rejection)
    }

    @Test fun crashReleaseDoesNotScheduleAReplacement() {
        val fence = HostFence(owner)
        val active = token(fence.reserveStart(0))
        assertTrue(fence.confirmedExit(active, true, 1).effects.isEmpty())
        assertEquals(Phase.IDLE, fence.snapshot().phase)
        assertNotNull(fence.started(active, 2).rejection)
        assertTrue(fence.tick(100_000).effects.isEmpty())
        assertNull(fence.snapshot().token)
    }

    @Test fun clocksAndGenerationLimitsCannotWrapOrStrandAnExplicitStop() {
        val exhausted = HostFence(owner, initialGeneration = Int.MAX_VALUE)
        assertEquals(Rejection.GENERATION_EXHAUSTED, exhausted.reserveStart(0).rejection)
        val last = HostFence(owner, initialGeneration = Int.MAX_VALUE - 1)
        val active = token(last.reserveStart(0))
        assertEquals(Int.MAX_VALUE, active.generation)
        last.confirmedExit(active, true, 1)
        assertEquals(Rejection.GENERATION_EXHAUSTED, last.reserveStart(2).rejection)
        val clock = HostFence(owner)
        assertEquals(Rejection.CLOCK_EXHAUSTED, clock.reserveStart(Long.MAX_VALUE).rejection)
        assertEquals(Phase.IDLE, clock.snapshot().phase)
        val edge = HostFence(owner, startTimeoutMs = 1)
        val edgeToken = token(edge.reserveStart(Long.MAX_VALUE - 1))
        assertEquals(Long.MAX_VALUE, edge.snapshot().deadlineMs)
        assertEquals(listOf(Effect.TerminateOwned(edgeToken, Reason.START_TIMEOUT)), edge.tick(Long.MAX_VALUE).effects)
        val running = HostFence(owner)
        val runningToken = token(running.reserveStart(0))
        running.started(runningToken, 1)
        assertEquals(listOf(Effect.TerminateOwned(runningToken, Reason.CLOCK_EXHAUSTED)), running.requestStop(Long.MAX_VALUE).effects)
        assertEquals(Rejection.BUSY, running.reserveStart(Long.MAX_VALUE).rejection)
    }

    @Test fun invalidConstructionAndRegressingTimeDoNotMutateOwnership() {
        for (id in listOf("", "a".repeat(31), "A".repeat(32), "z".repeat(32))) {
            assertThrows(IllegalArgumentException::class.java) { HostFence(id) }
        }
        for (timeout in listOf(0L, -1L, 60_001L, Long.MAX_VALUE)) {
            assertThrows(IllegalArgumentException::class.java) { HostFence(owner, startTimeoutMs = timeout) }
            assertThrows(IllegalArgumentException::class.java) { HostFence(owner, stopTimeoutMs = timeout) }
        }
        assertThrows(IllegalArgumentException::class.java) { HostFence(owner, initialGeneration = -1) }
        val fence = HostFence(owner)
        fence.reserveStart(10)
        val before = fence.snapshot()
        assertThrows(IllegalArgumentException::class.java) { fence.reserveStart(9) }
        assertThrows(IllegalArgumentException::class.java) { fence.tick(-1) }
        assertEquals(before, fence.snapshot())
    }

    @Test fun invalidClockCannotBlockStopOrDuplicateTermination() {
        for (badTime in listOf(-1L, 9L)) {
            for (phase in listOf(Phase.STARTING, Phase.RUNNING, Phase.STOPPING)) {
                val fence = HostFence(owner)
                val active = token(fence.reserveStart(10))
                if (phase == Phase.RUNNING) fence.started(active, 11)
                if (phase == Phase.STOPPING) fence.requestStop(11)
                assertEquals(listOf(Effect.TerminateOwned(active, Reason.CLOCK_INVALID)), fence.requestStop(badTime).effects)
                assertTrue(fence.requestStop(badTime).effects.isEmpty())
                assertEquals(Phase.AWAITING_DEATH, fence.snapshot().phase)
            }
        }
        assertTrue(HostFence(owner).requestStop(-1).effects.isEmpty())
    }

    @Test fun concurrentStartAndStopHaveOneEffectEach() {
        val pool = Executors.newFixedThreadPool(8)
        try {
            val fence = HostFence(owner)
            val starts = pool.invokeAll((1..100).map { Callable { fence.reserveStart(0) } }).map { it.get() }
            assertEquals(1, starts.flatMap { it.effects }.filterIsInstance<Effect.Launch>().size)
            assertEquals(99, starts.count { it.rejection == Rejection.BUSY })
            val stops = pool.invokeAll((1..100).map { Callable { fence.requestStop(0) } }).map { it.get() }
            assertEquals(1, stops.flatMap { it.effects }.filterIsInstance<Effect.GracefulStop>().size)
            assertEquals(Phase.STOPPING, fence.snapshot().phase)
        } finally { pool.shutdownNow() }
    }

    @Test fun randomizedEventSequencesPreserveTheSingleOwnerFence() {
        val fence = HostFence(owner, startTimeoutMs = 3, stopTimeoutMs = 2)
        val random = Random(443)
        val launched = mutableSetOf<HostFence.Token>()
        val terminated = mutableSetOf<HostFence.Token>()
        repeat(10_000) { step ->
            val before = fence.snapshot()
            val candidate = if (random.nextBoolean() && before.token != null) checkNotNull(before.token)
                else HostFence.Token("b".repeat(32), random.nextInt(100))
            val now = step.toLong()
            val result = when (random.nextInt(7)) {
                0 -> fence.reserveStart(now)
                1 -> fence.started(candidate, now)
                2 -> fence.requestStop(now)
                3 -> fence.tick(now)
                4 -> fence.terminateForHang(candidate, now)
                5 -> fence.confirmedExit(candidate, random.nextBoolean(), now)
                else -> fence.confirmedRelease(candidate, now)
            }
            for (effect in result.effects) {
                if (effect is Effect.Launch) {
                    assertEquals(Phase.IDLE, before.phase)
                    assertTrue(launched.add(effect.token))
                } else {
                    assertEquals(before.token, effect.token)
                    if (effect is Effect.TerminateOwned) assertTrue(terminated.add(effect.token))
                }
            }
            val after = result.snapshot
            assertEquals(after.phase == Phase.IDLE, after.token == null)
            assertEquals(after.phase in setOf(Phase.STARTING, Phase.STOPPING), after.deadlineMs != null)
            if (before.token != null && after.token != null) assertEquals(before.token, after.token)
        }
    }
}
