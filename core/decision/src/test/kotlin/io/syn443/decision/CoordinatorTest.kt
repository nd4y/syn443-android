package io.syn443.decision

import org.junit.Assert.*
import org.junit.Test
import java.util.concurrent.CountDownLatch
import kotlin.concurrent.thread

class CoordinatorTest {
    private val initial = Context(1, 1, "cfg-1", "alg-1", 1, "a".repeat(64))

    @Test fun stopWinsConcurrentCompletions() {
        val coordinator = Coordinator(initial)
        assertFalse(coordinator.tryApply(initial, "path"))
        val token = coordinator.start()
        assertTrue(coordinator.tryApply(token, "path"))
        assertFalse(coordinator.tryApply(token, "../bad"))
        val gate = CountDownLatch(1)
        val workers = (1..32).map { thread { gate.await(); repeat(100) { coordinator.tryApply(token, "path"); coordinator.snapshot() } } }
        gate.countDown()
        coordinator.stop()
        workers.forEach { it.join() }
        assertFalse(coordinator.tryApply(token, "path"))
        assertFalse(coordinator.snapshot().desiredOn)
        assertNull(coordinator.snapshot().activePathId)
    }

    @Test fun allContextFieldsParticipate() {
        val coordinator = Coordinator(initial)
        val token = coordinator.start()
        listOf(
            token.copy(networkEpoch = 2),
            token.copy(activationGeneration = 3),
            token.copy(configRevision = "cfg-2"),
            token.copy(algorithmRevision = "alg-2"),
            token.copy(engineGeneration = 2),
            token.copy(dependencyHash = "b".repeat(64)),
        ).forEach { assertFalse(coordinator.tryApply(it, "path")) }
        coordinator.networkChanged()
        assertFalse(coordinator.tryApply(token, "path"))
        val candidate = coordinator.activate("cfg-2", "alg-2", "b".repeat(64))
        coordinator.engineChanged()
        assertFalse(coordinator.tryApply(candidate, "path"))
        assertTrue(coordinator.tryApply(coordinator.snapshot().context, "path"))
    }

    @Test fun overflowAndInvalidActivationAreAtomic() {
        listOf(
            initial.copy(activationGeneration = Decision.MAX_GENERATION),
            initial.copy(networkEpoch = Decision.MAX_GENERATION),
            initial.copy(engineGeneration = Decision.MAX_GENERATION),
        ).forEachIndexed { index, ctx ->
            val coordinator = Coordinator(ctx)
            val before = coordinator.snapshot()
            val actions: List<() -> Any> = when (index) {
                0 -> listOf({ coordinator.start() }, { coordinator.stop() }, { coordinator.activate("cfg-2", "alg-2", "b".repeat(64)) })
                1 -> listOf({ coordinator.networkChanged() })
                else -> listOf({ coordinator.engineChanged() })
            }
            actions.forEach { action ->
                try { action(); fail("overflow accepted") } catch (_: IllegalStateException) { }
                assertEquals(before, coordinator.snapshot())
            }
        }
        val coordinator = Coordinator(initial)
        val before = coordinator.snapshot()
        try { coordinator.activate("INVALID", "alg-2", "b".repeat(64)); fail("invalid activation") } catch (_: IllegalArgumentException) { }
        assertEquals(before, coordinator.snapshot())
        try { Coordinator(initial.copy(networkEpoch = -1)); fail("invalid context") } catch (_: IllegalArgumentException) { }
    }
}

