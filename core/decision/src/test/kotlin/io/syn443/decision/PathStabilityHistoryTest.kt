package io.syn443.decision

import org.junit.Assert.*
import org.junit.Test

class PathStabilityHistoryTest {
    private val path = PathHealthKey("path-a", ExitClass.NON_RU, "web")
    private val pass = ProbeVerdict.VERIFIED
    private val fail = ProbeVerdict.CONFIRMED_PATH_FAILURE

    @Test fun threeAttributedFailuresAmongFiveRequireThreeFreshSuccessesForRecovery() {
        val history = PathStabilityHistory()
        val outcomes = listOf(fail, pass, fail, pass, fail, pass, pass, pass)
        val expected = listOf("INSUFFICIENT", "INSUFFICIENT", "INSUFFICIENT", "INSUFFICIENT",
            "DEGRADED", "DEGRADED", "DEGRADED", "STEADY")
        outcomes.forEachIndexed { i, outcome ->
            val at = 100L + i
            assertTrue(history.observe(path, at, at, at, outcome))
            assertEquals(expected[i], history.quality(path, at).name)
        }
        assertEquals(PathStabilityHistory.Quality.INSUFFICIENT, history.quality(path, 600_107))
    }

    @Test fun duplicateStaleCommonAndForeignOutcomesCannotRepairDegradedHistory() {
        val history = PathStabilityHistory()
        for (i in 1L..3L) assertTrue(history.observe(path, i, i, i, fail))
        for (verdict in ProbeVerdict.values().filter { it != pass && it != fail }) {
            assertFalse(history.observe(path, 4, 4, 4, verdict))
        }
        assertFalse(history.observe(path, 3, 4, 4, pass))
        assertFalse(history.observe(path, 4, 2, 4, pass))
        assertFalse(history.observe(path, 4, 4, 30_005, pass))
        val other = path.copy(metricGroup = "other")
        for (i in 30_006L..30_008L) assertTrue(history.observe(other, i, i, i, pass))
        assertEquals(PathStabilityHistory.Quality.DEGRADED, history.quality(path, 30_008))
        assertEquals(PathStabilityHistory.Quality.STEADY, history.quality(other, 30_008))
        history.clear()
        assertEquals(PathStabilityHistory.Quality.INSUFFICIENT, history.quality(path, 30_009))
    }

    @Test fun oldAndEvictedMeasurementsDoNotBecomePositiveEvidence() {
        val history = PathStabilityHistory()
        for (i in 1L..2L) assertTrue(history.observe(path, i, i, i, fail))
        for (i in 3L..6L) assertTrue(history.observe(path, i, i, i, pass))
        assertTrue(history.observe(path, 7, 7, 7, fail))
        assertEquals(PathStabilityHistory.Quality.INSUFFICIENT, history.quality(path, 7))
        for (i in 1..64) {
            val key = path.copy(pathId = "peer-$i")
            for (j in 1L..3L) assertTrue(history.observe(key, j, 10, 10, fail))
        }
        assertFalse(history.observe(path, 8, 11, 11, pass))
        assertEquals(PathStabilityHistory.Quality.DEGRADED, history.quality(path.copy(pathId = "peer-1"), 11))
        assertTrue(history.observe(path, 9, 600_011, 600_011, pass))
        assertEquals(PathStabilityHistory.Quality.INSUFFICIENT, history.quality(path, 600_011))
    }
}
