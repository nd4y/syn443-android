package io.syn443.decision

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class RouteFrontierTest {
    private val context = Context(1, 2, "policy", "algorithm", 3, "a".repeat(64))
    private val tcp = setOf(PathFeature.TCP, PathFeature.IPV4)
    private val udp = tcp + PathFeature.UDP
    private val restricted = setOf(NetworkMode.CELLULAR_RESTRICTED)
    private val fixture = listOf(
        RouteHop("entry", restricted, ExitClass.RU, udp),
        RouteHop("transit", emptySet(), null, udp),
        RouteHop("exit-a", emptySet(), ExitClass.NON_RU, udp),
        RouteHop("exit-b", setOf(NetworkMode.WIFI), ExitClass.NON_RU, udp),
    )
    private val edges = listOf(
        RouteEdge("entry", "transit", udp),
        RouteEdge("transit", "exit-a", udp),
        RouteEdge("entry", "exit-b", tcp),
        RouteEdge("transit", "entry", udp),
    )
    private val all = fixture.map { it.id }.toSet()
    private val templates = listOf(
        RouteTemplate("one", listOf(all)),
        RouteTemplate("two", listOf(all, all)),
        RouteTemplate("three", listOf(all, all, all)),
        RouteTemplate("duplicate", listOf(setOf("entry"), setOf("exit-b"))),
    )

    private fun planner(
        mode: NetworkMode = NetworkMode.CELLULAR_RESTRICTED,
        intent: ExitClass = ExitClass.NON_RU,
        features: Set<PathFeature> = tcp,
        hints: List<List<String>> = emptyList(),
    ) = RouteFrontier(context, mode, intent, features, fixture, edges, templates, hints, 100, 20_000)

    private fun enumerate(frontier: RouteFrontier): Pair<List<PlannedPath>, FrontierBatch> {
        val paths = mutableListOf<PlannedPath>()
        var previous = 0
        repeat(100) {
            val batch = frontier.next(context, 100L + it, 1, 2)
            assertFalse(batch.invalidated)
            assertTrue(batch.examined - previous in 0..2)
            paths += batch.paths
            previous = batch.examined
            if (batch.exhausted) return paths to batch
        }
        error("finite scan did not reach its end")
    }

    @Test fun boundedCursorCoversSparseGraphWithoutDuplicateOrWrongExitPaths() {
        val (paths, coverage) = enumerate(planner())
        assertEquals(listOf(listOf("entry", "exit-b"), listOf("entry", "transit", "exit-a")), paths.map { it.hops })
        assertEquals(paths, enumerate(planner()).first)
        assertEquals(85, coverage.examined)
        assertEquals(coverage.upperBound, coverage.examined)
        assertEquals(2, paths.map { it.id }.toSet().size)
        assertTrue(paths.all { Decision.validId(it.id) })
        assertEquals(listOf(listOf("entry")), enumerate(planner(intent = ExitClass.RU)).first.map { it.hops })
    }

    @Test fun allHopsAndEdgesSatisfyModeAndFullPathCapabilityRequirements() {
        assertEquals(listOf(listOf("entry", "transit", "exit-a")), enumerate(planner(features = udp)).first.map { it.hops })
        assertEquals(listOf(listOf("exit-b")), enumerate(planner(mode = NetworkMode.WIFI)).first.map { it.hops })
        assertTrue(enumerate(planner(mode = NetworkMode.HOME_WIFI)).first.isEmpty())
        assertTrue(enumerate(planner(mode = NetworkMode.CELLULAR)).first.isEmpty())
    }

    @Test fun warmHintComesFirstOnlyIfItStillBelongsToTheGraph() {
        val longPath = listOf("entry", "transit", "exit-a")
        val frontier = planner(hints = listOf(listOf("entry"), longPath))
        val first = frontier.next(context, 100, 1, 1)
        assertEquals(listOf(longPath), first.paths.map { it.hops })
        assertEquals(0, first.examined)
        assertEquals(listOf(listOf("entry", "exit-b")), enumerate(frontier).first.map { it.hops })
    }

    @Test fun oldOrExpiredCursorNeverResumes() {
        val changed = planner()
        assertTrue(changed.next(context.copy(networkEpoch = 2), 100, 1, 1).invalidated)
        assertTrue(changed.next(context, 101, 1, 1).invalidated)
        assertTrue(planner().next(context, 20_100, 1, 1).invalidated)
        val rewind = planner()
        rewind.next(context, 150, 1, 1)
        assertTrue(rewind.next(context, 149, 1, 1).invalidated)
    }

    @Test fun oversizedTemplateFailsInsteadOfReportingTruncatedCoverage() {
        val nodes = (1..9).map { RouteHop("hop-$it", restricted, ExitClass.NON_RU, tcp) }
        val ids = nodes.map { it.id }.toSet()
        assertThrows(IllegalArgumentException::class.java) {
            RouteFrontier(context, NetworkMode.CELLULAR_RESTRICTED, ExitClass.NON_RU, tcp, nodes, emptyList(),
                listOf(RouteTemplate("too-wide", List(4) { ids })), emptyList(), 100, 100)
        }
    }
}
