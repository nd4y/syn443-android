package io.syn443.decision

import kotlinx.serialization.json.*
import org.junit.Assert.*
import org.junit.Test

class RouteFrontierResumeTest {
    private val context = Context(1, 2, "policy", "algorithm", 3, "a".repeat(64))
    private val wifi = NetworkMode.WIFI

    private fun fixture(choices: Int = 500, copies: Int = 1): Pair<ByteArray, List<String>> {
        val ids = (0 until choices).map { "hop-%03d".format(it) }
        val hops = ids.map { id -> buildJsonObject {
            put("id", id); put("entryModes", buildJsonArray { add("WIFI") })
            put("exitClass", "INTERNAL"); put("features", buildJsonArray { add("TCP"); add("IPV4") })
        } }
        val templates = (0 until copies).map { n -> buildJsonObject {
            put("id", "template-%02d".format(n)); put("slots", buildJsonArray { add(JsonArray(ids.map(::JsonPrimitive))) })
        } }
        val groups = listOf("inside", "other").map { id -> buildJsonObject {
            put("id", id); put("intent", "INTERNAL"); put("features", buildJsonArray { add("TCP"); add("IPV4") })
            put("templates", JsonArray(templates.map { it.getValue("id") }))
        } }
        return buildJsonObject {
            put("schemaVersion", 1); put("hops", JsonArray(hops)); put("edges", JsonArray(emptyList()))
            put("templates", JsonArray(templates)); put("groups", JsonArray(groups))
        }.toString().toByteArray() to ids
    }

    private fun graph(fixture: Pair<ByteArray, List<String>>) = RouteGraph.decode(fixture.first, fixture.second)
    private fun cursor(g: RouteGraph, now: Long = 100, hints: List<List<String>> = emptyList()) =
        g.frontier("inside", context, wifi, hints, now, 600_000)
    private fun resume(g: RouteGraph, f: RouteFrontier, now: Long, hints: List<List<String>> = emptyList()): RouteFrontier =
        checkNotNull(g.resumeFrontier("inside", context, wifi, hints, now, 600_000, checkNotNull(f.checkpoint(context, now))))

    @Test fun fiveHundredCandidatesResumeAcrossExpiryWithoutPrefixReplay() {
        val fixture = fixture()
        val g = graph(fixture)
        var now = 100L
        var f = cursor(g, now)
        val actual = mutableListOf<List<String>>()
        repeat(500) { index ->
            if (index > 0 && index % 17 == 0) {
                now += 600_000
                assertTrue(f.next(context, now, 1, 64).invalidated)
                val checkpoint = checkNotNull(f.checkpoint(context, now))
                assertEquals("FrontierPosition([redacted])", checkpoint.toString())
                assertFalse(checkpoint.toString().contains("policy"))
                f = checkNotNull(g.resumeFrontier("inside", context, wifi, emptyList(), now, 600_000, checkpoint))
            }
            val batch = f.next(context, now++, 1, 64)
            assertFalse(batch.invalidated)
            assertEquals(index + 1, batch.examined)
            assertEquals(500, batch.upperBound)
            assertEquals(index == 499, batch.exhausted)
            actual += batch.paths.single().hops
        }
        assertEquals(fixture.second.map { listOf(it) }, actual)
        assertEquals(500, actual.toSet().size)
        val completed = resume(g, f, now)
        val last = completed.next(context, now, 1, 64)
        assertTrue(last.exhausted); assertTrue(last.paths.isEmpty()); assertEquals(500, last.examined)
        assertEquals(listOf("hop-000"), cursor(g, now).next(context, now, 1, 64).paths.single().hops)
    }

    @Test fun positionBindsGraphInstanceGroupModeEveryContextFieldAndHints() {
        val fixture = fixture(4)
        val g = graph(fixture)
        val hints = listOf(listOf("hop-003"), listOf("hop-001"))
        val f = cursor(g, hints = hints)
        assertEquals(listOf("hop-003"), f.next(context, 100, 1, 1).paths.single().hops)
        val position = checkNotNull(f.checkpoint(context, 101))
        assertNotNull(g.resumeFrontier("inside", context, wifi, hints, 101, 600_000, position))
        assertNull(graph(fixture).resumeFrontier("inside", context, wifi, hints, 101, 600_000, position))
        assertNull(g.resumeFrontier("other", context, wifi, hints, 101, 600_000, position))
        assertNull(g.resumeFrontier("missing", context, wifi, hints, 101, 600_000, position))
        assertNull(g.resumeFrontier("inside", context, NetworkMode.HOME_WIFI, hints, 101, 600_000, position))
        assertNull(g.resumeFrontier("inside", context, wifi, hints.reversed(), 101, 600_000, position))
        assertNull(g.resumeFrontier("inside", context, wifi, emptyList(), 101, 600_000, position))
        for (changed in listOf(context.copy(networkEpoch = 2), context.copy(activationGeneration = 3),
            context.copy(configRevision = "new-policy"), context.copy(algorithmRevision = "new-algorithm"),
            context.copy(engineGeneration = 4), context.copy(dependencyHash = "b".repeat(64)))) {
            assertNull(g.resumeFrontier("inside", changed, wifi, hints, 101, 600_000, position))
        }
        assertNull(g.resumeFrontier("inside", context, wifi, hints, 100, 600_000, position))
        assertNull(g.resumeFrontier("inside", context, wifi, hints, Decision.MAX_TIME - 599_999, 600_000, position))
        assertNull(g.resumeFrontier("inside", context, wifi, hints, 101, 0, position))
        assertNull(g.resumeFrontier("inside", context, wifi, hints, 101, 600_001, position))
        assertNull(g.resumeFrontier("inside", context, wifi, hints+listOf(listOf("hop-000")), 101, 600_000, position))
        assertNull(g.resumeFrontier("inside", context, wifi, listOf(List(5) { "hop-000" }), 101, 600_000, position))
        assertNull(g.resumeFrontier("inside", context, wifi, listOf(listOf("invalid hint")), 101, 600_000, position))
        val changedSource = fixture.first.toString(Charsets.UTF_8).replace("\"WIFI\"", "\"CELLULAR\"").toByteArray()
        assertNull(RouteGraph.decode(changedSource, fixture.second).resumeFrontier("inside", context, wifi, hints, 101, 600_000, position))
    }

    @Test fun unsafeContextAndClockInvalidationCannotBecomeRenewableExpiry() {
        val g = graph(fixture(4))
        val wrong = context.copy(networkEpoch = 2)
        val f = cursor(g)
        assertTrue(f.next(wrong, 101, 1, 1).invalidated)
        assertNull(f.checkpoint(context, 600_100))
        assertTrue(f.next(context, 600_101, 1, 1).invalidated)
        val clock = cursor(g)
        assertNull(clock.checkpoint(context, 99))
        assertNull(clock.checkpoint(context, 600_100))
        val expired = cursor(g)
        assertTrue(expired.next(context, 600_100, 1, 1).invalidated)
        assertTrue(expired.next(wrong, 600_101, 1, 1).invalidated)
        assertNull(expired.checkpoint(context, 600_102))
        val oldTime = cursor(g)
        assertTrue(oldTime.next(context, 600_100, 1, 1).invalidated)
        assertNull(oldTime.checkpoint(context, 600_099))
        val boundary = g.frontier("inside", context, wifi, emptyList(), Decision.MAX_TIME - 600_000, 600_000)
        boundary.next(context, Decision.MAX_TIME - 600_000, 1, 1)
        val position = checkNotNull(boundary.checkpoint(context, Decision.MAX_TIME - 600_000))
        assertNotNull(g.resumeFrontier("inside", context, wifi, emptyList(), Decision.MAX_TIME - 600_000, 600_000, position))
        assertTrue(boundary.next(context, Decision.MAX_TIME, 1, 1).invalidated)
        assertNull(boundary.checkpoint(context, Decision.MAX_TIME))
    }

    @Test fun warmHintsAndSixtyFourOverlappingTemplatesStayDeduplicatedAfterRenewal() {
        val fixture = fixture(4, 64)
        val g = graph(fixture)
        val hints = listOf(listOf("hop-003"), listOf("hop-001"))
        val early = cursor(g, hints = hints)
        assertEquals(listOf("hop-003"), early.next(context, 100, 1, 1).paths.single().hops)
        assertTrue(early.next(context, 600_100, 1, 1).invalidated)
        assertEquals(listOf("hop-001"), resume(g, early, 600_100, hints).next(context, 600_100, 1, 1).paths.single().hops)
        var now = 100L
        var f = cursor(g, now, hints)
        val actual = mutableListOf<List<String>>()
        var complete = false
        repeat(300) { step ->
            if (complete) return@repeat
            if (step > 0 && step % 5 == 0) {
                now += 600_000
                assertTrue(f.next(context, now, 1, 1).invalidated)
                f = resume(g, f, now, hints)
            }
            val batch = f.next(context, now++, 1, 1)
            assertFalse(batch.invalidated)
            actual += batch.paths.map { it.hops }
            if (batch.exhausted) {
                complete = true
                assertEquals(256, batch.examined)
            }
        }
        assertTrue(complete)
        assertEquals(listOf("hop-003", "hop-001", "hop-000", "hop-002"), actual.map { it.single() })
        assertEquals(4, actual.toSet().size)
    }

    @Test fun fourSlotsAnd4096RawPositionsResumePastIneligibleAndDuplicateQuanta() {
        assertThrows(IllegalArgumentException::class.java) { graph(fixture(1, 65)) }
        assertThrows(IllegalArgumentException::class.java) { graph(fixture(500, 9)) }
        val sizes = listOf(4, 4, 2, 2)
        val slots = sizes.mapIndexed { slot, count -> (0 until count).map { "slot-$slot-hop-$it" } }
        val ids = slots.flatten()
        val last = slots.map { it.last() }
        val hops = slots.flatMapIndexed { slot, names -> names.map { name -> buildJsonObject {
            put("id", name); put("entryModes", buildJsonArray { if (slot == 0) add("WIFI") })
            put("exitClass", if (slot == 3) JsonPrimitive("INTERNAL") else JsonNull)
            put("features", buildJsonArray { add("TCP"); add("IPV4") })
        } } }
        val edges = last.zipWithNext().map { (from, to) -> buildJsonObject {
            put("from", from); put("to", to); put("features", buildJsonArray { add("TCP"); add("IPV4") })
        } }
        val templates = (0 until 64).map { index -> buildJsonObject {
            put("id", "template-%02d".format(index)); put("slots", JsonArray(slots.map { JsonArray(it.map(::JsonPrimitive)) }))
        } }
        val raw = buildJsonObject {
            put("schemaVersion", 1); put("hops", JsonArray(hops)); put("edges", JsonArray(edges)); put("templates", JsonArray(templates))
            put("groups", buildJsonArray { add(buildJsonObject {
                put("id", "inside"); put("intent", "INTERNAL"); put("features", buildJsonArray { add("TCP"); add("IPV4") })
                put("templates", JsonArray(templates.map { it.getValue("id") }))
            }) })
        }.toString().toByteArray()
        val g = RouteGraph.decode(raw, ids)
        var now = 100L
        var f = cursor(g, now)
        var complete = false
        var empty = 0
        var previous = 0
        val actual = mutableListOf<List<String>>()
        repeat(600) { step ->
            if (complete) return@repeat
            if (step > 0 && step % 5 == 0) { now += 600_000; f = resume(g, f, now) }
            val batch = f.next(context, now++, 1, 7)
            assertFalse(batch.invalidated)
            assertTrue(batch.examined - previous in 1..7)
            assertEquals(4096, batch.upperBound)
            previous = batch.examined
            if (batch.paths.isEmpty()) empty++
            actual += batch.paths.map { it.hops }
            if (batch.exhausted) complete = true
        }
        assertTrue(complete); assertEquals(4096, previous); assertTrue(empty > 500)
        assertEquals(listOf(last), actual)
    }

    @Test fun positionAndGraphOwnershipSurviveCallerBufferAndHintMutation() {
        val fixture = fixture(4)
        val g = graph(fixture)
        val hint = mutableListOf("hop-003")
        val hints = mutableListOf<List<String>>(hint)
        val f = cursor(g, hints = hints)
        assertEquals(listOf("hop-003"), f.next(context, 100, 1, 1).paths.single().hops)
        val position = checkNotNull(f.checkpoint(context, 101))
        fixture.first.fill(0); hint[0] = "unknown"; hints.clear()
        val resumed = checkNotNull(g.resumeFrontier("inside", context, wifi, listOf(listOf("hop-003")), 102, 600_000, position))
        assertEquals(listOf("hop-000"), resumed.next(context, 102, 1, 1).paths.single().hops)
        assertFalse(position.toString().contains("hop"))
        assertFalse(position.toString().contains(context.dependencyHash))
    }
}
