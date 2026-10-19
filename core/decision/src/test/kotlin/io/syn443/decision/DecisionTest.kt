package io.syn443.decision

import kotlinx.serialization.json.*
import org.junit.Assert.*
import org.junit.Test
import kotlin.random.Random

class DecisionTest {
    private fun vectors(): JsonObject = Decision.json.parseToJsonElement(
        javaClass.getResource("/decision-vectors.json")!!.readText(),
    ).jsonObject

    private fun first(): Request = Decision.decode(vectors()["cases"]!!.jsonArray.first().jsonObject["input"].toString())

    private fun fails(block: () -> Unit) {
        try { block(); fail("Invalid input accepted") } catch (_: IllegalArgumentException) {
        } catch (_: IllegalStateException) { }
    }

    @Test fun sharedConformanceAndPermutation() {
        for (item in vectors()["cases"]!!.jsonArray) {
            val case = item.jsonObject
            val request = Decision.decode(case["input"].toString())
            val expected = Decision.json.decodeFromJsonElement<Result>(case["expected"]!!)
            assertEquals(case["name"].toString(), expected, Decision.select(request))
            repeat(12) {
                assertEquals(expected, Decision.select(request.copy(candidates = request.candidates.shuffled(Random(it)))))
            }
        }
        for (item in vectors()["invalidCases"]!!.jsonArray) {
            fails { Decision.decode(item.jsonObject["input"].toString()) }
        }
    }

    @Test fun strictWire() {
        val raw = vectors()["cases"]!!.jsonArray.first().jsonObject["input"].toString()
        val invalid = listOf(
            "", "null", "true", "[]", "{", "{\"x\":1,\"x\":2}", "{\"x\":1,\"\\u0078\":2}",
            "{\"x\":-1}", "{\"x\":1.0}", "{\"x\":1e1}", raw + raw,
            "[".repeat(18) + "]".repeat(18),
            "[" + "0,".repeat(4096) + "0]",
            "{" + (0..64).joinToString(",") { "\"key" + it + "\":0" } + "}",
            " ".repeat((1 shl 20) + 1),
            "\"" + "\u2603".repeat((1 shl 20) / 3 + 1) + "\"",
        )
        invalid.forEach { fails { Decision.decode(it) } }
    }

    @Test fun candidateLimitsAndWorstEnergy() {
        val r = first()
        val base = r.candidates.first()
        val full = r.copy(candidates = (0 until 4096).map { base.copy(id = "p-" + it.toString().padStart(4, '0')) })
        assertEquals(4096, Decision.select(full).orderedPathIds.size)
        fails { Decision.select(full.copy(candidates = full.candidates + base)) }
        fails { Decision.select(r.copy(candidates = listOf(base.copy(samples = -1)))) }
        val low = base.copy(id = "low", bytesPerMinute = 0, handshakesPerMinute = 0, activeBackups = 0)
        for (high in listOf(
            low.copy(id = "high", bytesPerMinute = null, latencyMs = 0),
            low.copy(id = "high", handshakesPerMinute = 100, latencyMs = 0),
            low.copy(id = "high", activeBackups = 3, latencyMs = 0),
        )) assertEquals("low", Decision.select(r.copy(candidates = listOf(high, low))).selectedPathId)
    }

    @Test fun scalarBoundariesMatchSchema() {
        val r = first()
        val c = r.candidates.first()
        listOf(
            r.copy(schemaVersion = 2), r.copy(nowMs = -1), r.copy(nowMs = Decision.MAX_TIME + 1),
            r.copy(evidenceTtlMs = 0), r.copy(evidenceTtlMs = 600001),
            r.copy(intent = "ANY"), r.copy(metricGroup = "bad/value"),
        ).forEach { fails { Decision.select(it) } }
        listOf(
            c.copy(observedAtMs = -1), c.copy(observedAtMs = Decision.MAX_TIME + 1),
            c.copy(samples = -1), c.copy(samples = 21), c.copy(failures = -1),
            c.copy(failures = c.samples + 1), c.copy(trailingSuccesses = -1),
            c.copy(trailingSuccesses = c.samples + 1),
            c.copy(bytesPerMinute = -1), c.copy(bytesPerMinute = 2147483648L),
            c.copy(handshakesPerMinute = -1), c.copy(handshakesPerMinute = 1000001),
            c.copy(activeBackups = -1), c.copy(activeBackups = 65),
            c.copy(latencyMs = -1), c.copy(latencyMs = 600001),
            c.copy(exitClass = "ANY"), c.copy(id = "BAD"), c.copy(metricGroup = ""),
        ).forEach { fails { Decision.select(r.copy(candidates = listOf(it))) } }
        listOf(
            r.context.copy(networkEpoch = Decision.MAX_GENERATION + 1),
            r.context.copy(activationGeneration = -1),
            r.context.copy(engineGeneration = Decision.MAX_GENERATION + 1),
            r.context.copy(configRevision = "x".repeat(65)),
            r.context.copy(algorithmRevision = ""),
            r.context.copy(dependencyHash = "b".repeat(63)),
        ).forEach { context ->
            fails { Decision.select(r.copy(context = context)) }
            fails { Decision.select(r.copy(candidates = listOf(c.copy(context = context)))) }
        }
        fails { Decision.select(r.copy(candidates = listOf(c, c))) }
    }

    @Test fun randomWireDoesNotProduceInvalidWinner() {
        val random = Random(443)
        repeat(1000) {
            val raw = random.nextBytes(random.nextInt(0, 200)).toString(Charsets.UTF_8)
            try {
                val result = Decision.select(Decision.decode(raw))
                assertEquals(result.orderedPathIds.firstOrNull(), result.selectedPathId)
            } catch (_: IllegalArgumentException) {
            } catch (_: IllegalStateException) { }
        }
    }
}

