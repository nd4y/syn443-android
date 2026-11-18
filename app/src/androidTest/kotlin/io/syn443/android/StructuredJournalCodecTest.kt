package io.syn443.android

import io.syn443.android.observability.JournalFrame
import io.syn443.android.observability.StructuredJournalCodec
import io.syn443.observability.DecisionStamp
import io.syn443.observability.EngineSignal
import io.syn443.observability.EventClock
import io.syn443.observability.EventCode
import io.syn443.observability.EventCorrelation
import io.syn443.observability.EventDetail
import io.syn443.observability.EventGenerations
import io.syn443.observability.EventLevel
import io.syn443.observability.EventPhase
import io.syn443.observability.JournalRetention
import io.syn443.observability.StructuredEvent
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

/** Typed synthetic metadata only. No context, identity, key, store or provider. */
class StructuredJournalCodecTest {
    private fun event(sequence: Long, detail: EventDetail = EventDetail.Lifecycle(
        EventPhase.RECOVERING, EventCode.MANAGED_ROUTE_RECHECK, DecisionStamp(42, 2),
    )) = StructuredEvent(sequence, EventClock(7, 1_000 + sequence, sequence),
        EventCorrelation.fromBytes(ByteArray(16) { it.toByte() }), EventGenerations(3, 4, 5, 6), detail)
    private fun frame() = JournalFrame(EventClock(7, 5_000, 1_000),
        listOf(event(1), event(2, EventDetail.Engine(EngineSignal.READY))))
    private fun rejected(block: () -> Any?) {
        var rejected = false
        try { block() } catch (_: Exception) { rejected = true }
        assertTrue("Malformed journal input accepted", rejected)
    }
    private fun changed(raw: ByteArray, change: (JSONObject) -> Unit): ByteArray =
        JSONObject(raw.toString(Charsets.UTF_8)).also(change).toString().toByteArray(Charsets.UTF_8)
    private fun row(value: JSONObject) = value.getJSONArray("events").getJSONObject(0)

    @Test fun typedLifecycleAndEngineFramesRoundTripWithoutMutableOrFreeTextAliases() {
        val inputs = mutableListOf(event(1), event(2, EventDetail.Engine(EngineSignal.READY)))
        val owned = JournalFrame(EventClock(7, 5_000, 1_000), inputs)
        inputs.clear()
        assertEquals(2, owned.events.size)
        val raw = StructuredJournalCodec.encode(owned)
        val original = raw.copyOf()
        val restored = StructuredJournalCodec.decode(raw)
        raw.fill(0)
        assertEquals(owned.committed, restored.committed)
        assertEquals(owned.first, restored.first)
        assertEquals(owned.events, restored.events)
        assertArrayEquals(original, StructuredJournalCodec.encode(restored))
        restored.events.first().correlation.bytes().fill(0)
        assertEquals(owned.events, restored.events)
        for (events in listOf(owned.events, restored.events)) {
            try { (events as MutableList<StructuredEvent>).clear(); fail("Mutable validated frame") }
            catch (_: UnsupportedOperationException) { }
        }
        val common = setOf("sequence", "boot", "at", "elapsed", "correlationId", "intentGeneration", "networkEpoch",
            "channel", "level", "source", "activationGeneration", "engineGeneration")
        val lifecycleBytes = StructuredJournalCodec.projectedLine(restored.events[0])
        assertEquals('\n'.code.toByte(), lifecycleBytes.last())
        val lifecycle = JSONObject(lifecycleBytes.toString(Charsets.UTF_8))
        assertEquals(common + setOf("phase", "code", "policyRevision", "algorithmRevision"), lifecycle.keys().asSequence().toSet())
        assertEquals(42L, lifecycle.getLong("policyRevision"))
        assertEquals(2, lifecycle.getInt("algorithmRevision"))
        assertEquals("selector", lifecycle.getString("channel"))
        assertEquals("controller", lifecycle.getString("source"))
        val engine = JSONObject(StructuredJournalCodec.projectedLine(restored.events[1]).toString(Charsets.UTF_8))
        assertEquals(common + "engineSignal", engine.keys().asSequence().toSet())
        assertEquals("ready", engine.getString("engineSignal"))
        assertEquals("engine", engine.getString("source"))
        lifecycleBytes.fill(0)
        assertEquals("managed_route_recheck", JSONObject(StructuredJournalCodec.projectedLine(restored.events[0])
            .toString(Charsets.UTF_8)).getString("code"))
        assertEquals("JournalFrame([redacted])", restored.toString())
    }

    @Test fun malformedDuplicateUnknownDeepAndSecretBearingFramesNeverExport() {
        val raw = StructuredJournalCodec.encode(frame())
        val text = raw.toString(Charsets.UTF_8)
        val secret = "synthetic-private-material"
        val malformed = mutableListOf(
            changed(raw) { it.put("path", secret) },
            changed(raw) { it.remove("committed") },
            changed(raw) { it.put("SchemaVersion", it.remove("schemaVersion")) },
            changed(raw) { row(it).put("message", secret) },
            changed(raw) { row(it).getJSONObject("detail").put("headers", JSONObject().put("authorization", secret)) },
            changed(raw) { row(it).getJSONObject("detail").put("code", secret) },
            changed(raw) { row(it).getJSONObject("detail").put("phase", secret) },
            changed(raw) { row(it).getJSONObject("detail").put("kind", "foreign") },
            changed(raw) { row(it).getJSONObject("detail").getJSONObject("decision").put("query", secret) },
            changed(raw) { row(it).getJSONObject("generations").put("subscriptionUrl", secret) },
            changed(raw) { row(it).put("level", "debug") },
            changed(raw) { row(it).put("correlation", "A".repeat(32)) },
            changed(raw) { it.getJSONArray("events").getJSONObject(1).getJSONObject("detail").put("signal", "pulse") },
            changed(raw) {
                var nested: Any = secret
                repeat(9) { nested = JSONArray().put(nested) }
                it.put("nested", nested)
            },
            text.replaceFirst("\"schemaVersion\":1", "\"schemaVersion\":1,\"schemaVersion\":1").toByteArray(),
            text.replaceFirst("\"schemaVersion\":1", "\"schemaVersion\":1,\"\\u0073chemaVersion\":1").toByteArray(),
            text.replaceFirst("\"schemaVersion\":1", "\"schemaVersion\":1.0").toByteArray(),
            text.replaceFirst("\"schemaVersion\":1", "\"schemaVersion\":1e0").toByteArray(),
            text.replaceFirst("\"schemaVersion\":1", "\"schemaVersion\":NaN").toByteArray(),
            text.replaceFirst("\"schemaVersion\":1", "\"schemaVersion\":Infinity").toByteArray(),
            text.replaceFirst("Recovering", "\\u0052ecovering").toByteArray(),
            (" " + text).toByteArray(), (text + "\n").toByteArray(), (text + "{}").toByteArray(),
            byteArrayOf(0xff.toByte()), byteArrayOf(0xc3.toByte(), 0x28), byteArrayOf(0xed.toByte(), 0xa0.toByte(), 0x80.toByte()),
        )
        malformed += changed(raw) { row(it).getJSONObject("detail").put("code", "x".repeat(65)) }
        malformed.forEach { candidate -> rejected { StructuredJournalCodec.decode(candidate) } }
        val sanitized = event(1, EventDetail.Lifecycle(EventPhase.RECOVERING, EventCode.fromWire(secret)))
        val sanitizedFrame = StructuredJournalCodec.decode(StructuredJournalCodec.encode(JournalFrame(frame().committed, listOf(sanitized))))
        val projection = StructuredJournalCodec.projectedLine(sanitizedFrame.events.single()).toString(Charsets.UTF_8)
        assertFalse(projection.contains(secret))
        assertEquals("redacted", JSONObject(projection).getString("code"))
        assertNull(EventPhase.fromWire(secret))
    }

    @Test fun exactFrameRowNumericAndWholeFrameBoundariesRemainClosed() {
        val maximum = StructuredEvent.MAX_SAFE
        val rows = (0..63).map { index ->
            val value = maximum - 63 + index
            StructuredEvent(value, EventClock(Int.MAX_VALUE, value, value),
                EventCorrelation.fromBytes(ByteArray(16) { 0x7f.toByte() }), EventGenerations(maximum, maximum, maximum, maximum),
                EventDetail.Lifecycle(EventPhase.BLOCKED_BY_POLICY, EventCode.MANAGED_ROUTE_RECHECK, DecisionStamp(maximum, 2)), EventLevel.ERROR)
        }
        val largestTyped = JournalFrame(EventClock(Int.MAX_VALUE, maximum, maximum), rows)
        val encoded = StructuredJournalCodec.encode(largestTyped)
        val restored = StructuredJournalCodec.decode(encoded)
        assertEquals(64, restored.events.size)
        assertEquals(maximum, restored.events.last().sequence)
        assertEquals(rows, restored.events)
        assertTrue(encoded.size <= StructuredJournalCodec.MAX_PLAINTEXT)
        assertEquals(65_507, StructuredJournalCodec.MAX_PLAINTEXT)
        assertEquals(JournalRetention.MAX_FRAME_BYTES, StructuredJournalCodec.MAX_PLAINTEXT.toLong() + 29)
        restored.events.forEach { assertTrue(StructuredJournalCodec.projectedLine(it).size <= 2048) }
        rejected { JournalFrame(frame().committed, emptyList()) }
        rejected { JournalFrame(largestTyped.committed, rows + rows.last()) }
        rejected { JournalFrame(frame().committed, listOf(event(2), event(1))) }
        rejected { JournalFrame(frame().committed, listOf(event(1), event(1))) }
        rejected { JournalFrame(EventClock(8, 5_000, 1_000), listOf(event(1))) }
        val raw = StructuredJournalCodec.encode(frame())
        for (mutation in listOf<(JSONObject) -> Unit>(
            { row(it).put("sequence", 0) }, { row(it).put("sequence", maximum + 1) },
            { row(it).put("sequence", "1") }, { row(it).put("sequence", true) },
            { row(it).getJSONObject("clock").put("boot", Int.MAX_VALUE.toLong() + 1) },
            { row(it).getJSONObject("clock").put("elapsedMs", -1) },
            { row(it).getJSONObject("clock").put("elapsedMs", 1_001) },
            { row(it).getJSONObject("generations").put("activation", JSONObject.NULL) },
            { row(it).getJSONObject("generations").put("network", maximum + 1) },
            { row(it).getJSONObject("detail").getJSONObject("decision").put("algorithmRevision", 3) },
            { row(it).getJSONObject("detail").getJSONObject("decision").put("policyRevision", 0) },
            { row(it).getJSONObject("detail").put("code", "tls_failed") },
        )) rejected { StructuredJournalCodec.decode(changed(raw, mutation)) }
        val atCap = raw + ByteArray(StructuredJournalCodec.MAX_PLAINTEXT - raw.size) { 32 }
        assertEquals(65_507, atCap.size)
        // The exact cap does not grant permission for noncanonical padding.
        rejected { StructuredJournalCodec.decode(atCap) }
        rejected { StructuredJournalCodec.decode(atCap + byteArrayOf(32)) }
        rejected { StructuredJournalCodec.decode(byteArrayOf()) }
    }
}
