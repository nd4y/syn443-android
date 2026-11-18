package io.syn443.android.observability

import io.syn443.observability.DecisionStamp
import io.syn443.observability.EngineSignal
import io.syn443.observability.EventClock
import io.syn443.observability.EventCode
import io.syn443.observability.EventCorrelation
import io.syn443.observability.EventDetail
import io.syn443.observability.EventGenerations
import io.syn443.observability.EventLevel
import io.syn443.observability.EventPhase
import io.syn443.observability.StructuredEvent
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.util.Collections
import org.json.JSONArray
import org.json.JSONObject
import org.json.JSONTokener

/** No arbitrary payload belongs to a journal frame. The committed clock is a
 * durable comparison floor, never a replacement timestamp for older events. */
internal class JournalFrame(val committed: EventClock, events: List<StructuredEvent>) {
    val events: List<StructuredEvent>
    val first: EventClock get() = events.first().clock
    init {
        require(events.size in 1..64)
        this.events = Collections.unmodifiableList(ArrayList(events))
        this.events.forEach { event ->
            require(event.clock.boot == committed.boot && event.clock.elapsedMs <= committed.elapsedMs &&
                event.clock.wallMs <= committed.wallMs)
        }
        this.events.zipWithNext().forEach { (before, after) ->
            require(before.sequence < after.sequence && before.clock.elapsedMs <= after.clock.elapsedMs &&
                before.clock.wallMs <= after.clock.wallMs)
        }
    }
    override fun toString() = "JournalFrame([redacted])"
}

/** A canonical, bounded representation of typed records only. Re-encoding
 * rejects duplicate keys, alternate numeric forms and foreign JSON subtrees. */
internal object StructuredJournalCodec {
    const val MAX_PLAINTEXT = 65_507 // 64KiB whole frame minus version, nonce and GCM tag.
    private val correlationPattern = Regex("[a-f0-9]{32}")

    fun encode(frame: JournalFrame): ByteArray {
        val rows = JSONArray()
        for (event in frame.events) rows.put(row(event))
        val bytes = JSONObject().put("schemaVersion", 1).put("committed", clock(frame.committed))
            .put("events", rows).toString().toByteArray(Charsets.UTF_8)
        require(bytes.size in 1..MAX_PLAINTEXT)
        return bytes
    }

    fun decode(raw: ByteArray): JournalFrame {
        require(raw.size in 1..MAX_PLAINTEXT)
        val text = Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(raw)).toString()
        // Bound recursion before JSONTokener can descend through hostile input.
        var depth = 0
        var quoted = false
        var escaped = false
        for (char in text) {
            if (quoted) {
                if (escaped) escaped = false else if (char == '\\') escaped = true else if (char == '"') quoted = false
            } else when (char) {
                '"' -> quoted = true
                '{', '[' -> { depth++; require(depth <= 8) }
                '}', ']' -> { depth--; require(depth >= 0) }
            }
        }
        require(depth == 0 && !quoted)
        val token = JSONTokener(text)
        val value = token.nextValue() as? JSONObject ?: error("journal_invalid")
        require(token.nextClean() == '\u0000')
        keys(value, setOf("schemaVersion", "committed", "events"))
        require(number(value, "schemaVersion") == 1L)
        val rows = value.getJSONArray("events")
        require(rows.length() in 1..64)
        val frame = JournalFrame(readClock(value.getJSONObject("committed")),
            (0 until rows.length()).map { readRow(rows.getJSONObject(it)) })
        val canonical = encode(frame)
        try { require(canonical.contentEquals(raw)) } finally { canonical.fill(0) }
        return frame
    }

    fun projectedLine(event: StructuredEvent): ByteArray {
        val result = JSONObject().put("sequence", event.sequence)
            .put("boot", event.clock.boot).put("at", event.clock.wallMs).put("elapsed", event.clock.elapsedMs)
            .put("correlationId", correlation(event.correlation))
            .put("intentGeneration", event.generations.intent).put("networkEpoch", event.generations.network)
            .put("channel", event.channel.wire).put("level", event.level.wire)
            .put("source", event.source.name.lowercase(java.util.Locale.ROOT))
        event.generations.activation?.let { result.put("activationGeneration", it) }
        event.generations.engine?.let { result.put("engineGeneration", it) }
        when (val detail = event.detail) {
            is EventDetail.Lifecycle -> {
                result.put("phase", detail.phase.wire).put("code", detail.code.wire)
                detail.decision?.let { result.put("policyRevision", it.policyRevision).put("algorithmRevision", it.algorithmRevision) }
            }
            is EventDetail.Engine -> result.put("engineSignal", detail.signal.wire)
        }
        return (result.toString() + "\n").toByteArray(Charsets.UTF_8).also { require(it.size <= 2048) }
    }

    private fun row(event: StructuredEvent): JSONObject {
        val generations = JSONObject().put("intent", event.generations.intent).put("network", event.generations.network)
        event.generations.activation?.let { generations.put("activation", it) }
        event.generations.engine?.let { generations.put("engine", it) }
        val detail = when (val input = event.detail) {
            is EventDetail.Lifecycle -> JSONObject().put("kind", "lifecycle").put("phase", input.phase.wire).put("code", input.code.wire).also { out ->
                input.decision?.let { out.put("decision", JSONObject().put("policyRevision", it.policyRevision).put("algorithmRevision", it.algorithmRevision)) }
            }
            is EventDetail.Engine -> JSONObject().put("kind", "engine").put("signal", input.signal.wire)
        }
        return JSONObject().put("sequence", event.sequence).put("clock", clock(event.clock))
            .put("correlation", correlation(event.correlation)).put("generations", generations)
            .put("detail", detail).put("level", event.level.wire)
    }

    private fun readRow(value: JSONObject): StructuredEvent {
        keys(value, setOf("sequence", "clock", "correlation", "generations", "detail", "level"))
        val generations = value.getJSONObject("generations")
        val allowedGenerations = setOf("intent", "network", "activation", "engine")
        require(generations.length() in 2..4 && generations.has("intent") && generations.has("network") &&
            generations.keys().asSequence().all(allowedGenerations::contains))
        val detail = value.getJSONObject("detail")
        val typed = when (string(detail, "kind")) {
            "lifecycle" -> {
                keys(detail, if (detail.has("decision")) setOf("kind", "phase", "code", "decision") else setOf("kind", "phase", "code"))
                val codeRaw = string(detail, "code")
                val code = EventCode.fromWire(codeRaw)
                require(code.wire == codeRaw)
                val decision = if (detail.has("decision")) detail.getJSONObject("decision").let {
                    keys(it, setOf("policyRevision", "algorithmRevision"))
                    DecisionStamp(number(it, "policyRevision"), number(it, "algorithmRevision").also { n -> require(n in 1..2) }.toInt())
                } else null
                EventDetail.Lifecycle(checkNotNull(EventPhase.fromWire(string(detail, "phase"))), code, decision)
            }
            "engine" -> {
                keys(detail, setOf("kind", "signal"))
                EventDetail.Engine(checkNotNull(EngineSignal.fromWire(string(detail, "signal"))))
            }
            else -> error("journal_invalid")
        }
        val bytes = correlationBytes(string(value, "correlation"))
        val correlation = try { EventCorrelation.fromBytes(bytes) } finally { bytes.fill(0) }
        return StructuredEvent(number(value, "sequence"), readClock(value.getJSONObject("clock")), correlation,
            EventGenerations(number(generations, "intent"), number(generations, "network"),
                if (generations.has("activation")) number(generations, "activation") else null,
                if (generations.has("engine")) number(generations, "engine") else null),
            typed, checkNotNull(EventLevel.fromWire(string(value, "level"))))
    }

    private fun clock(value: EventClock) = JSONObject().put("boot", value.boot).put("wallMs", value.wallMs).put("elapsedMs", value.elapsedMs)
    private fun readClock(value: JSONObject): EventClock {
        keys(value, setOf("boot", "wallMs", "elapsedMs"))
        return EventClock(number(value, "boot").also { require(it <= Int.MAX_VALUE) }.toInt(), number(value, "wallMs"), number(value, "elapsedMs"))
    }
    private fun number(value: JSONObject, name: String): Long = when (val input = value.opt(name)) {
        is Int -> input.toLong()
        is Long -> input
        else -> error("journal_invalid")
    }.also { require(it in 0..StructuredEvent.MAX_SAFE) }
    private fun string(value: JSONObject, name: String): String = (value.opt(name) as? String)?.also {
        require(it.length in 1..64)
    } ?: error("journal_invalid")
    private fun keys(value: JSONObject, expected: Set<String>) {
        require(value.length() == expected.size && value.keys().asSequence().all(expected::contains))
    }
    private fun correlation(value: EventCorrelation): String {
        val bytes = value.bytes()
        return try { bytes.joinToString("") { "%02x".format(it.toInt() and 255) } } finally { bytes.fill(0) }
    }
    private fun correlationBytes(value: String): ByteArray {
        require(correlationPattern.matches(value))
        return ByteArray(16) { value.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }
}
