package io.syn443.observability

enum class Role { CONTROLLER, ENGINE }
enum class Availability { AVAILABLE, NOT_RUNNING, UNAVAILABLE, PROCESS_CHANGED }

/** Identity is local comparison data; it must never be serialized into diagnostics. */
data class Counters(val identity: String, val cpuMs: Long, val rssBytes: Long?, val threads: Int?, val fds: Int?)
data class Reading(val state: Availability, val counters: Counters? = null)
data class Window(val state: String, val elapsedMs: Long? = null, val awakeMs: Long? = null, val cpuMs: Long? = null) {
    // 1000 = one logical CPU. This is process CPU, not battery consumption.
    val cpuPermille: Long? get() = if (elapsedMs != null && cpuMs != null) (cpuMs.toDouble() * 1000 / elapsedMs).toLong() else null
}
data class Observation(val role: Role, val reading: Reading, val window: Window)
data class ResourceReport(val elapsedMs: Long, val uptimeMs: Long, val ageMs: Long, val cached: Boolean,
    val processes: List<Observation>, val clockReadSpanMs: Long = 0)

/** No timers, IO, persistence or network. A controller owns exactly one bounded cache. */
class ResourceSampler(private val source: (Role) -> Reading) {
    companion object { const val MIN_INTERVAL_MS = 30_000L }
    private var last: ResourceReport? = null

    @Synchronized fun sample(elapsedMs: Long, uptimeMs: Long, clockReadSpanMs: Long = 0): ResourceReport {
        require(elapsedMs >= 0 && uptimeMs in 0..elapsedMs && clockReadSpanMs in 0..1000)
        val previous = last
        if (previous != null && elapsedMs >= previous.elapsedMs && uptimeMs >= previous.uptimeMs &&
            elapsedMs - previous.elapsedMs < MIN_INTERVAL_MS) {
            return previous.copy(ageMs = elapsedMs - previous.elapsedMs, cached = true)
        }
        val observations = Role.entries.map { role ->
            val reading = try { source(role) } catch (_: Exception) { Reading(Availability.UNAVAILABLE) }
            val current = reading.counters?.takeIf { reading.state == Availability.AVAILABLE }
            val old = previous?.processes?.first { it.role == role }?.reading?.counters
            val state = when {
                current == null -> "unavailable"
                previous == null || old == null -> "baseline"
                elapsedMs <= previous.elapsedMs || uptimeMs < previous.uptimeMs ||
                    uptimeMs - previous.uptimeMs - (elapsedMs - previous.elapsedMs) > previous.clockReadSpanMs + 1 -> "clock_reset"
                current.identity != old.identity -> "process_changed"
                current.cpuMs < old.cpuMs -> "counter_reset"
                else -> "measured"
            }
            val window = if (state == "measured") Window(state, elapsedMs - previous!!.elapsedMs,
                // The uptime read precedes the elapsed read. Previous read span and
                // millisecond quantization can make awake exceed elapsed slightly.
                (uptimeMs - previous.uptimeMs).coerceAtMost(elapsedMs - previous.elapsedMs), current!!.cpuMs - old!!.cpuMs) else Window(state)
            Observation(role, if (current == null) reading.copy(counters = null) else reading, window)
        }
        return ResourceReport(elapsedMs, uptimeMs, 0, false, observations, clockReadSpanMs).also { last = it }
    }
}

/** Linux proc inputs only. No file paths, command lines or arbitrary text reach the result. */
object ProcCounters {
    fun parse(stat: String, status: String, fds: Int?, pid: Int, uid: Int, hz: Long): Counters {
        require(stat.length <= 16_384 && status.length <= 16_384 && pid > 0 && uid >= 0 && hz in 1..1_000_000)
        val end = stat.lastIndexOf(')')
        require(end > 0 && stat.substringBefore(' ').toInt() == pid)
        val fields = stat.substring(end + 1).trim().split(Regex("\\s+")) // Starts at field 3, state.
        require(fields.size >= 22)
        val statusFields = status.lineSequence().filter { ':' in it }.associate { it.substringBefore(':') to it.substringAfter(':').trim() }
        val uids = requireNotNull(statusFields["Uid"]).split(Regex("\\s+")).map { it.toInt() }
        require(uids.size == 4 && uids.all { it == uid })
        val user = fields[11].toLong(); val system = fields[12].toLong(); val start = fields[19].toLong()
        require(user >= 0 && system >= 0 && start >= 0)
        val ticks = Math.addExact(user, system)
        val cpuMs = Math.addExact(Math.multiplyExact(ticks / hz, 1000), (ticks % hz) * 1000 / hz)
        val rss = statusFields["VmRSS"]?.let {
            val value = it.split(Regex("\\s+"))
            require(value.size == 2 && value[1] == "kB")
            Math.multiplyExact(value[0].toLong().also { n -> require(n >= 0) }, 1024)
        }
        val threads = statusFields["Threads"]?.toInt()?.also { require(it > 0) }
        require(fds == null || fds in 0..4096)
        return Counters("$pid:$start", cpuMs, rss, threads, fds)
    }
}
