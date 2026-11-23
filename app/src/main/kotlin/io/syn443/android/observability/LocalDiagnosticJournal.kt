package io.syn443.android.observability

import android.app.Application
import android.content.Context
import android.os.SystemClock
import android.provider.Settings
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import io.syn443.android.support.DiagnosticArchive
import io.syn443.android.vpn.LifecycleAccess
import io.syn443.observability.DecisionStamp
import io.syn443.observability.EventClock
import io.syn443.observability.EventCode
import io.syn443.observability.EventCorrelation
import io.syn443.observability.EventDetail
import io.syn443.observability.EventGenerations
import io.syn443.observability.EventLevel
import io.syn443.observability.EventPhase
import io.syn443.observability.EngineSignal
import io.syn443.observability.StructuredEvent
import java.io.File
import java.security.KeyStore
import java.security.SecureRandom
import java.util.ArrayDeque
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

/** Fixed memory-only input. No arbitrary original strings survive admission. */
internal data class PendingJournalEvent(
    val wallMs: Long, val elapsedMs: Long, val generations: EventGenerations,
    val detail: EventDetail, val level: EventLevel = EventLevel.INFO,
) {
    init { require(wallMs in 0..StructuredEvent.MAX_SAFE && elapsedMs in 0..StructuredEvent.MAX_SAFE) }
    override fun toString() = "PendingJournalEvent([redacted])"
}

/** One actual executor thread owns correlation, sequence, crypto and file IO.
 * Producers never wait for that thread or refund its slot on a timeout. */
internal class JournalWriter(
    private val executor: ExecutorService,
    private val clock: () -> EventClock,
    private val correlation: () -> EventCorrelation,
    private val append: (List<StructuredEvent>) -> Unit,
    private val elapsed: () -> Long = SystemClock::elapsedRealtime,
    private val pause: (Long) -> Unit = Thread::sleep,
) {
    internal data class Status(val running: Boolean, val failed: Boolean, val queued: Int, val dropped: Long) {
        override fun toString() = "JournalWriterStatus([redacted])"
    }
    private val lock = Any()
    private val queue = ArrayDeque<PendingJournalEvent>(64)
    private var running = false
    private var failed = false
    private var dropped = 0L
    // These fields belong exclusively to the actual single executor thread.
    private var ownedCorrelation: EventCorrelation? = null
    private var sequence = 0L
    private var lastWrite: Long? = null
    private var lastEventClock: EventClock? = null

    fun offer(event: PendingJournalEvent): Boolean {
        var submit = false
        synchronized(lock) {
            if (failed || queue.size >= 64) { lose(1); return false }
            queue.addLast(event)
            if (!running) { running = true; submit = true }
        }
        if (submit) dispatch()
        return true
    }
    fun status(): Status = synchronized(lock) { Status(running, failed, queue.size, dropped) }
    private fun lose(count: Int) { dropped = (dropped + count).coerceAtMost(StructuredEvent.MAX_SAFE) }
    private fun dispatch() {
        try { executor.execute(::drain) }
        catch (_: Exception) {
            synchronized(lock) { failed = true; running = false; lose(queue.size); queue.clear() }
        }
    }
    private fun drain() {
        var inFlight = 0
        try {
            while (true) {
                val batch = synchronized(lock) {
                    if (queue.isEmpty()) return
                    ArrayList<PendingJournalEvent>(queue.size).also { output -> while (queue.isNotEmpty()) output += queue.removeFirst() }
                }
                inFlight = batch.size
                val current = elapsed()
                require(current >= 0)
                lastWrite?.let { before ->
                    require(current >= before)
                    if (current - before < 500) pause(500 - (current - before))
                }
                val observed = clock()
                val owned = ownedCorrelation ?: correlation().also { ownedCorrelation = it }
                val records = ArrayList<StructuredEvent>(batch.size)
                var last = lastEventClock
                for (pending in batch) {
                    val previous = last
                    if (pending.wallMs > observed.wallMs || pending.elapsedMs > observed.elapsedMs ||
                        previous != null && (pending.wallMs < previous.wallMs || pending.elapsedMs < previous.elapsedMs)
                    ) continue
                    check(sequence < StructuredEvent.MAX_SAFE)
                    val eventClock = EventClock(observed.boot, pending.wallMs, pending.elapsedMs)
                    records += StructuredEvent(++sequence, eventClock, owned, pending.generations, pending.detail, pending.level)
                    last = eventClock
                }
                // A delayed producer may enqueue an older event after a newer
                // native callback. Preserve times and count the dropped row.
                synchronized(lock) { lose(batch.size - records.size) }
                inFlight = records.size
                if (records.isEmpty()) continue
                lastWrite = elapsed().also { require(it >= current) }
                append(records)
                lastEventClock = last
                inFlight = 0
            }
        } catch (_: Exception) {
            // Logging failure is isolated from VPN control. No implicit retry
            // loop, second writer or source/SDK operation is admitted.
            synchronized(lock) { failed = true; lose(inFlight + queue.size); queue.clear() }
        } finally {
            var again = false
            synchronized(lock) {
                running = false
                if (!failed && queue.isNotEmpty()) { running = true; again = true }
            }
            if (again) dispatch() // The owned single-thread executor waits for actual exit.
        }
    }
}

internal object LocalDiagnosticJournal {
    private const val DIRECTORY = "structured-events-v1"
    private const val ALIAS = "syn443-structured-events-v1"
    private val publication = JournalPublicationFence()
    @Volatile private var writer: JournalWriter? = null

    fun lifecycle(context: Context, base: File, phase: String, code: String, epoch: Long, generation: Long,
        wallMs: Long, elapsedMs: Long, decision: DecisionStamp? = null) {
        if (Application.getProcessName() != context.packageName + ":controller") return
        val knownPhase = EventPhase.fromWire(phase) ?: return
        val knownCode = EventCode.fromWire(code)
        val safeDecision = decision?.takeIf { knownCode == EventCode.MANAGED_ROUTE_RECHECK }
        val level = if (knownCode == EventCode.AUTH_ACCESS_DENIED || knownPhase in setOf(EventPhase.DEGRADED, EventPhase.RECOVERING, EventPhase.NEEDS_ACTION, EventPhase.BLOCKED_BY_POLICY))
            EventLevel.WARN else EventLevel.INFO
        val pending = PendingJournalEvent(wallMs, elapsedMs, EventGenerations(generation, epoch),
            EventDetail.Lifecycle(knownPhase, knownCode, safeDecision), level)
        owner(context.applicationContext, base).offer(pending)
    }
    fun engine(context: Context, base: File, signal: EngineSignal, epoch: Long, generation: Long, wallMs: Long, elapsedMs: Long) {
        if (Application.getProcessName() != context.packageName + ":controller") return
        val level = if (signal == EngineSignal.FAILED || signal == EngineSignal.INVALID) EventLevel.ERROR else EventLevel.INFO
        owner(context.applicationContext, base).offer(PendingJournalEvent(wallMs, elapsedMs, EventGenerations(generation, epoch),
            EventDetail.Engine(signal), level))
    }
    private fun owner(context: Context, base: File): JournalWriter = writer ?: synchronized(this) {
        writer ?: run {
            // Construction performs no IO, entropy read, Keystore operation or
            // boot-count query. Those closures run only in the actual worker.
            val store = JournalCipherStore(File(base, DIRECTORY), { create -> key(create) }, { clock(context) }, publication)
            JournalWriter(Executors.newSingleThreadExecutor { task -> Thread(task, "structured-log-writer").apply { isDaemon = true } },
                { clock(context) }, {
                    val bytes = ByteArray(16).also { SecureRandom().nextBytes(it) }
                    try { EventCorrelation.fromBytes(bytes) } finally { bytes.fill(0) }
                }, store::append).also { writer = it }
        }
    }

    /** Called only by the explicit archive worker. Never enters owner(),
     * creates an alias/directory, prunes files or changes telemetry consent. */
    fun passive(context: Context): DiagnosticArchive.Component? {
        if (!LifecycleAccess.unlocked(context)) return missing()
        return try {
            val store = JournalCipherStore(File(context.noBackupFilesDir, DIRECTORY), { create ->
                check(!create); key(false)
            }, { clock(context) }, publication)
            projection(store.snapshot(), writer?.status())
        } catch (_: Exception) {
            unavailable()
        }
    }
    internal fun projection(result: JournalCipherStore.Snapshot, status: JournalWriter.Status?): DiagnosticArchive.Component? {
        val reportedLoss = status != null && (status.failed || status.dropped > 0)
        return result.bytes?.let { bytes ->
            DiagnosticArchive.Component(DiagnosticArchive.Name.EVENTS, bytes,
                if (result.partial || reportedLoss) DiagnosticArchive.State.TRUNCATED else DiagnosticArchive.State.AVAILABLE,
                DiagnosticArchive.Reason.PROJECTION_ONLY)
        } ?: when {
            status?.failed == true -> unavailable()
            result.partial || reportedLoss -> missing()
            else -> null
        }
    }
    private fun unavailable() = DiagnosticArchive.Component(DiagnosticArchive.Name.EVENTS, null,
        DiagnosticArchive.State.ERROR, DiagnosticArchive.Reason.IO_ERROR)
    private fun missing() = DiagnosticArchive.Component(DiagnosticArchive.Name.EVENTS, null,
        DiagnosticArchive.State.MISSING, DiagnosticArchive.Reason.UNAVAILABLE)
    private fun clock(context: Context) = EventClock(Settings.Global.getInt(context.contentResolver, Settings.Global.BOOT_COUNT),
        System.currentTimeMillis(), SystemClock.elapsedRealtime())
    private fun key(create: Boolean): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        check(create) { "journal_key_unavailable" }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
            init(KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).setKeySize(256).build())
        }.generateKey()
    }
}
