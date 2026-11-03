package io.syn443.health

import io.syn443.policy.Check
import java.net.Socket
import java.util.concurrent.*
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

enum class Outcome { PASS, FAIL, UNAVAILABLE, CANCELLED, DEADLINE }
enum class Failure { DNS, TLS, EOF, TIMEOUT, TRANSPORT }
/** Fixed vocabulary only: never contains an endpoint, exception message or response bytes. */
enum class Stage { QUEUED, RESOLVE, CONNECT, TLS, REQUEST, RESPONSE }
/** Positional diagnostic only. No check identifier, target, exception or response is retained. */
data class CheckObservation(val outcome: Outcome, val failure: Failure? = null, val stage: Stage? = null)
data class Batch(val outcomes: List<Outcome>, val observations: List<CheckObservation> = emptyList()) {
    init { require(observations.isEmpty() || observations.map { it.outcome } == outcomes) }
    val complete: Boolean get() = outcomes.all { it == Outcome.PASS || it == Outcome.FAIL }
    val incompleteOutcome: Outcome? get() = outcomes.firstOrNull { it != Outcome.PASS && it != Outcome.FAIL }
    fun values(): List<Boolean> { check(complete); return outcomes.map { it == Outcome.PASS } }
}

/** Owns only the raw socket, so TLS close-notify cannot delay cancellation. */
class ProbeScope {
    private val cancelled = AtomicBoolean()
    private val socket = AtomicReference<Socket?>()
    @Volatile var stage: Stage = Stage.QUEUED
        private set
    @Synchronized fun enter(value: Stage) { requireActive(); stage = value }
    fun attach(value: Socket) {
        check(socket.compareAndSet(null, value))
        if (cancelled.get()) socket.getAndSet(null)?.let { runCatching { it.close() } }
    }
    /** Retire one failed connection before attaching its bounded alternative. */
    fun release(value: Socket) {
        if(socket.compareAndSet(value,null))runCatching {value.close()}
    }
    fun cancel() {
        synchronized(this) { cancelled.set(true) }
        socket.getAndSet(null)?.let { runCatching { it.close() } }
    }
    fun requireActive() { check(!cancelled.get()) }
}

fun interface Probe { fun run(check: Check, scope: ProbeScope): Boolean }

/** One process-wide pool: two workers and one waiting slot, including uninterruptible platform DNS. */
class ProbePool : AutoCloseable {
    internal val executor = ThreadPoolExecutor(2, 2, 30, TimeUnit.SECONDS, ArrayBlockingQueue(1),
        ThreadFactory { task -> Thread(task, "syn443-policy-probe").apply { isDaemon = true } },
        ThreadPoolExecutor.AbortPolicy()).apply { allowCoreThreadTimeOut(true) }
    /** Read-only capacity counters; never opens another worker or clears queued work. */
    fun counters(): Map<String, Long> = mapOf("workers" to executor.poolSize.toLong(), "active" to executor.activeCount.toLong(),
        "queued" to executor.queue.size.toLong(), "completed" to executor.completedTaskCount, "shutdown" to if(executor.isShutdown) 1L else 0L)
    override fun close() { executor.shutdownNow() }
}

/** Single-use batch, including scheduling, DNS, connect, TLS, headers and slow banner reads. */
class CheckJob(private val pool: ProbePool, private val probe: Probe,
    private val clockMillis: () -> Long = { System.nanoTime() / 1_000_000 },
    private val checkMillis: Long = 3_000, private val batchMillis: Long = 30_000) {
    private val used = AtomicBoolean()
    private val cancelled = AtomicBoolean()
    private val active = AtomicReference<ProbeScope?>()
    private val pending = AtomicReference<Future<Boolean>?>()
    @Volatile var failure: Failure? = null
        private set
    @Volatile var failureStage: Stage? = null
        private set
    init { require(checkMillis in 1..3_000 && batchMillis in 1..30_000) }
    fun cancel() {
        cancelled.set(true)
        active.get()?.cancel()
        pending.get()?.cancel(true)
    }
    fun run(checks: List<Check>): Batch {
        check(used.compareAndSet(false, true)); require(checks.size in 1..8)
        val deadline = clockMillis() + batchMillis
        val observations = checks.map { check ->
            when {
                cancelled.get() -> CheckObservation(Outcome.CANCELLED)
                clockMillis() >= deadline -> CheckObservation(Outcome.DEADLINE)
                else -> execute(check, minOf(checkMillis, deadline - clockMillis()), deadline)
            }
        }
        return Batch(observations.map { it.outcome }, observations)
    }
    private fun execute(check: Check, waitMillis: Long, deadline: Long): CheckObservation {
        if (waitMillis <= 0) return CheckObservation(Outcome.DEADLINE)
        val checkDeadline = clockMillis() + waitMillis
        val started = AtomicBoolean()
        val scope = ProbeScope(); active.set(scope)
        if (cancelled.get()) { scope.cancel(); active.compareAndSet(scope, null); return CheckObservation(Outcome.CANCELLED) }
        var checkFailure: Failure? = null
        fun failed(value: Failure) { checkFailure = value; failure = value; failureStage = scope.stage }
        var future: Future<Boolean>? = null
        val outcome = try {
            future = pool.executor.submit<Boolean> { scope.requireActive(); started.set(true); probe.run(check, scope) }
            pending.set(future)
            if (cancelled.get()) { scope.cancel(); future.cancel(true) }
            val value = future.get(waitMillis, TimeUnit.MILLISECONDS)
            when {
                cancelled.get() -> Outcome.CANCELLED
                clockMillis() >= deadline -> Outcome.DEADLINE
                clockMillis() >= checkDeadline -> { failed(Failure.TIMEOUT); Outcome.FAIL }
                value -> Outcome.PASS
                else -> Outcome.FAIL
            }
        } catch (_: RejectedExecutionException) { Outcome.UNAVAILABLE
        } catch (_: CancellationException) { Outcome.CANCELLED
        } catch (_: InterruptedException) { Thread.currentThread().interrupt(); cancel(); Outcome.CANCELLED
        } catch (_: TimeoutException) {
            // Freeze progress before attribution: a cancelled resolver may return later.
            scope.cancel()
            if (started.get() && !cancelled.get()) failed(Failure.TIMEOUT)
            if (cancelled.get()) Outcome.CANCELLED else if (clockMillis() >= deadline) Outcome.DEADLINE
            else if (!started.get()) Outcome.UNAVAILABLE else Outcome.FAIL
        } catch (error: ExecutionException) {
            failed(when (error.cause) {
                is java.net.UnknownHostException -> Failure.DNS
                is javax.net.ssl.SSLException -> Failure.TLS
                is java.io.EOFException -> Failure.EOF
                is java.net.SocketTimeoutException -> Failure.TIMEOUT
                else -> Failure.TRANSPORT
            })
            if (cancelled.get()) Outcome.CANCELLED else Outcome.FAIL
        } finally {
            scope.cancel(); future?.cancel(true)
            (future as? Runnable)?.let { pool.executor.remove(it) }
            active.compareAndSet(scope, null); pending.compareAndSet(future, null)
        }
        return CheckObservation(outcome, checkFailure, if (started.get()) scope.stage else null)
    }
}
