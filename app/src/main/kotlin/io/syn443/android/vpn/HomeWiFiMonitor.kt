package io.syn443.android.vpn

import android.net.Network
import android.os.SystemClock
import io.syn443.recovery.RouteScope
import io.syn443.policy.HomeWiFiProof
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.TimeUnit

internal data class HomeProofScope(val path: RouteScope, val networkHandle: Long, val revision: Long,
    val authority: String, val boot: Int) {
    override fun toString() = "HomeProofScope([redacted])"
}

/** Owned by the service main thread. A replaced worker keeps its slot until it exits. */
internal class HomeWiFiMonitor(private val elapsed: () -> Long) {
    private var scope: HomeProofScope? = null
    private var worker: Attempt? = null
    private var nextAt = 0L
    private var validUntil = 0L
    private var failures = 0
    internal class Attempt(val scope: HomeProofScope, val started: Long) {
        var cancel: (() -> Unit)? = null
        var retired = false
    }

    fun observe(current: HomeProofScope?) {
        if (current == scope) return
        scope = current
        validUntil = 0
        nextAt = 0
        failures = 0
        worker?.let { pending ->
            pending.retired = true
            pending.cancel?.invoke()
            pending.cancel = null
        }
    }

    fun begin(current: HomeProofScope): Attempt? {
        val now = elapsed()
        if (current != scope || worker != null || now < nextAt) return null
        return Attempt(current, now).also { worker = it }
    }

    fun finish(attempt: Attempt, verified: Boolean, observedAt: Long) {
        if (worker !== attempt) return
        worker = null
        if (attempt.scope != scope || attempt.retired) return
        val now = elapsed()
        if (verified && observedAt in attempt.started..(attempt.started+8_000L) && now >= observedAt && now-observedAt < VALID_MS) {
            failures = 0
            validUntil = observedAt + VALID_MS
            nextAt = observedAt + REFRESH_MS
        } else {
            validUntil = 0
            nextAt = now + (30_000L shl failures.coerceAtMost(4)).coerceAtMost(300_000L)
            failures = (failures + 1).coerceAtMost(4)
        }
    }

    fun deadline(current: HomeProofScope?): Long =
        if (current != null && current == scope && elapsed() < validUntil) validUntil else 0L

    companion object {
        const val VALID_MS = 180_000L
        private const val REFRESH_MS = 120_000L
    }
}

internal class HomeWiFiWorker(private val post: (() -> Unit) -> Unit) : AutoCloseable {
    // One bounded handshake and one independent absolute timeout, even during
    // a slow TLS exchange. Threads are created only for a configured probe.
    private val pool = ScheduledThreadPoolExecutor(2).apply {
        removeOnCancelPolicy = true
        setKeepAliveTime(30,TimeUnit.SECONDS)
        allowCoreThreadTimeOut(true)
    }

    fun check(attempt: HomeWiFiMonitor.Attempt, proof: HomeWiFiProof, network: Network, complete: (Boolean, Long) -> Unit) {
        var timeout: ScheduledFuture<*>? = null
        try {
            val handshake = HomeWiFiHandshake(proof, network)
            attempt.cancel = { runCatching { handshake.close() } }
            val limit = pool.schedule({ runCatching { handshake.close() } }, 8, TimeUnit.SECONDS)
            timeout = limit
            pool.execute {
                val ok = try { handshake.verify() } finally { limit.cancel(false) }
                val observedAt = SystemClock.elapsedRealtime()
                post { complete(ok, observedAt) }
            }
        } catch (_: Exception) {
            timeout?.cancel(false)
            attempt.cancel?.invoke()
            val observedAt = SystemClock.elapsedRealtime()
            post { complete(false, observedAt) }
        }
    }

    override fun close() { pool.shutdownNow() }
}
