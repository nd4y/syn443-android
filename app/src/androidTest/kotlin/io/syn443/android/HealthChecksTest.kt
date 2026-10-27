package io.syn443.android

import io.syn443.health.*
import io.syn443.policy.Check
import io.syn443.android.vpn.AndroidProbeResolver
import android.os.CancellationSignal
import org.junit.Assert.*
import org.junit.Test
import java.net.InetAddress
import java.net.ServerSocket
import java.util.concurrent.*

/** Loopback only, safe on a configured physical phone; no VPN/configuration/OS changes. */
class HealthChecksTest {
    @Test fun slowAndroidSocketReadHasAnAbsoluteDeadline() {
        val server = ServerSocket(0, 1, InetAddress.getLoopbackAddress())
        val worker = Executors.newSingleThreadExecutor { r -> Thread(r).apply { isDaemon = true } }
        val serving = worker.submit { runCatching { server.accept().use { socket ->
            for (b in "SSH-2.0-test".toByteArray()) {
                socket.getOutputStream().write(b.toInt()); Thread.sleep(100)
            }
        } } }
        try {
            ProbePool().use { pool ->
                val job = CheckJob(pool, NetworkProbe(), { android.os.SystemClock.elapsedRealtime() }, 250)
                val result = job.run(listOf(Check("ssh", "tcp_banner", server.inetAddress.hostAddress, server.localPort, "SSH-2.0")))
                assertEquals(listOf(Outcome.FAIL), result.outcomes)
            }
        } finally { server.close(); worker.shutdownNow(); serving.get(3, TimeUnit.SECONDS) }
    }
    @Test fun cancelledAndroidBatchCannotBecomeAFalseBaseline() {
        ProbePool().use { pool ->
            val job = CheckJob(pool, Probe { _, _ -> error("cancelled probe must not run") }, { android.os.SystemClock.elapsedRealtime() })
            job.cancel()
            val result = job.run(listOf(Check("internet", "https_204", "https://example.org/")))
            assertFalse(result.complete)
            assertEquals(listOf(Outcome.CANCELLED), result.outcomes)
            assertThrows(IllegalStateException::class.java) { result.values() }
        }
    }

    @Test fun androidDnsLiteralNeverStartsPlatformQuery() {
        val resolver = AndroidProbeResolver(query = { _, _, _ -> error("literal must not query DNS") })
        assertEquals("192.0.2.1", resolver.resolve("192.0.2.1").hostAddress)
        assertEquals(16, resolver.resolve("2001:db8::1").address.size)
    }
    @Test fun androidDnsCallbacksKeepFailuresDistinctAndCancelQuery() {
        val expected = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
        var signal: CancellationSignal? = null
        val success = AndroidProbeResolver(query = { _, cancel, callback ->
            signal = cancel; callback.onAnswer(listOf(expected), 0)
        })
        assertEquals(expected, success.resolve("host.example.org")); assertTrue(checkNotNull(signal).isCanceled)
        for (mode in 0..2) {
            val failure = AndroidProbeResolver(query = { _, cancel, callback ->
                signal = cancel
                when (mode) {
                    0 -> callback.onAnswer(listOf(expected), 3)
                    1 -> callback.onAnswer(emptyList(), 0)
                    else -> callback.onError()
                }
            })
            assertThrows(java.net.UnknownHostException::class.java) { failure.resolve("host.example.org") }
            assertTrue(checkNotNull(signal).isCanceled)
        }
    }
    @Test fun androidDnsDeadlineCancelsQueryAndRejectsLateSuccess() {
        lateinit var callback: AndroidProbeResolver.Answer
        lateinit var signal: CancellationSignal
        val resolver = AndroidProbeResolver(query = { _, cancel, cb -> signal = cancel; callback = cb }, timeoutMillis = 50)
        assertThrows(java.net.SocketTimeoutException::class.java) { resolver.resolve("host.example.org") }
        assertTrue(signal.isCanceled)
        callback.onAnswer(listOf(InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))), 0)
        for (limit in listOf(0L, 2_501L)) assertThrows(IllegalArgumentException::class.java) {
            AndroidProbeResolver(timeoutMillis = limit)
        }
    }
    @Test fun androidDnsCancellationReleasesWorkersForNextPolicyCheck() {
        ProbePool().use { pool ->
            val caller = Executors.newSingleThreadExecutor()
            try {
                repeat(3) {
                    val entered = CountDownLatch(1); val cancelled = CountDownLatch(1)
                    val resolver = AndroidProbeResolver(query = { _, signal, _ ->
                        signal.setOnCancelListener { cancelled.countDown() }; entered.countDown()
                    })
                    val job = CheckJob(pool, Probe { _, scope ->
                        scope.enter(Stage.RESOLVE); resolver.resolve("host.example.org"); true
                    })
                    val result = caller.submit<Batch> { job.run(listOf(Check("internet", "https_204", "https://example.org/"))) }
                    assertTrue(entered.await(2, TimeUnit.SECONDS)); job.cancel()
                    assertEquals(Outcome.CANCELLED, result.get(2, TimeUnit.SECONDS).outcomes.single())
                    assertTrue(cancelled.await(2, TimeUnit.SECONDS))
                }
                val resolver = AndroidProbeResolver(query = { _, _, callback ->
                    callback.onAnswer(listOf(InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))), 0)
                })
                val next = CheckJob(pool, Probe { _, _ -> resolver.resolve("host.example.org"); true })
                assertEquals(Outcome.PASS, next.run(listOf(Check("internet", "https_204", "https://example.org/"))).outcomes.single())
            } finally { caller.shutdownNow() }
        }
    }
}
