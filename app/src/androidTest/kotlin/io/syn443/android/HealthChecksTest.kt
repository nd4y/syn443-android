package io.syn443.android

import io.syn443.health.*
import io.syn443.policy.Check
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
}
