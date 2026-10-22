package io.syn443.android.vpn

import io.syn443.policy.Check
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicBoolean

/** One bounded job; Stop/network/config cancellation closes its own sockets. */
class PolicyChecks(private val synthetic: Boolean = false) {
    private val cancelled = AtomicBoolean()
    private val close = CopyOnWriteArrayList<() -> Unit>()
    fun cancel() { cancelled.set(true); close.forEach { runCatching(it) }; close.clear() }
    fun run(checks: List<Check>): List<Boolean> {
        val deadline = android.os.SystemClock.elapsedRealtime() + 30_000
        return checks.map { c ->
            if (cancelled.get() || android.os.SystemClock.elapsedRealtime() >= deadline) false else runCatching {
                when (c.type) {
                    "https_204" -> {
                        val target = if (synthetic && c.target == "https://health.example.org/generate_204") "http://203.0.113.10/generate_204" else c.target
                        val connection = URL(target).openConnection() as HttpURLConnection
                        val stop = { connection.disconnect() }; close.add(stop)
                        try {
                            connection.connectTimeout = 3_000; connection.readTimeout = 3_000; connection.instanceFollowRedirects = false
                            !cancelled.get() && connection.responseCode == 204
                        } finally { connection.disconnect(); close.remove(stop) }
                    }
                    "tcp_banner" -> {
                        val socket = Socket(); val stop = { socket.close() }; close.add(stop)
                        try {
                            if (cancelled.get()) false else {
                                socket.soTimeout = 3_000; socket.connect(InetSocketAddress(c.target, c.port), 3_000)
                                val expected = c.expected.toByteArray(Charsets.US_ASCII)
                                val received = ByteArray(expected.size)
                                var size = 0
                                while (!cancelled.get() && size < received.size) {
                                    val n = socket.getInputStream().read(received, size, received.size - size)
                                    if (n < 0) break; size += n
                                }
                                !cancelled.get() && size == expected.size && received.contentEquals(expected)
                            }
                        } finally { socket.close(); close.remove(stop) }
                    }
                    else -> false
                }
            }.getOrDefault(false)
        }
    }
}
