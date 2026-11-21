package io.syn443.android.support

import android.os.Looper
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/** Keep one external provider call active during an explicit shell export. No archive authority lives here. */
internal class BundleShellConnection(private val maxMillis: Long = 135_000) {
    private class Client(val id: String, val closed: CountDownLatch = CountDownLatch(1))
    private val active = AtomicReference<Client?>()

    fun command(method: String, id: String): String {
        require(id.matches(Regex("[0-9a-f]{32}")))
        if (method == "bundle-shell-hold") {
            check(Looper.myLooper() != Looper.getMainLooper())
            val client = Client(id)
            if (!active.compareAndSet(null, client)) return "busy"
            try {
                return if (client.closed.await(maxMillis, TimeUnit.MILLISECONDS)) "released" else "expired"
            } finally {
                active.compareAndSet(client, null)
            }
        }
        val client = active.get()
        return when (method) {
            "bundle-shell-state" -> when {
                client == null -> "absent"
                client.id != id -> "busy"
                client.closed.count == 0L -> "released"
                else -> "held"
            }
            "bundle-shell-release" -> {
                if (client?.id != id) return "absent"
                client.closed.countDown()
                "released"
            }
            else -> error("invalid_method")
        }
    }
}
