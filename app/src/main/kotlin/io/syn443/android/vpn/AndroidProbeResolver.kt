package io.syn443.android.vpn

import android.net.DnsResolver
import android.net.InetAddresses
import android.os.CancellationSignal
import java.net.InetAddress
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/** Uses the current VPN DNS path. Cancellation releases the platform query, not just its caller. */
internal class AndroidProbeResolver(
    private val query: (String, CancellationSignal, Answer) -> Unit = { host, cancel, callback ->
        DnsResolver.getInstance().query(null, host, DnsResolver.FLAG_EMPTY,
            Executor { it.run() }, cancel, object : DnsResolver.Callback<List<InetAddress>> {
                override fun onAnswer(answer: List<InetAddress>, rcode: Int) = callback.onAnswer(answer, rcode)
                override fun onError(error: DnsResolver.DnsException) = callback.onError()
            })
    },
    private val timeoutMillis: Long = 2_500
) {
    interface Answer {
        fun onAnswer(answer: List<InetAddress>, rcode: Int)
        fun onError()
    }
    init { require(timeoutMillis in 1..2_500) }
    fun resolve(host: String): InetAddress {
        if (InetAddresses.isNumericAddress(host)) return InetAddresses.parseNumericAddress(host)
        val cancel = CancellationSignal()
        val done = CountDownLatch(1)
        val address = AtomicReference<InetAddress?>()
        try {
            query(host, cancel, object : Answer {
                override fun onAnswer(answer: List<InetAddress>, rcode: Int) {
                    if (!cancel.isCanceled && rcode == 0) address.set(answer.firstOrNull())
                    done.countDown()
                }
                override fun onError() { done.countDown() }
            })
            if (!done.await(timeoutMillis, TimeUnit.MILLISECONDS)) throw SocketTimeoutException()
            return address.get() ?: throw UnknownHostException()
        } finally { cancel.cancel() }
    }
}
