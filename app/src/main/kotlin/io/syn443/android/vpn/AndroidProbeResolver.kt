package io.syn443.android.vpn

import android.net.DnsResolver
import android.net.InetAddresses
import android.os.CancellationSignal
import java.net.InetAddress
import java.net.SocketTimeoutException
import io.syn443.health.DnsResult
import io.syn443.health.ProbeDnsException
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
    private data class Reply(val addresses:List<InetAddress> = emptyList(), val failure:DnsResult? = null)
    init { require(timeoutMillis in 1..2_500) }
    fun resolve(host: String): InetAddress = resolveAll(host).first()
    fun resolveAll(host: String): List<InetAddress> {
        if (InetAddresses.isNumericAddress(host)) return listOf(InetAddresses.parseNumericAddress(host))
        val cancel = CancellationSignal()
        val done = CountDownLatch(1)
        val reply = AtomicReference<Reply>()
        fun finish(result: Reply) {
            if (!cancel.isCanceled && reply.compareAndSet(null, result)) done.countDown()
        }
        try {
            query(host, cancel, object : Answer {
                override fun onAnswer(answer: List<InetAddress>, rcode: Int) {
                    val failure = when (rcode) {
                        0 -> if (answer.isEmpty()) DnsResult.NO_ADDRESSES else null
                        2 -> DnsResult.SERVFAIL
                        3 -> DnsResult.NXDOMAIN
                        5 -> DnsResult.REFUSED
                        else -> DnsResult.OTHER_RCODE
                    }
                    finish(if (failure == null) Reply(answer.take(16).distinct()) else Reply(failure=failure))
                }
                override fun onError() { finish(Reply(failure=DnsResult.RESOLVER_ERROR)) }
            })
            if (!done.await(timeoutMillis, TimeUnit.MILLISECONDS)) throw SocketTimeoutException()
            val completed = checkNotNull(reply.get())
            completed.failure?.let { throw ProbeDnsException(it) }
            return completed.addresses
        } finally { cancel.cancel() }
    }
}
