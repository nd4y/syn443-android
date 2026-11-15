package io.syn443.health

import io.syn443.policy.Check
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URI
import java.net.InetAddress
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/** No redirects, credentials, response body or unbounded header storage. Default platform TLS trust. */
class NetworkProbe(private val synthetic: Boolean = false,
    private val tls: SSLSocketFactory? = null,
    private val resolve: (String) -> List<InetAddress> = {InetAddress.getAllByName(it).toList()},
    private val socketFactory: () -> Socket = {Socket()}) : Probe {
    private fun connect(host:String,port:Int,scope:ProbeScope):Socket {
        scope.enter(Stage.RESOLVE)
        val answers=resolve(host).take(16).distinct()
        if(answers.isEmpty())throw UnknownHostException()
        val first=answers.first()
        // Give the other family a chance before spending the bounded budget on
        // several addresses from the unavailable family. No extra worker/thread.
        val addresses=(listOfNotNull(first,answers.firstOrNull {it.address.size!=first.address.size})+answers).distinct().take(4)
        for((index,address) in addresses.withIndex()) {
            scope.requireActive()
            val socket=socketFactory()
            try {scope.attach(socket)} catch(error:Throwable) {runCatching {socket.close()};throw error}
            try {
                socket.soTimeout=3_000;scope.enter(Stage.CONNECT)
                socket.connect(InetSocketAddress(address,port),if(index==addresses.lastIndex)3_000 else 500)
                scope.requireActive();return socket
            } catch(error:Throwable) {
                scope.release(socket)
                if(error !is java.io.IOException || index==addresses.lastIndex)throw error
            }
        }
        throw SocketTimeoutException()
    }
    override fun run(check: Check, scope: ProbeScope): Boolean {
        var socket:Socket?=null
        try {
            scope.requireActive()
            return when (check.type) {
                "tcp_banner" -> {
                    val transport=connect(check.target,check.port,scope);socket=transport
                    scope.requireActive()
                    val expected = check.expected.toByteArray(Charsets.US_ASCII)
                    val received = ByteArray(expected.size)
                    var size = 0
                    scope.enter(Stage.RESPONSE)
                    while (size < received.size) {
                        scope.requireActive()
                        val n = transport.getInputStream().read(received, size, received.size - size)
                        if (n < 0) return false
                        size += n
                    }
                    received.contentEquals(expected)
                }
                "https_204" -> {
                    val fake = synthetic && check.target == "https://health.example.org/generate_204"
                    val uri = URI(if (fake) "http://203.0.113.10/generate_204" else check.target)
                    require(uri.scheme == "https" || fake)
                    val port = if (uri.port > 0) uri.port else if (fake) 80 else 443
                    val connected=connect(uri.host,port,scope);socket=connected
                    scope.requireActive()
                    scope.enter(Stage.TLS)
                    val transport = if (fake) connected else ((tls ?: SSLSocketFactory.getDefault() as SSLSocketFactory)
                        .createSocket(connected, uri.host, port, true) as SSLSocket).apply {
                        soTimeout = 3_000
                        sslParameters = sslParameters.apply { endpointIdentificationAlgorithm = "HTTPS" }
                        startHandshake()
                    }
                    scope.requireActive()
                    val path = (uri.rawPath.takeUnless { it.isNullOrEmpty() } ?: "/") + (uri.rawQuery?.let { "?$it" } ?: "")
                    val host = uri.host + if (uri.port > 0) ":${uri.port}" else ""
                    scope.enter(Stage.REQUEST)
                    transport.getOutputStream().write("GET $path HTTP/1.1\r\nHost: $host\r\nConnection: close\r\n\r\n".toByteArray(Charsets.US_ASCII))
                    scope.enter(Stage.RESPONSE)
                    status204(transport.getInputStream())
                }
                else -> false
            }
        } finally { socket?.let(scope::release) }
    }
}

internal fun status204(input: java.io.InputStream): Boolean {
    var remaining = 16_384
    fun line(): String {
        val result = StringBuilder()
        while (remaining-- > 0) {
            val value = input.read(); if (value < 0) throw java.io.EOFException()
            if (value == 10) { require(result.endsWith("\r")); return result.dropLast(1).toString() }
            require(value == 13 || value in 32..126); result.append(value.toChar())
        }
        throw IllegalArgumentException("header_limit")
    }
    val status = line()
    if (!status.matches(Regex("HTTP/1\\.[01] 204(?: .*)?"))) return false
    while (true) {
        val header = line()
        if (header.isEmpty()) return true
        require(header.indexOf(':') > 0)
    }
}
