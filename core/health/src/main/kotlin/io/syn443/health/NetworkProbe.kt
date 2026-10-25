package io.syn443.health

import io.syn443.policy.Check
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URI
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/** No redirects, credentials, response body or unbounded header storage. Default platform TLS trust. */
class NetworkProbe(private val synthetic: Boolean = false,
    private val tls: SSLSocketFactory? = null) : Probe {
    override fun run(check: Check, scope: ProbeScope): Boolean {
        val socket = Socket(); scope.attach(socket)
        try {
            scope.requireActive(); socket.soTimeout = 3_000
            return when (check.type) {
                "tcp_banner" -> {
                    socket.connect(InetSocketAddress(check.target, check.port), 3_000)
                    scope.requireActive()
                    val expected = check.expected.toByteArray(Charsets.US_ASCII)
                    val received = ByteArray(expected.size)
                    var size = 0
                    while (size < received.size) {
                        scope.requireActive()
                        val n = socket.getInputStream().read(received, size, received.size - size)
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
                    socket.connect(InetSocketAddress(uri.host, port), 3_000)
                    scope.requireActive()
                    val factory = tls ?: SSLSocketFactory.getDefault() as SSLSocketFactory
                    val transport = if (fake) socket else (factory.createSocket(socket, uri.host, port, true) as SSLSocket).apply {
                        soTimeout = 3_000
                        sslParameters = sslParameters.apply { endpointIdentificationAlgorithm = "HTTPS" }
                        startHandshake()
                    }
                    scope.requireActive()
                    val path = (uri.rawPath.takeUnless { it.isNullOrEmpty() } ?: "/") + (uri.rawQuery?.let { "?$it" } ?: "")
                    val host = uri.host + if (uri.port > 0) ":${uri.port}" else ""
                    transport.getOutputStream().write("GET $path HTTP/1.1\r\nHost: $host\r\nConnection: close\r\n\r\n".toByteArray(Charsets.US_ASCII))
                    status204(transport.getInputStream())
                }
                else -> false
            }
        } finally { socket.close() }
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
