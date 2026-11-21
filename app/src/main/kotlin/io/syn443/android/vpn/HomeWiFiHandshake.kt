package io.syn443.android.vpn

import android.net.Network
import io.syn443.policy.HomeWiFiProof
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.util.Base64
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/** One TCP socket bound before connect. Closing it cancels both TCP and TLS. */
internal class HomeWiFiHandshake(
    private val proof: HomeWiFiProof,
    private val bind: (Socket) -> Unit,
    private val socketFactory: SSLSocketFactory? = null,
    private val socket: Socket = Socket(Proxy.NO_PROXY),
) : AutoCloseable {
    constructor(proof: HomeWiFiProof, network: Network) : this(proof, network::bindSocket)

    override fun close() = socket.close()

    fun verify(): Boolean = runCatching {
        socket.use {
            bind(it)
            it.soTimeout = 3500
            it.connect(InetSocketAddress(proof.socketAddress(), proof.port), 3500)
            val factory = socketFactory ?: SSLSocketFactory.getDefault() as SSLSocketFactory
            (factory.createSocket(it, proof.hostname, proof.port, true) as SSLSocket).use { tls ->
                tls.soTimeout = 3500
                tls.sslParameters = tls.sslParameters.apply {
                    endpointIdentificationAlgorithm = "HTTPS"
                    serverNames = listOf(SNIHostName(proof.hostname))
                }
                tls.startHandshake()
                val cert = tls.session.peerCertificates.first() as X509Certificate
                val digest = MessageDigest.getInstance("SHA-256").digest(cert.publicKey.encoded)
                MessageDigest.isEqual(digest, Base64.getUrlDecoder().decode(proof.spkiSha256))
            }
        }
    }.getOrDefault(false)

    override fun toString() = "HomeWiFiHandshake([redacted])"
}
