package io.syn443.android

import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.net.ConnectivityManager
import android.net.DnsResolver
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Bundle
import android.os.CancellationSignal
import androidx.test.platform.app.InstrumentationRegistry
import bridge.Bridge
import bridge.Protector
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import mockwebserver3.SocketHandler
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import okio.buffer
import java.io.DataInputStream
import java.io.File
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.UUID
import java.util.concurrent.CompletableFuture
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class PackagedProxyChainTest {
    private val loopback = InetAddress.getByName("127.0.0.1")
    private val banner = "SSH-2.0-SYN443-Fixture\r\n".toByteArray(Charsets.US_ASCII)
    private val uuid = UUID.randomUUID()

    private fun listener() = ServerSocket(0, 2, loopback).apply { soTimeout = 8000 }
    private fun withEndpoints(test: (ServerSocket, ServerSocket, ServerSocket) -> Unit) {
        listener().use { entry ->
            listener().use { exit ->
                listener().use { target -> test(entry, exit, target) }
            }
        }
    }

    private fun localSocket(port: Int) = Socket().apply {
        connect(InetSocketAddress(loopback, port), 2000)
        soTimeout = 6000
    }

    private fun bytes(socket: Socket, size: Int) = ByteArray(size).also {
        DataInputStream(socket.getInputStream()).readFully(it)
    }

    private fun expectConnect(socket: Socket, port: Int) {
        val headers = StringBuilder()
        repeat(2048) {
            val next = socket.getInputStream().read()
            check(next >= 0) { "unexpected end of CONNECT headers" }
            headers.append(next.toChar())
            if (headers.endsWith("\r\n\r\n")) {
                assertEquals("CONNECT 127.0.0.1:$port HTTP/1.1", headers.toString().substringBefore("\r\n"))
                return
            }
        }
        error("oversized CONNECT headers")
    }

    private fun expectVless(socket: Socket, port: Int) {
        expectVless(DataInputStream(socket.getInputStream()), port)
    }

    private fun expectVless(data: DataInputStream, port: Int) {
        assertEquals(0, data.readUnsignedByte())
        assertEquals(uuid, UUID(data.readLong(), data.readLong()))
        assertEquals(0, data.readUnsignedByte()) // No flow extensions.
        assertEquals(1, data.readUnsignedByte()) // TCP.
        assertEquals(port, data.readUnsignedShort())
        assertEquals(1, data.readUnsignedByte()) // IPv4.
        assertArrayEquals(loopback.address, ByteArray(4).also(data::readFully))
    }

    private fun result(entry: Int, exit: Int, target: Int): JSONObject {
        // No inbounds or Android VPN permission. The production JNI library owns
        // the proxy dial and diagnostic, with only fixed loopback destinations.
        val config = """{"log":{"disabled":true},"inbounds":[],"outbounds":[
            {"type":"http","tag":"entry","server":"127.0.0.1","server_port":$entry},
            {"type":"vless","tag":"exit","server":"127.0.0.1","server_port":$exit,"uuid":"$uuid","detour":"entry"}
            ],"route":{"final":"exit"}}"""
        val request = """{"request":"packaged-proxy","routes":[{"id":"server","outbound":"exit",
            "checks":[{"method":"ssh_banner","target":"127.0.0.1:$target"}]}]}"""
        return completedCheck(config, request, listOf("route-2", "route-1"))
    }

    private fun completedCheck(config: String, request: String, expectedPath: List<String>, wifi: Network? = null): JSONObject {
        val protector = object : Protector {
            override fun protect(socket: Int) {
                check(socket >= 0)
                wifi?.let { network -> ParcelFileDescriptor.fromFd(socket).use { network.bindSocket(it.fileDescriptor) } }
            }
            override fun exchangeDNS(query: ByteArray): ByteArray {
                val network = checkNotNull(wifi) { "unexpected DNS" }
                val answer = CompletableFuture<ByteArray>()
                val cancel = CancellationSignal()
                try {
                    DnsResolver.getInstance().rawQuery(network, query, DnsResolver.FLAG_NO_RETRY,
                        java.util.concurrent.Executor { it.run() }, cancel, object : DnsResolver.Callback<ByteArray> {
                            override fun onAnswer(response: ByteArray, rcode: Int) { answer.complete(response) }
                            override fun onError(error: DnsResolver.DnsException) { answer.completeExceptionally(error) }
                        })
                    return answer.get(3, TimeUnit.SECONDS)
                } finally {
                    cancel.cancel()
                }
            }
            override fun physicalInterfaces(): String = "[]"
        }
        ParcelFileDescriptor.open(File("/dev/null"), ParcelFileDescriptor.MODE_READ_WRITE).use { fd ->
            val core = Bridge.newRuntime(config, "", fd.fd, protector, "lo", 1, 0L)
            try {
                core.start()
                assertTrue(core.startRouteChecks(request))
                val deadline = SystemClock.elapsedRealtime() + 10000
                while (SystemClock.elapsedRealtime() < deadline) {
                    val report = JSONObject(core.routeCheckStatus())
                    if (report.optString("request") == "packaged-proxy" && !report.getBoolean("running")) {
                        val rows = report.getJSONArray("results")
                        assertEquals(1, rows.length())
                        val row = rows.getJSONObject(0)
                        assertEquals("server", row.getString("id"))
                        assertTrue(row.getBoolean("complete"))
                        assertEquals(expectedPath, row.getJSONArray("path").let { paths ->
                            (0 until paths.length()).map { paths.getString(it) }
                        })
                        return row
                    }
                    SystemClock.sleep(20)
                }
                error("packaged route check did not complete")
            } finally {
                core.close()
            }
        }
    }

    @Test fun packagedHttpEntryCarriesVlessToBannerTarget() {
        withEndpoints { entry, exit, target ->
            val workers = Executors.newFixedThreadPool(3)
            try {
                val peer = workers.submit { target.accept().use { it.getOutputStream().write(banner) } }
                val vless = workers.submit {
                    exit.accept().use { client ->
                        client.soTimeout = 6000
                        expectVless(client, target.localPort)
                        localSocket(target.localPort).use { allowed ->
                            client.getOutputStream().write(byteArrayOf(0, 0) + bytes(allowed, banner.size))
                        }
                    }
                }
                val http = workers.submit {
                    entry.accept().use { client ->
                        client.soTimeout = 6000
                        expectConnect(client, exit.localPort)
                        localSocket(exit.localPort).use { allowed ->
                            client.getOutputStream().write("HTTP/1.1 200 OK\r\n\r\n".toByteArray(Charsets.US_ASCII))
                            // Fixed VLESS request size for this synthetic IPv4 fixture.
                            allowed.getOutputStream().write(bytes(client, 26))
                            client.getOutputStream().write(bytes(allowed, banner.size + 2))
                        }
                    }
                }
                val status = result(entry.localPort, exit.localPort, target.localPort)
                for (stage in listOf(http, vless, peer)) stage.get(8, TimeUnit.SECONDS)
                assertEquals("ok", status.getString("code"))
                assertTrue(status.getBoolean("ok"))
            } finally {
                workers.shutdownNow()
            }
        }
    }

    @Test fun packagedXhttpStreamOneCarriesVlessOverTlsHttp2AndRejectsWrongName() {
        val serverName = "wire.example.invalid"
        val identity = HeldCertificate.Builder().addSubjectAlternativeName(serverName).build()
        val tls = HandshakeCertificates.Builder().heldCertificate(identity).build()
        listener().use { target ->
            val executor = Executors.newSingleThreadExecutor()
            try {
                val peer = executor.submit {
                    target.accept().use { it.getOutputStream().write(banner) }
                }
                MockWebServer().use { server ->
                    server.useHttps(tls.sslSocketFactory())
                    val served = CompletableFuture<Unit>()
                    server.enqueue(MockResponse.Builder().removeHeader("Content-Length").socketHandler(object : SocketHandler {
                        override fun handle(socket: okio.Socket) {
                            try {
                                socket.source.timeout().timeout(5, TimeUnit.SECONDS)
                                val request = socket.source.buffer().inputStream()
                                expectVless(DataInputStream(request), target.localPort)
                                localSocket(target.localPort).use { endpoint ->
                                    socket.sink.buffer().use { it.write(byteArrayOf(0, 0)).write(bytes(endpoint, banner.size)) }
                                }
                                served.complete(Unit)
                            } catch (failure: Throwable) {
                                served.completeExceptionally(failure)
                                socket.cancel()
                            }
                        }
                    }).build())
                    server.start(loopback, 0)
                    fun probe(name: String): JSONObject {
                        val certificate = JSONObject.quote(identity.certificatePem())
                        val config = """{"log":{"disabled":true},"inbounds":[],"outbounds":[
                            {"type":"vless","tag":"exit","server":"127.0.0.1","server_port":${server.port},"uuid":"$uuid",
                             "tls":{"enabled":true,"server_name":"$name","certificate":[$certificate],"alpn":["h2"]},
                             "transport":{"type":"xhttp","mode":"stream-one","path":"/fixture"}}],"route":{"final":"exit"}}"""
                        val request = """{"request":"packaged-proxy","routes":[{"id":"server","outbound":"exit",
                            "checks":[{"method":"ssh_banner","target":"127.0.0.1:${target.localPort}"}]}]}"""
                        return completedCheck(config, request, listOf("route-1"))
                    }
                    val success = probe(serverName)
                    assertTrue(success.getBoolean("ok"))
                    assertEquals("ok", success.getString("code"))
                    served.get(5, TimeUnit.SECONDS)
                    peer.get(5, TimeUnit.SECONDS)
                    val request = checkNotNull(server.takeRequest(2, TimeUnit.SECONDS))
                    assertEquals("HTTP/2", request.version)
                    assertEquals("POST", request.method)
                    assertEquals("/fixture", request.url.encodedPath.trimEnd('/'))
                    assertNotNull(request.handshake)
                    server.enqueue(MockResponse(code = 403))
                    assertFalse(probe("wrong.example.invalid").getBoolean("ok"))
                    assertEquals(1, server.requestCount)
                    target.soTimeout = 300
                    assertThrows(SocketTimeoutException::class.java) { target.accept().close() }
                }
            } finally {
                executor.shutdownNow()
            }
        }
    }

    @Test fun refusedTcpConnectionReportsItsCauseWithoutEndpointDetails() {
        Socket().use { refused ->
            refused.bind(InetSocketAddress(loopback, 0))
            val config = """{"log":{"disabled":true},"inbounds":[],"outbounds":[{"type":"direct","tag":"local"}],"route":{"final":"local"}}"""
            val request = """{"request":"packaged-proxy","routes":[{"id":"server","outbound":"local","checks":[{"method":"tcp","target":"127.0.0.1:${refused.localPort}"}]}]}"""
            val status = completedCheck(config, request, listOf("route-1"))
            assertFalse(status.getBoolean("ok"))
            assertEquals("dial_failed", status.getString("code"))
            assertEquals("connection_refused", status.getString("cause"))
            assertFalse(status.toString().contains("127.0.0.1"))
        }
    }

    @Test fun packagedHTTPSStatusChecksExactResponseAndRequiresTLS() {
        val config = """{"log":{"disabled":true},"inbounds":[],"outbounds":[{"type":"direct","tag":"local"}],
            "dns":{"servers":[{"type":"local","tag":"physical"}],"final":"physical","strategy":"prefer_ipv4"},
            "route":{"final":"local","default_domain_resolver":"physical"}}"""
        fun check(target: String, verb: String, status: Int, network: Network? = null): JSONObject {
            val quoted = JSONObject.quote(target)
            val request = """{"request":"packaged-proxy","routes":[{"id":"server","outbound":"local",
                "checks":[{"method":"https_status","target":$quoted,"http_method":"$verb","expected_status":$status}]}]}"""
            return completedCheck(config, request, listOf("route-1"), network)
        }
        listener().use { plain ->
            val worker = Executors.newSingleThreadExecutor()
            try {
                val serve = worker.submit { plain.accept().use { it.getOutputStream().write("HTTP/1.1 200 OK\r\n\r\n".toByteArray()) } }
                val result = check("https://127.0.0.1:${plain.localPort}/", "GET", 200)
                serve.get(8, TimeUnit.SECONDS)
                assertFalse(result.getBoolean("ok"))
                assertEquals("tls_failed", result.getString("code"))
            } finally {
                worker.shutdownNow()
            }
        }

        // An explicitly supplied endpoint exercises real Wi-Fi in device acceptance.
        val args = InstrumentationRegistry.getArguments()
        val target = args.getString("httpsStatusTarget") ?: return
        val uri = java.net.URI(target)
        require(uri.scheme == "https" && uri.host != null && uri.userInfo == null && uri.fragment == null)
        val status = checkNotNull(args.getString("httpsStatusExpected")?.toIntOrNull())
        require(status in 200..599)
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val cm = instrumentation.targetContext.getSystemService(ConnectivityManager::class.java)
        val wifi = checkNotNull(cm.activeNetwork)
        val caps = checkNotNull(cm.getNetworkCapabilities(wifi))
        assertTrue(caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI))
        assertTrue(caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN))
        for (verb in listOf("GET", "HEAD")) {
            val result = check(target, verb, status, wifi)
            assertEquals("ok", result.getString("code"))
            assertTrue(result.getBoolean("ok"))
        }
        val wrong = check(target, "GET", if (status == 599) 598 else 599, wifi)
        assertEquals("http_response_mismatch", wrong.getString("code"))
        assertFalse(wrong.getBoolean("ok"))
        assertEquals(wifi, cm.activeNetwork)
        instrumentation.sendStatus(0, Bundle().apply { putString("httpsStatusWiFi", "GET_HEAD_MATCH_AND_MISMATCH") })
    }

    @Test fun refusedHttpEntryNeverFallsBackToVlessOrTarget() {
        withEndpoints { entry, exit, target ->
            val worker = Executors.newSingleThreadExecutor()
            try {
                val denial = worker.submit {
                    entry.accept().use { client ->
                        client.soTimeout = 6000
                        expectConnect(client, exit.localPort)
                        client.getOutputStream().write("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n".toByteArray(Charsets.US_ASCII))
                    }
                }
                val status = result(entry.localPort, exit.localPort, target.localPort)
                denial.get(8, TimeUnit.SECONDS)
                assertFalse(status.getBoolean("ok"))
                assertNotEquals("ok", status.getString("code"))
                for (unused in listOf(exit, target)) {
                    unused.soTimeout = 200
                    try {
                        unused.accept().use { fail("refused chain made a direct connection") }
                    } catch (_: SocketTimeoutException) {
                        // No connection was queued at this endpoint.
                    }
                }
            } finally {
                worker.shutdownNow()
            }
        }
    }
}
