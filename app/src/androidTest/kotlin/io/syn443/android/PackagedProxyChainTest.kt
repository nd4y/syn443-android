package io.syn443.android

import android.os.ParcelFileDescriptor
import android.os.SystemClock
import bridge.Bridge
import bridge.Protector
import java.io.DataInputStream
import java.io.File
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.UUID
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
        val data = DataInputStream(socket.getInputStream())
        assertEquals(0, data.readUnsignedByte())
        assertEquals(uuid, UUID(data.readLong(), data.readLong()))
        assertEquals(0, data.readUnsignedByte()) // No flow extensions.
        assertEquals(1, data.readUnsignedByte()) // TCP.
        assertEquals(port, data.readUnsignedShort())
        assertEquals(1, data.readUnsignedByte()) // IPv4.
        assertArrayEquals(loopback.address, bytes(socket, 4))
    }

    private fun result(entry: Int, exit: Int, target: Int): JSONObject {
        // No inbounds or Android VPN permission. The production JNI library owns
        // the proxy dial and diagnostic, with only fixed loopback destinations.
        val config = """{"log":{"disabled":true},"inbounds":[],"outbounds":[
            {"type":"http","tag":"entry","server":"127.0.0.1","server_port":$entry},
            {"type":"vless","tag":"exit","server":"127.0.0.1","server_port":$exit,"uuid":"$uuid","detour":"entry"}
            ],"route":{"final":"exit"}}"""
        val protector = object : Protector {
            override fun protect(socket: Int) { check(socket >= 0) }
            override fun exchangeDNS(query: ByteArray): ByteArray = error("unexpected DNS")
            override fun physicalInterfaces(): String = "[]"
        }
        val request = """{"request":"packaged-proxy","routes":[{"id":"server","outbound":"exit",
            "checks":[{"method":"ssh_banner","target":"127.0.0.1:$target"}]}]}"""
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
                        assertEquals(listOf("route-2", "route-1"), row.getJSONArray("path").let { paths ->
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
