package io.syn443.health

import io.syn443.policy.Check
import org.junit.Assert.*
import org.junit.Test
import org.junit.BeforeClass
import org.junit.AfterClass
import java.net.InetAddress
import java.nio.file.Files
import java.security.KeyStore
import java.util.concurrent.*
import javax.net.ssl.*

class TlsTest {
    companion object {
        private val directory = Files.createTempDirectory("syn443-health-tls")
        private val file = directory.resolve("fixture.p12")
        private val password = "synthetic-test-fixture".toCharArray()
        private lateinit var serverContext: SSLContext
        private lateinit var trustedFactory: SSLSocketFactory
        @BeforeClass @JvmStatic fun generateEphemeralFixture() {
            val keytool = java.nio.file.Path.of(System.getProperty("java.home"), "bin", "keytool").toString()
            val process = ProcessBuilder(keytool, "-genkeypair", "-alias", "fixture", "-keyalg", "EC",
                "-groupname", "secp256r1", "-storetype", "PKCS12", "-keystore", file.toString(),
                "-storepass", String(password), "-dname", "CN=localhost", "-ext", "SAN=dns:localhost",
                "-validity", "1", "-noprompt").redirectOutput(ProcessBuilder.Redirect.DISCARD)
                .redirectError(ProcessBuilder.Redirect.DISCARD).start()
            assertTrue(process.waitFor(15, TimeUnit.SECONDS)); assertEquals(0, process.exitValue())
            val store = KeyStore.getInstance("PKCS12").apply { Files.newInputStream(file).use { load(it, password) } }
            val keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(store, password) }
            val trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(store) }
            serverContext = SSLContext.getInstance("TLS").apply { init(keys.keyManagers, null, null) }
            trustedFactory = SSLContext.getInstance("TLS").apply { init(null, trust.trustManagers, null) }.socketFactory
        }
        @AfterClass @JvmStatic fun deleteFixture() { Files.deleteIfExists(file); Files.deleteIfExists(directory) }
    }
    private fun request(host: String = "localhost", trusted: Boolean = true,
        response: String = "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"): Outcome {
        val server = serverContext.serverSocketFactory.createServerSocket(0, 4, InetAddress.getByName("127.0.0.1")) as SSLServerSocket
        val worker = Executors.newSingleThreadExecutor { r -> Thread(r).apply { isDaemon = true } }
        val serving = worker.submit { runCatching {
            server.accept().use { socket ->
                socket.soTimeout = 2_000
                val input = socket.getInputStream().bufferedReader(Charsets.US_ASCII)
                while (!input.readLine().isNullOrEmpty()) { /* bounded by socket timeout */ }
                socket.getOutputStream().write(response.toByteArray(Charsets.US_ASCII))
            }
        } }
        return try {
            ProbePool().use { pool ->
                val probe = if (trusted) NetworkProbe(tls = trustedFactory) else NetworkProbe()
                CheckJob(pool, probe).run(listOf(Check("tls", "https_204", "https://$host:${server.localPort}/?check=1"))).outcomes.single()
            }
        } finally {
            server.close(); serving.get(4, TimeUnit.SECONDS); worker.shutdownNow()
        }
    }
    @Test fun validTlsAndComplete204HeadersPass() { assertEquals(Outcome.PASS, request()) }
    @Test fun certificateTrustIsRequired() { assertEquals(Outcome.FAIL, request(trusted = false)) }
    @Test fun certificateHostnameIsRequired() { assertEquals(Outcome.FAIL, request(host = "127.0.0.1")) }
    @Test fun redirectIsNotFollowed() { assertEquals(Outcome.FAIL, request(response = "HTTP/1.1 302 Found\r\nLocation: https://example.org/\r\n\r\n")) }
    @Test fun incompleteHeadersAreNotSuccess() { assertEquals(Outcome.FAIL, request(response = "HTTP/1.1 204 No Content\r\n")) }
}
