package io.syn443.android

import android.app.ActivityManager
import androidx.core.net.toUri
import android.net.VpnService
import android.os.Build
import android.util.Base64
import androidx.test.core.app.ActivityScenario
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import java.io.FileInputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger

/** Hermetic real TUN -> Go TCP/IP stack -> HTTP CONNECT proxy -> synthetic HTTP response. */
class VpnLifecycleTest {
    @Test fun externalConnectExtraCannotTurnVpnOn() {
        scenario.close()
        scenario = ActivityScenario.launch(android.content.Intent(context, MainActivity::class.java)
            .addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK).putExtra("syn443.connect", true)
            .putExtra("syn443.consentGeneration", status().optLong("generation")))
        Thread.sleep(1500)
        assertFalse(status().getBoolean("desiredOn"))
        assertNull(pid())
    }
    @Test fun duplicateEngineFieldsCannotReplaceConfiguration() {
        val before = status().getString("configRevision")
        val invalid = """{"outbounds":[{"type":"direct","tag":"direct","tag":"other"}]}"""
        val result = context.contentResolver.call(uri, "import", Base64.encodeToString(invalid.toByteArray(), Base64.NO_WRAP), null)
        assertFalse(result!!.getBoolean("ok"))
        assertEquals(before, status().getString("configRevision"))
    }
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private val uri = "content://io.syn443.control".toUri()
    private lateinit var scenario: ActivityScenario<MainActivity>
    private lateinit var server: ServerSocket
    private val workers = Executors.newFixedThreadPool(4)
    private val tunnels = AtomicInteger()
    @Volatile private var serving = true
    private fun shell(command: String) = instrumentation.uiAutomation.executeShellCommand(command).use { fd ->
        FileInputStream(fd.fileDescriptor).use { it.readBytes() }
    }
    private fun call(method: String, arg: String? = null) {
        assertTrue("Control command failed: $method", context.contentResolver.call(uri, method, arg, null)?.getBoolean("ok") == true)
    }
    private fun status() = JSONObject(checkNotNull(context.contentResolver.call(uri, "status", null, null)?.getString("json")))
    private fun pid() = context.getSystemService(ActivityManager::class.java).runningAppProcesses
        ?.firstOrNull { it.processName == "${context.packageName}:engine" }?.pid
    private fun await(timeout: Long = 35_000, predicate: () -> Boolean) {
        val end = android.os.SystemClock.elapsedRealtime() + timeout
        while (android.os.SystemClock.elapsedRealtime() < end) {
            if (predicate()) return
            Thread.sleep(200)
        }
        fail("VPN lifecycle deadline exceeded")
    }
    @Before fun setup() {
        val emulator = Build.HARDWARE in setOf("ranchu", "goldfish") || Build.FINGERPRINT.startsWith("generic")
        require(emulator) { "Hermetic tests may overwrite synthetic config; physical acceptance uses a separate operator driver" }
        scenario = ActivityScenario.launch(MainActivity::class.java)
        assertNull("Emulator harness must grant VPN permission before instrumentation starts", VpnService.prepare(context))
        call("disconnect")
        await { pid() == null && !status().optBoolean("engineActive") }
        // Each scenario starts with an independent synthetic budget. No reset
        // occurs inside a scenario; real-device and release calls are rejected.
        call("test-reset")
        server = ServerSocket(0, 16, InetAddress.getByName("127.0.0.1"))
        workers.execute { while (serving) runCatching { val socket = server.accept(); workers.execute { respond(socket) } } }
        val config = """{"outbounds":[{"type":"http","tag":"test-proxy","server":"127.0.0.1","server_port":${server.localPort}}],"route":{"final":"test-proxy"}}"""
        call("import", Base64.encodeToString(config.toByteArray(), Base64.NO_WRAP))
        call("test-health", "synthetic-http")
    }
    private fun respond(socket: Socket) {
        socket.use {
            socket.soTimeout = 10_000
            val reader = socket.getInputStream().bufferedReader()
            val first = reader.readLine() ?: return
            while (!reader.readLine().isNullOrEmpty()) { /* bounded by socket timeout */ }
            if (!first.startsWith("CONNECT 203.0.113.10:80 ")) return
            tunnels.incrementAndGet()
            socket.getOutputStream().write("HTTP/1.1 200 Connection established\r\n\r\n".toByteArray())
            socket.getOutputStream().flush()
            val get = reader.readLine() ?: return
            if (!get.startsWith("GET /generate_204 ")) return
            while (!reader.readLine().isNullOrEmpty()) { }
            socket.getOutputStream().write("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".toByteArray())
            socket.getOutputStream().flush()
        }
    }
    private fun connect() { call("connect"); await { status().optString("phase") == "Online" }; assertTrue(tunnels.get() > 0) }
    @After fun cleanup() {
        runCatching { call("disconnect") }
        serving = false
        if (::server.isInitialized) server.close()
        workers.shutdownNow()
        runCatching { call("test-health", "production-https") }
        if (::scenario.isInitialized) scenario.close()
    }
    @Test fun realTunTrafficAndExplicitStop() {
        connect()
        assertTrue(status().getBoolean("desiredOn"))
        assertNotNull(pid())
        call("disconnect")
        await { !status().optBoolean("desiredOn") && pid() == null }
        Thread.sleep(1_500)
        assertFalse(status().getBoolean("desiredOn"))
    }
    @Test fun unavailableOptionalOverlayDoesNotBlockVpnOrLeakPrivateRoute() {
        val config = """{"outbounds":[
            {"type":"http","tag":"test-proxy","server":"127.0.0.1","server_port":${server.localPort}},
            {"type":"netbird","tag":"overlay","management_url":"https://example.invalid","setup_key":"","state_directory":"/rejected-import-path"}],
            "route":{"rules":[{"ip_cidr":["198.51.100.0/24"],"outbound":"overlay"}],"final":"test-proxy"}}"""
        val rendered = JSONObject(io.syn443.android.vpn.EngineConfig.render(config, context.noBackupFilesDir))
            .getJSONArray("outbounds").getJSONObject(1)
        assertTrue(rendered.getString("state_directory").startsWith(context.noBackupFilesDir.absolutePath + "/netbird/"))
        assertEquals("direct", rendered.getString("connection_mode"))
        call("import", Base64.encodeToString(config.toByteArray(), Base64.NO_WRAP))
        connect()
        val native = pid()
        await { status().optJSONObject("netbird")?.optString("reason") == "enrollment_required" }
        // No identity or fallback may be constructed without enrollment.
        val began = android.os.SystemClock.elapsedRealtime()
        assertTrue(runCatching { Socket().use { it.connect(java.net.InetSocketAddress("198.51.100.7", 443), 3_000) } }.isFailure)
        assertTrue(android.os.SystemClock.elapsedRealtime() - began < 5_000)
        Thread.sleep(11_000)
        assertEquals(native, pid())
        assertEquals("Online", status().optString("phase"))
        assertTrue(tunnels.get() >= 2)
        assertFalse(context.contentResolver.call(uri, "logs", null, null)!!.getString("json")!!.contains("peer_state"))
    }
    @Test fun nativeCrashRecoversButNewerStopWins() {
        connect()
        val old = pid()
        shell("content call --uri content://io.syn443.control --method fault-crash")
        await { pid() != null && pid() != old && status().optString("phase") == "Online" }
        shell("content call --uri content://io.syn443.control --method fault-crash")
        call("disconnect")
        await { pid() == null && !status().optBoolean("desiredOn") }
        Thread.sleep(4_000)
        assertNull(pid())
        assertFalse(status().getBoolean("desiredOn"))
    }
    @Test fun fullyFrozenNativeProcessIsKilledOutsideItsControlLoop() {
        connect()
        val old = pid()
        shell("content call --uri content://io.syn443.control --method fault-hang")
        await(90_000) { pid() != null && pid() != old && status().optString("phase") == "Online" }
        assertTrue(status().getBoolean("desiredOn"))
        assertTrue(tunnels.get() >= 2)
    }
    @Test fun closingActivityDoesNotStopVpn() {
        connect()
        scenario.close()
        Thread.sleep(1_000)
        assertTrue(status().getBoolean("desiredOn"))
        assertNotNull(pid())
        call("disconnect")
        await { pid() == null }
    }
    @Test fun lostNetworkCannotRemainSelectedFromAStaleSystemSnapshot() {
        connect()
        val old = pid()
        val epoch = status().optLong("networkEpoch")
        try {
            shell("svc wifi disable")
            shell("svc data disable")
            await { status().optString("phase") == "NoNetwork" }
            assertTrue(status().getBoolean("desiredOn"))
            assertEquals(old, pid())
            Thread.sleep(2_000)
            assertEquals("NoNetwork", status().optString("phase"))
        } finally {
            shell("svc wifi enable")
            shell("svc data enable")
        }
        await(60_000) { status().optString("phase") == "Online" }
        assertEquals(old, pid())
        assertTrue(status().optLong("networkEpoch") > epoch)
    }
    @Test fun stopDuringForegroundServiceStartupNeverCrashesController() {
        repeat(3) { call("connect"); call("disconnect") }
        await { !status().optBoolean("desiredOn") && pid() == null }
        Thread.sleep(8_000)
        assertFalse(status().getBoolean("desiredOn"))
        assertNull(pid())
    }
    @Test fun notificationStopRetiresAFullyFrozenNativeHost() {
        connect()
        shell("content call --uri content://io.syn443.control --method fault-hang")
        val notification = context.getSystemService(android.app.NotificationManager::class.java)
            .activeNotifications.first { it.id == 443 }.notification
        checkNotNull(notification.actions.first().actionIntent).send()
        await { !status().optBoolean("desiredOn") && pid() == null && !status().optBoolean("engineActive") }
        Thread.sleep(4_000)
        assertFalse(status().getBoolean("desiredOn"))
        assertNull(pid())
    }
}
