package io.syn443.android

import android.app.ActivityManager
import android.net.ConnectivityManager
import android.net.InetAddresses
import android.net.NetworkCapabilities
import androidx.core.net.toUri
import android.net.VpnService
import android.os.Build
import android.util.Base64
import androidx.test.core.app.ActivityScenario
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONArray
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import java.io.IOException
import java.io.FileInputStream
import java.net.InetAddress
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketException
import java.net.SocketTimeoutException
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger

/** Hermetic real TUN -> Go TCP/IP stack -> HTTP CONNECT proxy -> synthetic HTTP response. */
class VpnLifecycleTest {
    @Test fun intentSentinelIsNonWakeupAndCancelledByStop() {
        connect()
        val alarm = shell("dumpsys alarm").toString(Charsets.UTF_8)
        val action = alarm.indexOf("io.syn443.USER_INTENT_MARKER")
        assertTrue("OS must retain the Force stop marker", action >= 0)
        val start = alarm.lastIndexOf("Alarm{", action).coerceAtLeast(0)
        val end = alarm.indexOf("Alarm{", action).takeIf { it >= 0 } ?: alarm.length
        assertTrue("Sentinel must not wake the device", Regex("type[= ]3\\b").containsMatchIn(alarm.substring(start, end)))
        call("disconnect")
        await { pid() == null }
        val marker = android.app.PendingIntent.getBroadcast(context, 4431,
            android.content.Intent(context, io.syn443.android.vpn.BootReceiver::class.java).setAction("io.syn443.USER_INTENT_MARKER"),
            android.app.PendingIntent.FLAG_NO_CREATE or android.app.PendingIntent.FLAG_IMMUTABLE)
        assertNull("Stop must cancel both marker and ownership sentinel", marker)
    }
    @Test fun physicalIdentitySocketBypassesTheRunningVpnProxy() {
        connect()
        // The ordinary process socket reaches the hermetic VPN proxy first.
        runCatching {Socket().use {it.connect(java.net.InetSocketAddress("198.51.100.11",80),1500);it.outputStream.write(1)}}
        await {controlProbes.get()==1}
        // Android may publish a new private-DNS validation/link snapshot while the
        // emulator settles. Such an in-flight request must fail its original fence.
        // Start a fresh request rather than silently rebinding the invalidated one.
        val end=android.os.SystemClock.elapsedRealtime()+10_000
        var completed=false
        while(!completed && android.os.SystemClock.elapsedRealtime()<end) {
            try {
                val route=io.syn443.android.vpn.PhysicalIdentityRoute.capture(context)
                assertTrue(route.resolve("localhost").isNotEmpty())
                // No HTTP or credentials: an unanswered documentation address is enough
                // to prove every attempt bypasses the active VPN's CONNECT proxy.
                Socket().use {socket->route.bind(socket);runCatching {socket.connect(java.net.InetSocketAddress("198.51.100.11",80),1500)}}
                route.check();completed=true
            } catch(e:io.syn443.identity.DeliveryException) {
                assertEquals(io.syn443.identity.DeliveryFailure.TRANSPORT,e.reason)
            }
            assertEquals(1,controlProbes.get())
            if(!completed)Thread.sleep(200)
        }
        assertTrue("No stable physical request completed within the bounded fixture window",completed)
        Thread.sleep(250)
        assertEquals(1,controlProbes.get());assertTrue(status().getBoolean("desiredOn"))
    }
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
    private val controlProbes = AtomicInteger()
    private val ipv4ApplicationRequests = AtomicInteger()
    private val ipv6ApplicationRequests = AtomicInteger()
    @Volatile private var serving = true
    private val peerSockets = ConcurrentHashMap.newKeySet<Socket>()
    private val fixtureFailure = AtomicReference<Throwable?>()
    @Volatile private var idleTimeoutMs = 10_000
    private fun shell(command: String) = instrumentation.uiAutomation.executeShellCommand(command).use { fd ->
        FileInputStream(fd.fileDescriptor).use { it.readBytes() }
    }
    private fun call(method: String, arg: String? = null) {
        assertTrue("Control command failed: $method", context.contentResolver.call(uri, method, arg, null)?.getBoolean("ok") == true)
    }
    private fun status() = JSONObject(checkNotNull(context.contentResolver.call(uri, "status", null, null)?.getString("json")))
    private fun resetReady():Boolean {
        val reply=context.contentResolver.call(uri,"test-reset-ready",null,null)
        assertTrue("Read-only fixture readiness command rejected",reply?.getBoolean("ok")==true)
        return reply!!.getBoolean("ready")
    }
    private fun stoppedForFixture():Boolean {
        val observed=status()
        return !observed.optBoolean("desiredOn") && observed.optString("phase")=="Off" &&
            observed.optBoolean("engineStateKnown") && observed.opt("engineActive")==false && pid()==null && resetReady()
    }
    private fun pid() = context.getSystemService(ActivityManager::class.java).runningAppProcesses
        ?.firstOrNull { it.processName == "${context.packageName}:engine" }?.pid
    private fun await(timeout: Long = 35_000, predicate: () -> Boolean) {
        val end = android.os.SystemClock.elapsedRealtime() + timeout
        while (android.os.SystemClock.elapsedRealtime() < end) {
            fixtureFailure.get()?.let { throw AssertionError("Unexpected loopback fixture failure",it) }
            if (predicate()) return
            Thread.sleep(200)
        }
        val s = status()
        fail("VPN lifecycle deadline exceeded: phase=${s.optString("phase")}, reason=${s.optString("reason")}, " +
            "desiredOn=${s.optBoolean("desiredOn")}, resumeRequired=${s.optBoolean("resumeRequired")}, " +
            "attempt=${s.optInt("attempt")}, heavyCount=${s.optJSONArray("heavyWallMs")?.length()}, native=${pid()}, tunnels=${tunnels.get()}")
    }
    @Before fun setup() {
        val emulator = Build.HARDWARE in setOf("ranchu", "goldfish") || Build.FINGERPRINT.startsWith("generic")
        require(emulator) { "Hermetic tests may overwrite synthetic config; physical acceptance uses a separate operator driver" }
        scenario = ActivityScenario.launch(MainActivity::class.java)
        assertNull("Emulator harness must grant VPN permission before instrumentation starts", VpnService.prepare(context))
        call("disconnect")
        await { stoppedForFixture() }
        // Each scenario starts with an independent synthetic budget. No reset
        // occurs inside a scenario; real-device and release calls are rejected.
        call("test-reset")
        server = ServerSocket(0, 16, InetAddress.getByName("127.0.0.1"))
        workers.execute {
            while (serving) {
                val socket = try { server.accept() } catch(e:IOException) {
                    if(serving)fixtureFailure.compareAndSet(null,e)
                    break
                }
                peerSockets.add(socket)
                try {
                    workers.execute {
                        try { respond(socket) }
                        catch(e:IOException) {
                            // Faulted/frozen clients may leave an idle TCP stream or reset it.
                            // Closing that stream is not positive VPN/HTTP health evidence.
                            if(e !is SocketTimeoutException && e !is SocketException)fixtureFailure.compareAndSet(null,e)
                        } catch(e:Throwable) {fixtureFailure.compareAndSet(null,e)}
                        finally {closeFixtureSocket(socket)}
                    }
                } catch(e:RejectedExecutionException) {
                    closeFixtureSocket(socket)
                    if(serving)fixtureFailure.compareAndSet(null,e)
                }
            }
        }
        importProxyPolicy(blockIpv6 = false)
        call("test-health", "synthetic-http")
    }
    private fun importProxyPolicy(blockIpv6: Boolean) {
        val route = JSONObject().put("final", "test-proxy")
        if (blockIpv6) {
            val rule = JSONObject().put("ip_cidr", JSONArray().put("::/0"))
                .put("action", "reject").put("method", "drop")
            route.put("rules", JSONArray().put(rule))
        }
        val proxy = JSONObject().put("type", "http").put("tag", "test-proxy")
            .put("server", "127.0.0.1").put("server_port", server.localPort)
        val config = JSONObject().put("outbounds", JSONArray().put(proxy)).put("route", route)
        call("import", Base64.encodeToString(config.toString().toByteArray(), Base64.NO_WRAP))
    }
    private fun closeFixtureSocket(socket:Socket) {
        try {socket.close();peerSockets.remove(socket)}
        catch(e:IOException) {fixtureFailure.compareAndSet(null,e)}
    }
    private fun respond(socket: Socket) {
        socket.use {
            socket.soTimeout = idleTimeoutMs
            val reader = socket.getInputStream().bufferedReader()
            val first = reader.readLine() ?: return
            while (!reader.readLine().isNullOrEmpty()) { /* bounded by socket timeout */ }
            if (first.startsWith("CONNECT 198.51.100.11:80 ")) {controlProbes.incrementAndGet();return}
            if (!first.startsWith("CONNECT ")) return
            val target = first.substringBeforeLast(' ').removePrefix("CONNECT ")
            val requestCounter = when {
                target == "203.0.113.10:80" -> tunnels
                target == "203.0.113.43:80" -> ipv4ApplicationRequests
                target.startsWith("[") && target.endsWith("]:80") &&
                    InetAddresses.parseNumericAddress(target.substring(1, target.length - 4)) ==
                    InetAddresses.parseNumericAddress("2001:db8::443") -> ipv6ApplicationRequests
                else -> return
            }
            requestCounter.incrementAndGet()
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
        var terminated = false
        try {
            if (::server.isInitialized)try {server.close()}catch(e:IOException) {fixtureFailure.compareAndSet(null,e)}
            workers.shutdownNow()
            peerSockets.toList().forEach(::closeFixtureSocket)
            terminated = workers.awaitTermination(2,TimeUnit.SECONDS)
        } finally {
            runCatching { call("test-health", "production-https") }
            if (::scenario.isInitialized) scenario.close()
        }
        assertTrue("Loopback fixture workers did not retire",terminated)
        assertTrue("Loopback fixture left owned sockets",peerSockets.isEmpty())
        fixtureFailure.get()?.let {throw AssertionError("Unexpected loopback fixture failure",it)}
    }
    @Test fun resetReadinessIsReadOnlyAndCannotAuthorizeAnActiveOwner() {
        val off=status();assertTrue(resetReady());assertEquals(off.getLong("generation"),status().getLong("generation"))
        connect();val active=status();assertFalse(resetReady())
        assertFalse(context.contentResolver.call(uri,"test-reset",null,null)!!.getBoolean("ok"))
        val unchanged=status();assertEquals(active.getLong("generation"),unchanged.getLong("generation"))
        assertTrue(unchanged.getBoolean("desiredOn"));assertTrue(unchanged.getBoolean("engineActive"))
        call("disconnect");await {stoppedForFixture()}
        assertTrue(resetReady());assertEquals(active.getLong("generation")+1,status().getLong("generation"))
    }
    @Test fun idleFaultClientClosesWithoutFalseHealthOrEscapingItsWorker() {
        idleTimeoutMs = 100
        Socket(InetAddress.getByName("127.0.0.1"),server.localPort).use {client ->
            client.soTimeout = 2_000
            assertEquals("An idle fault client must be closed without a response",-1,client.getInputStream().read())
        }
        assertEquals(0,tunnels.get())
        assertEquals(0,controlProbes.get())
        assertNull(fixtureFailure.get())
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
    private fun awaitOwnedDefaultRoutes() = await {
        val connectivity = context.getSystemService(ConnectivityManager::class.java)
        val tunnelAddress = InetAddresses.parseNumericAddress("fd00:443::1")
        val active = connectivity.activeNetwork ?: return@await false
        val caps = connectivity.getNetworkCapabilities(active) ?: return@await false
        val link = connectivity.getLinkProperties(active) ?: return@await false
        caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
            link.linkAddresses.any { it.address == tunnelAddress } &&
            link.routes.any { it.isDefaultRoute && it.destination.address is Inet4Address } &&
            link.routes.any { it.isDefaultRoute && it.destination.address is Inet6Address }
    }

    private fun requestFixture(address: String): String? = Socket().use { socket ->
        socket.soTimeout = 3_000
        socket.connect(InetSocketAddress(InetAddresses.parseNumericAddress(address), 80), 3_000)
        socket.getOutputStream().write("GET /generate_204 HTTP/1.1\r\nHost: fixture.invalid\r\nConnection: close\r\n\r\n".toByteArray())
        socket.getInputStream().bufferedReader().readLine()
    }

    @Test fun defaultVpnRoutesCaptureBothFamiliesAndExplicitIpv6DenialPreservesIpv4() {
        importProxyPolicy(blockIpv6 = true)
        connect()
        awaitOwnedDefaultRoutes()
        val blockedResponse = try { requestFixture("2001:db8::443") } catch (_: IOException) { null }
        assertNull("Blocked IPv6 produced an application response", blockedResponse)
        assertEquals("HTTP/1.1 204 No Content", requestFixture("203.0.113.43"))
        assertEquals(0, ipv6ApplicationRequests.get())
        assertEquals(1, ipv4ApplicationRequests.get())

        call("disconnect")
        await { stoppedForFixture() }
        importProxyPolicy(blockIpv6 = false)
        connect()
        awaitOwnedDefaultRoutes()
        assertEquals("HTTP/1.1 204 No Content", requestFixture("2001:db8::443"))
        assertEquals("HTTP/1.1 204 No Content", requestFixture("203.0.113.43"))
        assertEquals(1, ipv6ApplicationRequests.get())
        assertEquals(2, ipv4ApplicationRequests.get())
    }
    @Test fun unavailableOptionalOverlayDoesNotBlockVpnOrLeakPrivateRoute() {
        // Prove the default proxy would serve both exact destinations if a rule fell through.
        connect()
        awaitOwnedDefaultRoutes()
        assertEquals("HTTP/1.1 204 No Content", requestFixture("203.0.113.43"))
        assertEquals("HTTP/1.1 204 No Content", requestFixture("2001:db8::443"))
        assertEquals(1, ipv4ApplicationRequests.get())
        assertEquals(1, ipv6ApplicationRequests.get())
        call("disconnect")
        await { stoppedForFixture() }
        val config = """{"outbounds":[
            {"type":"http","tag":"test-proxy","server":"127.0.0.1","server_port":${server.localPort}},
            {"type":"netbird","tag":"overlay","management_url":"https://example.invalid","setup_key":"","state_directory":"/rejected-import-path"}],
            "route":{"rules":[{"ip_cidr":["203.0.113.43/32","2001:db8::443/128"],"outbound":"overlay"}],"final":"test-proxy"}}"""
        val rendered = JSONObject(io.syn443.android.vpn.EngineConfig.render(config, context.noBackupFilesDir))
            .getJSONArray("outbounds").getJSONObject(1)
        assertTrue(rendered.getString("state_directory").startsWith(context.noBackupFilesDir.absolutePath + "/netbird/"))
        assertEquals("direct", rendered.getString("connection_mode"))
        call("import", Base64.encodeToString(config.toByteArray(), Base64.NO_WRAP))
        connect()
        val native = pid()
        await { status().optJSONObject("netbird")?.optString("reason") == "enrollment_required" }
        awaitOwnedDefaultRoutes()
        for (target in listOf("203.0.113.43", "2001:db8::443")) {
            val began = android.os.SystemClock.elapsedRealtime()
            val response = try { requestFixture(target) } catch (_: IOException) { null }
            assertNull("Unavailable overlay returned an application response", response)
            assertTrue(android.os.SystemClock.elapsedRealtime() - began < 5_000)
        }
        assertEquals("HTTP/1.1 204 No Content", requestFixture("203.0.113.10"))
        Thread.sleep(11_000)
        assertEquals("Private IPv4 reached the default proxy", 1, ipv4ApplicationRequests.get())
        assertEquals("Private IPv6 reached the default proxy", 1, ipv6ApplicationRequests.get())
        assertEquals(native, pid())
        assertEquals("Online", status().optString("phase"))
        assertTrue(tunnels.get() >= 2)
        val logs = JSONObject(checkNotNull(context.contentResolver.call(uri, "logs", null, null)?.getString("json")))
        assertTrue(logs.keys().asSequence().all { it in setOf("generation", "networkEpoch", "activationGeneration", "eventSequence", "events") })
        assertTrue(logs.getJSONArray("events").length() in 1..64)
        assertEquals(status().getLong("generation"), logs.getLong("generation"))
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
