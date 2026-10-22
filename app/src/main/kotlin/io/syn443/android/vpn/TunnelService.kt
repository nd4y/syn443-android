package io.syn443.android.vpn

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.os.Process
import android.os.SystemClock
import io.syn443.android.MainActivity
import io.syn443.android.R
import io.syn443.recovery.Recovery
import io.syn443.host.HostFence
import java.io.File
import java.io.RandomAccessFile
import java.net.NetworkInterface
import java.net.URL
import java.net.HttpURLConnection
import java.util.UUID
import java.util.concurrent.Executors
import javax.net.ssl.HttpsURLConnection

/** Sole TUN owner, durable intent reconciler and native-process watchdog. Never loads Go. */
class TunnelService : VpnService() {
    private val handler = Handler(Looper.getMainLooper())
    private val checks = Executors.newSingleThreadExecutor()
    private val dnsCallbacks = Executors.newFixedThreadPool(2)
    private val dnsAdmission = java.util.concurrent.Semaphore(2)
    private lateinit var store: StateStore
    private lateinit var connectivity: ConnectivityManager
    @Volatile private var network: Network? = null
    @Volatile private var epoch = 0L
    private var host: IEngineHost? = null
    private var binding = false
    @Volatile private var token: String? = null
    private var hostPid = 0
    private var pidIdentity: String? = null
    private var tun: ParcelFileDescriptor? = null
    private var ready = false
    private var lastPulse = 0L
    private var startAt = 0L
    private var stableSince = 0L
    private var successes = 0
    private var probeInFlight = false
    private var retryHeavy = false
    private var retiring = false
    @Volatile private var boundGeneration = -1L
    private var lastProbe = 0L
    private var registered = false
    private var foreground = false
    private var notificationText = ""
    private var bindingAt = 0L
    private val fence = HostFence(UUID.randomUUID().toString().replace("-", ""), startTimeoutMs = 15_000, stopTimeoutMs = 3_000)
    private var hostToken: HostFence.Token? = null
    private var connection: ServiceConnection? = null
    private var retirementAt = 0L
    private var latestStartId = 0
    private var startNetworkEpoch = -1L
    // onLost can precede removal from ConnectivityManager.allNetworks/capabilities.
    // Never select a network after its explicit loss notification.
    private val lostNetworks = linkedSetOf<Network>()

    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) { handler.post { lostNetworks.remove(network); refreshNetwork() } }
        override fun onLost(network: Network) { handler.post {
            lostNetworks.add(network)
            while (lostNetworks.size > 64) lostNetworks.remove(lostNetworks.first())
            refreshNetwork()
        } }
        override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) = changed()
        override fun onLinkPropertiesChanged(network: Network, properties: LinkProperties) = changed()
        private fun changed() { handler.post { refreshNetwork() } }
    }
    override fun onCreate() {
        super.onCreate()
        // Satisfy every pending startForegroundService request even when a newer
        // Stop arrives before onStartCommand, or a network callback arrives first.
        notifyForeground("Подключаемся")
        foreground = true
        store = StateStore.get(this)
        connectivity = getSystemService(ConnectivityManager::class.java)
        epoch = store.read().optLong("networkEpoch")
        retryHeavy = store.read().optBoolean("engineActive") || store.checkpoint().attempt > 0
        terminateOwned() // A previous controller may have died with its host frozen.
        connectivity.registerNetworkCallback(NetworkRequest.Builder().addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build(), networkCallback)
        registered = true
    }
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        latestStartId = startId
        // A later foreground start may be queued on the same instance after a
        // previous Stop removed its notification. Re-promote before inspecting intent.
        if (!foreground) { notifyForeground("Подключаемся"); foreground = true }
        if (intent?.action == STOP) store.update { store.put(it, Recovery.command(store.checkpoint(it), false)) }
        if (!store.checkpoint().desiredOn) { retire(false); return START_NOT_STICKY }
        if (intent?.action == "fault-crash" && io.syn443.android.BuildConfig.DEBUG) terminateOwned()
        if (intent?.action == "fault-hang" && io.syn443.android.BuildConfig.DEBUG && verifiedPid()) Process.sendSignal(hostPid, 19)
        if (intent?.action == "netbird-diagnose" && ready) token?.let { host?.diagnoseNetBird(it) }
        refreshNetwork()
        reconcile()
        handler.removeCallbacks(tick)
        handler.post(tick)
        return START_STICKY
    }
    private fun phase(name: String, reason: String, generation: Long? = null) {
        val previous = store.read()
        if (generation != null && !Recovery.current(store.checkpoint(previous), generation)) return
        if (!previous.optBoolean("desiredOn") && name != "Off") return
        if (previous.optString("phase") != name || previous.optString("reason") != reason) {
            if (!store.event(name, reason, epoch, generation ?: previous.optLong("generation"))) return
        }
        val text = when (name) {
            "Online" -> "Работает"
            "NoNetwork" -> "Ожидание сети"
            "Recovering" -> "Восстанавливаем соединение"
            "NeedsPermission", "NeedsAction" -> "Требуется действие пользователя"
            else -> "Подключаемся"
        }
        if (foreground && notificationText != text) notifyForeground(text)
    }
    private fun notifyForeground(text: String) {
        notificationText = text
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(NotificationChannel("vpn", "VPN", NotificationManager.IMPORTANCE_LOW))
        val open = PendingIntent.getActivity(this, 1, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        val stop = PendingIntent.getService(this, 2, Intent(this, TunnelService::class.java).setAction(STOP), PendingIntent.FLAG_IMMUTABLE)
        val notification = android.app.Notification.Builder(this, "vpn").setSmallIcon(R.drawable.ic_launcher)
            .setContentTitle("SYN443").setContentText(text).setContentIntent(open).setOngoing(true)
            .addAction(android.app.Notification.Action.Builder(null, "Отключить", stop).build()).build()
        startForeground(443, notification)
    }
    private fun refreshNetwork() {
        val candidates = connectivity.allNetworks.filter { n ->
            n !in lostNetworks && connectivity.getNetworkCapabilities(n)?.let { it.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) &&
                it.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) } == true &&
                connectivity.getLinkProperties(n)?.interfaceName != null
        }
        val selected = candidates.firstOrNull { connectivity.getNetworkCapabilities(it)?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true }
            ?: candidates.firstOrNull()
        val signature = selected?.let { connectivity.getLinkProperties(it)?.toString() }
        if (selected == network && signature == linkSignature) return
        linkSignature = signature
        network = selected
        epoch++
        stableSince = 0; successes = 0
        store.update { value -> value.put("networkEpoch", epoch); store.put(value, Recovery.networkOpportunity(store.checkpoint(value), System.currentTimeMillis())) }
        if (selected == null) { phase("NoNetwork", "network_unavailable"); return }
        setUnderlyingNetworks(arrayOf(selected))
        val properties = connectivity.getLinkProperties(selected)
        val name = properties?.interfaceName
        val index = name?.let { runCatching { NetworkInterface.getByName(it)?.index }.getOrNull() }
        if (ready && name != null && index != null) {
            runCatching { host?.networkChanged(checkNotNull(token), name, index) }.onFailure { failed("network_update_failed") }
            phase("Recovering", "network_changed")
            probe()
        }
        reconcile()
        handler.removeCallbacks(tick)
        handler.post(tick)
    }
    private val tick = object : Runnable {
        override fun run() {
            if (!store.checkpoint().desiredOn) { retire(false); return }
            val now = SystemClock.uptimeMillis()
            fence.tick(now).effects.forEach { if (it is HostFence.Effect.TerminateOwned) terminateOwned() }
            if (binding && host == null && now - bindingAt > 15_000 && !retiring) failed("native_binding_timeout")
            if (retiring) return // The bounded drain loop owns retirement progress.
            if (host != null) {
                if ((!ready && now - startAt > 15_000) || (ready && now - lastPulse > 35_000)) failed("native_progress_timeout")
                else if (now - lastPulse > 8_000) runCatching { host?.pulse(checkNotNull(token)) }.onFailure { failed("native_ipc_failed") }
                if (ready && network != null && now - lastProbe >= 10_000) probe()
            } else reconcile()
            if (host == null && (network == null || store.read().optString("phase") in setOf("NeedsAction", "NeedsPermission"))) return
            val delay = if (host == null) (store.checkpoint().nextWallMs - System.currentTimeMillis()).coerceIn(1_000, 60_000) else if (network == null) 10_000 else 1_000
            handler.postDelayed(this, delay)
        }
    }
    private fun reconcile() {
        val cp = store.adjustCheckpoint { Recovery.normalizeClock(it, System.currentTimeMillis()) }
        if (!cp.desiredOn) return
        if (host != null && boundGeneration != cp.generation) { retire(false); return }
        if (host != null || binding || retiring) return
        if (network == null) { phase("NoNetwork", "network_unavailable"); return }
        if (prepare(this) != null) { phase("NeedsPermission", "vpn_permission_required"); return }
        if (store.read().optString("phase") == "NeedsAction") return
        if (!ownerReleased()) {
            val orphan = getSystemService(android.app.ActivityManager::class.java).runningAppProcesses
                ?.firstOrNull { it.uid == Process.myUid() && it.processName == "$packageName:engine" }
            if (orphan != null && processIdentity(orphan.pid) != null) Process.killProcess(orphan.pid)
            phase("Recovering", "awaiting_identity_release"); return
        }
        val now = System.currentTimeMillis()
        if (now < cp.nextWallMs) { phase("Recovering", "retry_scheduled"); return }
        if (retryHeavy) {
            var allowed = false
            store.adjustCheckpoint { current ->
                if (!Recovery.current(current, cp.generation)) current
                else Recovery.heavyAdmission(current, now).let { (admitted, accepted) -> allowed = accepted; admitted }
            }
            if (!allowed) { phase("Recovering", "native_restart_budget"); return }
        }
        try {
            val n = checkNotNull(network)
            val properties = checkNotNull(connectivity.getLinkProperties(n))
            val rendered = EngineConfig.render(store.config(), noBackupFilesDir)
            tun = tun ?: Builder().setSession("SYN443").setMtu(1400)
                .addAddress("192.0.2.1", 30).addAddress("fd00:443::1", 126)
                .addRoute("0.0.0.0", 0).addRoute("::", 0).addDnsServer("192.0.2.2")
                .setBlocking(false).establish() ?: error("VPN unavailable")
            token = UUID.randomUUID().toString()
            stableSince = 0; successes = 0; lastProbe = 0
            boundGeneration = cp.generation
            pendingConfig = rendered
            startAt = SystemClock.uptimeMillis(); lastPulse = startAt
            val reservation = fence.reserveStart(startAt)
            check(reservation.rejection == null)
            hostToken = reservation.snapshot.token
            val newConnection = connectionFor(checkNotNull(token), cp.generation)
            connection = newConnection
            if (!store.updateCurrent(cp.generation) { it.put("engineActive", true) }) { retire(false); return }
            binding = bindService(Intent(this, EngineHostService::class.java), newConnection, Context.BIND_AUTO_CREATE)
            bindingAt = SystemClock.uptimeMillis()
            if (!binding) failed("native_bind_failed") else phase("Connecting", "native_start", cp.generation)
        } catch (_: IllegalArgumentException) { phase("NeedsAction", "configuration_invalid", cp.generation) }
        catch (_: Exception) { failed("start_failed", cp.generation) }
    }
    private var pendingConfig = ""
    private var linkSignature: String? = null // RAM only; never log physical addresses.
    private val platform = object : IPlatform.Stub() {
        override fun physicalInterfaces(session: String): String {
            check(session == token && Recovery.current(store.checkpoint(), boundGeneration))
            val selected = checkNotNull(network)
            val selectedEpoch = epoch
            val properties = checkNotNull(connectivity.getLinkProperties(selected))
            val name = checkNotNull(properties.interfaceName)
            val iface = checkNotNull(NetworkInterface.getByName(name))
            val addresses = properties.linkAddresses.filter { it.address is java.net.Inet4Address && !it.address.isLoopbackAddress && !it.address.isLinkLocalAddress }
                .joinToString(" ") { "${it.address.hostAddress}/${it.prefixLength}" }
            check(selected == network && selectedEpoch == epoch && session == token && Recovery.current(store.checkpoint(), boundGeneration))
            if (addresses.isEmpty()) return ""
            return "$name ${iface.index} ${iface.mtu} ${iface.isUp} true false ${iface.isPointToPoint} ${iface.supportsMulticast()}|$addresses"
        }
        override fun overlayState(session: String, raw: String) { handler.post {
            if (session == token && Recovery.current(store.checkpoint(), boundGeneration) && !retiring)
                runCatching { OverlaySnapshot.update(raw) }
        } }
        override fun exchangeDNS(query: ByteArray, session: String): ByteArray {
            check(query.size in 12..4096 && session == token && Recovery.current(store.checkpoint(), boundGeneration))
            val selected = checkNotNull(network)
            val selectedEpoch = epoch
            check(dnsAdmission.tryAcquire()) { "DNS budget exhausted" }
            val cancellation = android.os.CancellationSignal()
            try {
                val answer = java.util.concurrent.CompletableFuture<ByteArray>()
                android.net.DnsResolver.getInstance().rawQuery(selected, query, android.net.DnsResolver.FLAG_NO_RETRY,
                    dnsCallbacks, cancellation, object : android.net.DnsResolver.Callback<ByteArray> {
                        override fun onAnswer(response: ByteArray, rcode: Int) { answer.complete(response) }
                        override fun onError(error: android.net.DnsResolver.DnsException) { answer.completeExceptionally(error) }
                    })
                val response = answer.get(3, java.util.concurrent.TimeUnit.SECONDS)
                check(selected == network && selectedEpoch == epoch && session == token && Recovery.current(store.checkpoint(), boundGeneration))
                check(response.size <= 65535)
                return response
            } finally { cancellation.cancel(); dnsAdmission.release() }
        }
        override fun protect(fd: ParcelFileDescriptor, session: String): Boolean = fd.use {
            if (session != token || !store.checkpoint().let { it.desiredOn && it.generation == boundGeneration }) return false
            val n = network ?: return false
            return try { if (!protect(it.fd)) false else { n.bindSocket(it.fileDescriptor); true } } catch (_: Exception) { false }
        }
        override fun event(session: String, kind: Int) { handler.post {
            if (session != token || !Recovery.current(store.checkpoint(), boundGeneration)) return@post
            when (kind) {
                EngineHostService.READY -> {
                    val transition = fence.started(checkNotNull(hostToken), SystemClock.uptimeMillis())
                    if (transition.snapshot.phase == HostFence.Phase.RUNNING) {
                        ready = true; lastPulse = SystemClock.uptimeMillis()
                        if (epoch != startNetworkEpoch && network != null) {
                            val properties = connectivity.getLinkProperties(checkNotNull(network))
                            val name = properties?.interfaceName
                            val index = name?.let { NetworkInterface.getByName(it)?.index }
                            if (name != null && index != null) runCatching { host?.networkChanged(session, name, index) }
                                .onFailure { failed("network_update_failed") }
                        }
                        probe()
                    }
                    else { terminateOwned(); failed("native_late_start") }
                }
                EngineHostService.PULSE -> lastPulse = SystemClock.uptimeMillis()
                EngineHostService.FAILED -> failed("native_start_failed")
                EngineHostService.INVALID -> { phase("NeedsAction", "configuration_or_capability_invalid", boundGeneration); retire(false) }
            }
        } }
    }
    private fun connectionFor(session: String, generation: Long) = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName, binder: IBinder) {
            if (session != token || !Recovery.current(store.checkpoint(), generation) || retiring) {
                runCatching { unbindService(this) }; return
            }
            host = IEngineHost.Stub.asInterface(binder)
            try {
                // Do not make a synchronous IPC on the watchdog's looper: a host
                // frozen before the handshake must not freeze the supervisor.
                hostPid = checkNotNull(getSystemService(android.app.ActivityManager::class.java).runningAppProcesses
                    ?.firstOrNull { it.uid == Process.myUid() && it.processName == "$packageName:engine" }).pid
                pidIdentity = processIdentity(hostPid)
                check(verifiedPid())
                binder.linkToDeath({ handler.post { if (session == token && !retiring) failed("native_died") } }, 0)
                val properties = checkNotNull(connectivity.getLinkProperties(checkNotNull(network)))
                val iface = checkNotNull(properties.interfaceName)
                val index = checkNotNull(NetworkInterface.getByName(iface)).index
                startNetworkEpoch = epoch
                checkNotNull(host).start(checkNotNull(tun), pendingConfig, checkNotNull(token), iface, index, platform)
            } catch (_: Exception) { failed("native_handshake_failed") }
        }
        override fun onServiceDisconnected(name: ComponentName) { if (session == token && !retiring) failed("native_disconnected") }
        override fun onBindingDied(name: ComponentName) { if (session == token && !retiring) failed("native_binding_died") }
        override fun onNullBinding(name: ComponentName) { if (session == token) failed("native_null_binding") }
    }
    private fun processIdentity(pid: Int): String? = runCatching {
        val cmd = File("/proc/$pid/cmdline").readText().trimEnd('\u0000')
        if (cmd != "$packageName:engine") return null
        val stat = File("/proc/$pid/stat").readText().substringAfterLast(") ").split(' ')
        "$cmd:${stat[19]}"
    }.getOrNull()
    private fun verifiedPid() = hostPid > 0 && hostPid != Process.myPid() && pidIdentity != null && processIdentity(hostPid) == pidIdentity
    private fun terminateOwned() {
        if (verifiedPid()) Process.killProcess(hostPid)
        else if (hostPid == 0) {
            getSystemService(android.app.ActivityManager::class.java).runningAppProcesses
                ?.filter { it.uid == Process.myUid() && it.processName == "$packageName:engine" }
                ?.forEach { if (processIdentity(it.pid) != null) Process.killProcess(it.pid) }
        }
    }
    private fun ownerReleased(): Boolean = runCatching {
        RandomAccessFile(File(noBackupFilesDir, "engine-owner.lock"), "rw").use { file ->
            file.channel.tryLock()?.use { true } ?: false
        }
    }.getOrDefault(false)
    private fun retire(heavy: Boolean) {
        OverlaySnapshot.clear()
        if (retiring) return
        ready = false; retiring = true; retryHeavy = heavy || retryHeavy || store.checkpoint().attempt > 0
        retirementAt = SystemClock.uptimeMillis()
        fence.requestStop(retirementAt)
        token?.let { runCatching { host?.stop(it) } }
        completeRetirement()
        if (retiring) handler.postDelayed(drain, 250)
    }
    private val drain = object : Runnable {
        override fun run() {
            if (!retiring) return
            if (SystemClock.uptimeMillis() - retirementAt >= 3_000) terminateOwned()
            completeRetirement()
            if (retiring) handler.postDelayed(this, 250)
        }
    }
    private fun completeRetirement() {
        if (binding && hostPid == 0 && SystemClock.uptimeMillis() - retirementAt < 3_000) return
        if (verifiedPid() || !ownerReleased()) return
        if (binding) connection?.let { runCatching { unbindService(it) } }
        hostToken?.let { fence.confirmedExit(it, true, SystemClock.uptimeMillis()) }
        hostToken = null
        connection = null
        binding = false; host = null; token = null; hostPid = 0; pidIdentity = null; retiring = false; boundGeneration = -1
        pendingConfig = ""
        handler.removeCallbacks(drain)
        handler.removeCallbacks(tick)
        val stopped = store.checkpoint()
        if (!stopped.desiredOn) {
            tun?.close(); tun = null
            store.update { it.put("engineActive", false) }
            store.event("Off", "user_stop", epoch, stopped.generation)
            stopForeground(STOP_FOREGROUND_REMOVE); foreground = false
            stopSelf(latestStartId)
        } else handler.post(tick)
    }
    private fun failed(code: String, expectedGeneration: Long? = null) {
        if (!store.checkpoint().desiredOn || retiring) return
        val generation = expectedGeneration ?: boundGeneration.takeIf { it >= 0 } ?: store.checkpoint().generation
        if (!store.updateCurrent(generation) { store.put(it, Recovery.failed(store.checkpoint(it), System.currentTimeMillis(), Math.random())) }) return
        stableSince = 0; successes = 0
        phase("Recovering", code, generation)
        retire(true)
    }
    private fun probe() {
        if (probeInFlight || !ready || network == null || System.currentTimeMillis() < store.checkpoint().nextWallMs) return
        val remaining = 5_000 - (SystemClock.uptimeMillis() - lastProbe)
        if (lastProbe > 0 && remaining > 0) {
            handler.removeCallbacks(earlyProbe)
            handler.postDelayed(earlyProbe, remaining)
            return
        }
        handler.removeCallbacks(earlyProbe)
        val currentToken = token; val currentEpoch = epoch; val generation = boundGeneration
        lastProbe = SystemClock.uptimeMillis(); probeInFlight = true
        checks.execute {
            val result = runCatching {
                val synthetic = io.syn443.android.BuildConfig.DEBUG && store.read().optBoolean("testHealth")
                val connection = URL(if (synthetic) "http://203.0.113.10/generate_204" else "https://www.gstatic.com/generate_204")
                    .openConnection() as HttpURLConnection
                try { connection.connectTimeout = 5_000; connection.readTimeout = 5_000; connection.instanceFollowRedirects = false
                    connection.responseCode == 204 } finally { connection.disconnect() }
            }
            val ok = result.getOrDefault(false)
            val code = when (result.exceptionOrNull()) {
                is java.net.UnknownHostException -> "dns_resolution_failed"
                is javax.net.ssl.SSLException -> "tls_failed"
                is java.io.EOFException -> "transport_eof"
                is java.net.SocketTimeoutException -> "network_timeout"
                null -> "required_https_failed"
                else -> "transport_failed"
            }
            handler.post {
                probeInFlight = false
                if (currentToken != token || currentEpoch != epoch || !Recovery.current(store.checkpoint(), generation)) return@post
                if (ok) {
                    val now = SystemClock.uptimeMillis()
                    if (stableSince == 0L) stableSince = now
                    successes++
                    if (!store.updateCurrent(generation) { store.put(it, Recovery.stable(store.checkpoint(it), now - stableSince, successes)) }) return@post
                    phase("Online", "required_https_ok", generation)
                } else {
                    stableSince = 0; successes = 0
                    if (!store.updateCurrent(generation) { store.put(it, Recovery.failed(store.checkpoint(it), System.currentTimeMillis(), Math.random())) }) return@post
                    phase("Recovering", code, generation)
                    // A target/network failure is not evidence that the native process must restart.
                }
            }
        }
    }
    private val earlyProbe = Runnable { probe() }
    override fun onRevoke() {
        store.update { store.put(it, Recovery.command(store.checkpoint(it), false)) }
        store.event("Off", "vpn_permission_revoked", epoch)
        retire(false); stopSelf(); super.onRevoke()
    }
    override fun onDestroy() {
        handler.removeCallbacksAndMessages(null)
        if (registered) connectivity.unregisterNetworkCallback(networkCallback)
        terminateOwned()
        if (binding) connection?.let { runCatching { unbindService(it) } }
        tun?.close(); tun = null
        checks.shutdownNow()
        dnsCallbacks.shutdownNow()
        super.onDestroy()
    }
    companion object {
        const val RECONCILE = "io.syn443.RECONCILE"
        const val STOP = "io.syn443.STOP"
    }
}
