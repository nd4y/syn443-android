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
import io.syn443.policy.Policy
import io.syn443.policy.Preparation

/** Sole TUN owner, durable intent reconciler and native-process watchdog. Never loads Go. */
class TunnelService : VpnService() {
    private val handler = Handler(Looper.getMainLooper())
    private val checks = Executors.newSingleThreadExecutor()
    private val policyWorker = Executors.newSingleThreadExecutor()
    private lateinit var policies: RuntimePolicies
    private var stopPolicyObservation:(()->Unit)?=null
    private var policyJob: PolicyChecks? = null
    private var policyFetchRunning = false
    private var forcePolicyFetch = false
    private var lastPolicyCheck = -10_000L
    private var runningConfigHash = ""
    @Volatile private var destroyed = false
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
    private var healthJob: PolicyChecks? = null
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
        policies = RuntimePolicies(this)
        stopPolicyObservation=LoginController.get(this).observePolicy {
            handler.post {if(!destroyed) {handler.removeCallbacks(tick);handler.post(tick)}}
        }
        runCatching { policies.recover() }
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
        store.update { it.put("alwaysOn", isAlwaysOn).put("lockdown", isLockdownEnabled) }
        // A later foreground start may be queued on the same instance after a
        // previous Stop removed its notification. Re-promote before inspecting intent.
        if (!foreground) { notifyForeground("Подключаемся"); foreground = true }
        if (intent?.action == STOP) store.update { store.put(it, Recovery.command(store.checkpoint(it), false)); OsIntentGate.command(this, it, false) }
        if (intent?.action == "fault-revoke" && io.syn443.android.BuildConfig.DEBUG &&
            android.os.Build.HARDWARE in setOf("ranchu", "goldfish")) {
            checks.execute { onRevoke() }; return START_NOT_STICKY
        }
        if (!store.checkpoint().desiredOn) { retire(false); return START_NOT_STICKY }
        if (!OsIntentGate.allowed(this, store)) { store.update { it.put("resumeRequired", true) }; phase("NeedsAction", "explicit_resume_required"); retire(false); return START_NOT_STICKY }
        if (intent?.action == "fault-crash" && io.syn443.android.BuildConfig.DEBUG) terminateOwned()
        if (intent?.action == "fault-owner" && io.syn443.android.BuildConfig.DEBUG) retire(true)
        if (intent?.action == "fault-hang" && io.syn443.android.BuildConfig.DEBUG && verifiedPid()) Process.sendSignal(hostPid, 19)
        if (intent?.action == "netbird-diagnose" && ready) token?.let { host?.diagnoseNetBird(it) }
        if (intent?.action == "policy-refresh") forcePolicyFetch = true
        refreshNetwork()
        reconcile()
        handler.removeCallbacks(tick)
        handler.post(tick)
        return START_STICKY
    }
    private fun phase(name: String, reason: String, generation: Long? = null) {
        val policyPhase = runCatching { policies.read().journal.phase }.getOrDefault("blocked")
        if (name == "Online" && policyPhase == "applying") { phase("Connecting", "policy_gate_pending", generation); return }
        if (name == "Online" && policyPhase == "degraded") { phase("Degraded", "policy_baseline_degraded", generation); return }
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
            "NeedsPermission", "NeedsAction", "BlockedByPolicy" -> "Требуется действие пользователя"
            "Degraded" -> "Частично работает"
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
        if (destroyed) return
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
        policyJob?.cancel()
        healthJob?.cancel(); healthJob = null
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
            if (!store.adjustCheckpoint { Recovery.normalizeClock(it, System.currentTimeMillis()) }.desiredOn) { retire(false); return }
            policyTick()
            if (retiring) return
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
            val delay = if (host == null && store.read().optString("phase") == "BlockedByPolicy") 60_000L else if (host == null) (store.checkpoint().nextWallMs - System.currentTimeMillis()).coerceIn(1_000, 60_000) else if (network == null) 10_000 else 1_000
            handler.postDelayed(this, delay)
        }
    }
    private fun reconcile() {
        if (destroyed) return
        val cp = store.adjustCheckpoint { Recovery.normalizeClock(it, System.currentTimeMillis()) }
        if (!cp.desiredOn) return
        if (!OsIntentGate.allowed(this, store)) { store.update { it.put("resumeRequired", true) }; phase("NeedsAction", "explicit_resume_required"); return }
        if (store.read().optBoolean("resumeRequired")) { phase("NeedsAction", "explicit_resume_required"); return }
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
        try {
            val n = checkNotNull(network)
            val properties = checkNotNull(connectivity.getLinkProperties(n))
            val raw = try { store.config() } catch (_: Exception) {
                blackhole(); phase("BlockedByPolicy", "policy_lease_time_or_scope_invalid", cp.generation); return
            }
            val rendered = EngineConfig.render(raw, noBackupFilesDir)
            runningConfigHash = raw?.let { Policy.hash(it) }.orEmpty()
            pendingLeaseDeadline = policies.leaseDeadline(runningConfigHash)
            // An expired/invalid config cannot spend the budget while waiting for a replacement.
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
            blackhole()
            appliedLeaseDeadline = pendingLeaseDeadline
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
    private var pendingLeaseDeadline = 0L
    private var appliedLeaseDeadline = -1L
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
                EngineHostService.LEASE_RESTART -> retire(true)
                EngineHostService.FAILED -> failed("native_start_failed")
                EngineHostService.INVALID -> {
                    if (policies.read().journal.phase == "applying") { policies.rollback("native_configuration_rejected"); phase("Recovering", "policy_rollback", boundGeneration) }
                    else phase("NeedsAction", "configuration_or_capability_invalid", boundGeneration)
                    retire(false)
                }
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
                var authorized = false
                store.effectCurrent(generation) {
                    val deadline = runCatching { policies.leaseDeadline(runningConfigHash) }.getOrNull()
                    if (deadline != null) {
                        appliedLeaseDeadline = deadline
                        checkNotNull(host).start(checkNotNull(tun), pendingConfig, checkNotNull(token), iface, index, deadline, platform)
                        authorized = true
                    }
                }
                if (!authorized) retire(false)
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
        policyJob?.cancel()
        healthJob?.cancel(); healthJob = null
        OverlaySnapshot.clear()
        if (retiring) return
        token?.let { runCatching { host?.leaseDeadline(it, 1L) } }
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
        store.update { it.put("engineActive", false) }
        val stopped = store.checkpoint()
        if (!stopped.desiredOn) {
            tun?.close(); tun = null
            store.event("Off", "user_stop", epoch, stopped.generation)
            stopForeground(STOP_FOREGROUND_REMOVE); foreground = false
            stopSelf(latestStartId)
        } else handler.post(tick)
    }
    private fun failed(code: String, expectedGeneration: Long? = null) {
        if (!store.checkpoint().desiredOn || retiring) return
        if (policies.read().journal.phase == "applying") {
            policies.rollback("native_activation_failed"); phase("Recovering", "policy_rollback"); retire(true); return
        }
        val generation = expectedGeneration ?: boundGeneration.takeIf { it >= 0 } ?: store.checkpoint().generation
        if (!store.updateCurrent(generation) { store.put(it, Recovery.failed(store.checkpoint(it), System.currentTimeMillis(), Math.random())) }) return
        stableSince = 0; successes = 0
        phase("Recovering", code, generation)
        retire(true)
    }
    private fun probe() {
        if (healthJob != null || !ready || network == null || System.currentTimeMillis() < store.checkpoint().nextWallMs) return
        val remaining = 5_000 - (SystemClock.uptimeMillis() - lastProbe)
        if (lastProbe > 0 && remaining > 0) {
            handler.removeCallbacks(earlyProbe)
            handler.postDelayed(earlyProbe, remaining)
            return
        }
        handler.removeCallbacks(earlyProbe)
        val currentToken = token; val currentEpoch = epoch; val generation = boundGeneration
        val activation = policies.read().journal.activationGeneration
        val synthetic = io.syn443.android.BuildConfig.DEBUG && android.os.Build.HARDWARE in setOf("ranchu", "goldfish") && store.read().optBoolean("testHealth")
        val job = PolicyChecks(synthetic); healthJob = job
        lastProbe = SystemClock.uptimeMillis()
        checks.execute {
            val result = job.run(listOf(io.syn443.policy.Check("internet", "https_204", if (synthetic) "https://health.example.org/generate_204" else "https://www.gstatic.com/generate_204")))
            val ok = result.complete && result.values().single()
            val code = when (job.failure) {
                io.syn443.health.Failure.DNS -> "dns_resolution_failed"
                io.syn443.health.Failure.TLS -> "tls_failed"
                io.syn443.health.Failure.EOF -> "transport_eof"
                io.syn443.health.Failure.TIMEOUT -> when (job.failureStage) {
                    io.syn443.health.Stage.RESOLVE -> "dns_timeout"
                    io.syn443.health.Stage.CONNECT -> "tcp_timeout"
                    io.syn443.health.Stage.TLS -> "tls_timeout"
                    io.syn443.health.Stage.REQUEST -> "request_timeout"
                    io.syn443.health.Stage.RESPONSE -> "response_timeout"
                    else -> "network_timeout"
                }
                null -> "required_https_failed"
                else -> "transport_failed"
            }
            handler.post {
                if (healthJob !== job) return@post
                healthJob = null
                if (destroyed || retiring || !ready || currentToken != token || currentEpoch != epoch || activation != policies.read().journal.activationGeneration || !Recovery.current(store.checkpoint(), generation)) return@post
                if (!result.complete) { phase("Recovering", "health_check_" + checkNotNull(result.incompleteOutcome).name.lowercase(java.util.Locale.ROOT), generation); return@post }
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
    private fun blackhole() {
        tun = tun ?: Builder().setSession("SYN443").setMtu(1400)
            .addAddress("192.0.2.1", 30).addAddress("fd00:443::1", 126)
            .addRoute("0.0.0.0", 0).addRoute("::", 0).addDnsServer("192.0.2.2")
            .setBlocking(false).establish() ?: error("VPN unavailable")
    }
    private fun policyTick() = store.serialized {
        policyStep()
        if (host != null && ready && !retiring) {
            val deadline = runCatching { policies.leaseDeadline(runningConfigHash) }.getOrDefault(1L)
            if (deadline == 1L) {
                terminateOwned(); retire(false); phase("BlockedByPolicy", "policy_lease_time_or_scope_invalid")
            } else if (appliedLeaseDeadline > 0 && SystemClock.elapsedRealtime() >= appliedLeaseDeadline) {
                // A TUN whose native reader expired is never resurrected by a lease renewal.
                retire(true)
            } else if (deadline != appliedLeaseDeadline) {
                runCatching { host?.leaseDeadline(checkNotNull(token), deadline); appliedLeaseDeadline = deadline }
                    .onFailure { failed("native_lease_update_failed") }
            }
        }
    }
    private fun policyStep() {
        if (!store.checkpoint().desiredOn) { policyJob?.cancel(); return }
        val d = runCatching { policies.read() }.getOrElse {
            if (host != null) retire(false)
            phase("BlockedByPolicy", "policy_store_unavailable"); return
        }
        if(!d.managed)return
        if(d.enrolled && network!=null && policies.refreshAssigned(forcePolicyFetch))forcePolicyFetch=false
        if (!d.enrolled && network != null && !policyFetchRunning && policies.admitFetch(forcePolicyFetch)) {
            val delivery = checkNotNull(d.binding)
            policyFetchRunning = true; forcePolicyFetch = false
            val generation = store.checkpoint().generation; val physical = network; val currentEpoch = epoch
            val activation = d.journal.activationGeneration
            policyWorker.execute {
                val response = runCatching {
                    val c = policies.deliveryConnection(checkNotNull(physical), delivery)
                    try {
                        c.connectTimeout = 5_000; c.readTimeout = 5_000; c.instanceFollowRedirects = false
                        val cancel = Runnable { c.disconnect() }; handler.postDelayed(cancel, 12_000)
                        c.setRequestProperty("Authorization", "Bearer " + delivery.bearer)
                        c.setRequestProperty("X-SYN443-Device", delivery.device)
                        require(c.responseCode == 200 && c.date > 0)
                        val bytes = try { c.inputStream.use { input ->
                            val result = java.io.ByteArrayOutputStream(); val chunk = ByteArray(8192)
                            while (true) { val n = input.read(chunk); if (n < 0) break; require(n > 0 && result.size() + n <= 524_288); result.write(chunk, 0, n) }
                            result.toByteArray()
                        } } finally { handler.removeCallbacks(cancel) }
                        Policy.utf8(bytes).trim() to c.date
                    } finally { c.disconnect() }
                }
                handler.post {
                    policyFetchRunning = false
                    if (destroyed || !Recovery.current(store.checkpoint(), generation) || currentEpoch != epoch || policies.read().binding != delivery || policies.read().journal.activationGeneration != activation) return@post
                    response.onSuccess { (raw, time) -> runCatching { store.effectCurrent(generation) {
                        if (policies.read().journal.activationGeneration == activation && policies.read().binding == delivery) policies.received(raw, time, store.originalConfig())
                    } }
                        .onFailure { store.event(store.read().optString("phase"), "policy_response_rejected", epoch) } }
                    reconcile()
                    handler.removeCallbacks(tick); handler.post(tick)
                }
            }
        }
        if (d.journal.phase == "applying" && android.os.SystemClock.elapsedRealtime() >= d.applyDeadlineElapsed) {
            policies.rollback("activation_deadline"); retire(false); phase("Recovering", "policy_rollback"); return
        }
        if (d.journal.phase !in setOf("prepared", "applying")) {
            if (runCatching { policies.config {null} }.isFailure) {
                if (host != null) { terminateOwned(); retire(false) }
                if (prepare(this) == null) runCatching { blackhole() }
                phase("BlockedByPolicy", "policy_lease_time_or_scope_invalid")
            }
            return
        }
        val candidate = runCatching { policies.allowed(d.journal.candidate, d) }.getOrNull()
        if (candidate == null) {
            if (runCatching { policies.now(d) }.isSuccess) {
                if (d.journal.phase == "applying") policies.rollback("candidate_expired_or_revoked") else policies.discardPrepared("candidate_expired_or_revoked")
            }
            if (runCatching { policies.allowed(d.journal.active, d) }.getOrNull() == null) {
                if (host != null) { terminateOwned(); retire(false) }
                if (prepare(this) == null) runCatching { blackhole() }
                phase("BlockedByPolicy", "policy_lease_time_or_scope_invalid")
            }
            return
        }
        if (d.journal.phase == "prepared") {
            val activeAuthorized = runCatching { policies.allowed(d.journal.active, d) }.getOrNull() != null
            when (Policy.preparation(store.checkpoint().desiredOn, d.journal.active != null, activeAuthorized,
                host != null || binding || retiring, ready && !retiring, runningConfigHash != candidate.payload.contentHash,
                Recovery.replacementReady(store.checkpoint(), System.currentTimeMillis()), unsignedBaselineAllowed = !d.enrolled)) {
                Preparation.REVOKE_OWNER -> { terminateOwned(); retire(true); return }
                Preparation.BEGIN_WITHOUT_BASELINE -> { policies.begin(List(candidate.payload.activation.checks.size) { false }); return }
                Preparation.WAIT -> {
                    if (d.journal.active != null && !activeAuthorized) {
                        if (prepare(this) == null) runCatching { blackhole() }
                        phase("BlockedByPolicy", "policy_waiting_restart_budget")
                    }
                    return
                }
                Preparation.CHECK_BASELINE -> Unit
            }
        }
        if (!ready || retiring || policyJob != null || network == null) return
        if (d.journal.phase == "applying" && runningConfigHash != candidate.payload.contentHash) { retire(true); return }
        if (android.os.SystemClock.elapsedRealtime() - lastPolicyCheck < 10_000) return
        lastPolicyCheck = android.os.SystemClock.elapsedRealtime()
        val job = PolicyChecks(io.syn443.android.BuildConfig.DEBUG && android.os.Build.HARDWARE in setOf("ranchu", "goldfish") && store.read().optBoolean("testHealth")); policyJob = job
        val generation = store.checkpoint().generation; val activation = d.journal.activationGeneration
        val currentEpoch = epoch; val session = token
        policyWorker.execute {
            val batch = job.run(candidate.payload.activation.checks)
            handler.post {
                if (policyJob === job) policyJob = null
                if (destroyed || retiring || !ready || !Recovery.current(store.checkpoint(), generation) || currentEpoch != epoch || session != token || activation != policies.read().journal.activationGeneration) return@post
                if (!batch.complete) {
                    store.event(store.read().optString("phase"), "policy_checks_" + checkNotNull(batch.incompleteOutcome).name.lowercase(java.util.Locale.ROOT), epoch)
                    return@post
                }
                val results = batch.values()
                if (policies.read().journal.phase == "prepared") {
                    var began = false
                    store.effectCurrent(generation) {
                        if (policies.read().journal.activationGeneration == activation && policies.read().journal.candidate == candidate.envelope &&
                            (runningConfigHash == candidate.payload.contentHash || Recovery.replacementReady(store.checkpoint(), System.currentTimeMillis()))) {
                            began = policies.begin(results)
                        }
                    }
                    // Enrolled begin is asynchronous: keep the baseline owner until the durable
                    // applying view wakes policyTick, which then retires it before replacement.
                    if (began && !d.enrolled && runningConfigHash != candidate.payload.contentHash) retire(true)
                } else if (policies.read().journal.phase == "applying") {
                    val passed = candidate.payload.activation.checks.indices.all { !candidate.payload.activation.checks[it].required || results[it] }
                    val regressed = candidate.payload.activation.checks.indices.any { candidate.payload.activation.checks[it].required && !results[it] && policies.read().journal.baseline[it] }
                    if (passed || (!regressed && candidate.payload.activation.allowDegraded) || android.os.SystemClock.elapsedRealtime() >= policies.read().applyDeadlineElapsed) {
                        var finished = false
                        store.effectCurrent(generation) { if (policies.read().journal.activationGeneration == activation && policies.read().journal.candidate == candidate.envelope) { finished = policies.finish(results, true) } }
                        if (!finished) return@post
                        if (policies.read().journal.phase == "rolled_back") { retire(false); phase("Recovering", "policy_rollback") }
                        else { store.config(); probe() }
                    }
                }
            }
        }
    }
    override fun onRevoke() {
        // Framework callbacks may arrive on a Binder thread. Persist the revoked
        // intent first; confine ownership changes and the bounded drain to main.
        val generation = store.serialized {
            val stopped = store.update {
                store.put(it, Recovery.command(store.checkpoint(it), false))
                OsIntentGate.command(this, it, false)
            }
            val current = store.checkpoint(stopped).generation
            store.event("Off", "vpn_permission_revoked", stopped.optLong("networkEpoch"), current)
            current
        }
        handler.post {
            // Retire an older owner even if a newer Connect now needs permission.
            // A replacement already owned by that newer intent must be preserved.
            if (destroyed || boundGeneration > generation) return@post
            // The default onRevoke calls stopSelf and cancels this drain in
            // onDestroy. completeRetirement stops only after the owner exits.
            retire(false)
        }
    }
    override fun onDestroy() {
        destroyed = true; token = null; ready = false
        stopPolicyObservation?.invoke();stopPolicyObservation=null
        handler.removeCallbacksAndMessages(null)
        if (registered) connectivity.unregisterNetworkCallback(networkCallback)
        terminateOwned()
        if (binding) connection?.let { runCatching { unbindService(it) } }
        tun?.close(); tun = null
        checks.shutdownNow()
        policyJob?.cancel(); policyWorker.shutdownNow()
        healthJob?.cancel(); healthJob = null
        dnsCallbacks.shutdownNow()
        super.onDestroy()
    }
    companion object {
        const val RECONCILE = "io.syn443.RECONCILE"
        const val STOP = "io.syn443.STOP"
    }
}
