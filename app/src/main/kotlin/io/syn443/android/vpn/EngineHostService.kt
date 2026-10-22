package io.syn443.android.vpn

import android.app.Service
import android.content.Intent
import android.os.Handler
import android.os.HandlerThread
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.os.Process
import bridge.Bridge
import bridge.Runtime
import bridge.Protector
import java.io.File
import java.io.RandomAccessFile
import java.nio.channels.FileLock

/** No TUN creation or durable user intent here. All Go code lives in this process. */
class EngineHostService : Service() {
    private val workerThread = HandlerThread("native-engine")
    private lateinit var worker: Handler
    @Volatile private var engine: Runtime? = null
    @Volatile private var token: String? = null
    private var tun: ParcelFileDescriptor? = null
    private var lockFile: RandomAccessFile? = null
    private var lock: FileLock? = null
    private data class NetworkUpdate(val session: String, val name: String, val index: Int)
    @Volatile private var latestNetwork: NetworkUpdate? = null
    private val applyNetwork = Runnable {
        latestNetwork?.let { if (it.session == token) engine?.updateNetwork(it.name, it.index) }
    }

    override fun onCreate() { super.onCreate(); workerThread.start(); worker = Handler(workerThread.looper) }
    private val binder = object : IEngineHost.Stub() {
        override fun pid() = Process.myPid()
        override fun start(fd: ParcelFileDescriptor, config: String, session: String, name: String, index: Int, leaseDeadline: Long, platform: IPlatform) {
            worker.post {
                if (token != null) { fd.close(); platform.event(session, FAILED); return@post }
                token = session
                try {
                    lockFile = RandomAccessFile(File(noBackupFilesDir, "engine-owner.lock"), "rw")
                    lock = lockFile!!.channel.tryLock() ?: error("identity already owned")
                    tun = fd
                    engine = Bridge.newRuntime(config, fd.fd, object : Protector {
                        override fun protect(socket: Int) {
                            ParcelFileDescriptor.fromFd(socket).use { if (!platform.protect(it, session)) error("socket protection rejected") }
                        }
                        override fun exchangeDNS(query: ByteArray): ByteArray = platform.exchangeDNS(query, session)
                        override fun physicalInterfaces(): String = platform.physicalInterfaces(session)
                    }, name, index, leaseDeadline)
                    engine!!.start()
                    platform.event(session, READY)
                } catch (_: Exception) { platform.event(session, if (engine == null) INVALID else FAILED) }
            }
        }
        override fun leaseDeadline(session: String, deadline: Long) {
            if (session != token) return
            // This Go call is an atomic store; it does not enter the SDK/control worker.
            runCatching { engine?.setLeaseDeadline(deadline) }.onFailure { callback?.event(session, LEASE_RESTART) }
        }
        override fun stop(session: String) {
            if (session != token) return
            worker.post { runCatching { engine?.cancel(); engine?.close() }; finishHost() }
        }
        override fun pulse(session: String) {
            if (session != token) return
            worker.post { if (session == token && engine?.pulse() == 1L) {
                callback?.event(session, PULSE)
                engine?.netBirdStatus()?.let { callback?.overlayState(session, it) }
            } }
        }
        override fun networkChanged(session: String, name: String, index: Int) {
            if (session != token) return
            latestNetwork = NetworkUpdate(session, name, index)
            worker.removeCallbacks(applyNetwork)
            worker.post(applyNetwork)
        }
        override fun diagnoseNetBird(session: String) {
            if (session != token) return
            worker.post { if (session == token) engine?.diagnoseNetBird() }
        }
    }
    @Volatile private var callback: IPlatform? = null
    override fun onBind(intent: Intent): IBinder = object : IEngineHost.Stub() {
        override fun pid() = binder.pid()
        override fun start(fd: ParcelFileDescriptor, config: String, token: String, name: String, index: Int, leaseDeadline: Long, platform: IPlatform) {
            callback = platform; binder.start(fd, config, token, name, index, leaseDeadline, platform)
        }
        override fun leaseDeadline(token: String, deadline: Long) = binder.leaseDeadline(token, deadline)
        override fun stop(token: String) = binder.stop(token)
        override fun pulse(token: String) = binder.pulse(token)
        override fun diagnoseNetBird(token: String) = binder.diagnoseNetBird(token)
        override fun networkChanged(token: String, name: String, index: Int) = binder.networkChanged(token, name, index)
    }
    private fun finishHost() {
        runCatching { tun?.close() }; runCatching { lock?.release() }; runCatching { lockFile?.close() }
        Process.killProcess(Process.myPid())
    }
    override fun onUnbind(intent: Intent): Boolean {
        // An orphan never keeps ownership indefinitely if its supervisor dies.
        Handler(mainLooper).postDelayed({ finishHost() }, 3_000)
        token?.let { binder.stop(it) }
        return false
    }
    companion object { const val READY = 1; const val FAILED = 2; const val PULSE = 3; const val INVALID = 4; const val LEASE_RESTART = 5 }
}
