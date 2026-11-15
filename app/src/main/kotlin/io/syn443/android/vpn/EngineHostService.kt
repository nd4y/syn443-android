package io.syn443.android.vpn

import android.app.Service
import android.content.Intent
import android.os.Handler
import android.os.HandlerThread
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.os.Process
import android.os.SystemClock
import bridge.Bridge
import bridge.Runtime
import bridge.Protector
import io.syn443.host.RouteReportWindow
import java.io.File
import java.io.RandomAccessFile
import java.nio.channels.FileLock

/** No TUN creation or durable user intent here. All Go code lives in this process. */
class EngineHostService : Service() {
    private val workerThread = HandlerThread("native-engine")
    private lateinit var worker: Handler
    @Volatile private var engine: Runtime? = null
    @Volatile private var token: String? = null
    private val controlLock = Any()
    @Volatile private var desiredLease = 0L
    private var tun: ParcelFileDescriptor? = null
    private var lockFile: RandomAccessFile? = null
    private var lock: FileLock? = null
    private data class NetworkUpdate(val session: String, val name: String, val index: Int)
    @Volatile private var latestNetwork: NetworkUpdate? = null
    private val proofRunning=java.util.concurrent.atomic.AtomicBoolean()
    private var managedProofEnabled=false
    private var routePoll:Runnable?=null // native worker only
    private fun stopRoutePoll() {
        routePoll?.let(worker::removeCallbacks)
        routePoll=null
    }
    private fun startRoutePoll(session:String,request:String,runtime:Runtime) {
        stopRoutePoll()
        val window=RouteReportWindow(request,SystemClock.elapsedRealtime())
        val task=object:Runnable {
            override fun run() {
                if(routePoll!==this)return
                if(token!=session || engine!==runtime) {stopRoutePoll();return}
                val report=runCatching {runtime.routeCheckStatus()}.getOrNull()
                val parsed=report?.let {runCatching {org.json.JSONObject(it)}.getOrNull()}
                val decision=parsed?.let {window.accept(it.optString("request"),it.optBoolean("running"),SystemClock.elapsedRealtime())}
                    ?:RouteReportWindow.Decision.DISCARD
                if(report!=null && decision!=RouteReportWindow.Decision.DISCARD)
                    runCatching {callback?.routeState(session,report)}
                if(decision==RouteReportWindow.Decision.PUBLISH_AND_POLL)worker.postDelayed(this,RouteReportWindow.INTERVAL_MS)
                else stopRoutePoll()
            }
        }
        routePoll=task
        task.run()
    }
    private fun sampleIdentity(session:String) {
        if(!managedProofEnabled)return
        val runtime=engine ?: return
        if(!proofRunning.compareAndSet(false,true))return
        // SDK snapshot code can block. One disposable worker per isolated host
        // keeps it off the lease/Stop/control loop; host retirement bounds it.
        Thread({try {
            val proof=runtime.netBirdIdentityProof()
            if(proof.length in 3..512 && token==session && engine===runtime)callback?.overlayIdentity(session,proof)
        }catch(_:Exception){}finally{proofRunning.set(false)}},"native-overlay-proof").apply{isDaemon=true;start()}
    }
    private val applyNetwork = Runnable {
        latestNetwork?.let { if (it.session == token) {stopRoutePoll();engine?.updateNetwork(it.name, it.index)} }
    }

    override fun onCreate() { super.onCreate(); workerThread.start(); worker = Handler(workerThread.looper) }
    private val binder = object : IEngineHost.Stub() {
        override fun pid() = Process.myPid()
        override fun start(fd: ParcelFileDescriptor, config: String, routeSelection: String, session: String, name: String, index: Int, leaseDeadline: Long, platform: IPlatform) {
            synchronized(controlLock) {
                if (token != null) { fd.close(); platform.event(session, FAILED); return }
                token = session; callback = platform; desiredLease = leaseDeadline
            }
            worker.post {
                try {
                    val outbounds=org.json.JSONObject(config).getJSONArray("outbounds")
                    managedProofEnabled=(0 until outbounds.length()).any {
                        val outbound=outbounds.getJSONObject(it)
                        outbound.optString("managed_namespace").isNotEmpty() &&
                            (outbound.optString("setup_key").isNotEmpty() || outbound.optBoolean("recover_existing",false))
                    }
                    lockFile = RandomAccessFile(File(noBackupFilesDir, "engine-owner.lock"), "rw")
                    lock = lockFile!!.channel.tryLock() ?: error("identity already owned")
                    tun = fd
                    val created = Bridge.newRuntime(config, routeSelection, fd.fd, object : Protector {
                        override fun protect(socket: Int) {
                            ParcelFileDescriptor.fromFd(socket).use { if (!platform.protect(it, session)) error("socket protection rejected") }
                        }
                        override fun exchangeDNS(query: ByteArray): ByteArray = platform.exchangeDNS(query, session)
                        override fun physicalInterfaces(): String = platform.physicalInterfaces(session)
                    }, name, index, desiredLease)
                    synchronized(controlLock) {
                        engine = created
                        // Revocation received during construction must precede the first packet.
                        created.setLeaseDeadline(desiredLease)
                    }
                    created.start()
                    platform.event(session, READY)
                } catch (_: Exception) { platform.event(session, if (engine == null) INVALID else FAILED) }
            }
        }
        override fun leaseDeadline(session: String, deadline: Long) {
            synchronized(controlLock) {
                if (session != token) return
                desiredLease = deadline
                // Buffer even before Go exists. This setter never enters the SDK worker.
                runCatching { engine?.setLeaseDeadline(deadline) }.onFailure {
                    if (deadline != 1L) callback?.event(session, LEASE_RESTART)
                }
            }
        }
        override fun stop(session: String) {
            if (session != token) return
            leaseDeadline(session, 1L)
            worker.post { stopRoutePoll();runCatching { engine?.cancel(); engine?.close() }; finishHost() }
        }
        override fun pulse(session: String) {
            if (session != token) return
            worker.post { if (session == token && engine?.pulse() == 1L) {
                callback?.event(session, PULSE)
                engine?.netBirdStatus()?.let { callback?.overlayState(session, it) }
                if(routePoll==null)engine?.routeCheckStatus()?.let { callback?.routeState(session, it) }
                sampleIdentity(session)
            } }
        }
        override fun networkChanged(session: String, name: String, index: Int) {
            if (session != token) return
            latestNetwork = NetworkUpdate(session, name, index)
            worker.removeCallbacks(applyNetwork)
            worker.post(applyNetwork)
        }
        override fun debugFatal(session: String, kind: String) {
            if (!io.syn443.android.BuildConfig.DEBUG || android.os.Binder.getCallingUid() != Process.myUid() ||
                session != token || kind !in setOf("java", "native")) return
            worker.post {
                if (session == token && engine != null) {
                    if (kind == "native") engine?.debugFatal()
                    else throw IllegalStateException("SYN443 synthetic Java failure")
                }
            }
        }
        override fun diagnoseNetBird(session: String) {
            if (session != token) return
            worker.post { if (session == token) engine?.diagnoseNetBird() }
        }
        override fun checkRoutes(session:String,request:String) {
            if(session!=token || android.os.Binder.getCallingUid()!=Process.myUid() || request.length>32768)return
            worker.post {if(session==token) {
                val key=runCatching {org.json.JSONObject(request).getString("request")}.getOrNull()
                val runtime=engine
                if(key!=null && key.length in 1..80) {
                    if(runtime!=null && runCatching {runtime.startRouteChecks(request)}.getOrDefault(false))startRoutePoll(session,key,runtime)
                    else callback?.routeState(session,org.json.JSONObject().put("request",key)
                        .put("running",false).put("results",org.json.JSONArray()).toString())
                }
            }}
        }
        override fun cancelRouteChecks(session:String) {
            if(session!=token || android.os.Binder.getCallingUid()!=Process.myUid())return
            worker.post {if(session==token){stopRoutePoll();engine?.cancelRouteChecks()}}
        }
        override fun selectVerifiedRoute(session:String,receipt:String,checkId:String,group:String,previous:String,candidate:String) {
            if(session!=token || android.os.Binder.getCallingUid()!=Process.myUid() ||
                listOf(receipt,checkId,group,previous,candidate).any {it.length !in 1..64})return
            worker.post {if(session==token) {
                val selected=runCatching {engine?.selectVerifiedRoute(receipt,checkId,group,previous,candidate)==true}.getOrDefault(false)
                runCatching {callback?.routeSelected(session,receipt,selected)}
            }}
        }
    }
    @Volatile private var callback: IPlatform? = null
    override fun onBind(intent: Intent): IBinder = object : IEngineHost.Stub() {
        override fun pid() = binder.pid()
        override fun start(fd: ParcelFileDescriptor, config: String, routeSelection: String, token: String, name: String, index: Int, leaseDeadline: Long, platform: IPlatform) {
            binder.start(fd, config, routeSelection, token, name, index, leaseDeadline, platform)
        }
        override fun leaseDeadline(token: String, deadline: Long) = binder.leaseDeadline(token, deadline)
        override fun stop(token: String) = binder.stop(token)
        override fun pulse(token: String) = binder.pulse(token)
        override fun diagnoseNetBird(token: String) = binder.diagnoseNetBird(token)
        override fun checkRoutes(token:String,request:String)=binder.checkRoutes(token,request)
        override fun cancelRouteChecks(token:String)=binder.cancelRouteChecks(token)
        override fun selectVerifiedRoute(token:String,receipt:String,checkId:String,group:String,previous:String,candidate:String)=
            binder.selectVerifiedRoute(token,receipt,checkId,group,previous,candidate)
        override fun debugFatal(token: String, kind: String) = binder.debugFatal(token, kind)
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
