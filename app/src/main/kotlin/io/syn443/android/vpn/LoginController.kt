package io.syn443.android.vpn

import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume

import io.syn443.android.support.EffectiveConfig

import android.content.Context
import android.os.SystemClock
import android.provider.Settings
import android.util.AtomicFile
import androidx.core.net.toUri
import io.syn443.identity.*
import io.syn443.policy.Canonical
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.json.JSONObject
import java.io.File
import java.net.URI
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.util.Base64
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManagerFactory

/** Controller-process pilot. One bounded worker; intent writes never wait for Keystore/network. */
class LoginController private constructor(private val context:android.app.Application,
    private val namespace:String="device-login-v1",private val testExchange:IdentityExchange?=null,
    private val testBeforeQueue:(()->Unit)?=null,private val testTrustAnchor:TrustAnchor?=null,
    private val testReportVpnOn:(()->Boolean)?=null,private val testVpnStopped:(()->Boolean)?=null,
    private val monotonicMillis:()->Long=SystemClock::elapsedRealtime) {
    companion object {
        @Volatile private var instance:LoginController?=null
        @Synchronized fun get(context:Context):LoginController = instance ?: LoginController(context.applicationContext as android.app.Application).also {instance=it}
        internal fun isolatedForTest(context:Context,namespace:String,exchange:IdentityExchange,beforeQueue:(()->Unit)?=null,
            anchor:TrustAnchor?=null,reportVpnOn:(()->Boolean)?=null,monotonicMillis:()->Long=SystemClock::elapsedRealtime):LoginController {
            require(io.syn443.android.BuildConfig.DEBUG && android.os.Build.HARDWARE in setOf("ranchu","goldfish") && namespace.matches(Regex("test-[a-z0-9-]{1,40}")))
            return LoginController(context.applicationContext as android.app.Application,namespace,exchange,beforeQueue,anchor,reportVpnOn,
                monotonicMillis=monotonicMillis, testVpnStopped={
                    val status=context.contentResolver.call("content://io.syn443.control".toUri(),"status",null,null)
                        ?.getString("json")?.let(::JSONObject)
                    status!=null && status.optString("phase")=="Off" && !status.optBoolean("desiredOn") &&
                        status.optBoolean("engineStateKnown") && !status.getBoolean("engineActive")
                })
        }
    }
    private val journal=LoginJournal(context,namespace)
    private val bootstrapTrust=BootstrapTrustStore(context,if(namespace=="device-login-v1")"installation-trust-v1" else "$namespace-trust",testTrustAnchor)
    private data class InvitePreview(val id:String,val raw:String,val until:Long,var result:JSONObject?=null)
    private var invitePreview:InvitePreview?=null
    @Volatile private var invitePair=""
    @Volatile private var inviteState=""
    internal val assignedRuntime=AssignedPolicyRuntime(::boot,::elapsed,{bootstrapTrust.adaptiveAuthorityFingerprint()}){overlayMaterials[it]}
    private val commands=Any()
    @Volatile private var commandEpoch=0L
    @Volatile private var workerEpoch= -1L
    @Volatile private var workingAlias=""
    @Volatile private var cancelledGeneration= -1L
    private var activeScope:IdentityScope?=null
    private val http=BoundedHttp()
    private val worker=ThreadPoolExecutor(1,1,30,TimeUnit.SECONDS,ArrayBlockingQueue(1),
        {r->Thread(r,"syn443-login").apply {isDaemon=true}},ThreadPoolExecutor.AbortPolicy()).apply {allowCoreThreadTimeOut(true)}
    // Trust anchors are public material. This private, no-backup file never contains credentials.
    private val setup=AtomicFile(File(context.noBackupFilesDir,if(namespace=="device-login-v1")"identity-bootstrap.json" else "$namespace-bootstrap.json"))
    @Volatile private var configured=false
    @Volatile private var error=""
    @Volatile private var browser:Pair<Long,String>?=null
    @Volatile private var cached:Pair<LoginIntent,LoginPayload>?=null
    private data class OverlayAuthority(val epoch:Long,val generation:Long,val time:TrustedTime,
        val bindings:Map<String,OverlayCredentialBinding>)
    @Volatile private var overlayAuthority:OverlayAuthority?=null
    @Volatile private var overlayMaterials:Map<String,OverlayRuntimeMaterial> = emptyMap()
    private data class OverlayOwner(val session:String,val hash:String)
    @Volatile private var overlayOwner:OverlayOwner?=null
    internal fun overlayStarting(session:String,hash:String) {
        require(session.length in 16..128)
        if(overlayMaterials[hash]?.authorized()==true)overlayOwner=OverlayOwner(session,hash)
    }
    internal fun overlayStopped(session:String) {if(overlayOwner?.session==session)overlayOwner=null}
    @Volatile private var lastAssignmentFetch= -300_000L
    private var provisioningRetry=ProvisioningRetry()
    @Volatile private var lastOverlayFetch=0L
    private var overlayRetry=ProvisioningRetry()
    private data class ActivationDelivery(val generation:Long,val hash:String,val retryAt:Long,val done:Boolean)
    private var activationDelivery:ActivationDelivery?=null
    private data class PanelHint(val intent:LoginIntent,val untilElapsed:Long)
    private var panelHint:PanelHint?=null
    private var panelPoll:Pair<Long,Long>?=null
    private var deviceSourcePollAfter=0L
    private data class DeviceSourceAuthority(val generation:Long,val session:Long,val conditional:Boolean)
    private var deviceSourceAuthority:DeviceSourceAuthority?=null
    private data class TelemetryAuthority(val generation:Long,val sessionGeneration:Long,val scope:String)
    @Volatile private var telemetryAuthority:TelemetryAuthority?=null
    private val telemetryCapture by lazy {
        if(namespace=="device-login-v1")TelemetryCapture(context) else TelemetryCapture(context,"$namespace-consent")
    }
    private val telemetryDisk by lazy {
        if(namespace=="device-login-v1")TechnicalTelemetryDisk(context) else TechnicalTelemetryDisk(context,"$namespace-telemetry")
    }
    private val telemetryTransport=java.util.concurrent.atomic.AtomicReference<IdentityScope?>()
    private val runtimeTransport=java.util.concurrent.atomic.AtomicReference<IdentityScope?>()
    private val runtimeDisk by lazy {RuntimeObservationDisk(context,
        if(namespace=="device-login-v1")"runtime-observation-v1" else "$namespace-runtime")}
    private var nextRuntimeElapsed=0L
    private val telemetryPurge=java.util.concurrent.atomic.AtomicBoolean()
    @Volatile private var telemetryPressureSession: String? = null
    private var nextTelemetryPressureElapsed=0L
    private var nextTelemetryElapsed=0L
    private val deviceSourceScope=java.util.concurrent.atomic.AtomicReference<IdentityScope?>()
    private data class ChatTicket(val id:String,val generation:Long,val expires:Long,var state:String="pending",var body:String="",var reason:String="")
    private var chatTicket:ChatTicket?=null
    /** Private UI mailbox: at most one bounded operation; no content enters public status. */
    fun chatStart(id:String,generation:Long,action:String,body:String):Boolean {
        require(id.matches(Regex("[0-9a-f]{32}")) && action.length<=32 && body.toByteArray(Charsets.UTF_8).size<=360_448)
        return submitIfIdle(onAdmission={chatTicket=ChatTicket(id,generation,elapsed()+60_000)},admit={
            val s=journal.snapshot()
            s.generation==generation && s.phase in setOf(LoginPhase.PROVISIONING,LoginPhase.POLICY_CACHED,LoginPhase.REFRESHING) &&
                (chatTicket==null || chatTicket!!.expires<elapsed() || chatTicket!!.state!="pending")
        }) {
            var result="";var failure=""
            try {
                val initial=journal.snapshot();current(initial);require(initial.generation==generation)
                val original=payload(initial)
                if(initial.phase==LoginPhase.REFRESHING &&
                    LoginRecovery.resume(initial,true,true,boot(),elapsed(),anchorBoot=original.session?.time?.boot?: -1)!=LoginResume.RETRY_REFRESH) {
                    reauthenticate(initial);throw AuthException(AuthFailure.REAUTHENTICATE)
                }
                withProtocol(initial,original.bootstrap) {protocol,scope->
                    synchronized(commands) {require(chatTicket?.let {it.id==id && it.state=="pending"}==true)}
                    resumeSession(initial,original,protocol,scope,false)
                    val now=journal.snapshot();current(now);require(now.generation==generation)
                    val session=checkNotNull(payload(now).session)
                    result=protocol.chat(action,body,session,scope)
                    current(journal.snapshot())
                }
            } catch(e:AuthException) {failure=e.reason.name
                if(e.reason in setOf(AuthFailure.REAUTHENTICATE,AuthFailure.SESSION_EXPIRED))
                    runCatching {handleSessionFailure(e.reason)}
            } catch(_:Exception) {failure="UNAVAILABLE"}
            synchronized(commands) {
                val ticket=chatTicket
                if(ticket?.id==id && ticket.generation==generation && ticket.state=="pending" && workerEpoch==commandEpoch && journal.snapshot().generation==generation) {
                    ticket.body=result;ticket.reason=failure;ticket.state=if(failure.isEmpty())"done" else "failed"
                }
            }
        }
    }
    fun chatResult(id:String,generation:Long):JSONObject=synchronized(commands) {
        val t=chatTicket
        if(t==null || t.id!=id || t.generation!=generation || journal.snapshot().generation!=generation || t.expires<elapsed())
            JSONObject().put("state","gone")
        else JSONObject().put("state",t.state).put("body",t.body).put("reason",t.reason)
    }
    fun chatCancel(id:String) {synchronized(commands) {
        if(chatTicket?.id==id) {
            if(chatTicket?.state=="pending")activeScope?.cancel()
            chatTicket=null
        }
    }}
    @Volatile private var policyListener:(()->Unit)?=null
    internal fun observePolicy(listener:()->Unit):()->Unit {
        synchronized(commands) {policyListener=listener}
        return {synchronized(commands) {if(policyListener===listener)policyListener=null}}
    }
    private fun policyChanged() {runCatching {policyListener?.invoke()}}
    private fun boot()=Settings.Global.getInt(context.contentResolver,Settings.Global.BOOT_COUNT,-1).also {require(it>=0)}
    private fun elapsed()=monotonicMillis()
    private val pendingCommands=java.util.concurrent.atomic.AtomicInteger()
    private inner class Command(private val admitted:Long,private val block:()->Unit,private val quiet:Boolean=false):Runnable {
        private val completed=java.util.concurrent.atomic.AtomicBoolean()
        fun obsolete()=admitted!=commandEpoch
        fun complete() {if(completed.compareAndSet(false,true))check(pendingCommands.decrementAndGet()>=0)}
        override fun run() {try {
            val reason=try {
                if(synchronized(commands) {if(admitted!=commandEpoch)true else {workerEpoch=admitted;false}})return
                block();""
            } catch(e:AuthException) {
                if(!quiet && e.reason in setOf(AuthFailure.ACCESS_DENIED,AuthFailure.REAUTHENTICATE,AuthFailure.SESSION_EXPIRED))
                    runCatching {handleSessionFailure(e.reason)}
                e.reason.name
            }
            catch(e:LoginStorageException) {if(e.reason==LoginStorageFailure.STALE)"" else e.reason.name}
            catch(_:Exception) {"LOGIN_UNAVAILABLE"}
            if(!quiet)synchronized(commands) {if(admitted==commandEpoch)error=reason}
        } finally {
            complete()
            if(telemetryPurge.getAndSet(false))runCatching {telemetryDisk.erase()}
                .also {runCatching {runtimeDisk.clearPending()}}
        }}
    }
    private fun submit(block:()->Unit) {
        val task=synchronized(commands) {pendingCommands.incrementAndGet();Command(commandEpoch,block)}
        enqueue(task)
    }
    private fun enqueue(task:Command) {
        try {
            testBeforeQueue?.invoke()
            synchronized(commands) {
                // Logout may have admitted retirement while this older ticket was not queued.
                // A cancelled ticket must not compete with that work for the bounded queue.
                if(task.obsolete())task.complete() else worker.execute(task)
            }
        } catch(e:Exception) {task.complete();throw e}
    }
    private fun submitIfIdle(onAdmission:()->Unit={},admit:()->Boolean={true},quiet:Boolean=false,block:()->Unit):Boolean {
        val task=synchronized(commands) {
            if(pendingCommands.get()!=0 || !admit())return false
            onAdmission()
            pendingCommands.incrementAndGet();Command(commandEpoch,block,quiet)
        }
        enqueue(task);return true
    }
    private fun discardQueued() {
        val dropped=arrayListOf<Runnable>();worker.queue.drainTo(dropped)
        dropped.forEach {(it as Command).complete()}
    }
    private fun bootstrap():Bootstrap {
        val path=setup.baseFile
        if(namespace=="device-login-v1" && !path.exists() && !File(path.path+".bak").exists() && !File(path.path+".new").exists())
            return bootstrapTrust.defaultBootstrap()
        val raw=setup.openRead().use {stream->
            val buffer=ByteArray(16_385);var n=0
            while(n<buffer.size) {val count=stream.read(buffer,n,buffer.size-n);if(count<0)break;check(count>0);n+=count}
            require(n in 1..16_384);io.syn443.policy.Policy.utf8(buffer.copyOf(n))
        }
        return Canonical.json.decodeFromJsonElement<Bootstrap>(Identity.objectJSON(raw)).also {it.validate()}
    }
    private fun current(s:LoginIntent) {
        if(workerEpoch!=commandEpoch || cancelledGeneration==s.generation || !journal.isCurrent(s))throw LoginStorageException(LoginStorageFailure.STALE)
    }
    private fun commit(s:LoginIntent,next:LoginIntent):LoginIntent=synchronized(commands) {current(s);journal.commit(s,next)}
    private fun state()=StateStore.get(context)
    private fun noVpn() {
        // The disposable fixture runs outside the controller process. Reading
        // its AtomicFile directly would bypass the controller's writer lock.
        val stopped=testVpnStopped?.invoke() ?: (!state().checkpoint().desiredOn && !state().read().optBoolean("engineActive"))
        require(stopped)
    }
    internal fun loginIntent()=journal.snapshot()
    private fun adminContextWorker() {
        check(android.os.Looper.myLooper()!=android.os.Looper.getMainLooper() &&
            !Thread.currentThread().name.startsWith("Binder:"))
    }
    private fun activeAdminContext(s:LoginIntent)=s.phase in setOf(LoginPhase.POLICY_CACHED,LoginPhase.REFRESHING) &&
        s.maybeRegistered && s.deviceId.isNotEmpty() && cancelledGeneration!=s.generation
    private fun adminContextBinding(s:LoginIntent)=Identity.hash(Canonical.encode(buildJsonObject {
        put("domain","syn443.admin-device-context.v1");put("generation",s.generation);put("reauthRevision",s.reauthRevision)
        put("authority",s.authority);put("device",s.deviceId);put("owner",s.ownerTag)
        put("keyAlias",s.keyAlias);put("thumbprint",s.thumbprint)
    }).toByteArray(Charsets.UTF_8))
    private fun currentAdminContext(binding:String):Boolean=synchronized(commands) {
        val state=journal.snapshot();val owned=cached
        activeAdminContext(state) && adminContextBinding(state)==binding && owned!=null &&
            adminContextBinding(owned.first)==binding
    }
    /** Worker-only ordinary context. Validation/KeyFactory happens outside the
     * command lock; only public intent fields and copied roots are captured there. */
    internal fun adminBootstrapContext():AdminBootstrapContext? {
        adminContextWorker()
        return try {
            val captured=synchronized(commands) {
                val state=journal.snapshot();val owned=cached
                if(!activeAdminContext(state) || owned==null ||
                    adminContextBinding(owned.first)!=adminContextBinding(state))return@synchronized null
                val bootstrap=owned.second.bootstrap.copy(roots=owned.second.bootstrap.roots.toMap())
                Triple(adminContextBinding(state),state.authority,bootstrap)
            } ?: return null
            if(Identity.bootstrapAuthority(captured.third)!=captured.second || !currentAdminContext(captured.first))return null
            AdminBootstrapContext(captured.first,captured.third)
        }catch(_:Exception){null}
    }
    /** Read-only worker adapter. It borrows no VPN/device session credential and
     * never starts, refreshes, cancels or retires ordinary device authentication. */
    internal fun adminDiscoveryContext():AdminDeviceContext? {
        adminContextWorker()
        return try {
            val ordinary=adminBootstrapContext() ?:return null
            val discovery=bootstrapTrust.adminDiscovery(ordinary.bootstrap) ?:return null
            if(currentAdminContext(ordinary.binding))AdminDeviceContext(ordinary.binding,discovery) else null
        }catch(_:Exception){null}
    }
    /** Explicit signed public-metadata update, not device provisioning. A
     * service-global floor can advance during an owner race, but its ticket
     * must never be published into a different ordinary authentication context. */
    internal fun applyAdminDescriptor(expectedBinding:String,raw:String):AdminDeviceContext? {
        adminContextWorker()
        return try {
            val ordinary=adminBootstrapContext() ?:return null
            if(ordinary.binding!=expectedBinding)return null
            if(!bootstrapTrust.refreshAdminDescriptor(raw,ordinary.bootstrap))return null
            adminDiscoveryContext()?.takeIf {it.binding==expectedBinding}
        }catch(_:Exception){null}
    }
    /** Memory/public-intent reads only. Never call StateStore, Keystore or network in this block. */
    internal fun <T> assignedRead(block:(LoginIntent)->T):T=synchronized(commands) {block(journal.snapshot())}
    /** Same-UID UI projection. Only facts from the live registered session and committed policy leave the controller. */
    internal fun releaseContext():android.os.Bundle {
        val root = BootstrapTrust.installationProfile(io.syn443.android.BuildConfig.INSTALLATION_PROFILE).releaseAuthority
            ?: error("Release channel unavailable")
        val currentBoot = boot()
        return assignedRead { login ->
            val owned = checkNotNull(cached)
            require(activeAdminContext(login) && adminContextBinding(login) == adminContextBinding(owned.first))
            val session = checkNotNull(owned.second.session)
            require(session.session.deviceId == login.deviceId && session.keyThumbprint == login.thumbprint &&
                session.authority == login.authority && root.appliesTo(owned.second.bootstrap))
            val view = assignedRuntime.read(login)
            require(view.state.journal.phase in setOf("committed", "rolled_back", "degraded"))
            val now = elapsed()
            val time = session.time.window(currentBoot, now)
            require(time.upperMs < session.session.accessUntilMs)
            val policy = checkNotNull(view.permit).authorized(login, view.state, currentBoot, now).payload
            android.os.Bundle().apply {
                putBoolean("ok", true)
                putString("device", login.deviceId)
                putString("binding", adminContextBinding(login))
                putString("policy", policy.contentHash)
                putString("evaluator", policy.algorithmRevision)
                putString("schema", "policy-v" + policy.schemaVersion)
                putStringArrayList("capabilities", ArrayList(policy.requiredCapabilities))
                putLong("lowerMs", time.lowerMs)
                putLong("upperMs", time.upperMs)
            }
        }
    }
    internal fun ownsPolicy()=runCatching {journal.snapshot().phase!=LoginPhase.SIGNED_OUT}.getOrDefault(true)
    fun allowsConnect():Boolean = runCatching {
        val s=journal.snapshot()
        s.phase==LoginPhase.SIGNED_OUT || assignedRuntime.status(s).let {
            it.optBoolean("candidateValidated") || it.optBoolean("runtimeAuthorized")
        }
    }.getOrDefault(false)
    // null includes a command which has not yet published its browser URL.
    private fun browserCurrent(s:LoginIntent):Boolean? {
        if (s.phase!=LoginPhase.BROWSER || browser?.first!=s.generation) return null
        val active=cached?.takeIf { it.first==s } ?: return null
        return active.second.pending?.current(s.generation,boot(),elapsed())
    }

    fun status():JSONObject = runCatching {
        val s=journal.snapshot()
        val linkCurrent=browserCurrent(s)
        val telemetry=telemetryFor(s)
        val telemetryScope=telemetry?.scope ?: cached?.takeIf {it.first.generation==s.generation &&
            it.first.sessionGeneration==s.sessionGeneration}?.second?.session?.let(::telemetryKey)
        JSONObject().put("phase",s.phase.name).put("method",s.method).put("generation",s.generation).put("configured",configured)
            .put("busy",pendingCommands.get()>0).put("reason",error)
            .put("intentRevision",s.revision).put("canReauthenticate",LoginRecovery.canReauthenticate(s))
            .put("registrationMayExist",s.maybeRegistered)
            .put("browserReady",linkCurrent==true).put("browserExpired",linkCurrent==false)
            .put("controlPanelConfigured",panelOrigin(s)!=null)
            .put("controlPanelAvailable",adminPanelUrl(s.generation)!=null)
            .put("telemetryAvailable",telemetry!=null)
            .put("telemetryEnabled",telemetryScope?.let {runCatching {telemetryCapture.consent(it)!=null}.getOrDefault(false)}==true)
            .put("inviteState",if(s.phase==LoginPhase.INVITING)inviteState else "").put("pairCode",if(s.phase==LoginPhase.INVITING)invitePair else "")
            .put("cleanupPending",s.tombstones.size).put("assignedPolicy",assignedRuntime.status(s))
    }.getOrElse {JSONObject().put("phase","BLOCKED").put("reason","LOGIN_STORE_UNAVAILABLE")
        .put("busy",pendingCommands.get()>0)}
    fun previewInvitation(id:String,raw:String):Boolean {
        require(id.matches(Regex("[0-9a-f]{32}")) && raw.length<=BootstrapTrust.MAX_LINK)
        return submitIfIdle(onAdmission={invitePreview=InvitePreview(id,raw,elapsed()+120_000)},admit={journal.snapshot().phase==LoginPhase.SIGNED_OUT}) {
            val verified=bootstrapTrust.preview(raw)
            val result=JSONObject().put("serviceId",verified.descriptor.serviceId).put("origin",verified.descriptor.apiOrigin)
                .put("issuer",verified.descriptor.issuer).put("revision",verified.descriptor.revision)
            synchronized(commands){if(invitePreview?.id==id && workerEpoch==commandEpoch)invitePreview?.result=result}
        }
    }
    fun invitationPreview(id:String):JSONObject=synchronized(commands) {
        val preview=invitePreview
        if(preview?.id!=id || preview.until<elapsed())JSONObject().put("state","gone")
        else preview.result?.let {JSONObject(it.toString()).put("state","verified")}?:JSONObject().put("state",if(pendingCommands.get()>0)"pending" else "rejected")
    }
    fun startInvitation(id:String,manual:Boolean=true) {
        val entry=synchronized(commands) {
            val preview=checkNotNull(invitePreview);require(preview.id==id && preview.until>=elapsed() && preview.result!=null)
            require(journal.snapshot().phase==LoginPhase.SIGNED_OUT && pendingCommands.get()==0)
            commandEpoch++;invitePreview=null;preview
        }
        submit {
            val verified=bootstrapTrust.accept(entry.raw);val standard=verified.bootstrap()
            // Only an explicit operator-installed debug loopback CA can supplement
            // a matching signed service. An incoming link never supplies TLS roots.
            val b=if(io.syn443.android.BuildConfig.DEBUG && URI(standard.apiOrigin).host=="127.0.0.1") {
                val existing=runCatching {bootstrap()}.getOrNull()
                if(existing!=null && existing.copy(tlsCaDer="")==standard)standard.copy(tlsCaDer=existing.tlsCaDer)else standard
            }else standard
            val alias=DeviceKey.newAlias()
            val reserved=state().serialized {synchronized(commands){
                check(workerEpoch==commandEpoch);noVpn();require(!ManagedPolicyStore.get(context).managed())
                val before=journal.snapshot();require(before.phase==LoginPhase.SIGNED_OUT)
                writeBootstrap(b);commit(before,LoginRecovery.reserve(before,before.generation,b,alias,if(manual)"invite" else "oidc"))
            }}
            if(!manual){prepareBrowser(reserved,b);return@submit}
            workingAlias=alias
            val key=checkNotNull(DeviceKey.createIfCurrent(alias){workerEpoch==commandEpoch && cancelledGeneration!=reserved.generation && journal.isCurrent(reserved)})
            val pending=InvitationPending(InvitationOperation.claim(verified.code,key.publicKey))
            val payload=LoginPayload(b,invitation=pending)
            val prepared=protect(reserved,payload){hash->LoginRecovery.invitationPrepared(reserved,reserved.generation,Identity.thumbprint(key.publicKey),hash)}
            resumeInvitation(prepared,payload)
        }
    }
    fun rotateBootstrap(raw:String) {require(raw.length<=16_384);submit {bootstrapTrust.rotate(raw)}}
    private fun writeBootstrap(b:Bootstrap) {
        val bytes=Canonical.encode(Canonical.parse(Canonical.json.encodeToString(b))).toByteArray(Charsets.UTF_8)
        val output=setup.startWrite()
        try {output.write(bytes);setup.finishWrite(output)}catch(e:Exception){setup.failWrite(output);throw e}
        require(Identity.bootstrapAuthority(bootstrap())==Identity.bootstrapAuthority(b));configured=true
    }
    fun configure(raw:String) {
        require(io.syn443.android.BuildConfig.DEBUG && raw.toByteArray(Charsets.UTF_8).size<=16_384)
        submit {
            val b=Canonical.json.decodeFromJsonElement<Bootstrap>(Identity.objectJSON(raw));b.validate()
            val bytes=Canonical.encode(Canonical.parse(Canonical.json.encodeToString(b))).toByteArray(Charsets.UTF_8)
            state().serialized {synchronized(commands) {
                check(workerEpoch==commandEpoch);noVpn();require(journal.snapshot().phase==LoginPhase.SIGNED_OUT)
                val out=setup.startWrite()
                try {out.write(bytes);setup.finishWrite(out)} catch(e:Exception) {setup.failWrite(out);throw e}
                require(Identity.bootstrapAuthority(bootstrap())==Identity.bootstrapAuthority(b));configured=true
            }}
        }
    }
    fun recover() {submit {
        configured=runCatching {bootstrap();true}.getOrDefault(false)
        val s=journal.snapshot()
        when(s.phase) {
            LoginPhase.SIGNED_OUT->Unit
            LoginPhase.RETIRING->retire(s)
            LoginPhase.RESERVED->if(s.method=="invite"){val retired=commit(s,LoginRecovery.cancel(s,s.generation));retire(retired)}else prepareBrowser(s,bootstrap())
            else->resumeWorker(s)
        }
    }}
    fun start(expectedGeneration:Long) {
        val epoch=synchronized(commands) {
            val s=journal.snapshot()
            require(s.phase==LoginPhase.SIGNED_OUT && s.generation==expectedGeneration && pendingCommands.get()==0)
            ++commandEpoch
        }
        submit {
            val b=bootstrap();val alias=DeviceKey.newAlias()
            val s=state().serialized {synchronized(commands) {
                check(epoch==commandEpoch);noVpn();require(!ManagedPolicyStore.get(context).managed())
                val old=journal.snapshot();require(old.generation==expectedGeneration)
                commit(old,LoginRecovery.reserve(old,expectedGeneration,b,alias))
            }}
            prepareBrowser(s,b)
        }
    }
    fun startReauthentication(generation:Long,revision:Long):Boolean {
        lateinit var expected:LoginIntent
        // The ordinary browser cannot reach Keycloak through the blocked
        // data tunnel. Only a confirmed explicit VPN Stop can open sign-in.
        noVpn()
        return submitIfIdle(admit={
            val s=journal.snapshot()
            val canRenewFirst = !s.maybeRegistered && s.method=="oidc" && browserCurrent(s)==false
            if(s.generation!=generation || s.revision!=revision || !(LoginRecovery.canReauthenticate(s) || canRenewFirst))false
            else {expected=s;true}
        },onAdmission={
            commandEpoch++;browser=null;chatTicket=null;activationDelivery=null;panelHint=null;panelPoll=null
            deviceSourcePollAfter=0;deviceSourceAuthority=null;telemetryAuthority=null;nextTelemetryElapsed=0;nextRuntimeElapsed=0
        }) {
            noVpn()
            val old=payload(expected)
            val registered=LoginRecovery.canReauthenticate(expected)
            val next=if (registered) LoginRecovery.beginReauthentication(expected,generation)
                else LoginRecovery.renewFirstBrowser(expected,generation)
            val pending=Identity.newPending(generation,expected.thumbprint,boot(),elapsed())
            val protected=LoginPayload(old.bootstrap,pending=pending,registration=RegisteredLogin.from(next))
            val ready=protect(expected,protected) {hash->next.copy(protectedHash=hash)}
            synchronized(commands) {current(ready);browser=generation to Identity.authorization(old.bootstrap,pending,registered)}
        }
    }

    private fun prepareBrowser(s:LoginIntent,b:Bootstrap) {
        current(s);workingAlias=s.keyAlias;require(Identity.bootstrapAuthority(b)==s.authority)
        val key=runCatching {DeviceKey.open(s.keyAlias)}.getOrElse {
            checkNotNull(DeviceKey.createIfCurrent(s.keyAlias) {workerEpoch==commandEpoch && cancelledGeneration!=s.generation && journal.isCurrent(s)})
        }
        val thumb=Identity.thumbprint(key.publicKey)
        val pending=Identity.newPending(s.generation,thumb,boot(),elapsed())
        val payload=LoginPayload(b,pending=pending)
        val next=protect(s,payload) {hash->LoginRecovery.prepared(s,s.generation,thumb,hash)}
        synchronized(commands) {current(next);browser=next.generation to Identity.authorization(b,pending)}
    }
    private fun protect(s:LoginIntent,payload:LoginPayload,next:(String)->LoginIntent):LoginIntent =
        journal.prepare(s,payload.encode()).use {prepared->synchronized(commands) {
            current(s)
            val target=next(prepared.hash);payload.requireBound(target)
            journal.commit(s,target,prepared).also {cached=it to payload}
        }}
    private fun payload(s:LoginIntent):LoginPayload=LoginPayload.decode(journal.readProtected(s),s).also {
        require(Identity.thumbprint(DeviceKey.open(s.keyAlias).publicKey)==s.thumbprint)
        synchronized(commands) {current(s);cached=s to it}
    }
    /** Exact URL is returned only to this app's UI, not placed in the public status/log feed. */
    fun browserUrl(expectedGeneration:Long):String=synchronized(commands) {
        val s=journal.snapshot();require(s.generation==expectedGeneration && s.phase==LoginPhase.BROWSER)
        require(browserCurrent(s)==true)
        requireNotNull(browser).second
    }
    /** Navigation metadata only; the browser obtains its own control-audience
     * session and fresh MFA. No device/user credential enters the URL. */
    private fun panelOrigin(s:LoginIntent):String? {
        val active=cached?:return null
        if(s.phase !in setOf(LoginPhase.PROVISIONING,LoginPhase.POLICY_CACHED,LoginPhase.REFRESHING) ||
            active.first.generation!=s.generation || active.first.ownerTag!=s.ownerTag || active.first.deviceId!=s.deviceId)return null
        return active.second.bootstrap.controlPanelOrigin.takeIf {it.isNotEmpty()}?.also {Identity.controlOrigin(it)}
    }
    fun adminPanelUrl(expectedGeneration:Long):String?=synchronized(commands) {
        val s=journal.snapshot()
        if(s.generation!=expectedGeneration)return@synchronized null
        val hint=panelHint?:return@synchronized null
        if(hint.intent.generation!=s.generation || hint.intent.sessionGeneration!=s.sessionGeneration ||
            hint.intent.ownerTag!=s.ownerTag || hint.intent.deviceId!=s.deviceId || elapsed()>=hint.untilElapsed)return@synchronized null
        val origin=panelOrigin(s) ?: return@synchronized null
        if(s.deviceId.isEmpty())return@synchronized null
        // Origin and device come from the same current authenticated intent,
        // never from a later UI/status read or a deep-link-supplied target.
        runCatching {AdminPanelBrowser.target(origin,s.deviceId)}.getOrNull()
    }
    fun pollAdminPanel(expectedGeneration:Long):Boolean {
        lateinit var expected:LoginIntent
        return submitIfIdle(quiet=true,admit={
            val s=journal.snapshot()
            if(s.generation!=expectedGeneration || s.phase !in setOf(LoginPhase.PROVISIONING,LoginPhase.POLICY_CACHED) ||
                panelOrigin(s)==null ||
                panelPoll?.let {it.first==s.generation && elapsed()<it.second}==true)false
            else {expected=s;true}
        },onAdmission={panelPoll=expected.generation to (elapsed()+60_000)}) {
            current(expected)
            val p=payload(expected)
            withProtocol(expected,p.bootstrap) {protocol,scope->
                val until=try {protocol.controlPanelUntilElapsed(checkNotNull(p.session),scope)}catch(error:AuthException) {
                    if(error.reason !in setOf(AuthFailure.ACCESS_DENIED,AuthFailure.REAUTHENTICATE))throw error
                    0L
                }
                synchronized(commands) {current(expected);panelHint=PanelHint(expected,until)}
            }
        }
    }
    fun callback(raw:String) {
        require(raw.length<=8192)
        val expected=journal.snapshot();require(expected.phase==LoginPhase.BROWSER)
        submit {
            val payload=payload(expected);val pending=checkNotNull(payload.pending)
            val callback=Identity.callback(raw,payload.bootstrap,pending,expected.generation,boot(),elapsed())
            val consumed=synchronized(commands) {
                commit(expected,LoginRecovery.consumeCallback(expected,expected.generation)).also {browser=null}
            }
            if(callback.error!=null) {reauthenticate(consumed);return@submit}
            withProtocol(consumed,payload.bootstrap) {protocol,scope->
                val issuer=protocol.discover(scope)
                val user=protocol.exchangeCode(checkNotNull(callback.code),pending,issuer,scope)
                if(payload.registration!=null && LoginRecovery.ownerTag(payload.bootstrap,user.subject)!=consumed.ownerTag) {
                    reauthenticate(consumed)
                    throw AuthException(AuthFailure.ACCESS_DENIED)
                }
                val signedIn=LoginPayload(payload.bootstrap,user=user,registration=payload.registration)
                val auth=protect(consumed,signedIn) {hash->
                    LoginRecovery.authenticated(consumed,consumed.generation,payload.bootstrap,user,hash)
                }
                provision(auth,signedIn,protocol,scope)
            }
        }
    }
    private fun tls(b:Bootstrap,uri:URI):SSLSocketFactory {
        if(b.tlsCaDer.isEmpty() || uri.host!="127.0.0.1")return SSLSocketFactory.getDefault() as SSLSocketFactory
        require(uri.rawAuthority==URI(b.apiOrigin).rawAuthority)
        val cert=CertificateFactory.getInstance("X.509").generateCertificate(Base64.getDecoder().decode(b.tlsCaDer).inputStream())
        val store=KeyStore.getInstance(KeyStore.getDefaultType()).apply {load(null);setCertificateEntry("operator",cert)}
        val managers=TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply {init(store)}
        return SSLContext.getInstance("TLS").apply {init(null,managers.trustManagers,null)}.socketFactory
    }
    private fun <T> withProtocol(s:LoginIntent,b:Bootstrap,physical:HttpRoute?=null,block:(AuthProtocol,IdentityScope)->T):T {
        val scope=IdentityScope()
        synchronized(commands) {current(s);check(activeScope==null);activeScope=scope}
        try {
            return block(AuthProtocol(b,DeviceKey.open(s.keyAlias),exchange(s.generation,b,false,physical),::boot,::elapsed),scope)
        } finally {scope.cancel();synchronized(commands) {if(activeScope===scope)activeScope=null}}
    }
    private fun exchange(generation:Long,b:Bootstrap,retiring:Boolean,fixedPhysical:HttpRoute?=null)=IdentityExchange {method,url,headers,body,child,maxBody->
        fun admitted() {
            val current=journal.snapshot()
            require(workerEpoch==commandEpoch && current.generation==generation && (current.phase==LoginPhase.RETIRING)==retiring && cancelledGeneration!=generation)
            if(current.phase !in setOf(LoginPhase.POLICY_CACHED,LoginPhase.REFRESHING))noVpn()
        }
        // Established account requests use a physical Network even while its TUN is running.
        admitted();val uri=Identity.https(url)
        if(testExchange!=null)return@IdentityExchange testExchange.request(method,url,headers,body,child,maxBody)
        val physical=fixedPhysical?:PhysicalIdentityRoute.capture(context)
        val route=object:HttpRoute {
            override fun resolve(host:String)=physical.resolve(host)
            override fun bind(socket:java.net.Socket)=physical.bind(socket)
            override fun check() {admitted();physical.check()}
        }
        val requestLimit=if(uri.path==DeviceSubscription.RESULT_PATH)DeviceSubscription.MAX_FRAME else if(uri.path=="/v1/chat/uploads/part")360_448 else if(uri.path.startsWith("/v1/chat/"))32_768 else 8192
        http.exchange(method,url,headers,body,child,maxBody=maxBody,factory=tls(b,uri),route=route,maxRequestBody=requestLimit)
    }
    private fun resumeInvitation(initial:LoginIntent,original:LoginPayload) {
        var state=initial;var pending=checkNotNull(original.invitation)
        lastAssignmentFetch=elapsed()
        val scope=IdentityScope();var registered:Pair<LoginIntent,LoginPayload>?=null
        synchronized(commands){current(state);check(activeScope==null);activeScope=scope}
        try {
            val protocol=InvitationProtocol(original.bootstrap,DeviceKey.open(state.keyAlias),exchange(state.generation,original.bootstrap,false),::boot,::elapsed)
            fun save(next:InvitationPending) {
                val before=state;val value=LoginPayload(original.bootstrap,invitation=next)
                state=protect(before,value){hash->LoginRecovery.invitationProgress(before,before.generation,next.reply?.state?.ownerTag?:"",next.completion!=null,hash)}
                pending=next
            }
            var time=pending.time
            if(time==null || runCatching {time.window(boot(),elapsed())}.isFailure) {
                time=protocol.time(scope,time);save(pending.copy(time=time))
            }
            val now=checkNotNull(time)
            if(pending.reply==null) {
                val claimed=protocol.claim(pending.claim,now,scope);save(pending.copy(reply=claimed,time=claimed.time))
            } else if(pending.completion==null) {
                val previous=checkNotNull(pending.reply)
                val observed=protocol.status(InvitationOperation.mutation("status",previous.state.id),previous,now,scope)
                save(pending.copy(reply=observed,time=observed.time))
            }
            val reply=checkNotNull(pending.reply)
            synchronized(commands){current(state);invitePair=reply.state.pairCode;inviteState=reply.state.state}
            if(reply.state.error in setOf("authorization_changed","reauthentication_required"))throw AuthException(AuthFailure.REAUTHENTICATE)
            if(reply.state.error=="unsupported_capabilities")throw AuthException(AuthFailure.ACCESS_DENIED)
            if(reply.state.state in setOf("expired","revoked"))throw AuthException(AuthFailure.ACCESS_DENIED)
            if(reply.state.state !in setOf("ready","completed"))throw AuthException(AuthFailure.PENDING)
            if(pending.completion==null)save(pending.copy(completion=InvitationOperation.mutation("complete",reply.state.id)))
            val completed=protocol.complete(checkNotNull(pending.completion),reply,checkNotNull(pending.time),scope)
            val declared=Identity.objectJSON(pending.claim.body).getValue("capabilities").jsonArray.map {it.jsonPrimitive.content}
            val session=LoginPayload(original.bootstrap,session=completed.session,advertisedCapabilities=CapabilityNegotiation.canonical(declared));val before=state
            val next=protect(before,session){hash->LoginRecovery.invited(before,before.generation,completed,hash)}
            synchronized(commands){current(next);invitePair="";inviteState=""}
            registered=next to session
        } finally {scope.cancel();synchronized(commands){if(activeScope===scope)activeScope=null}}
        registered.let {(next,payload)->withProtocol(next,payload.bootstrap){protocol,child->fetchAssignment(next,payload,protocol,child)}}
    }
    private fun provision(initial:LoginIntent,p:LoginPayload,protocol:AuthProtocol,scope:IdentityScope) {
        var s=initial;val user=checkNotNull(p.user)
        repeat(2) {
            if(s.reauthRevision==0L && (s.phase==LoginPhase.CLEANUP || s.tombstones.any {it.ownerTag==s.ownerTag})) {
                val next=LoginRecovery.beginCleanup(s,s.generation,boot(),elapsed())
                if(next!=s)s=commit(s,next)
                val op=checkNotNull(s.operation);protocol.cleanup(op,user,scope)
                s=commit(s,LoginRecovery.cleanupAcknowledged(s,s.generation,op.body))
            }
        }
        val public=DeviceKey.open(s.keyAlias).publicKey
        val next=LoginRecovery.beginEnrollment(s,s.generation,public,boot(),elapsed())
        if(next!=s)s=commit(s,next)
        var operation=checkNotNull(s.operation)
        var reply=protocol.enroll(operation,user,scope)
        if(operation.enrollmentCapabilities().toSet()!=IdentityOperation.supportedCapabilities.toSet()) {
            // This call returned its ACK. A new persisted operation can safely
            // declare current modules without rewriting an unknown old request.
            s=commit(s,LoginRecovery.renewEnrollmentAfterAck(s,s.generation,operation.body,reply,public,boot(),elapsed()))
            operation=checkNotNull(s.operation)
            reply=protocol.enroll(operation,user,scope)
        }
        if(p.registration!=null && reply.session.deviceId!=s.deviceId) {
            reauthenticate(s)
            throw AuthException(AuthFailure.ACCESS_DENIED)
        }
        val sessionPayload=LoginPayload(p.bootstrap,session=reply,registration=p.registration,
            advertisedCapabilities=CapabilityNegotiation.canonical(operation.enrollmentCapabilities()))
        val registered=protect(s,sessionPayload) {hash->LoginRecovery.enrolled(s,s.generation,reply,hash)}
        fetchAssignment(registered,sessionPayload,protocol,scope)
    }
    private fun fetchAssignment(s:LoginIntent,p:LoginPayload,protocol:AuthProtocol,scope:IdentityScope) {
        current(s)
        lastAssignmentFetch=elapsed()
        val response=protocol.policy(checkNotNull(p.session),scope)
        var previous=journal.readAssignment(s)?:AssignmentState()
        if(s.phase==LoginPhase.PROVISIONING && s.reauthRevision>0 && previous.journal.phase=="applying")
            previous=Assignments.abort(previous,s,p,"interrupted_activation")
        val next=Assignments.receive(previous,s,p,response,boot(),elapsed())
        val receipt=Assignments.receipt(next,s,p,boot(),elapsed())
        val target=if(s.phase==LoginPhase.POLICY_CACHED && s.policyHash==receipt)s
            else LoginRecovery.policyCached(s,s.generation,receipt,s.protectedHash)
        val accepted=persistAssignment(s,p,next,target)
        synchronized(commands) {
            current(accepted)
            deviceSourceAuthority=if(response.deviceSourceFetch)DeviceSourceAuthority(accepted.generation,accepted.sessionGeneration,
                response.deviceSourceValidators) else null
            telemetryAuthority=if(response.technicalTelemetry) {
                val session=checkNotNull(p.session)
                TelemetryAuthority(accepted.generation,accepted.sessionGeneration,telemetryKey(session))
            } else null
        }
        reconcileTelemetrySchedule(response.technicalTelemetry)
        prepareOverlays(accepted,p,next,protocol,scope)
    }
    private fun persistAssignment(s:LoginIntent,p:LoginPayload,next:AssignmentState,target:LoginIntent=s,canCommit:()->Boolean={true}):LoginIntent {
        val runtime=assignedRuntime.prepare(target,p,next)
        var accepted=target
        journal.prepareAssignment(s,next).use {prepared->state().serialized {synchronized(commands) {
            current(s);if(!canCommit())throw LoginStorageException(LoginStorageFailure.STALE)
            journal.commitAssignment(s,prepared)
            accepted=if(target==s)s else commit(s,target)
            cached=accepted to p;assignedRuntime.publish(runtime)
        }}}
        policyChanged()
        return accepted
    }
    private fun clearOverlays() {
        lastOverlayFetch=0L;overlayRetry=ProvisioningRetry()
        overlayAuthority=null
        overlayOwner=null
        val previous=overlayMaterials;overlayMaterials=emptyMap()
        previous.values.forEach{it.close()}
    }
    private fun overlayAdmitted(binding:OverlayCredentialBinding,hash:String,generation:Long):Boolean {
        val authority=overlayAuthority ?: return false
        return authority.epoch==commandEpoch && authority.generation==generation &&
            cancelledGeneration!=generation && authority.bindings[hash]==binding
    }
    private fun overlayWindow(hash:String,generation:Long):TimeWindow {
        val authority=checkNotNull(overlayAuthority)
        check(authority.epoch==commandEpoch && authority.generation==generation && hash in authority.bindings)
        // A process cannot survive reboot. The worker admitted this anchor using
        // actual BOOT_COUNT; native/Binder reads need only its immutable boot.
        return authority.time.window(authority.time.boot,elapsed())
    }
    private fun overlayVault(binding:OverlayCredentialBinding,hash:String,generation:Long)=OverlayVault(context,
        ManagedOverlay.namespace(binding.address),{record->overlayAdmitted(binding,hash,generation) &&
            runCatching{OverlayEnrollments.requireIdentity(record,binding,generation)}.isSuccess},
        {overlayWindow(hash,generation).upperMs},if(namespace=="device-login-v1")"managed-overlay-v1" else namespace)
    private fun overlayProvisioner(s:LoginIntent,p:LoginPayload,binding:OverlayCredentialBinding,hash:String,
        protocol:AuthProtocol?=null,scope:IdentityScope?=null,network:Boolean=true):ManagedOverlayProvisioner {
        fun delivery(operation:OverlayOperation,consume:Boolean):OverlayDeliveryReply {
            if(!network)throw AuthException(AuthFailure.TRANSPORT)
            current(s)
            if(!consume)lastOverlayFetch=elapsed()
            fun request(api:AuthProtocol,child:IdentityScope)=api.overlay(operation,consume,binding,checkNotNull(p.session),child)
            val delivered=if(protocol!=null)request(protocol,checkNotNull(scope))
                else withProtocol(s,p.bootstrap){api,child->request(api,child)}
            adoptOverlayTime(s,p,binding,hash,delivered.time)
            return delivered
        }
        return ManagedOverlayProvisioner(overlayVault(binding,hash,s.generation),binding,s.generation,p.bootstrap.roots,
            {overlayAdmitted(binding,hash,s.generation)},{overlayWindow(hash,s.generation)},
            {checkNotNull(delivery(it,false).envelope)},{delivery(it,true);Unit})
    }
    private fun consumeOverlay(provisioner:ManagedOverlayProvisioner) {
        runCatching{provisioner.acknowledge()}.exceptionOrNull()?.let {e->
            if(e is AuthException && e.reason in setOf(AuthFailure.ACCESS_DENIED,AuthFailure.REAUTHENTICATE))throw e
            if(e is LoginStorageException && e.reason==LoginStorageFailure.STALE)throw e
        }
    }
    /** The addressed API reply already passed proof/signature checks. Persist
     * its trusted Date before the vault verifies a newly issued not-before time;
     * otherwise an older policy anchor can reject a valid fresh credential.
     * Neither signed lease nor identity/activation generation changes here. */
    private fun adoptOverlayTime(s:LoginIntent,p:LoginPayload,binding:OverlayCredentialBinding,hash:String,time:TrustedTime) {
        current(s);require(overlayAdmitted(binding,hash,s.generation))
        val before=checkNotNull(journal.readAssignment(s));val at=elapsed();val currentBoot=boot()
        val previous=checkNotNull(before.time).window(currentBoot,at);val observed=time.window(currentBoot,at)
        require(observed.upperMs>=previous.lowerMs && observed.lowerMs<=Math.addExact(previous.upperMs,30_000))
        val next=before.copy(time=time)
        require(listOf(true,false).any{candidate->runCatching {
            Assignments.authorized(next,s,p,currentBoot,at,candidate).payload.contentHash==hash
        }.getOrDefault(false)})
        persistAssignment(s,p,next)
        synchronized(commands) {
            current(s);require(overlayAdmitted(binding,hash,s.generation))
            overlayAuthority=checkNotNull(overlayAuthority).copy(time=time)
        }
    }
    /** Persist namespace ownership before any grant/SDK effect. Preparation can
     * recover a cached/keyless identity offline; a missing grant does not invent
     * authority or displace an independently usable active configuration. */
    private fun prepareOverlays(initial:LoginIntent,p:LoginPayload,assignment:AssignmentState,
        protocol:AuthProtocol?=null,scope:IdentityScope?=null,network:Boolean=true) {
        current(initial)
        val versions=listOfNotNull(
            runCatching{Assignments.authorized(assignment,initial,p,boot(),elapsed(),true)}.getOrNull(),
            runCatching{Assignments.authorized(assignment,initial,p,boot(),elapsed())}.getOrNull()).distinctBy{it.payload.contentHash}
        val bindings=versions.mapNotNull {v->OverlayAssignments.resolve(v,p.bootstrap.serviceId,initial.ownerTag,initial.deviceId,initial.thumbprint)?.let{v.payload.contentHash to it}}.toMap()
        var s=initial
        for(owned in bindings.values.map{ManagedOverlay.namespace(it.address)}.distinct()) {
            if(owned !in s.overlayNamespaces) {
                val next=LoginRecovery.claimOverlay(s,s.generation,owned)
                s=commit(s,next);synchronized(commands){current(s);cached=s to p}
            }
        }
        synchronized(commands) {
            current(s);overlayAuthority=OverlayAuthority(commandEpoch,s.generation,checkNotNull(assignment.time),bindings.toMap())
            val keep=overlayMaterials.filter{(hash,material)->bindings[hash]==material.binding && material.authorized() &&
                (material.available() || overlayOwner?.hash==hash)}
            val removed=overlayMaterials.filterKeys{it !in keep};overlayMaterials=keep
            removed.values.forEach{it.close()}
        }
        // An active and a candidate config can name the same SDK identity with
        // different grants. Never alternately discard each other's pending key.
        // Let its current native owner finish registration; otherwise prepare
        // the candidate (versions are ordered candidate, active). Once confirmed,
        // both configs can independently prepare the same keyless SDK identity.
        val selected=bindings.entries.groupBy{ManagedOverlay.namespace(it.value.address)}.values.flatMap{group->
            val first=group.first();val record=overlayVault(first.value,first.key,s.generation).snapshot()
            if(record?.phase in setOf(OverlayPhase.REGISTERED,OverlayPhase.ERASING,OverlayPhase.ERASED,OverlayPhase.ACKNOWLEDGED))group.map{it.key}
            else {
                val preferred=group.firstOrNull{it.key==overlayOwner?.hash && overlayMaterials[it.key]?.launchMode=="enrolling"} ?: first
                group.filter{it.value.reference==preferred.value.reference && it.value.version==preferred.value.version &&
                    it.value.securityEpoch==preferred.value.securityEpoch}.map{it.key}
            }
        }.toSet()
        for((hash,binding) in bindings) {
            if(hash !in selected)continue
            if(overlayMaterials[hash]?.let{!it.waiting && (it.available() || it.authorized() && overlayOwner?.hash==hash)}==true) {
                if(network && overlayVault(binding,hash,s.generation).snapshot()?.phase==OverlayPhase.ERASED)
                    consumeOverlay(overlayProvisioner(s,p,binding,hash,protocol,scope))
                continue
            }
            var secret:OverlaySetupSecret?=null
            try {
                secret=overlayProvisioner(s,p,binding,hash,protocol,scope,network).prepare()
                val record=checkNotNull(overlayVault(binding,hash,s.generation).snapshot())
                val material=OverlayRuntimeMaterial(binding,hash,s.generation,if(secret==null)record.identityEvidence else "",secret,
                    {overlayAdmitted(binding,hash,s.generation)},{overlayWindow(hash,s.generation)},reconciling=record.phase==OverlayPhase.RECONCILING)
                try {synchronized(commands) {
                    current(s);material.requireCurrent()
                    val old=overlayMaterials[hash];overlayMaterials=(overlayMaterials+(hash to material)).toMap();old?.close();secret=null
                }}catch(e:Exception){material.close();throw e}
                if(network && record.phase==OverlayPhase.ERASED)
                    consumeOverlay(overlayProvisioner(s,p,binding,hash,protocol,scope))
            } catch(e:AuthException) {
                if(e.reason !in setOf(AuthFailure.TRANSPORT,AuthFailure.THROTTLED,AuthFailure.UNAVAILABLE,
                    AuthFailure.INVALID_REPLY,AuthFailure.PENDING,AuthFailure.CONFLICT))throw e
            } catch(e:LoginStorageException) {if(e.reason==LoginStorageFailure.STALE)throw e
            } catch(_:IllegalArgumentException) { // Invalid/missing material remains unavailable, never an operator fallback.
            } finally {secret?.close()}
            // A missing optional setup grant must not remove a valid base
            // policy. Native receives a local-only closed overlay placeholder:
            // no SDK constructor, filesystem work or private-route fallback.
            if(overlayMaterials[hash]?.let{!it.waiting && it.available()}!=true) {
                val waiting=OverlayRuntimeMaterial(binding,hash,s.generation,"",null,
                    {overlayAdmitted(binding,hash,s.generation)},{overlayWindow(hash,s.generation)},waiting=true)
                try {synchronized(commands) {
                    current(s);waiting.requireCurrent()
                    val old=overlayMaterials[hash];overlayMaterials=(overlayMaterials+(hash to waiting)).toMap();old?.close()
                }}catch(e:Exception){waiting.close();throw e}
            }
        }
        // A delivery may have durably advanced the trusted time. Do not publish
        // the older argument over that freshly anchored worker view.
        val prepared=assignedRuntime.prepare(s,p,checkNotNull(journal.readAssignment(s)))
        synchronized(commands){current(s);assignedRuntime.publish(prepared)}
        policyChanged()
    }
    internal fun renderAssigned(raw:String,stateRoot:File, observe: ((EffectiveConfig) -> Unit)? = null):String {
        val material=overlayMaterials[io.syn443.policy.Policy.hash(raw)]
        if(material==null) {
            val outbounds=JSONObject(raw).getJSONArray("outbounds")
            if((0 until outbounds.length()).any{outbounds.getJSONObject(it).optString("type")=="netbird"})throw OverlayLaunchPending()
            return EngineConfig.renderObserved(raw,stateRoot,observe)
        }
        if(!material.available())throw OverlayLaunchPending()
        return try{EngineConfig.renderManaged(raw,stateRoot,material,observe)}catch(_:IllegalStateException){throw OverlayLaunchPending()}
    }
    internal fun overlayHasSetup(hash:String)=overlayMaterials[hash]?.launchMode=="enrolling"
    internal fun overlayLaunchMode(hash:String)=overlayMaterials[hash]?.takeIf{it.available()}?.launchMode.orEmpty()
    internal fun overlayNeedsRotation(hash:String)=overlayMaterials[hash]?.let{it.identityEvidence.isNotEmpty() && it.available()}==true
    /** Private Binder input only. The service supplies a RAM-only host/config/
     * recovery fence; it is checked before and after durable registration. */
    internal fun overlayIdentity(session:String,hash:String,raw:String,stillCurrent:()->Boolean):Boolean {
        if(raw.length !in 1..512 || !stillCurrent())return false
        val expected=OverlayOwner(session,hash)
        fun owned()=overlayOwner==expected && stillCurrent()
        return submitIfIdle(admit={owned() && overlayMaterials[hash]?.authorized()==true}) {
            val s=journal.snapshot();current(s);val p=payload(s)
            val binding=checkNotNull(overlayAuthority?.bindings?.get(hash))
            require(overlayAdmitted(binding,hash,s.generation) && owned())
            val proof=Identity.objectJSON(raw);require(proof.keys==setOf("namespace","identityEvidence"))
            fun text(key:String)=proof.getValue(key).let{require(it is kotlinx.serialization.json.JsonPrimitive && it.isString);it.content}
            val provisioner=overlayProvisioner(s,p,binding,hash)
            val registered=provisioner.registered(text("namespace"),text("identityEvidence"),::owned)
            val material=OverlayRuntimeMaterial(binding,hash,s.generation,registered.identityEvidence,null,
                {overlayAdmitted(binding,hash,s.generation)},{overlayWindow(hash,s.generation)})
            synchronized(commands) {
                current(s);require(owned());material.requireCurrent()
                val old=overlayMaterials[hash];overlayMaterials=(overlayMaterials+(hash to material)).toMap();old?.close()
            }
            prepareOverlays(s,p,checkNotNull(journal.readAssignment(s)),network=false)
            // No network error can recreate erased setup material. The durable
            // ERASED operation retries independently on later preparation.
            consumeOverlay(provisioner)
        }
    }
    internal fun assignmentTicket():AssignedPolicyRuntime.Ticket = assignedRead {assignedRuntime.ticket(it)}
    /** Commands persist on the identity worker. The native caller observes the resulting view;
     * acceptance is not a completed transition, and a lost/stale command grants no new permit. */
    private fun transitionAssignment(ticket:AssignedPolicyRuntime.Ticket,invalidate:Boolean=false,canCommit:()->Boolean={true},
        change:(AssignmentState,LoginIntent,LoginPayload)->AssignmentState):Boolean = submitIfIdle(onAdmission={
        if(invalidate && runCatching {assignmentTicket()==ticket}.getOrDefault(false)) {assignedRuntime.clear();policyChanged()}
    }) {
        val s=journal.snapshot();current(s)
        require(s.phase==LoginPhase.POLICY_CACHED && s.generation==ticket.loginGeneration &&
            s.reauthRevision==ticket.reauthRevision && s.policyHash==ticket.receipt)
        val p=payload(s);val before=checkNotNull(journal.readAssignment(s))
        require(before.journal.activationGeneration==ticket.activation)
        if(!canCommit())throw LoginStorageException(LoginStorageFailure.STALE)
        val after=change(before,s,p)
        val accepted=persistAssignment(s,p,after,canCommit=canCommit)
        // Activation consumes already prepared local authority. Credential
        // network retries belong to synchronization/explicit retry, not each
        // begin/commit transition on its bounded activation deadline.
        prepareOverlays(accepted,p,after,network=false)
    }
    internal fun beginAssignment(ticket:AssignedPolicyRuntime.Ticket,baseline:List<Boolean>):Boolean {
        val values=baseline.toList();require(values.size in 1..8)
        return transitionAssignment(ticket) {before,s,p->
            require(assignedRuntime.prepare(s,p,before).candidate!=null)
            Assignments.begin(before,s,p,values,boot(),elapsed())
        }
    }
    internal fun finishAssignment(ticket:AssignedPolicyRuntime.Ticket,actual:List<Boolean>,started:Boolean,canCommit:()->Boolean={true}):Boolean {
        val values=actual.toList();require(values.size in 1..8)
        return transitionAssignment(ticket,canCommit=canCommit) {before,s,p->Assignments.finish(before,s,p,values,started,boot(),elapsed())}
    }
    internal fun abortAssignment(ticket:AssignedPolicyRuntime.Ticket,reason:String):Boolean {
        require(reason in setOf("activation_deadline","interrupted_activation","native_activation_failed","candidate_expired_or_revoked","required_route_failed"))
        // Invalidate the old view before waiting for encrypted persistence. A stale ticket cannot
        // erase the current account's permit; the worker independently checks the journal again.
        return transitionAssignment(ticket,true) {before,s,p->Assignments.abort(before,s,p,reason)}
    }
    /** Visible UI asks; controller owns rate/queue/generation fences. Hidden UI has no timer. */
    fun pollProvisioning(expectedGeneration:Long):Boolean {
        val expected=journal.snapshot()
        if(expected.generation!=expectedGeneration)return false
        val assignment=if(expected.phase==LoginPhase.POLICY_CACHED)assignedRuntime.status(expected) else null
        var next:ProvisioningRetry?=null
        return submitIfIdle(admit={
            val s=journal.snapshot()
            val provisioning=s.phase in setOf(LoginPhase.PROVISIONING,LoginPhase.INVITING,LoginPhase.ENROLLING) &&
                error in setOf("PENDING","TRANSPORT","THROTTLED","UNAVAILABLE")
            if(s!=expected || !(provisioning || needsForegroundRenewal(s.phase.name,error,assignment)))false
            else {
                next=provisioningRetry.admit(s.generation,elapsed(),lastAssignmentFetch.coerceAtLeast(0),error=="THROTTLED")
                next!=null
            }
        },onAdmission={provisioningRetry=checkNotNull(next)}) {
            current(expected);resumeWorker(expected)
        }
    }
    internal fun refreshAssignment(force:Boolean, visibleGeneration:Long?=null):Boolean {
        val s=journal.snapshot()
        if(s.phase !in setOf(LoginPhase.POLICY_CACHED,LoginPhase.REFRESHING))return false
        if(visibleGeneration!=null && (s.generation!=visibleGeneration || reportVpnOn()))return false
        val remaining=if(force)null else runCatching {
            val view=assignedRuntime.read(s);val raw=view.state.journal.active ?: view.state.journal.candidate
            val policy=checkNotNull(assignedRuntime.allowed(s,raw))
            policy.payload.refreshAfterMs-checkNotNull(view.state.time).window(boot(),elapsed()).upperMs
        }.getOrNull()
        val previous=lastAssignmentFetch
        if(!assignmentRefreshDue(elapsed()-previous,remaining,force))return !force && visibleGeneration==null &&
            (refreshOverlayCredential() || reportActivation() || syncDeviceSubscription() || syncTechnicalTelemetry() || syncRuntimeObservation())
        if(runCatching {assignedRuntime.read(s).state.journal.phase=="applying"}.getOrDefault(false))return false
        return submitIfIdle(admit={journal.isCurrent(s) && lastAssignmentFetch==previous},
            onAdmission={lastAssignmentFetch=elapsed()}) {
            current(s);resumeWorker(s)
        }
    }
    /** Piggyback on the existing supervisor tick and physical account transport. */
    private fun reportVpnOn():Boolean = testReportVpnOn?.invoke() ?: state().checkpoint().desiredOn
    internal fun cancelDeviceSubscription() {deviceSourceScope.getAndSet(null)?.cancel()}
    internal fun cancelTechnicalTelemetry() {
        telemetryTransport.getAndSet(null)?.cancel();runtimeTransport.getAndSet(null)?.cancel()
    }
    internal fun cancelOptionalNetworkWork() {cancelDeviceSubscription();cancelTechnicalTelemetry()}
    private fun purgeTechnicalTelemetryWhenIdle() {
        telemetryPurge.set(true)
        // A running/queued command already drains this flag. Do not consume the retirement slot.
        runCatching {submitIfIdle(quiet=true) {}}
    }
    private fun disableTelemetryCapture() {
        val session = telemetryCapture.activeConsent()?.session
        telemetryCapture.disable()
        if (session != null && namespace == "device-login-v1") runCatching { TelemetryWork.cancel(context, session) }
    }
    private fun reconcileTelemetrySchedule(enabled: Boolean) {
        if (namespace != "device-login-v1") return
        val consent = telemetryCapture.activeConsent() ?: return
        runCatching {
            if (enabled) TelemetryWork.schedule(context, consent.session) else TelemetryWork.cancel(context, consent.session)
        }
    }
    private fun eraseTechnicalTelemetryOnRetirement() {
        runCatching {disableTelemetryCapture()}
        runCatching {telemetryDisk.erase()}
        runCatching {runtimeDisk.erase()}
    }
    private fun telemetryFor(s:LoginIntent)=telemetryAuthority?.takeIf {
        s.phase==LoginPhase.POLICY_CACHED && it.generation==s.generation && it.sessionGeneration==s.sessionGeneration
    }
    private fun telemetryKey(session:SessionReply)=Identity.hash(
        ("syn443/telemetry/"+session.session.deviceId+"/"+session.keyThumbprint).toByteArray(Charsets.US_ASCII))
    internal fun chooseTechnicalTelemetry(generation:Long,enabled:Boolean):Boolean=state().serialized {
        synchronized(commands) {
            val s=journal.snapshot()
            if(s.generation!=generation)return@synchronized false
            if(enabled) {
                val authority=telemetryFor(s) ?: return@synchronized false
                telemetryCapture.enable(authority.scope,state().read().optLong("eventSequence"))
                nextTelemetryElapsed=0
                nextRuntimeElapsed=0
            } else {
                cancelTechnicalTelemetry()
                disableTelemetryCapture()
                purgeTechnicalTelemetryWhenIdle()
            }
            true
        }
    }.also { changed -> if (changed && enabled) reconcileTelemetrySchedule(true) }
    private fun syncTechnicalTelemetry():Boolean {
        val snapshot = state().read()
        if (!(testReportVpnOn?.invoke() ?: snapshot.optBoolean("desiredOn"))) return false
        lateinit var expected:LoginIntent
        lateinit var authority:TelemetryAuthority
        lateinit var consent:TelemetryCapture.Consent
        return submitIfIdle(quiet=true,admit={
            val state=journal.snapshot()
            val active=telemetryFor(state)
            val preference=active?.let {runCatching {telemetryCapture.consent(it.scope)}.getOrNull()}
            if (active == null || preference == null) return@submitIfIdle false
            val now = elapsed()
            if (now < nextTelemetryElapsed) {
                if (now < nextTelemetryPressureElapsed) return@submitIfIdle false
                nextTelemetryPressureElapsed = now + TelemetryCapture.URGENT_MS
                if (telemetryPressureSession != preference.session && !TelemetryCapture.hasNewPressure(snapshot, preference.through)) return@submitIfIdle false
            }
            expected=state;authority=active;consent=preference;true
        },onAdmission={
            val now = elapsed()
            if (now >= nextTelemetryElapsed) nextTelemetryElapsed = now + TelemetryCapture.ROUTINE_MS
            nextTelemetryPressureElapsed = now + TelemetryCapture.URGENT_MS
        }) {
            fun currentConsent() {
                current(expected)
                require(telemetryFor(expected)==authority && telemetryCapture.consent(authority.scope)?.session==consent.session)
            }
            currentConsent()
            val p=payload(expected)
            val session=checkNotNull(p.session)
            val now=session.time.window(boot(),elapsed()).upperMs
            val queueKey=Identity.hash(("syn443/telemetry-queue/"+authority.scope+"/"+consent.session).toByteArray(Charsets.US_ASCII))
            val old=telemetryDisk.read(queueKey)
            var queue=old
            val (new,through)=telemetryCapture.sample(state().read(),consent,io.syn443.android.BuildConfig.VERSION_CODE)
            for(event in new)queue=queue.offer(queueKey,event)
            queue=queue.expired(queueKey,now)
            currentConsent()
            if(queue!=old)telemetryDisk.write(queueKey,queue)
            val batch = queue.peek(queueKey)
            val urgent = TelemetryCapture.isUrgent(queue)
            telemetryPressureSession = consent.session.takeIf { urgent }
            if (!urgent && !telemetryCapture.recorded(consent,through)) return@submitIfIdle
            if (batch == null || !reportVpnOn()) return@submitIfIdle
            val vpnGeneration=state().checkpoint().generation
            val physical=PhysicalIdentityRoute.capture(context,wifiOnly=true,unmeteredOnly=true)
            physical.check()
            val admitted = telemetryCapture.attempted(consent, now, batch, urgent)
            synchronized(commands) {
                currentConsent()
                nextTelemetryElapsed = elapsed() + (telemetryCapture.routineDelay(consent, now) ?: return@submitIfIdle)
            }
            if (!admitted) return@submitIfIdle
            if (urgent && !telemetryCapture.recorded(consent, through)) return@submitIfIdle
            telemetryPressureSession = null
            val route=object:HttpRoute {
                override fun resolve(host:String)=physical.resolve(host)
                override fun bind(socket:java.net.Socket)=physical.bind(socket)
                override fun check() {
                    currentConsent();require(state().checkpoint().let {it.desiredOn && it.generation==vpnGeneration})
                    physical.check()
                }
            }
            withProtocol(expected,p.bootstrap,route) {protocol,scope->
                check(telemetryTransport.compareAndSet(null,scope))
                try {
                    route.check()
                    if(protocol.uploadTechnicalTelemetry(batch,session,scope)) {
                        route.check()
                        val remaining = queue.acknowledged(queueKey, batch)
                        telemetryDisk.write(queueKey, remaining)
                        telemetryPressureSession = consent.session.takeIf { TelemetryCapture.isUrgent(remaining) }
                    }
                } finally {telemetryTransport.compareAndSet(scope,null)}
            }
        }
    }
    internal fun ownsTelemetrySchedule(ticket: String): Boolean =
        TelemetryWork.valid(ticket) && telemetryCapture.activeConsent()?.session == ticket

    /** WorkManager awaits the controller's existing identity worker and cancels only its own socket. */
    internal suspend fun deliverStoppedTelemetry(ticket: String): Boolean = suspendCancellableCoroutine { continuation ->
        val owned = java.util.concurrent.atomic.AtomicReference<IdentityScope?>()
        continuation.invokeOnCancellation { owned.get()?.cancel() }
        val admitted = submitIfIdle(quiet=true) {
            val success = runCatching {
                sendStoppedTelemetry(ticket, { continuation.isActive }, owned)
            }.getOrDefault(false)
            if (continuation.isActive) continuation.resume(success)
        }
        if (!admitted && continuation.isActive) continuation.resume(false)
    }

    private fun sendStoppedTelemetry(ticket: String, active: () -> Boolean,
                                     owned: java.util.concurrent.atomic.AtomicReference<IdentityScope?>): Boolean {
        if (!active() || !ownsTelemetrySchedule(ticket)) return true
        val initial = journal.snapshot()
        if (initial.phase != LoginPhase.POLICY_CACHED &&
            !(initial.phase == LoginPhase.REFRESHING && initial.refreshReturnPhase == LoginPhase.POLICY_CACHED)) return true
        val stopped = LifecycleAccess.engineStatus(context, state().read())
        when (TelemetryWork.vpnState(stopped)) {
            TelemetryWork.VpnState.ACTIVE -> return true
            TelemetryWork.VpnState.UNKNOWN -> return false
            TelemetryWork.VpnState.STOPPED -> Unit
        }
        val generation = stopped.getLong("generation")
        val original = payload(initial)
        val scopeKey = telemetryKey(checkNotNull(original.session))
        val consent = telemetryCapture.consent(scopeKey)?.takeIf { it.session == ticket } ?: return true
        val queueKey = Identity.hash(("syn443/telemetry-queue/" + scopeKey + "/" + ticket).toByteArray(Charsets.US_ASCII))
        fun checkOwner() {
            val identity = journal.snapshot()
            check(active() && identity.generation == initial.generation && identity.reauthRevision == initial.reauthRevision &&
                telemetryCapture.consent(scopeKey)?.session == ticket)
            val vpn = LifecycleAccess.engineStatus(context, state().read())
            check(TelemetryWork.vpnState(vpn) == TelemetryWork.VpnState.STOPPED && vpn.getLong("generation") == generation)
        }
        checkOwner()
        val old = telemetryDisk.read(queueKey)
        val (events, through) = telemetryCapture.sample(stopped, consent, io.syn443.android.BuildConfig.VERSION_CODE)
        if (events.isEmpty() && old.entries.isEmpty()) {
            return through == consent.through || telemetryCapture.recorded(consent, through)
        }
        val physical = PhysicalIdentityRoute.capture(context, wifiOnly=true, unmeteredOnly=true)
        val route = object : HttpRoute {
            override fun check() { checkOwner(); physical.check() }
            override fun resolve(host: String): List<java.net.InetAddress> {
                check()
                return physical.resolve(host).also { check() }
            }
            override fun bind(socket: java.net.Socket) { check(); physical.bind(socket) }
        }
        route.check()
        return withProtocol(initial, original.bootstrap, route) { protocol, scope ->
            owned.set(scope)
            try {
                check(telemetryTransport.compareAndSet(null, scope))
                route.check()
                resumeSession(initial, original, protocol, scope, fetch=false)
                val current = journal.snapshot()
                check(current.phase == LoginPhase.POLICY_CACHED)
                val p = payload(current)
                val session = checkNotNull(p.session)
                check(telemetryKey(session) == scopeKey)
                val permission = protocol.policy(session, scope)
                val previous = checkNotNull(journal.readAssignment(current))
                val verified = Assignments.receive(previous, current, p, permission, boot(), elapsed())
                Assignments.receipt(verified, current, p, boot(), elapsed())
                route.check()
                if (!permission.technicalTelemetry) return@withProtocol true
                val now = permission.time.window(boot(),elapsed()).upperMs
                var queue = old
                for (event in events) queue = queue.offer(queueKey, event)
                queue = queue.expired(queueKey, now)
                if (queue != old) telemetryDisk.write(queueKey, queue)
                if (!telemetryCapture.recorded(consent, through)) return@withProtocol true
                val batch = queue.peek(queueKey) ?: return@withProtocol true
                if (!telemetryCapture.attempted(consent, now, batch, urgent=false)) return@withProtocol true
                route.check()
                if (!protocol.uploadTechnicalTelemetry(batch,session,scope)) return@withProtocol false
                route.check()
                telemetryDisk.write(queueKey, queue.acknowledged(queueKey,batch))
                true
            } finally {
                telemetryTransport.compareAndSet(scope,null)
                owned.compareAndSet(scope,null)
            }
        }
    }

    /** Reuse the supervisor's worker and consent; no new timer, wake lock or probe. */
    internal fun syncRuntimeObservation():Boolean {
        if(!reportVpnOn())return false
        lateinit var expected:LoginIntent
        lateinit var authority:TelemetryAuthority
        lateinit var consent:TelemetryCapture.Consent
        return submitIfIdle(quiet=true,admit={
            val s=journal.snapshot();val a=telemetryFor(s)
            val c=a?.let {runCatching {telemetryCapture.consent(it.scope)}.getOrNull()}
            if(a==null || c==null || elapsed()<nextRuntimeElapsed)false
            else {expected=s;authority=a;consent=c;true}
        },onAdmission={nextRuntimeElapsed=elapsed()+60_000}) {
            fun currentConsent() {
                current(expected)
                require(telemetryFor(expected)==authority && telemetryCapture.consent(authority.scope)?.session==consent.session)
            }
            currentConsent();val p=payload(expected);val session=checkNotNull(p.session)
            val physical=PhysicalIdentityRoute.capture(context)
            // Metered networks use a five-minute budget. They can truthfully age
            // to stale in the console rather than causing extra radio wakeups.
            val interval=if(physical.unmetered)60_000L else 300_000L
            synchronized(commands) {currentConsent();nextRuntimeElapsed=elapsed()+interval}
            val time=session.time.window(boot(),elapsed())
            val sampleTime=io.syn443.identity.RuntimeObservation.sampleTime(time)
            val checkpoint=state().checkpoint();require(checkpoint.desiredOn)
            val revision=assignedRuntime.read(expected).state.journal.active?.let {assignedRuntime.allowed(expected,it)?.payload?.revision} ?: 0
            val status=LifecycleAccess.engineStatus(context,state().read())
            val sample=RuntimeObservationCapture.sample(status,revision,physical.networkKind,sampleTime,
                io.syn443.android.BuildConfig.VERSION_CODE)
            val queueKey=Identity.hash(("syn443/runtime/"+expected.authority+"/"+session.session.deviceId+"/"+session.keyThumbprint).toByteArray(Charsets.US_ASCII))
            val prepared=runtimeDisk.read(queueKey).offer(queueKey,sample)
            if(!prepared.ready(queueKey,time.lowerMs)) {
                // Reuse the same supervisor tick close to the durable deadline.
                // A restart must not repeatedly decrypt a one-hour backoff,
                // nor add another full minute when the deadline is imminent.
                synchronized(commands) {
                    currentConsent()
                    nextRuntimeElapsed=elapsed()+(prepared.notBeforeMs-time.lowerMs).coerceIn(1000,3_600_000)
                }
                return@submitIfIdle
            }
            val report=checkNotNull(prepared.pending)
            val queue=prepared.attempted(queueKey,report,time,interval)
            val route=object:HttpRoute {
                override fun resolve(host:String)=physical.resolve(host)
                override fun bind(socket:java.net.Socket)=physical.bind(socket)
                override fun check() {
                    currentConsent();require(state().checkpoint().let {it.desiredOn && it.generation==checkpoint.generation})
                    physical.check()
                }
            }
            route.check();runtimeDisk.write(queueKey,queue)
            withProtocol(expected,p.bootstrap,route) {protocol,scope->
                check(runtimeTransport.compareAndSet(null,scope))
                try {
                    route.check()
                    val result=protocol.reportRuntime(report,session,scope)
                    route.check()
                    when(result) {
                        AuthProtocol.RuntimeResult.ACKNOWLEDGED->runtimeDisk.write(queueKey,queue.acknowledged(queueKey,report))
                        AuthProtocol.RuntimeResult.CONFLICT->{
                            runtimeDisk.write(queueKey,queue.discard(queueKey).deferred(queueKey,session.time.window(boot(),elapsed()),300_000))
                            nextRuntimeElapsed=elapsed()+300_000
                        }
                        AuthProtocol.RuntimeResult.UNSUPPORTED->{
                            runtimeDisk.write(queueKey,queue.deferred(queueKey,session.time.window(boot(),elapsed()),3_600_000))
                            nextRuntimeElapsed=elapsed()+3_600_000
                        }
                        AuthProtocol.RuntimeResult.THROTTLED->{
                            runtimeDisk.write(queueKey,queue.deferred(queueKey,session.time.window(boot(),elapsed()),300_000))
                            nextRuntimeElapsed=elapsed()+300_000
                        }
                    }
                }finally {runtimeTransport.compareAndSet(scope,null)}
            }
        }
    }
    private fun syncDeviceSubscription():Boolean {
        if(!reportVpnOn())return false
        lateinit var expected:LoginIntent
        var conditional=false
        return submitIfIdle(quiet=true,admit={
            val s=journal.snapshot()
            val authority=deviceSourceAuthority
            if(s.phase!=LoginPhase.POLICY_CACHED || authority==null || authority.generation!=s.generation ||
                authority.session!=s.sessionGeneration || elapsed()<deviceSourcePollAfter)false
            else {expected=s;conditional=authority.conditional;true}
        },onAdmission={deviceSourcePollAfter=elapsed()+300_000}) {
            current(expected);if(!reportVpnOn())return@submitIfIdle
            val p=payload(expected)
            val vpnGeneration=state().checkpoint().generation
            val physical=PhysicalIdentityRoute.capture(context,wifiOnly=true)
            val route=object:HttpRoute {
                override fun resolve(host:String)=physical.resolve(host)
                override fun bind(socket:java.net.Socket)=physical.bind(socket)
                override fun check() {
                    current(expected);require(state().checkpoint().let {it.desiredOn && it.generation==vpnGeneration})
                    physical.check()
                }
            }
            withProtocol(expected,p.bootstrap,route) {protocol,scope->
                check(deviceSourceScope.compareAndSet(null,scope))
                try {
                    route.check()
                    val session=checkNotNull(p.session)
                    val claim=protocol.claimSubscription(session,scope,conditional)
                    if(!claim.available) {
                        synchronized(commands) {current(expected);deviceSourcePollAfter=elapsed()+3_600_000}
                        return@withProtocol
                    }
                    val lease=claim.lease?:return@withProtocol
                    if("wifi" !in lease.networkModes)return@withProtocol
                    val blocked=setOf(p.bootstrap.apiOrigin,p.bootstrap.issuer,p.bootstrap.controlPanelOrigin).filter(String::isNotEmpty).toSet()
                    val response=SubscriptionDownload(http).fetch(lease.credential,route,scope,blocked,
                        lease.validators?.etag.orEmpty(),lease.validators?.lastModified.orEmpty())
                    try {
                        route.check()
                        protocol.submitSubscriptionResult(claim,response,session,scope)
                    } finally {response.body.fill(0)}
                    synchronized(commands) {current(expected);deviceSourcePollAfter=elapsed()+60_000}
                } finally {deviceSourceScope.compareAndSet(scope,null)}
            }
        }
    }
    private fun reportActivation():Boolean {
        if(!reportVpnOn())return false
        lateinit var expected:LoginIntent
        lateinit var report:DeviceActivationReport
        return submitIfIdle(quiet=true,admit={
            val s=journal.snapshot()
            val value=runCatching {assignedRuntime.read(s).state.activationReport}.getOrNull()
            val previous=activationDelivery
            if(s.phase!=LoginPhase.POLICY_CACHED || value==null ||
                previous?.let {it.generation==s.generation && it.hash==value.envelopeHash && (it.done || elapsed()<it.retryAt)}==true)false
            else {expected=s;report=value;true}
        },onAdmission={activationDelivery=ActivationDelivery(expected.generation,report.envelopeHash,elapsed()+60_000,false)}) {
            current(expected)
            val payload=payload(expected)
            val assignment=checkNotNull(journal.readAssignment(expected))
            require(Assignments.report(assignment,expected,payload,boot(),elapsed())==report)
            if(!reportVpnOn())return@submitIfIdle
            try {
                withProtocol(expected,payload.bootstrap) {protocol,scope->
                    protocol.reportActivation(report,checkNotNull(payload.session),scope)
                }
            } catch(error:AuthException) {
                // Superseded publications cannot be acknowledged. All other
                // failures retain the same bounded retry and never change login.
                if(error.reason!=AuthFailure.CONFLICT)throw error
            }
            synchronized(commands) {
                current(expected)
                activationDelivery=ActivationDelivery(expected.generation,report.envelopeHash,0,true)
            }
        }
    }
    /** Supervisor calls this only with desired On and an eligible physical
     * network. Reuse the bounded generation/backoff admission; no new timer,
     * policy fetch, native restart budget or foreground-service side effect. */
    private fun refreshOverlayCredential():Boolean {
        lateinit var expected:LoginIntent
        var admitted:ProvisioningRetry?=null
        return submitIfIdle(admit={
            val s=journal.snapshot()
            val waiting=overlayMaterials.values.any{it.waiting && it.available()}
            if(s.phase!=LoginPhase.POLICY_CACHED || !waiting ||
                runCatching{assignedRuntime.read(s).state.journal.phase=="applying"}.getOrDefault(true))false
            else {
                expected=s
                admitted=overlayRetry.admit(s.generation,elapsed(),lastOverlayFetch)
                admitted!=null
            }
        },onAdmission={overlayRetry=checkNotNull(admitted);lastOverlayFetch=elapsed()}) {
            current(expected)
            val original=payload(expected)
            withProtocol(expected,original.bootstrap){protocol,scope->
                // Refresh an expiring session before delivery. Read the new
                // protected payload after rotation, without fetching policy.
                resumeSession(expected,original,protocol,scope,fetch=false)
                val s=journal.snapshot();current(s)
                prepareOverlays(s,payload(s),checkNotNull(journal.readAssignment(s)),protocol,scope)
            }
        }
    }
    private fun resumeSession(initial:LoginIntent,original:LoginPayload,protocol:AuthProtocol,scope:IdentityScope,fetch:Boolean=true) {
        var s=initial;var p=original;var session=checkNotNull(p.session)
        val currentBoot=boot();val now=elapsed()
        val reanchor=session.time.boot!=currentBoot
        val trustedUpper=if(reanchor)null else {
            if(!session.time.isCurrent(currentBoot,now))throw AuthException(AuthFailure.SESSION_EXPIRED)
            session.time.window(currentBoot,now).upperMs.also {
                if(it>=session.session.refreshUntilMs)throw AuthException(AuthFailure.SESSION_EXPIRED)
            }
        }
        val refresh=s.phase==LoginPhase.REFRESHING || trustedUpper==null ||
            Math.addExact(trustedUpper,30_000)>=session.session.accessUntilMs
        if(refresh) {
            val next=LoginRecovery.beginRefresh(s,s.generation,boot(),elapsed())
            if(next!=s)s=commit(s,next)
            // A newly pinned issuer HTTPS Date is only a proof/expiry anchor. The device API
            // must still verify the old refresh credential and return a rotated session.
            if(reanchor)session=session.copy(time=protocol.discover(scope).time)
            val operation=checkNotNull(s.operation)
            val reply=protocol.refresh(operation,session,scope)
            val refreshed=p.copy(session=reply)
            val previous=s
            s=protect(previous,refreshed) {hash->LoginRecovery.refreshed(previous,previous.generation,operation.body,reply,hash)}
            p=refreshed
        }
        if(p.advertisedCapabilities!=CapabilityNegotiation.canonical(IdentityOperation.supportedCapabilities)) {
            val declared=protocol.negotiateCapabilities(checkNotNull(p.session),IdentityOperation.supportedCapabilities,scope)
            val recorded=p.copy(advertisedCapabilities=declared)
            val previous=s
            s=protect(previous,recorded) {hash->LoginRecovery.capabilitiesRecorded(previous,previous.generation,hash)}
            p=recorded
            // A metadata-only write keeps an existing lease/activation ticket.
            // Rebuild its immutable view without starting or stopping an engine.
            journal.readAssignment(s)?.let {assignment->
                val prepared=assignedRuntime.prepare(s,p,assignment)
                synchronized(commands) {current(s);assignedRuntime.publish(prepared)}
            }
        }
        if(fetch)fetchAssignment(s,p,protocol,scope)
    }
    private fun handleSessionFailure(reason:AuthFailure) {synchronized(commands) {
        val s=journal.snapshot();current(s)
        val registeredExchange=s.reauthRevision>0 && s.phase in setOf(LoginPhase.EXCHANGING,LoginPhase.AUTHENTICATED,LoginPhase.ENROLLING)
        if(!registeredExchange && s.phase !in setOf(LoginPhase.INVITING,LoginPhase.PROVISIONING,LoginPhase.POLICY_CACHED,LoginPhase.REFRESHING))return
        // Local credential expiry does not revoke a separately signed offline permit.
        if(reason==AuthFailure.SESSION_EXPIRED && assignedRuntime.status(s).optBoolean("runtimeAuthorized"))return
        reauthenticate(s)
    }}
    private fun reauthenticate(s:LoginIntent) {synchronized(commands) {
        clearOverlays();assignedRuntime.clear();commit(s,LoginRecovery.needsReauthentication(s,s.generation));browser=null;policyChanged()
    }}
    private fun resumeWorker(initial:LoginIntent) {
        var s=initial
        if(s.phase in setOf(LoginPhase.PROVISIONING,LoginPhase.ENROLLING))lastAssignmentFetch=elapsed()
        val p=payload(s)
        if(s.phase in setOf(LoginPhase.POLICY_CACHED,LoginPhase.REFRESHING)) {
            var assignment=journal.readAssignment(s)
            if(assignment!=null) {
                if(assignment.journal.phase=="applying" && !assignedRuntime.contains(s,assignment)) {
                    assignment=Assignments.abort(assignment,s,p,"interrupted_activation")
                    s=persistAssignment(s,p,assignment)
                    prepareOverlays(s,p,assignment,network=false);s=journal.snapshot();current(s)
                } else {
                    prepareOverlays(s,p,assignment,network=false);s=journal.snapshot();current(s)
                    val prepared=assignedRuntime.prepare(s,p,assignment)
                    synchronized(commands) {current(s);assignedRuntime.publish(prepared)}
                    policyChanged()
                }
            }
        }
        when(LoginRecovery.resume(s,true,true,boot(),elapsed(),p.pending,p.user?.time?.boot?:p.session?.time?.boot?: -1)) {
            LoginResume.RETRY_INVITATION->resumeInvitation(s,p)
            LoginResume.BROWSER->synchronized(commands) {current(s);browser=s.generation to Identity.authorization(p.bootstrap,checkNotNull(p.pending),p.registration!=null)}
            LoginResume.AUTHENTICATED,LoginResume.RETRY_CLEANUP,LoginResume.RETRY_ENROLLMENT->withProtocol(s,p.bootstrap) {protocol,scope->provision(s,p,protocol,scope)}
            LoginResume.SESSION,LoginResume.REANCHOR_SESSION,LoginResume.RETRY_REFRESH->withProtocol(s,p.bootstrap) {protocol,scope->resumeSession(s,p,protocol,scope)}
            else->reauthenticate(s)
        }
    }
    fun retry(expectedGeneration:Long) {submit {
        val s=journal.snapshot();require(s.generation==expectedGeneration)
        when(s.phase) {
            LoginPhase.RESERVED->if(s.method=="invite"){val retired=commit(s,LoginRecovery.cancel(s,s.generation));retire(retired)}else prepareBrowser(s,bootstrap())
            LoginPhase.RETIRING->retire(s)
            LoginPhase.SIGNED_OUT->Unit
            else->resumeWorker(s)
        }
    }}
    /** Compare the reviewed account before the caller changes VPN intent. */
    internal fun cancelReviewed(generation:Long, revision:Long, stopVpn:()->Unit):Boolean = synchronized(commands) {
        val current = journal.snapshot()
        if (current.generation != generation || current.revision != revision ||
            current.phase in setOf(LoginPhase.SIGNED_OUT, LoginPhase.RETIRING)) return@synchronized false
        stopVpn()
        cancel()
        true
    }

    /** Caller serializes this with VPN Stop. No network/Keystore wait is on this path. */
    fun cancel():LoginIntent = synchronized(commands) {
        commandEpoch++;browser=null;chatTicket=null;invitePreview=null;invitePair="";inviteState="";val previous=cached;cached=null;activationDelivery=null;panelHint=null;panelPoll=null;deviceSourcePollAfter=0;deviceSourceAuthority=null;clearOverlays();assignedRuntime.clear();discardQueued();policyChanged()
        telemetryAuthority=null;nextTelemetryElapsed=0;nextRuntimeElapsed=0;cancelTechnicalTelemetry()
        // Even unreadable storage must not leave an in-memory operation/network request active.
        activeScope?.cancel()
        val s=try {journal.snapshot()} catch(e:Exception) {
            val aliases=listOfNotNull(previous?.first?.keyAlias,workingAlias.takeIf {it.isNotEmpty()}).distinct()
            if(aliases.isNotEmpty())submit {noVpn();aliases.forEach(DeviceKey::deleteOwned);eraseTechnicalTelemetryOnRetirement();throw LoginStorageException(LoginStorageFailure.CORRUPT)}
            throw e
        }
        val next=LoginRecovery.cancel(s,s.generation)
        if(s.phase !in setOf(LoginPhase.SIGNED_OUT,LoginPhase.RETIRING))cancelledGeneration=s.generation
        val retiring=try {if(next==s)s else journal.commit(s,next)} catch(e:Exception) {
            // If disk persistence failed, the old private key must still become unusable. Keep
            // public recovery metadata; never report a durable successful logout in this case.
            if(s.keyAlias.isNotEmpty())submit {noVpn();DeviceKey.deleteOwned(s.keyAlias);eraseTechnicalTelemetryOnRetirement();throw LoginStorageException(LoginStorageFailure.UNAVAILABLE)}
            throw e
        } finally {activeScope?.cancel()}
        if(retiring.phase==LoginPhase.RETIRING)submit {retire(retiring,previous)}
        retiring
    }
    private fun retire(expected:LoginIntent,previous:Pair<LoginIntent,LoginPayload>?=null) {
        // Cancel already fenced the runtime view and persisted Off. Native death/lock release
        // must precede key retirement acknowledgement; keep the UI responsive while it drains.
        val deadline=elapsed()+10_000
        while(true) {
            current(expected)
            if(runCatching {noVpn();NativeRetirement.released(context)}.getOrDefault(false))break
            check(elapsed()<deadline) {"native_retirement_pending"};Thread.sleep(100)
        }
        var s=expected
        val vaultArea=if(namespace=="device-login-v1")"managed-overlay-v1" else namespace
        val sdkStorage=ManagedOverlayStorage(context,if(namespace=="device-login-v1")"" else namespace)
        for(owned in expected.retiringOverlays) {
            current(s)
            val vault=OverlayVault(context,owned,{false},{Long.MAX_VALUE},vaultArea)
            val record=vault.snapshot()
            fun allowed()=runCatching{current(s);noVpn();true}.getOrDefault(false)
            if(record==null)check(sdkStorage.retire(owned,null,::allowed))
            else {
                var ownedRecord=record
                if(ownedRecord.phase!=io.syn443.identity.OverlayPhase.RETIRED) {
                    if(ownedRecord.phase!=io.syn443.identity.OverlayPhase.RETIRING)ownedRecord=vault.retiring(ownedRecord)
                    val retiring=ownedRecord
                    check(vault.finishRetirement(retiring){sdkStorage.retire(owned,retiring.identityEvidence.takeIf{it.isNotEmpty()},::allowed)})
                    ownedRecord=checkNotNull(vault.snapshot())
                }
                check(vault.removeRetired(ownedRecord))
            }
            current(s);noVpn()
            s=commit(s,LoginRecovery.overlayRetired(s,s.generation,owned,true,true,true))
        }
        eraseTechnicalTelemetryOnRetirement()
        if(namespace=="device-login-v1")io.syn443.android.chat.ChatOutbox.erase(context)
        check(journal.eraseRetired(s))
        val session=previous?.second?.session
        if(previous!=null && session!=null && previous.first.keyAlias in s.retiringAliases) {
            val scope=IdentityScope()
            try {
                previous.second.requireBound(previous.first)
                synchronized(commands) {current(s);check(activeScope==null);activeScope=scope}
                val protocol=AuthProtocol(previous.second.bootstrap,DeviceKey.open(previous.first.keyAlias),
                    exchange(s.generation,previous.second.bootstrap,true),::boot,::elapsed)
                protocol.revoke(IdentityOperation.revoke(),session,scope)
                val tomb=RegistrationTombstone(previous.first.ownerTag,previous.first.thumbprint)
                s=commit(s,LoginRecovery.serverRevoked(s,s.generation,tomb))
            } catch(_:Exception) {
                // Unknown/offline results retain the public tombstone for a fresh owner login.
            } finally {scope.cancel();synchronized(commands) {if(activeScope===scope)activeScope=null}}
        }
        val pendingInvite=previous?.second?.invitation
        if(previous!=null && pendingInvite!=null && previous.first.keyAlias in s.retiringAliases) {
            val scope=IdentityScope()
            try {
                previous.second.requireBound(previous.first)
                synchronized(commands){current(s);check(activeScope==null);activeScope=scope}
                val protocol=InvitationProtocol(previous.second.bootstrap,DeviceKey.open(previous.first.keyAlias),exchange(s.generation,previous.second.bootstrap,true),::boot,::elapsed)
                val time=protocol.time(scope,pendingInvite.time)
                val claimed=pendingInvite.reply?:protocol.claim(pendingInvite.claim,time,scope)
                protocol.abandon(InvitationOperation.mutation("abandon",claimed.state.id),claimed,time,scope)
                val tomb=RegistrationTombstone(previous.first.ownerTag,previous.first.thumbprint)
                if(tomb in s.tombstones)s=commit(s,LoginRecovery.serverRevoked(s,s.generation,tomb))
            }catch(_:Exception){ /* Unknown server outcome keeps a registration tombstone when needed. */ }
            finally {scope.cancel();synchronized(commands){if(activeScope===scope)activeScope=null}}
        }
        for(alias in expected.retiringAliases) {
            DeviceKey.deleteOwned(alias)
            s=commit(s,LoginRecovery.retired(s,s.generation,alias,true,true))
        }
        workingAlias=""
    }
    internal fun shutdownTest() {
        require(testExchange!=null && namespace.startsWith("test-") && io.syn443.android.BuildConfig.DEBUG)
        check(pendingCommands.get()==0);clearOverlays();worker.shutdownNow();http.close()
    }
}
