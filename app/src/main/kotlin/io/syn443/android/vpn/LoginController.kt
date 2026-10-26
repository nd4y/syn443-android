package io.syn443.android.vpn

import android.content.Context
import android.os.SystemClock
import android.provider.Settings
import android.util.AtomicFile
import io.syn443.identity.*
import io.syn443.policy.Canonical
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.decodeFromJsonElement
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
    private val testBeforeQueue:(()->Unit)?=null) {
    companion object {
        @Volatile private var instance:LoginController?=null
        @Synchronized fun get(context:Context):LoginController = instance ?: LoginController(context.applicationContext as android.app.Application).also {instance=it}
        internal fun isolatedForTest(context:Context,namespace:String,exchange:IdentityExchange,beforeQueue:(()->Unit)?=null):LoginController {
            require(io.syn443.android.BuildConfig.DEBUG && android.os.Build.HARDWARE in setOf("ranchu","goldfish") && namespace.matches(Regex("test-[a-z0-9-]{1,40}")))
            return LoginController(context.applicationContext as android.app.Application,namespace,exchange,beforeQueue)
        }
    }
    private val journal=LoginJournal(context,namespace)
    internal val assignedRuntime=AssignedPolicyRuntime(::boot,::elapsed)
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
    @Volatile private var lastAssignmentFetch= -300_000L
    private var provisioningRetry=ProvisioningRetry()
    @Volatile private var policyListener:(()->Unit)?=null
    internal fun observePolicy(listener:()->Unit):()->Unit {
        synchronized(commands) {policyListener=listener}
        return {synchronized(commands) {if(policyListener===listener)policyListener=null}}
    }
    private fun policyChanged() {runCatching {policyListener?.invoke()}}
    private fun boot()=Settings.Global.getInt(context.contentResolver,Settings.Global.BOOT_COUNT,-1).also {require(it>=0)}
    private fun elapsed()=SystemClock.elapsedRealtime()
    private val pendingCommands=java.util.concurrent.atomic.AtomicInteger()
    private inner class Command(private val admitted:Long,private val block:()->Unit):Runnable {
        private val completed=java.util.concurrent.atomic.AtomicBoolean()
        fun obsolete()=admitted!=commandEpoch
        fun complete() {if(completed.compareAndSet(false,true))check(pendingCommands.decrementAndGet()>=0)}
        override fun run() {try {
            val reason=try {
                if(synchronized(commands) {if(admitted!=commandEpoch)true else {workerEpoch=admitted;false}})return
                block();""
            } catch(e:AuthException) {
                if(e.reason in setOf(AuthFailure.ACCESS_DENIED,AuthFailure.REAUTHENTICATE))runCatching {
                    val s=journal.snapshot()
                    if(s.phase in setOf(LoginPhase.POLICY_CACHED,LoginPhase.REFRESHING))reauthenticate(s)
                }
                e.reason.name
            }
            catch(e:LoginStorageException) {if(e.reason==LoginStorageFailure.STALE)"" else e.reason.name}
            catch(_:Exception) {"LOGIN_UNAVAILABLE"}
            synchronized(commands) {if(admitted==commandEpoch)error=reason}
        } finally {complete()}}
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
    private fun submitIfIdle(onAdmission:()->Unit={},admit:()->Boolean={true},block:()->Unit):Boolean {
        val task=synchronized(commands) {
            if(pendingCommands.get()!=0 || !admit())return false
            onAdmission()
            pendingCommands.incrementAndGet();Command(commandEpoch,block)
        }
        enqueue(task);return true
    }
    private fun discardQueued() {
        val dropped=arrayListOf<Runnable>();worker.queue.drainTo(dropped)
        dropped.forEach {(it as Command).complete()}
    }
    private fun bootstrap():Bootstrap {
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
    private fun noVpn() {require(!state().checkpoint().desiredOn && !state().read().optBoolean("engineActive"))}
    internal fun loginIntent()=journal.snapshot()
    /** Memory/public-intent reads only. Never call StateStore, Keystore or network in this block. */
    internal fun <T> assignedRead(block:(LoginIntent)->T):T=synchronized(commands) {block(journal.snapshot())}
    internal fun ownsPolicy()=runCatching {journal.snapshot().phase!=LoginPhase.SIGNED_OUT}.getOrDefault(true)
    fun allowsConnect():Boolean = runCatching {
        val s=journal.snapshot()
        s.phase==LoginPhase.SIGNED_OUT || assignedRuntime.status(s).let {
            it.optBoolean("candidateValidated") || it.optBoolean("runtimeAuthorized")
        }
    }.getOrDefault(false)
    fun status():JSONObject = runCatching {
        val s=journal.snapshot()
        JSONObject().put("phase",s.phase.name).put("generation",s.generation).put("configured",configured)
            .put("busy",pendingCommands.get()>0).put("reason",error)
            .put("browserReady",s.phase==LoginPhase.BROWSER && browser?.first==s.generation)
            .put("cleanupPending",s.tombstones.size).put("assignedPolicy",assignedRuntime.status(s))
    }.getOrElse {JSONObject().put("phase","BLOCKED").put("reason","LOGIN_STORE_UNAVAILABLE")
        .put("busy",pendingCommands.get()>0)}
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
            LoginPhase.RESERVED->prepareBrowser(s,bootstrap())
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
        requireNotNull(browser).also {require(it.first==s.generation)}.second
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
                val auth=protect(consumed,LoginPayload(payload.bootstrap,user=user)) {hash->
                    LoginRecovery.authenticated(consumed,consumed.generation,payload.bootstrap,user,hash)
                }
                provision(auth,LoginPayload(payload.bootstrap,user=user),protocol,scope)
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
    private fun <T> withProtocol(s:LoginIntent,b:Bootstrap,block:(AuthProtocol,IdentityScope)->T):T {
        val scope=IdentityScope()
        synchronized(commands) {current(s);check(activeScope==null);activeScope=scope}
        try {
            return block(AuthProtocol(b,DeviceKey.open(s.keyAlias),exchange(s.generation,b,false),::boot,::elapsed),scope)
        } finally {scope.cancel();synchronized(commands) {if(activeScope===scope)activeScope=null}}
    }
    private fun exchange(generation:Long,b:Bootstrap,retiring:Boolean)=IdentityExchange {method,url,headers,body,child,maxBody->
        fun admitted() {
            val current=journal.snapshot()
            require(workerEpoch==commandEpoch && current.generation==generation && (current.phase==LoginPhase.RETIRING)==retiring && cancelledGeneration!=generation)
            if(current.phase !in setOf(LoginPhase.POLICY_CACHED,LoginPhase.REFRESHING))noVpn()
        }
        // Established account requests use a physical Network even while its TUN is running.
        admitted();val uri=Identity.https(url)
        if(testExchange!=null)return@IdentityExchange testExchange.request(method,url,headers,body,child,maxBody)
        val physical=PhysicalIdentityRoute.capture(context)
        val route=object:HttpRoute {
            override fun resolve(host:String)=physical.resolve(host)
            override fun bind(socket:java.net.Socket)=physical.bind(socket)
            override fun check() {admitted();physical.check()}
        }
        http.exchange(method,url,headers,body,child,maxBody=maxBody,factory=tls(b,uri),route=route)
    }
    private fun provision(initial:LoginIntent,p:LoginPayload,protocol:AuthProtocol,scope:IdentityScope) {
        var s=initial;val user=checkNotNull(p.user)
        repeat(2) {
            if(s.phase==LoginPhase.CLEANUP || s.tombstones.any {it.ownerTag==s.ownerTag}) {
                val next=LoginRecovery.beginCleanup(s,s.generation,boot(),elapsed())
                if(next!=s)s=commit(s,next)
                val op=checkNotNull(s.operation);protocol.cleanup(op,user,scope)
                s=commit(s,LoginRecovery.cleanupAcknowledged(s,s.generation,op.body))
            }
        }
        val public=DeviceKey.open(s.keyAlias).publicKey
        val next=LoginRecovery.beginEnrollment(s,s.generation,public,boot(),elapsed())
        if(next!=s)s=commit(s,next)
        val reply=protocol.enroll(checkNotNull(s.operation),user,scope)
        val sessionPayload=LoginPayload(p.bootstrap,session=reply)
        val registered=protect(s,sessionPayload) {hash->LoginRecovery.enrolled(s,s.generation,reply,hash)}
        fetchAssignment(registered,sessionPayload,protocol,scope)
    }
    private fun fetchAssignment(s:LoginIntent,p:LoginPayload,protocol:AuthProtocol,scope:IdentityScope) {
        current(s)
        lastAssignmentFetch=elapsed()
        val response=protocol.policy(checkNotNull(p.session),scope)
        val next=Assignments.receive(journal.readAssignment(s)?:AssignmentState(),s,p,response,boot(),elapsed())
        val receipt=Assignments.receipt(next,s,p,boot(),elapsed())
        val target=if(s.phase==LoginPhase.POLICY_CACHED && s.policyHash==receipt)s
            else LoginRecovery.policyCached(s,s.generation,receipt,s.protectedHash)
        persistAssignment(s,p,next,target)
    }
    private fun persistAssignment(s:LoginIntent,p:LoginPayload,next:AssignmentState,target:LoginIntent=s) {
        val runtime=assignedRuntime.prepare(target,p,next)
        journal.prepareAssignment(s,next).use {prepared->synchronized(commands) {
            current(s);journal.commitAssignment(s,prepared)
            val accepted=if(target==s)s else commit(s,target)
            cached=accepted to p;assignedRuntime.publish(runtime)
        }}
        policyChanged()
    }
    internal fun assignmentTicket():AssignedPolicyRuntime.Ticket = assignedRead {assignedRuntime.ticket(it)}
    /** Commands persist on the identity worker. The native caller observes the resulting view;
     * acceptance is not a completed transition, and a lost/stale command grants no new permit. */
    private fun transitionAssignment(ticket:AssignedPolicyRuntime.Ticket,invalidate:Boolean=false,
        change:(AssignmentState,LoginIntent,LoginPayload)->AssignmentState):Boolean = submitIfIdle(onAdmission={
        if(invalidate && runCatching {assignmentTicket()==ticket}.getOrDefault(false)) {assignedRuntime.clear();policyChanged()}
    }) {
        val s=journal.snapshot();current(s)
        require(s.phase==LoginPhase.POLICY_CACHED && s.generation==ticket.loginGeneration && s.policyHash==ticket.receipt)
        val p=payload(s);val before=checkNotNull(journal.readAssignment(s))
        require(before.journal.activationGeneration==ticket.activation)
        persistAssignment(s,p,change(before,s,p))
    }
    internal fun beginAssignment(ticket:AssignedPolicyRuntime.Ticket,baseline:List<Boolean>):Boolean {
        val values=baseline.toList();require(values.size in 1..8)
        return transitionAssignment(ticket) {before,s,p->
            require(assignedRuntime.prepare(s,p,before).candidate!=null)
            Assignments.begin(before,s,p,values,boot(),elapsed())
        }
    }
    internal fun finishAssignment(ticket:AssignedPolicyRuntime.Ticket,actual:List<Boolean>,started:Boolean):Boolean {
        val values=actual.toList();require(values.size in 1..8)
        return transitionAssignment(ticket) {before,s,p->Assignments.finish(before,s,p,values,started,boot(),elapsed())}
    }
    internal fun abortAssignment(ticket:AssignedPolicyRuntime.Ticket,reason:String):Boolean {
        require(reason in setOf("activation_deadline","interrupted_activation","native_activation_failed","candidate_expired_or_revoked"))
        // Invalidate the old view before waiting for encrypted persistence. A stale ticket cannot
        // erase the current account's permit; the worker independently checks the journal again.
        return transitionAssignment(ticket,true) {before,s,p->Assignments.abort(before,s,p,reason)}
    }
    /** Visible UI asks; controller owns rate/queue/generation fences. Hidden UI has no timer. */
    fun pollProvisioning(expectedGeneration:Long):Boolean {
        lateinit var expected:LoginIntent
        var next:ProvisioningRetry?=null
        return submitIfIdle(admit={
            val s=journal.snapshot()
            if(s.generation!=expectedGeneration || s.phase!=LoginPhase.PROVISIONING ||
                error !in setOf("PENDING","TRANSPORT","THROTTLED","UNAVAILABLE"))false
            else {
                expected=s
                next=provisioningRetry.admit(s.generation,elapsed(),lastAssignmentFetch,error=="THROTTLED")
                next!=null
            }
        },onAdmission={provisioningRetry=checkNotNull(next)}) {
            current(expected);resumeWorker(expected)
        }
    }
    internal fun refreshAssignment(force:Boolean):Boolean {
        val s=journal.snapshot()
        if(s.phase !in setOf(LoginPhase.POLICY_CACHED,LoginPhase.REFRESHING))return false
        val interval=if(force)5_000L else runCatching {
            val view=assignedRuntime.read(s);val raw=view.state.journal.active ?: view.state.journal.candidate
            val policy=checkNotNull(assignedRuntime.allowed(s,raw))
            (policy.payload.refreshAfterMs-checkNotNull(view.state.time).window(boot(),elapsed()).upperMs).coerceIn(30_000,300_000)
        }.getOrDefault(30_000L)
        if(elapsed()-lastAssignmentFetch<interval)return false
        if(runCatching {assignedRuntime.read(s).state.journal.phase=="applying"}.getOrDefault(false))return false
        return submitIfIdle(onAdmission={lastAssignmentFetch=elapsed()}) {
            current(s);resumeWorker(s)
        }
    }
    private fun resumeSession(initial:LoginIntent,original:LoginPayload,protocol:AuthProtocol,scope:IdentityScope) {
        var s=initial;var p=original;var session=checkNotNull(p.session)
        val reanchor=session.time.boot!=boot()
        val refresh=s.phase==LoginPhase.REFRESHING || reanchor || Math.addExact(session.time.window(boot(),elapsed()).upperMs,30_000)>=session.session.accessUntilMs
        if(refresh) {
            val next=LoginRecovery.beginRefresh(s,s.generation,boot(),elapsed())
            if(next!=s)s=commit(s,next)
            // A newly pinned issuer HTTPS Date is only a proof/expiry anchor. The device API
            // must still verify the old refresh credential and return a rotated session.
            if(reanchor)session=session.copy(time=protocol.discover(scope).time)
            val operation=checkNotNull(s.operation)
            val reply=protocol.refresh(operation,session,scope)
            val refreshed=LoginPayload(p.bootstrap,session=reply)
            val previous=s
            s=protect(previous,refreshed) {hash->LoginRecovery.refreshed(previous,previous.generation,operation.body,reply,hash)}
            p=refreshed
        }
        fetchAssignment(s,p,protocol,scope)
    }
    private fun reauthenticate(s:LoginIntent) {synchronized(commands) {
        assignedRuntime.clear();commit(s,LoginRecovery.needsReauthentication(s,s.generation));browser=null;policyChanged()
    }}
    private fun resumeWorker(s:LoginIntent) {
        if(s.phase==LoginPhase.PROVISIONING)lastAssignmentFetch=elapsed()
        val p=payload(s)
        if(s.phase in setOf(LoginPhase.POLICY_CACHED,LoginPhase.REFRESHING)) {
            var assignment=journal.readAssignment(s)
            if(assignment!=null) {
                if(assignment.journal.phase=="applying" && !assignedRuntime.contains(s,assignment)) {
                    assignment=Assignments.abort(assignment,s,p,"interrupted_activation")
                    persistAssignment(s,p,assignment)
                } else {
                    val prepared=assignedRuntime.prepare(s,p,assignment)
                    synchronized(commands) {current(s);assignedRuntime.publish(prepared)}
                    policyChanged()
                }
            }
        }
        when(LoginRecovery.resume(s,true,true,boot(),elapsed(),p.pending,p.user?.time?.boot?:p.session?.time?.boot?: -1)) {
            LoginResume.BROWSER->synchronized(commands) {current(s);browser=s.generation to Identity.authorization(p.bootstrap,checkNotNull(p.pending))}
            LoginResume.AUTHENTICATED,LoginResume.RETRY_CLEANUP,LoginResume.RETRY_ENROLLMENT->withProtocol(s,p.bootstrap) {protocol,scope->provision(s,p,protocol,scope)}
            LoginResume.SESSION,LoginResume.REANCHOR_SESSION,LoginResume.RETRY_REFRESH->withProtocol(s,p.bootstrap) {protocol,scope->resumeSession(s,p,protocol,scope)}
            else->reauthenticate(s)
        }
    }
    fun retry(expectedGeneration:Long) {submit {
        val s=journal.snapshot();require(s.generation==expectedGeneration)
        when(s.phase) {
            LoginPhase.RESERVED->prepareBrowser(s,bootstrap())
            LoginPhase.RETIRING->retire(s)
            LoginPhase.SIGNED_OUT->Unit
            else->resumeWorker(s)
        }
    }}
    /** Caller serializes this with VPN Stop. No network/Keystore wait is on this path. */
    fun cancel():LoginIntent = synchronized(commands) {
        commandEpoch++;browser=null;val previous=cached;cached=null;assignedRuntime.clear();discardQueued();policyChanged()
        // Even unreadable storage must not leave an in-memory operation/network request active.
        activeScope?.cancel()
        val s=try {journal.snapshot()} catch(e:Exception) {
            val aliases=listOfNotNull(previous?.first?.keyAlias,workingAlias.takeIf {it.isNotEmpty()}).distinct()
            if(aliases.isNotEmpty())submit {noVpn();aliases.forEach(DeviceKey::deleteOwned);throw LoginStorageException(LoginStorageFailure.CORRUPT)}
            throw e
        }
        val next=LoginRecovery.cancel(s,s.generation)
        if(s.phase !in setOf(LoginPhase.SIGNED_OUT,LoginPhase.RETIRING))cancelledGeneration=s.generation
        val retiring=try {if(next==s)s else journal.commit(s,next)} catch(e:Exception) {
            // If disk persistence failed, the old private key must still become unusable. Keep
            // public recovery metadata; never report a durable successful logout in this case.
            if(s.keyAlias.isNotEmpty())submit {noVpn();DeviceKey.deleteOwned(s.keyAlias);throw LoginStorageException(LoginStorageFailure.UNAVAILABLE)}
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
        check(journal.eraseRetired(expected))
        var s=expected
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
        for(alias in expected.retiringAliases) {
            DeviceKey.deleteOwned(alias)
            s=commit(s,LoginRecovery.retired(s,s.generation,alias,true,true))
        }
        workingAlias=""
    }
    internal fun shutdownTest() {
        require(testExchange!=null && namespace.startsWith("test-") && io.syn443.android.BuildConfig.DEBUG)
        check(pendingCommands.get()==0);worker.shutdownNow();http.close()
    }
}
