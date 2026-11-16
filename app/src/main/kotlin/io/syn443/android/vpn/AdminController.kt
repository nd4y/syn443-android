package io.syn443.android.vpn

import android.app.Application
import android.content.Context
import android.os.SystemClock
import android.provider.Settings
import io.syn443.identity.*
import org.json.JSONObject
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/** Controller-process administrative owner. Credentials and browser attempts never survive this process. */
internal class AdminController private constructor(private val context:Application,private val namespace:String,
    private val test:TestDependencies?=null) {
    private class TestDependencies(val encryptionAlias:String,val source:()->AdminDeviceContext?,
        val exchange:IdentityExchange,val boot:()->Int,val elapsed:()->Long,
        val refreshDiscovery:(()->AdminDeviceContext?)?,val editorStore:(()->AdminEditorStore)?)
    companion object {
        @Volatile private var instance:AdminController?=null
        @Synchronized fun get(context:Context):AdminController {
            check(Application.getProcessName()==context.packageName+":controller") {"admin_controller_process_required"}
            return instance ?: AdminController(context.applicationContext as Application,"admin-login-v1").also {instance=it}
        }
        internal fun isolatedForTest(context:Context,namespace:String,encryptionAlias:String,
            source:()->AdminDeviceContext?,exchange:IdentityExchange,boot:()->Int,elapsed:()->Long,
            refreshDiscovery:(()->AdminDeviceContext?)?=null,editorStore:(()->AdminEditorStore)?=null):AdminController {
            require(io.syn443.android.BuildConfig.DEBUG && android.os.Build.HARDWARE in setOf("ranchu","goldfish") &&
                namespace.matches(Regex("test-[a-z0-9-]{1,43}")) &&
                encryptionAlias.matches(Regex("syn443-admin-store-test-[A-Za-z0-9_-]{43}")))
            return AdminController(context.applicationContext as Application,namespace,
                TestDependencies(encryptionAlias,source,exchange,boot,elapsed,refreshDiscovery,editorStore))
        }
        private val operationID=Regex("[a-f0-9]{32}")
        private val targetID=Regex("[A-Za-z0-9_-]{1,64}")
        private val digest=Regex("[A-Za-z0-9_-]{43}")
    }
    private enum class Phase { INITIALIZING, SIGNED_OUT, STARTING, BROWSER, AUTHENTICATED, REAUTHENTICATE, UNAVAILABLE }
    private class Owner(val record:AdminKeyRecord,val deviceBinding:String,val discoveryBinding:String,
        val protocol:AdminProtocol,val issuer:AdminIssuerState,val pending:AdminPending,val browser:String,
        val tokenPosts:AtomicInteger,var session:AdminSession?=null) {
        val generation:Long get()=record.generation
    }
    private class Mailbox(val id:String,val generation:Long,val createdAt:Long,val expiresAt:Long,
        var state:String="pending",var reason:String="",var body:ByteArray=ByteArray(0))
    private class BrowserTicket(val id:String,val generation:Long,val epoch:Long,var createdAt:Long,var expiresAt:Long,
        var state:String="pending",var reason:String="",var url:String?=null)
    class BrowserResult internal constructor(val state:String,val reason:String,val url:String?=null,val expiresAtElapsedMs:Long=0) {
        override fun toString()="AdminBrowserResult(state=$state, [redacted])"
    }
    class ReadResult internal constructor(val state:String,val reason:String,body:ByteArray=ByteArray(0)) {
        private val bytes=body.copyOf()
        fun bodyBytes():ByteArray=bytes.copyOf()
        override fun toString()="AdminReadResult(state=$state, [redacted])"
    }
    private val commands=Any()
    private val worker=ThreadPoolExecutor(1,1,30,TimeUnit.SECONDS,ArrayBlockingQueue(1),
        {r->Thread(r,"syn443-admin").apply {isDaemon=true}},ThreadPoolExecutor.AbortPolicy()).apply {allowCoreThreadTimeOut(true)}
    private val http=BoundedHttp()
    private val journal by lazy {test?.let {AdminKeyJournal.isolatedForTest(context,namespace,it.encryptionAlias)}
        ?:AdminKeyJournal(context,namespace)}
    private var phase=Phase.INITIALIZING
    private var reason=""
    private var generation=0L
    private var epoch=0L
    private var busy=true
    private var owner:Owner?=null
    // A RAM view may be retired freely; its encrypted outbox must survive logout.
    private var editorCoordinator:AdminEditorCoordinator?=null
    private var activeScope:IdentityScope?=null
    private var activeRead=""
    private var activeBrowser=""
    private var mailbox:Mailbox?=null
    private var browserTicket:BrowserTicket?=null
    private var retirementRequested=false
    private var retirementPhase=Phase.REAUTHENTICATE
    private var retirementReason="REAUTHENTICATE"
    init {enqueue {recover()}}
    private fun elapsed()=test?.elapsed?.invoke() ?:SystemClock.elapsedRealtime()
    private fun boot()=test?.boot?.invoke() ?:Settings.Global.getInt(context.contentResolver,Settings.Global.BOOT_COUNT,0)
    private fun source()=test?.source?.invoke() ?:if(test==null)LoginController.get(context).adminDiscoveryContext() else null
    private fun current(expected:Long)=synchronized(commands) {epoch==expected && !retirementRequested}
    private fun requireCurrent(expected:Long) {
        if(!current(expected))throw AdminException(AdminFailure.CANCELLED)
        synchronized(commands) {
            if(activeRead.isNotEmpty() && mailbox?.let {it.id==activeRead && it.generation==generation && elapsed() in it.createdAt..it.expiresAt}!=true)
                throw AdminException(AdminFailure.CANCELLED)
            if(activeBrowser.isNotEmpty() && browserTicket?.let {it.id==activeBrowser && it.generation==generation && it.epoch==expected}!=true)
                throw AdminException(AdminFailure.CANCELLED)
        }
    }
    private fun context(expected:Long,binding:String,discovery:String):AdminDeviceContext {
        requireCurrent(expected)
        val selected=source() ?:throw AdminException(AdminFailure.REAUTHENTICATE)
        if(selected.binding!=binding || selected.discovery.binding!=discovery)throw AdminException(AdminFailure.REAUTHENTICATE)
        requireCurrent(expected)
        return selected
    }
    private fun publishRecord(record:AdminKeyRecord)=synchronized(commands) {generation=maxOf(generation,record.generation)}
    private fun clearMailbox() {mailbox?.body?.fill(0);mailbox=null}
    private fun clearBrowser() {browserTicket?.url=null;browserTicket=null}
    private fun closeSession(value:Owner?) {
        val session=value?.session ?:return
        try {value.protocol.logout(session)}catch(_:Exception) { /* Epoch and durable retirement still fence this owner. */ }
    }
    private fun requestRetirement(expected:Long,why:String) {
        val retired=synchronized(commands) {
            if(epoch!=expected)return
            epoch++;retirementRequested=true;retirementPhase=Phase.REAUTHENTICATE;retirementReason=why
            phase=Phase.REAUTHENTICATE;reason=why;clearMailbox();clearBrowser()
            owner to activeScope
        }
        closeSession(retired.first);retired.second?.cancel()
    }
    /** No alias discovery, device mutation, network call or credential recovery. */
    private fun retireJournal() {
        var record=journal.read();publishRecord(record)
        if(record.phase in setOf(AdminKeyPhase.RESERVED,AdminKeyPhase.BROWSER,AdminKeyPhase.AUTHENTICATED)) {
            record=journal.commit(record,record.copy(revision=record.revision+1,generation=record.generation+1,phase=AdminKeyPhase.RETIRING))
            publishRecord(record)
        }
        if(record.phase==AdminKeyPhase.RETIRING) {
            AdminKey.deleteOwned(record.alias)
            record=journal.commit(record,record.copy(revision=record.revision+1,phase=AdminKeyPhase.SIGNED_OUT,alias=""))
            publishRecord(record)
        }
        check(record.phase==AdminKeyPhase.SIGNED_OUT)
    }
    private fun recover() {
        val record=journal.read();publishRecord(record)
        if(record.phase==AdminKeyPhase.SIGNED_OUT)synchronized(commands) {phase=Phase.SIGNED_OUT;reason=""}
        else synchronized(commands) {
            if(!retirementRequested) {
                retirementRequested=true;retirementPhase=Phase.REAUTHENTICATE;retirementReason="PROCESS_RECREATED"
                phase=Phase.REAUTHENTICATE;reason="PROCESS_RECREATED"
            }
        }
    }
    private fun finite(error:Exception)=when(error) {
        is AdminException->error.reason.name
        is AdminKeyStorageException->"STORAGE_"+error.reason.name
        is DeliveryException->if(error.reason==DeliveryFailure.CANCELLED)"CANCELLED" else "TRANSPORT"
        else->"UNAVAILABLE"
    }
    private fun enqueue(action:()->Unit):Boolean=try {
        worker.execute {
            try {action()}catch(error:Exception) {
                synchronized(commands) {phase=Phase.UNAVAILABLE;reason=finite(error)}
            }finally {finishWorker()}
        }
        true
    }catch(_:Exception) {
        synchronized(commands) {busy=false;phase=Phase.UNAVAILABLE;reason="QUEUE_UNAVAILABLE"}
        false
    }
    private fun finishWorker() {
        val scope=synchronized(commands) {activeScope.also {activeScope=null}}
        scope?.cancel()
        while(true) {
            val retire=synchronized(commands) {
                if(retirementRequested)true else {busy=false;activeRead="";activeBrowser="";false}
            }
            if(!retire)return
            try {retireJournal()}catch(error:Exception) {
                synchronized(commands) {busy=false;activeRead="";activeBrowser="";phase=Phase.UNAVAILABLE;reason=finite(error)}
                return // Keep retirementRequested set: a new sign-in cannot bypass an unknown cleanup.
            }
            synchronized(commands) {
                owner=null;editorCoordinator=null;clearMailbox();clearBrowser();retirementRequested=false;phase=retirementPhase;reason=retirementReason
            }
        }
    }
    private fun <T> withScope(expected:Long,action:(IdentityScope)->T):T {
        val scope=IdentityScope()
        synchronized(commands) {requireCurrent(expected);check(activeScope==null);activeScope=scope}
        try {requireCurrent(expected);return action(scope)}
        finally {scope.cancel();synchronized(commands) {if(activeScope===scope)activeScope=null}}
    }
    private fun exchange(expected:Long,binding:String,discovery:String,posts:AtomicInteger)=IdentityExchange {method,url,headers,body,child,maxBody->
        fun admitted() {context(expected,binding,discovery)}
        val metadata=context(expected,binding,discovery).discovery.metadata
        val oidc=metadata.issuer+"/protocol/openid-connect"
        require(method=="GET" && url in setOf(metadata.issuer+"/.well-known/openid-configuration",oidc+"/certs") ||
            method=="POST" && url in setOf(oidc+"/token",metadata.apiOrigin+"/v1/control/action"))
        require(headers.keys.none {it.equals("Origin",ignoreCase=true)})
        val physical=if(test==null)PhysicalIdentityRoute.capture(context) else null
        val route=physical?.let {owned->object:HttpRoute {
            override fun resolve(host:String)=owned.resolve(host)
            override fun bind(socket:java.net.Socket)=owned.bind(socket)
            override fun check() {admitted();owned.check()}
        }}
        if(method=="POST" && url.endsWith("/protocol/openid-connect/token"))posts.incrementAndGet()
        val reply=test?.exchange?.request(method,url,headers,body,child,maxBody)
            ?:http.exchange(method,url,headers,body,child,maxBody=maxBody,route=checkNotNull(route),
                maxRequestBody=if(url==metadata.apiOrigin+"/v1/control/action")262_144 else 8192)
        admitted();reply
    }
    fun status():JSONObject=synchronized(commands) {JSONObject().put("generation",generation).put("phase",phase.name)
        .put("busy",busy).put("reason",reason)}
    /** Explicit administrative sign-in only. This anonymous metadata request is
     * never a VPN operation or a replacement for the pinned-root store verifier. */
    private fun loginDiscovery(expected:Long):AdminDeviceContext {
        requireCurrent(expected)
        source()?.let {return it}
        fun accepted(selected:AdminDeviceContext?):AdminDeviceContext {
            requireCurrent(expected)
            val current=source() ?:throw AdminException(AdminFailure.REAUTHENTICATE)
            if(selected==null || current.binding!=selected.binding || current.discovery.binding!=selected.discovery.binding)
                throw AdminException(AdminFailure.REAUTHENTICATE)
            requireCurrent(expected)
            return current
        }
        if(test!=null) {
            val refreshed=test.refreshDiscovery?.invoke()
            return accepted(refreshed)
        }
        val login=LoginController.get(context)
        val original=login.adminBootstrapContext() ?:throw AdminException(AdminFailure.REAUTHENTICATE)
        fun admitted() {
            requireCurrent(expected)
            val current=login.adminBootstrapContext() ?:throw AdminException(AdminFailure.REAUTHENTICATE)
            if(current.binding!=original.binding || current.bootstrap!=original.bootstrap)
                throw AdminException(AdminFailure.REAUTHENTICATE)
            requireCurrent(expected)
        }
        val target=original.bootstrap.apiOrigin+"/.well-known/syn443/bootstrap/"+original.bootstrap.serviceId
        val transport=IdentityExchange {method,url,headers,body,child,maxBody->
            admitted()
            require(method=="GET" && url==target && body==null && maxBody==BootstrapTrust.MAX_MANIFEST &&
                headers==mapOf("Accept" to "application/jose","Cache-Control" to "no-store"))
            val physical=PhysicalIdentityRoute.capture(context)
            val route=object:HttpRoute {
                override fun resolve(host:String)=physical.resolve(host)
                override fun bind(socket:java.net.Socket)=physical.bind(socket)
                override fun check() {admitted();physical.check()}
            }
            http.exchange(method,url,headers,null,child,maxBody=maxBody,route=route).also {admitted()}
        }
        val fetched=withScope(expected) {scope->AdminServiceDiscovery(original.bootstrap,transport).fetch(scope)}
        admitted()
        val selected=login.applyAdminDescriptor(original.binding,fetched.raw)
        return accepted(selected)
    }
    fun start(expectedGeneration:Long):Boolean {
        val admitted=synchronized(commands) {
            if(busy || retirementRequested || generation!=expectedGeneration || phase !in setOf(Phase.SIGNED_OUT,Phase.REAUTHENTICATE))return false
            busy=true;phase=Phase.STARTING;reason="";clearMailbox();clearBrowser();epoch
        }
        return enqueue {
            try {
                requireCurrent(admitted)
                val selected=loginDiscovery(admitted)
                require(digest.matches(selected.binding));requireCurrent(admitted)
                val initial=journal.read();publishRecord(initial)
                check(initial.phase==AdminKeyPhase.SIGNED_OUT)
                val reserved=journal.commit(initial,initial.copy(revision=initial.revision+1,generation=initial.generation+1,
                    phase=AdminKeyPhase.RESERVED,alias=AdminKey.newAlias()))
                publishRecord(reserved)
                val key=AdminKey.createIfCurrent(reserved.alias) {current(admitted)} ?:throw AdminException(AdminFailure.CANCELLED)
                requireCurrent(admitted)
                val posts=AtomicInteger()
                val protocol=AdminProtocol.fromDiscovery({context(admitted,selected.binding,selected.discovery.binding).discovery},key,
                    exchange(admitted,selected.binding,selected.discovery.binding,posts),::boot,::elapsed)
                withScope(admitted) {scope->
                    val issuer=protocol.discover(scope);val pending=protocol.newPending(reserved.generation)
                    val browser=protocol.authorization(pending,reserved.generation)
                    requireCurrent(admitted)
                    val persisted=journal.commit(reserved,reserved.copy(revision=reserved.revision+1,phase=AdminKeyPhase.BROWSER))
                    publishRecord(persisted)
                    context(admitted,selected.binding,selected.discovery.binding)
                    synchronized(commands) {
                        requireCurrent(admitted)
                        owner=Owner(persisted,selected.binding,selected.discovery.binding,protocol,issuer,pending,browser,posts)
                        phase=Phase.BROWSER;reason=""
                    }
                }
            }catch(error:Exception) {requestRetirement(admitted,finite(error))}
        }
    }
    /** Fresh trust/authorization work precedes a short, consume-once UI handoff. No source I/O is on Binder. */
    fun prepareBrowser(id:String,expectedGeneration:Long):Boolean {
        if(!operationID.matches(id))return false
        val selected=synchronized(commands) {
            if(busy || retirementRequested || phase!=Phase.BROWSER || generation!=expectedGeneration)return false
            val owned=owner?.takeIf {it.generation==expectedGeneration} ?:return false
            val now=elapsed();if(now<0 || now>Long.MAX_VALUE-300_000)return false
            clearBrowser();browserTicket=BrowserTicket(id,expectedGeneration,epoch,now,now+60_000)
            busy=true;activeBrowser=id;epoch to owned
        }
        return enqueue {
            val (admitted,owned)=selected
            try {
                context(admitted,owned.deviceBinding,owned.discoveryBinding)
                val url=owned.protocol.authorization(owned.pending,owned.generation)
                context(admitted,owned.deviceBinding,owned.discoveryBinding)
                synchronized(commands) {
                    requireCurrent(admitted)
                    val ticket=checkNotNull(browserTicket);val now=elapsed()
                    check(ticket.id==id && ticket.epoch==admitted && ticket.generation==expectedGeneration)
                    if(now !in ticket.createdAt..ticket.expiresAt || now<owned.pending.startedElapsedMs ||
                        now-owned.pending.startedElapsedMs>=300_000) {
                        clearBrowser()
                    } else {
                        ticket.createdAt=now;ticket.expiresAt=minOf(now+5000,owned.pending.startedElapsedMs+300_000)
                        ticket.url=url;ticket.state="done"
                    }
                }
            }catch(error:Exception) {
                if(error is AdminException && error.reason in setOf(AdminFailure.REAUTHENTICATE,AdminFailure.SESSION_EXPIRED,AdminFailure.INVALID_REPLY))
                    requestRetirement(admitted,finite(error))
                else synchronized(commands) {browserTicket?.takeIf {it.id==id && it.epoch==admitted}?.let {it.state="failed";it.reason=finite(error)}}
            }
        }
    }
    fun browserResult(id:String,expectedGeneration:Long):BrowserResult=synchronized(commands) {
        val ticket=browserTicket;val now=elapsed()
        if(!operationID.matches(id) || retirementRequested || phase!=Phase.BROWSER || generation!=expectedGeneration ||
            ticket?.id!=id || ticket.generation!=expectedGeneration || ticket.epoch!=epoch)return@synchronized BrowserResult("gone","")
        if(now<ticket.createdAt || now>=ticket.expiresAt) {clearBrowser();return@synchronized BrowserResult("gone","")}
        if(ticket.state=="done") {
            if(busy)return@synchronized BrowserResult("pending","")
            val url=checkNotNull(ticket.url);clearBrowser();return@synchronized BrowserResult("done","",url,ticket.expiresAt)
        }
        BrowserResult(ticket.state,ticket.reason)
    }
    fun browserCancel(id:String,expectedGeneration:Long):Boolean=synchronized(commands) {
        val ticket=browserTicket
        if(generation!=expectedGeneration || ticket?.id!=id || ticket.generation!=expectedGeneration)return@synchronized false
        clearBrowser();true
    }
    fun callback(raw:String):Boolean {
        if(raw.length !in 1..8192 || raw.toByteArray(Charsets.UTF_8).size>8192)return false
        val selected=synchronized(commands) {
            if(busy || retirementRequested || phase!=Phase.BROWSER)return false
            val selected=owner ?:return false
            clearBrowser();busy=true;epoch to selected
        }
        return enqueue {
            val (admitted,owned)=selected;val posts=owned.tokenPosts.get()
            try {withScope(admitted) {scope->
                val session=owned.protocol.exchangeCallback(raw,owned.pending,owned.generation,owned.issuer,scope)
                try {
                    requireCurrent(admitted)
                    val before=journal.read();check(before==owned.record && before.phase==AdminKeyPhase.BROWSER)
                    val authenticated=journal.commit(before,before.copy(revision=before.revision+1,phase=AdminKeyPhase.AUTHENTICATED))
                    publishRecord(authenticated)
                    context(admitted,owned.deviceBinding,owned.discoveryBinding)
                    synchronized(commands) {requireCurrent(admitted);check(owner===owned);owned.session=session;phase=Phase.AUTHENTICATED;reason=""}
                }catch(error:Exception) {owned.protocol.logout(session);throw error}
            }}catch(error:Exception) {
                val keep=error is AdminException && error.reason==AdminFailure.INVALID_REPLY && owned.tokenPosts.get()==posts &&
                    current(admitted) && try {owned.protocol.authorization(owned.pending,owned.generation)==owned.browser}catch(_:Exception){false}
                if(keep)synchronized(commands) {if(current(admitted))reason="INVALID_REPLY"}
                else requestRetirement(admitted,finite(error))
            }
        }
    }
    fun logout(expectedGeneration:Long):Boolean {
        var schedule=false
        val retired=synchronized(commands) {
            if(generation!=expectedGeneration)return false
            if(!retirementRequested)epoch++
            retirementRequested=true;retirementPhase=Phase.SIGNED_OUT;retirementReason=""
            phase=Phase.REAUTHENTICATE;reason="SIGNING_OUT";clearMailbox();clearBrowser()
            if(!busy) {busy=true;schedule=true}
            owner to activeScope
        }
        closeSession(retired.first);retired.second?.cancel()
        return if(schedule)enqueue {} else true
    }
    fun readStart(id:String,expectedGeneration:Long,kind:String,target:String):Boolean {
        if(!operationID.matches(id) || target.length>64 || kind !in setOf("devices","configuration","runtime") ||
            !(targetID.matches(target) || kind=="devices" && target.isEmpty()))return false
        val selected=synchronized(commands) {
            if(busy || retirementRequested || phase!=Phase.AUTHENTICATED || generation!=expectedGeneration)return false
            val owned=owner?.takeIf {it.session!=null} ?:return false
            val now=elapsed();if(now<0 || now>Long.MAX_VALUE-60_000)return false
            clearMailbox();mailbox=Mailbox(id,expectedGeneration,now,now+60_000)
            busy=true;activeRead=id;epoch to owned
        }
        return enqueue {
            val (admitted,owned)=selected
            try {withScope(admitted) {scope->
                var session=checkNotNull(owned.session);val now=elapsed()
                if(now<0 || now>Long.MAX_VALUE-30_000)throw AdminException(AdminFailure.SESSION_EXPIRED)
                if(session.accessUntilElapsedMs<=now+30_000) {
                    val rotated=owned.protocol.refresh(session,owned.issuer,scope)
                    try {
                        context(admitted,owned.deviceBinding,owned.discoveryBinding)
                        synchronized(commands) {requireCurrent(admitted);check(owner===owned);owned.session=rotated;session=rotated}
                    }
                    catch(error:Exception) {
                        owned.protocol.logout(rotated)
                        requestRetirement(admitted,"REAUTHENTICATE")
                        throw error
                    }
                }
                val body=when(kind) {
                    "devices"->owned.protocol.listDevices(target,session,scope).wireJson()
                    "configuration"->owned.protocol.deviceConfiguration(target,session,scope).wireJson()
                    else->owned.protocol.deviceRuntime(target,session,scope).wireJson()
                }.toByteArray(Charsets.UTF_8)
                try {
                    require(body.size<=524_288);context(admitted,owned.deviceBinding,owned.discoveryBinding)
                    synchronized(commands) {
                        val ticket=mailbox
                        val ended=elapsed()
                        if(current(admitted) && ticket?.id==id && ticket.generation==expectedGeneration && ended in ticket.createdAt..ticket.expiresAt) {
                            ticket.body=body.copyOf();ticket.state="done"
                        }
                    }
                }finally {body.fill(0)}
            }}catch(error:Exception) {
                if(error is AdminException && error.reason in setOf(AdminFailure.REAUTHENTICATE,AdminFailure.SESSION_EXPIRED))
                    requestRetirement(admitted,finite(error))
                else synchronized(commands) {mailbox?.takeIf {it.id==id && it.generation==expectedGeneration}?.let {it.state="failed";it.reason=finite(error)}}
            }
        }
    }
    fun readResult(id:String,expectedGeneration:Long):ReadResult=synchronized(commands) {
        val ticket=mailbox;val now=elapsed()
        if(!operationID.matches(id) || generation!=expectedGeneration || ticket?.id!=id || ticket.generation!=expectedGeneration)
            return@synchronized ReadResult("gone","")
        if(now !in ticket.createdAt..ticket.expiresAt) {clearMailbox();return@synchronized ReadResult("gone","")}
        ReadResult(ticket.state,ticket.reason,ticket.body)
    }
    /** Same single controller worker and consume-once mailbox as administrative
     * reads. Binder never opens an editor, parses JSON or performs Keystore I/O. */
    fun editorStart(id:String,expectedGeneration:Long,command:AdminEditorCoordinator.Command):Boolean =
        editorOperationStart(id,expectedGeneration,command.kind !in setOf(AdminEditorCoordinator.Kind.SAVE_LOCAL,AdminEditorCoordinator.Kind.CLOSE)) {coordinator,access->
            io.syn443.android.admin.AdminEditorWire.encode(coordinator.execute(command,access))
        }
    fun comparisonStart(id:String,expectedGeneration:Long,command:AdminEditorCoordinator.ComparisonCommand):Boolean =
        editorOperationStart(id,expectedGeneration,command.kind==AdminEditorCoordinator.ComparisonKind.LOAD) {coordinator,access->
            io.syn443.android.admin.AdminComparisonWire.encode(coordinator.comparison(command,access))
        }
    private fun editorOperationStart(id:String,expectedGeneration:Long,refreshAccess:Boolean,
        work:(AdminEditorCoordinator,AdminEditorCoordinator.Access)->ByteArray):Boolean {
        if(!operationID.matches(id))return false
        val selected=synchronized(commands) {
            if(busy || retirementRequested || phase!=Phase.AUTHENTICATED || generation!=expectedGeneration)return false
            val owned=owner?.takeIf {it.session!=null} ?:return false
            val now=elapsed();if(now<0 || now>Long.MAX_VALUE-60_000)return false
            clearMailbox();mailbox=Mailbox(id,expectedGeneration,now,now+60_000)
            busy=true;activeRead=id;epoch to owned
        }
        return enqueue {
            val (admitted,owned)=selected
            try {withScope(admitted) {scope->
                fun checkedSession(refresh:Boolean):AdminSession {
                    context(admitted,owned.deviceBinding,owned.discoveryBinding)
                    var session=checkNotNull(owned.session)
                    val now=elapsed()
                    if(now<0 || now>Long.MAX_VALUE-30_000)throw AdminException(AdminFailure.SESSION_EXPIRED)
                    if(refresh && session.accessUntilElapsedMs<=now+30_000) {
                        val rotated=owned.protocol.refresh(session,owned.issuer,scope)
                        try {
                            context(admitted,owned.deviceBinding,owned.discoveryBinding)
                            synchronized(commands) {requireCurrent(admitted);check(owner===owned);owned.session=rotated;session=rotated}
                        }catch(error:Exception) {
                            owned.protocol.logout(rotated);requestRetirement(admitted,"REAUTHENTICATE");throw error
                        }
                    }
                    owned.protocol.layerOwnership(session)
                    return session
                }
                // Offline writes use the original account lease; network commands
                // refresh before the coordinator can prepare a durable mutation.
                checkedSession(refreshAccess)
                val access=object:AdminEditorCoordinator.Access {
                    override fun ownership()=owned.protocol.layerOwnership(checkedSession(false))
                    override fun check() {checkedSession(false)}
                    override fun action(request:AdminLayerRequest)=owned.protocol.layerAction(request,checkedSession(true),scope)
                    override fun reviewDeadline(preview:AdminLayerPreview)=owned.protocol.layerReviewDeadline(preview,checkedSession(false))
                }
                val coordinator=editorCoordinator ?:AdminEditorCoordinator({
                    if(test==null)AdminEditorStore(context)
                    else checkNotNull(test.editorStore) {"isolated_editor_store_required"}.invoke()
                },::boot,::elapsed).also {editorCoordinator=it}
                val body=work(coordinator,access)
                try {
                    require(body.size in 1..524_288);access.check()
                    context(admitted,owned.deviceBinding,owned.discoveryBinding)
                    synchronized(commands) {
                        val ticket=mailbox;val ended=elapsed()
                        if(current(admitted) && ticket?.id==id && ticket.generation==expectedGeneration && ended in ticket.createdAt..ticket.expiresAt) {
                            ticket.body=body.copyOf();ticket.state="done"
                        }
                    }
                }finally {body.fill(0)}
            }}catch(error:Exception) {
                if(error is AdminException && error.reason in setOf(AdminFailure.REAUTHENTICATE,AdminFailure.SESSION_EXPIRED))
                    requestRetirement(admitted,finite(error))
                else synchronized(commands) {mailbox?.takeIf {it.id==id && it.generation==expectedGeneration}?.let {it.state="failed";it.reason=finite(error)}}
            }
        }
    }
    fun readCancel(id:String,expectedGeneration:Long):Boolean {
        val scope=synchronized(commands) {
            val ticket=mailbox
            if(generation!=expectedGeneration || ticket?.id!=id || ticket.generation!=expectedGeneration)return false
            clearMailbox();if(activeRead==id)activeScope else null
        }
        scope?.cancel();return true
    }
    /** Fixture cleanup only. A blocked actual owner cannot be made idle or shut down through this hook. */
    internal fun shutdownForTest():Boolean {
        check(test!=null && android.os.Looper.myLooper()!=android.os.Looper.getMainLooper() &&
            !Thread.currentThread().name.startsWith("Binder:"))
        synchronized(commands) {if(busy)return false;worker.shutdown()}
        val stopped=worker.awaitTermination(10,TimeUnit.SECONDS)
        if(stopped)http.close()
        return stopped
    }
}
