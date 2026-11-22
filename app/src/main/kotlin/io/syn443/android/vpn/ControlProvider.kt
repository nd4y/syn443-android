package io.syn443.android.vpn

import android.content.ContentProvider
import android.content.ContentValues
import android.content.Intent
import android.database.Cursor
import android.net.Uri
import android.os.Binder
import android.os.Bundle
import android.os.Process
import android.util.Base64
import io.syn443.recovery.Recovery

/** One durable command writer in :controller. Shell access exists in debug builds only. */
class ControlProvider : ContentProvider() {
    private val resources by lazy { ResourceDiagnostics(checkNotNull(context).applicationContext) }
    private val bundleShell = io.syn443.android.support.BundleShellConnection()
    companion object { @Volatile var explicitConnectInProcess = false }
    private var initialized=false
    @Synchronized private fun initializeUnlocked() {
        if(initialized)return
        check(LifecycleAccess.unlocked(checkNotNull(context)))
        val store = StateStore.get(checkNotNull(context))
        OsIntentGate.observe(checkNotNull(context), store)
        LifecycleAccess.recordControllerStartup(store)
        LoginController.get(checkNotNull(context)).recover()
        runCatching {RouteSnapshot.configure(store.config(),store.read().optString("configRevision"))}
        initialized=true
    }
    override fun onCreate(): Boolean = true
    private fun requestReconcile(context: android.content.Context, store: StateStore, action: String = TunnelService.RECONCILE) {
        // A missing VPN grant also removes Android's background FGS exemption.
        // Persist intent, but wait for the ordinary Activity permission dialog.
        if (android.net.VpnService.prepare(context) != null) {
            store.event("NeedsPermission", "vpn_permission_required", store.read().optLong("networkEpoch"))
            return
        }
        context.startForegroundService(Intent(context, TunnelService::class.java).setAction(action))
    }
    override fun call(method: String, arg: String?, extras: Bundle?): Bundle {
        val context = checkNotNull(context)
        val caller = Binder.getCallingUid()
        require(caller == Process.myUid() || (io.syn443.android.BuildConfig.DEBUG && caller == 2000)) { "unauthorized caller" }
        if(!LifecycleAccess.unlocked(context))return Bundle().apply {
            putBoolean("ok",method=="status")
            if(method=="status")putString("json",LifecycleAccess.lockedStatus().toString()) else putString("error","needs_unlock")
        }
        return try {
            // Passive diagnostics must not initialize login, observe OS intent,
            // configure routes, or reconcile the VPN as a side effect of collection.
            if (method in setOf("bundle-shell-hold", "bundle-shell-state", "bundle-shell-release")) {
                require(io.syn443.android.BuildConfig.DEBUG && caller == 2000 && (extras == null || extras.isEmpty))
                val state = bundleShell.command(method, requireNotNull(arg))
                return Bundle().apply { putBoolean("ok", true); putString("json", org.json.JSONObject().put("state", state).toString()) }
            }
            if (method in setOf("bundle-collect", "bundle-status", "bundle-cancel", "bundle-open", "bundle-read")) {
                require(extras == null || extras.isEmpty)
                val bundles = io.syn443.android.support.SupportBundleController.get(context)
                val result = when (method) {
                    "bundle-collect" -> { require(arg == null); bundles.collect() }
                    "bundle-status" -> bundles.status(requireNotNull(arg))
                    "bundle-cancel" -> bundles.cancel(requireNotNull(arg))
                    "bundle-open" -> bundles.open(requireNotNull(arg))
                    else -> bundles.read(requireNotNull(arg))
                }
                return Bundle().apply { putBoolean("ok", true); putString("json", result.toString()) }
            }
            if (method == "overlay-status") {
                require(extras == null || extras.isEmpty)
                val result = OverlayProviderHealth.read(requireNotNull(arg)) {
                    val state = StateStore.get(context).read()
                    LifecycleAccess.engineStatus(context, state)
                    OverlaySnapshot.forStatus(state.optLong("generation", -1), state.optLong("networkEpoch", -1),
                        state.opt("desiredOn") == true, state.opt("engineActive") == true)
                }
                return Bundle().apply { putBoolean("ok", true); putString("json", result.toString()) }
            }
            if (method == "route-explain") {
                require(caller == Process.myUid() && arg != null && arg.length <= 2048 && extras == null)
                val query = LocalRouteQuery.parse(arg)
                val store = StateStore.get(context)
                val raw = checkNotNull(store.config())
                var selected: String? = null
                val result = LocalRouteExplanation.describe(raw, query) { selected = it }
                val revision = io.syn443.policy.Policy.hash(raw)
                // A revocation or replacement concurrent with evaluation invalidates the answer.
                require(store.config() == raw)
                return Bundle().apply {
                    putBoolean("ok", true)
                    putString("description", result)
                    putString("outbound", selected)
                    putString("revision", revision)
                }
            }
            initializeUnlocked()
            val store = StateStore.get(context)
            when (method) {
                "release-context" -> {
                    require(caller == Process.myUid() && arg == null && extras == null)
                    return LoginController.get(context).releaseContext()
                }
                "network-mode" -> {
                    require(caller==Process.myUid() && extras==null && arg!=null && arg.length<=96)
                    val values=arg.split('|')
                    require(values.size==3 && values[0].length==36 && values[1] in setOf("AUTO","WIFI","HOME_WIFI","CELLULAR","CELLULAR_RESTRICTED"))
                    val minutes=values[2].toIntOrNull() ?: throw IllegalArgumentException("invalid_duration")
                    require(minutes in 0..1440 && LifecycleAccess.requestNetworkMode(values[0],values[1],minutes))
                    return Bundle().apply {putBoolean("ok",true)}
                }
                "admin-status" -> {
                    require(caller==Process.myUid() && arg==null)
                    return Bundle().apply {putBoolean("ok",true);putString("json",AdminController.get(context).status().toString())}
                }
                "admin-login", "admin-logout" -> {
                    require(caller==Process.myUid())
                    val generation=requireNotNull(arg?.toLongOrNull()).also {require(it>=0)}
                    val admin=AdminController.get(context)
                    return Bundle().apply {
                        val admitted=if(method=="admin-login")admin.start(generation) else admin.logout(generation)
                        putBoolean("ok",true);putBoolean("admitted",admitted)
                    }
                }
                "admin-browser-start", "admin-browser-result", "admin-browser-cancel" -> {
                    require(caller==Process.myUid())
                    val id=requireNotNull(arg).also {require(it.matches(Regex("[a-f0-9]{32}")))}
                    val generation=requireNotNull(extras).getLong("generation",-1).also {require(it>=0)}
                    val admin=AdminController.get(context)
                    return Bundle().apply {
                        putBoolean("ok",true)
                        when(method) {
                            "admin-browser-start" -> putBoolean("admitted",admin.prepareBrowser(id,generation))
                            "admin-browser-cancel" -> putBoolean("admitted",admin.browserCancel(id,generation))
                            else -> {
                                val result=admin.browserResult(id,generation)
                                putString("json",org.json.JSONObject().put("state",result.state).put("reason",result.reason).toString())
                                if(result.state=="done") {putString("url",result.url);putLong("expiresAtElapsedMs",result.expiresAtElapsedMs)}
                            }
                        }
                    }
                }
                "admin-callback" -> {
                    require(caller==Process.myUid())
                    val callback=requireNotNull(arg).also {require(it.length in 1..8192)}
                    return Bundle().apply {putBoolean("ok",true);putBoolean("admitted",AdminController.get(context).callback(callback))}
                }
                "admin-editor-start" -> {
                    require(caller==Process.myUid())
                    val id=requireNotNull(arg).also {require(it.matches(Regex("[a-f0-9]{32}")))}
                    val input=requireNotNull(extras)
                    val fields=setOf("generation","kind","device","binding","localRevision","pages","reviewBinding","reviewDeadline","comparisonBinding")
                    require(input.keySet()==fields || input.keySet()==fields+"operationBinding")
                    val generation=input.getLong("generation",-1).also {require(it>=0)}
                    val kind=AdminEditorCoordinator.Kind.valueOf(requireNotNull(input.getString("kind")))
                    val device=requireNotNull(input.getString("device")).also {require(it.length<=64)}
                    val binding=requireNotNull(input.getString("binding")).also {require(it.length<=128)}
                    val local=input.getLong("localRevision",-1).also {require(it>=0)}
                    val pages=requireNotNull(input.getStringArrayList("pages")).also {
                        require(it.size<=64 && it.all {page->page.length<=8192} && it.sumOf {page->page.length}<=262_144)
                    }
                    val review=requireNotNull(input.getString("reviewBinding")).also {require(it.length<=128)}
                    val deadline=input.getLong("reviewDeadline",-1).also {require(it>=0)}
                    val comparison=requireNotNull(input.getString("comparisonBinding")).also {require(it.length<=43)}
                    val operation=input.getString("operationBinding","").also {require(it.length<=43)}
                    val command=AdminEditorCoordinator.Command(kind,device,binding,local,pages,review,deadline,comparison,operation)
                    return Bundle().apply {putBoolean("ok",true);putBoolean("admitted",AdminController.get(context).editorStart(id,generation,command))}
                }
                "admin-comparison-start" -> {
                    require(caller==Process.myUid())
                    val id=requireNotNull(arg).also {require(it.matches(Regex("[a-f0-9]{32}")))}
                    val input=requireNotNull(extras)
                    require(input.keySet()==setOf("generation","kind","device","documentBinding","localRevision","comparisonBinding",
                        "section","offset","rowId","side","page","choice"))
                    val generation=input.getLong("generation",-1).also {require(it>=0)}
                    val kind=AdminEditorCoordinator.ComparisonKind.valueOf(requireNotNull(input.getString("kind")))
                    val device=requireNotNull(input.getString("device")).also {require(it.length<=64)}
                    val document=requireNotNull(input.getString("documentBinding")).also {require(it.length<=128)}
                    val revision=input.getLong("localRevision",-1).also {require(it>=0)}
                    val binding=requireNotNull(input.getString("comparisonBinding")).also {require(it.length<=43)}
                    val section=io.syn443.android.admin.AdminComparisonSection.valueOf(requireNotNull(input.getString("section")))
                    val offset=input.getInt("offset",-1).also {require(it in 0..8194)}
                    val row=requireNotNull(input.getString("rowId")).also {require(it.length<=43)}
                    val side=io.syn443.android.admin.AdminComparisonSide.valueOf(requireNotNull(input.getString("side")))
                    val page=input.getInt("page",-1).also {require(it in 0..255)}
                    val choice=requireNotNull(input.getString("choice")).also {require(it in setOf("","LOCAL","CURRENT"))}
                    val command=AdminEditorCoordinator.ComparisonCommand(kind,device,document,revision,binding,section,offset,row,side,page,choice)
                    return Bundle().apply {putBoolean("ok",true);putBoolean("admitted",AdminController.get(context).comparisonStart(id,generation,command))}
                }
                "admin-read-start", "admin-read-result", "admin-read-cancel" -> {
                    require(caller==Process.myUid())
                    val id=requireNotNull(arg).also {require(it.matches(Regex("[a-f0-9]{32}")))}
                    val input=requireNotNull(extras);val generation=input.getLong("generation",-1).also {require(it>=0)}
                    val admin=AdminController.get(context)
                    return Bundle().apply {
                        putBoolean("ok",true)
                        when(method) {
                            "admin-read-start" -> putBoolean("admitted",admin.readStart(id,generation,
                                requireNotNull(input.getString("action")),requireNotNull(input.getString("target")),
                                if(input.containsKey("prefix"))requireNotNull(input.getString("prefix")) else ""))
                            "admin-read-cancel" -> putBoolean("admitted",admin.readCancel(id,generation))
                            else -> {
                                val result=admin.readResult(id,generation)
                                putString("json",org.json.JSONObject().put("state",result.state).put("reason",result.reason).toString())
                                if(result.state=="done")putByteArray("body",result.bodyBytes())
                            }
                        }
                    }
                }
                "chat-start" -> {
                    require(caller==Process.myUid());val input=requireNotNull(extras)
                    return Bundle().apply {putBoolean("ok",LoginController.get(context).chatStart(requireNotNull(arg),input.getLong("generation",-1),requireNotNull(input.getString("action")),requireNotNull(input.getString("body"))))}
                }
                "chat-result" -> {
                    require(caller==Process.myUid())
                    return Bundle().apply {putString("json",LoginController.get(context).chatResult(requireNotNull(arg),requireNotNull(extras).getLong("generation",-1)).toString())}
                }
                "chat-cancel" -> {require(caller==Process.myUid());LoginController.get(context).chatCancel(requireNotNull(arg))}
                "auth-invite-preview" -> {
                    require(caller==Process.myUid())
                    return Bundle().apply {putBoolean("admitted",LoginController.get(context).previewInvitation(requireNotNull(arg),requireNotNull(extras?.getString("link"))))}
                }
                "auth-invite-result" -> {require(caller==Process.myUid());return Bundle().apply {putString("json",LoginController.get(context).invitationPreview(requireNotNull(arg)).toString())}}
                "auth-invite-start" -> {require(caller==Process.myUid());LoginController.get(context).startInvitation(requireNotNull(arg))}
                "auth-service-start" -> {require(caller==Process.myUid());LoginController.get(context).startInvitation(requireNotNull(arg),false)}
                "auth-trust-rotation" -> {require(caller==Process.myUid());LoginController.get(context).rotateBootstrap(requireNotNull(arg))}
                "auth-status" -> return Bundle().apply {putBoolean("ok",true);putString("json",LoginController.get(context).status().toString())}
                "auth-telemetry" -> {
                    require(caller==Process.myUid())
                    val parts=requireNotNull(arg).split(':',limit=3)
                    require(parts.size==2)
                    val changed=LoginController.get(context).chooseTechnicalTelemetry(parts[0].toLong(),parts[1].toBooleanStrict())
                    return Bundle().apply {putBoolean("ok",changed)}
                }
                "auth-bootstrap-file" -> {
                    require(io.syn443.android.BuildConfig.DEBUG && caller==2000)
                    val file=java.io.File(context.noBackupFilesDir,"operator-identity.json")
                    val raw=try {require(file.length() in 1..16_384);file.readText(Charsets.UTF_8)} finally {file.delete()}
                    LoginController.get(context).configure(raw)
                }
                "auth-start" -> LoginController.get(context).start(requireNotNull(arg?.toLongOrNull()))
                "auth-retry" -> LoginController.get(context).retry(requireNotNull(arg?.toLongOrNull()))
                "auth-reauth" -> {
                    require(caller==Process.myUid())
                    val parts=requireNotNull(arg).split(':',limit=3)
                    require(parts.size==2)
                    val admitted=LoginController.get(context).startReauthentication(parts[0].toLong(),parts[1].toLong())
                    return Bundle().apply {putBoolean("ok",admitted)}
                }
                "auth-policy-poll" -> {
                    require(caller==Process.myUid() && extras==null)
                    val generation=requireNotNull(arg?.toLongOrNull()).also { require(it>=0) }
                    return Bundle().apply {
                        putBoolean("ok",true)
                        putBoolean("admitted",LoginController.get(context).refreshAssignment(false,generation))
                    }
                }
                "auth-poll" -> return Bundle().apply {
                    putBoolean("ok",true)
                    putBoolean("admitted",LoginController.get(context).pollProvisioning(requireNotNull(arg?.toLongOrNull())))
                }
                "auth-browser" -> {
                    require(caller==Process.myUid())
                    return Bundle().apply {putBoolean("ok",true);putString("url",LoginController.get(context).browserUrl(requireNotNull(arg?.toLongOrNull())))}
                }
                "auth-admin-panel" -> {
                    require(caller==Process.myUid())
                    val url=LoginController.get(context).adminPanelUrl(requireNotNull(arg?.toLongOrNull()))
                    return Bundle().apply {putBoolean("ok",url!=null);putString("url",url)}
                }
                "auth-admin-poll" -> {
                    require(caller==Process.myUid())
                    return Bundle().apply {
                        putBoolean("ok",true)
                        putBoolean("admitted",LoginController.get(context).pollAdminPanel(requireNotNull(arg?.toLongOrNull())))
                    }
                }
                "auth-callback" -> {
                    require(caller==Process.myUid());LoginController.get(context).callback(requireNotNull(arg))
                }
                "auth-cancel", "auth-reviewed-cancel" -> {
                    val reviewed = method == "auth-reviewed-cancel"
                    val stamp = if (reviewed) {
                        require(caller == Process.myUid() && extras == null)
                        val parts = requireNotNull(arg).split(':', limit = 3)
                        require(parts.size == 2)
                        parts[0].toLong() to parts[1].toLong()
                    } else null
                    var reconcile = false
                    try {
                        val accepted = store.serialized {
                            val controller = LoginController.get(context)
                            fun stopVpn() {
                                reconcile = true
                                store.update {
                                    store.put(it,Recovery.command(store.checkpoint(it),false))
                                    OsIntentGate.command(context,it,false)
                                    it.put("phase","Off")
                                }
                            }
                            if (stamp != null) controller.cancelReviewed(stamp.first, stamp.second, ::stopVpn)
                            else { stopVpn(); controller.cancel(); true }
                        }
                        if (reviewed) return Bundle().apply { putBoolean("ok",accepted) }
                    } finally {
                        if (reconcile) context.startService(Intent(context,TunnelService::class.java).setAction(TunnelService.RECONCILE))
                    }
                }
                "engine-exits" -> {
                    require(arg == null || (io.syn443.android.BuildConfig.DEBUG && caller == 2000 && arg.toIntOrNull()?.let { it > 0 } == true))
                    return Bundle().apply { putBoolean("ok", true); putString("json", EngineExitDiagnostics.snapshot(context, arg?.toInt()).toString()) }
                }
                "resources" -> return Bundle().apply { putBoolean("ok", true); putString("json", resources.snapshot().toString()) }
                "health-workers" -> {
                    require(io.syn443.android.BuildConfig.DEBUG && (caller==2000 || caller==Process.myUid()))
                    return Bundle().apply {putBoolean("ok",true);putString("json",PolicyChecks.diagnostics().toString())}
                }
                "status", "logs" -> Unit
                "foreground-open" -> {
                    val generation = arg?.toLongOrNull()
                    val cp = store.checkpoint()
                    val serviceExists = checkNotNull(context.getSystemService(android.app.ActivityManager::class.java)).getRunningServices(16)
                        .any { it.service.className == TunnelService::class.java.name }
                    if (cp.desiredOn && cp.generation == generation && !serviceExists && !explicitConnectInProcess) {
                        store.update { it.put("resumeRequired", true) }
                        store.event("NeedsAction", "explicit_resume_required", store.read().optLong("networkEpoch"))
                    }
                }
                "policy-bind-file", "policy-stage-file" -> {
                    require(io.syn443.android.BuildConfig.DEBUG && caller == 2000)
                    val file = java.io.File(context.noBackupFilesDir, "operator-policy.json")
                    val raw = try { require(file.length() in 1..524_288); file.readText(Charsets.UTF_8) } finally { file.delete() }
                    val policy = ManagedPolicyStore.get(context)
                    store.serialized {
                        require(!LoginController.get(context).ownsPolicy())
                        if (method == "policy-bind-file") policy.bind(raw) else policy.stage(raw.trim(), store.originalConfig())
                    }
                    if (store.checkpoint().desiredOn) requestReconcile(context, store)
                }
                "policy-refresh" -> {
                    val policies=RuntimePolicies(context)
                    require(policies.managed())
                    if (store.checkpoint().desiredOn) {
                        requestReconcile(context, store, method)
                    } else {
                        require(policies.read().enrolled)
                        val admitted=policies.refreshAssigned(true)
                        return Bundle().apply {
                            putBoolean("ok",true)
                            putString("json",org.json.JSONObject().put("admitted",admitted).toString())
                        }
                    }
                }
                "config-plan-file", "config-apply-file" -> {
                    require(io.syn443.android.BuildConfig.DEBUG && caller==2000)
                    val fields=requireNotNull(arg).split(':')
                    require(fields.size==3 && (fields[0]=="none" || fields[0].matches(Regex("[0-9a-f]{64}"))) &&
                        fields[1].matches(Regex("[0-9a-f]{64}")) && fields[2].matches(Regex("[0-9a-f]{32}")))
                    val file=java.io.File(context.noBackupFilesDir,"operator-local-config-${fields[2]}.json")
                    val raw=try {
                        require(file.length() in 1..262_144)
                        val bytes=ByteArray(262_145)
                        try {
                            var size=0
                            file.inputStream().use {input->
                                while(size<bytes.size) {
                                    val count=input.read(bytes,size,bytes.size-size)
                                    if(count<0)break
                                    require(count>0);size+=count
                                }
                            }
                            require(size in 1..262_144)
                            val frame=bytes.copyOf(size)
                            try {io.syn443.policy.Policy.utf8(frame)} finally {frame.fill(0)}
                        }finally {bytes.fill(0)}
                    }finally {check(!file.exists() || file.delete())}
                    val plan=store.serialized {
                        val checked=store.localConfig(raw,fields[0],fields[1],method=="config-apply-file")
                        if(checked.getBoolean("written"))RouteSnapshot.configure(raw,fields[1])
                        checked
                    }
                    return Bundle().apply {putBoolean("ok",true);putString("json",plan.toString())}
                }
                "import", "import-file" -> {
                    require(!store.checkpoint().desiredOn) { "stop before importing" }
                    val raw = if (method == "import-file") {
                        require(io.syn443.android.BuildConfig.DEBUG && caller == 2000)
                        // Fixed private staging path. Credentials travel over ADB stdin,
                        // never shell arguments, shared storage or an arbitrary path.
                        val file = java.io.File(context.noBackupFilesDir, "operator-import.json")
                        try {
                            require(file.length() in 1..262_144)
                            file.readText(Charsets.UTF_8)
                        } finally { file.delete() }
                    } else Base64.decode(requireNotNull(arg), Base64.NO_WRAP).toString(Charsets.UTF_8)
                    store.importConfig(raw)
                    RouteSnapshot.configure(raw,store.read().optString("configRevision"))
                }
                "connect", "disconnect" -> {
                    val on = method == "connect"
                    store.serialized {
                        require(!on || LoginController.get(context).allowsConnect())
                        store.update { store.put(it, Recovery.command(store.checkpoint(it), on)); OsIntentGate.command(context, it, on); it.put("phase", if (on) "Connecting" else "Off") }
                    }
                    explicitConnectInProcess = on
                    val intent = Intent(context, TunnelService::class.java).setAction(TunnelService.RECONCILE)
                    if (on) requestReconcile(context, store) else context.startService(intent)
                }
                "resume" -> {
                    require(store.checkpoint().desiredOn) { "newer Stop wins" }
                    require(!store.read().optBoolean("resumeRequired")) { "explicit_connect_required" }
                    requestReconcile(context, store)
                }
                "fault-revoke" -> {
                    require(io.syn443.android.BuildConfig.DEBUG && caller == 2000 &&
                        android.os.Build.HARDWARE in setOf("ranchu", "goldfish"))
                    context.startService(Intent(context, TunnelService::class.java).setAction(method))
                }
                "fault-crash", "fault-hang", "fault-owner", "fault-java", "fault-native" -> {
                    require(io.syn443.android.BuildConfig.DEBUG && caller == 2000)
                    val checkpoint = store.checkpoint()
                    require(method !in setOf("fault-java", "fault-native") ||
                        checkpoint.desiredOn && LifecycleAccess.ownsReadyEngine(checkpoint.generation))
                    context.startService(Intent(context, TunnelService::class.java).setAction(method))
                }
                "netbird-diagnose" -> {
                    require(store.checkpoint().desiredOn)
                    context.startService(Intent(context, TunnelService::class.java).setAction(method))
                }
                "netbird-cancel" -> {
                    val jobId = requireNotNull(arg)
                    require(NetBirdPresentation.validDiagnosticId(jobId) && (extras == null || extras.isEmpty))
                    val checkpoint = store.checkpoint()
                    require(checkpoint.desiredOn && LifecycleAccess.cancelNetBirdDiagnostic(checkpoint.generation, jobId))
                    return Bundle().apply {
                        putBoolean("ok", true)
                        putString("json", org.json.JSONObject().put("pending", true).toString())
                    }
                }
                "netbird-view" -> {
                    val checkpoint = store.checkpoint()
                    require(checkpoint.desiredOn && LifecycleAccess.ownsReadyEngine(checkpoint.generation))
                    val view = requireNotNull(OverlayViewRequest.parse(arg))
                    context.startService(Intent(context, TunnelService::class.java).setAction(method).putExtra("viewRequest", arg))
                    return Bundle().apply {
                        putBoolean("ok", true)
                        putString("json", org.json.JSONObject().put("pending", true).put("section", view.section)
                            .put("page", view.page).put("request", view.request).toString())
                    }
                }
                "routes-status" -> return Bundle().apply {
                    putBoolean("ok",true)
                    putString("json",RouteSnapshot.view(LifecycleAccess.engineStatus(context,store.read())).toString())
                }
                "routes-check", "routes-cancel" -> {
                    val checkpoint = store.checkpoint()
                    require(checkpoint.desiredOn && LifecycleAccess.ownsReadyEngine(checkpoint.generation))
                    require(arg==null || (method=="routes-check" && Regex("route-[1-9][0-9]?").matches(arg)))
                    require(method!="routes-check" || RouteSnapshot.accepts(arg))
                    val command=Intent(context,TunnelService::class.java).setAction(method)
                    if(arg!=null) {
                        val displayed=if(extras==null || extras.isEmpty) null else {
                            require(extras.keySet()==setOf("checkContext"))
                            requireNotNull(extras.getString("checkContext"))
                        }
                        val stamp=requireNotNull(RouteSnapshot.captureManualCheck(arg,checkpoint.generation,displayed))
                        command.putExtra("routeId",arg).putExtra("checkContext",stamp)
                    }
                    context.startService(command)
                }
                "fault-ui", "fault-controller" -> {
                    require(io.syn443.android.BuildConfig.DEBUG && caller == 2000)
                    if (method == "fault-controller") {
                        android.os.Handler(android.os.Looper.getMainLooper()).postDelayed({ Process.killProcess(Process.myPid()) }, 100)
                    } else {
                        val process = checkNotNull(context.getSystemService(android.app.ActivityManager::class.java).runningAppProcesses
                            ?.firstOrNull { it.uid == Process.myUid() && it.processName == context.packageName })
                        require(java.io.File("/proc/${process.pid}/cmdline").readText().trimEnd('\u0000') == context.packageName)
                        Process.killProcess(process.pid)
                    }
                }
                "test-health" -> {
                    require(io.syn443.android.BuildConfig.DEBUG)
                    require(arg == "synthetic-http" || arg == "production-https")
                    require(arg != "synthetic-http" || android.os.Build.HARDWARE in setOf("ranchu", "goldfish"))
                    store.update { it.put("testHealth", arg == "synthetic-http") }
                }
                "test-reset-ready" -> {
                    require(io.syn443.android.BuildConfig.DEBUG && android.os.Build.HARDWARE in setOf("ranchu", "goldfish"))
                    // Owner-only serialized snapshot: no foreign process reads AtomicFile
                    // and no budget-reset command is replayed while Stop is settling.
                    val ready=store.serialized {
                        val value=store.read()
                        !store.checkpoint(value).desiredOn && !value.optBoolean("engineActive")
                    }
                    return Bundle().apply {putBoolean("ok",true);putBoolean("ready",ready)}
                }
                "test-reset" -> {
                    require(io.syn443.android.BuildConfig.DEBUG && android.os.Build.HARDWARE in setOf("ranchu", "goldfish"))
                    store.update { value ->
                        require(!store.checkpoint(value).desiredOn && !value.optBoolean("engineActive"))
                        val isolated = io.syn443.recovery.Checkpoint(generation = store.checkpoint(value).generation)
                        store.put(value, Recovery.command(isolated, false))
                    }
                }
                "policy-test-reset" -> {
                    require(io.syn443.android.BuildConfig.DEBUG && caller == 2000 && android.os.Build.HARDWARE in setOf("ranchu", "goldfish"))
                    require(!store.checkpoint().desiredOn && !store.read().optBoolean("engineActive"))
                    ManagedPolicyStore.get(context).resetEmulator()
                }
                else -> error("unknown command")
            }
            val result = store.read()
            if (method == "status") {
                LifecycleAccess.engineStatus(context,result)
                result.put("physicalLink", LifecycleAccess.physicalLink(result) ?: org.json.JSONObject.NULL)
                result.put("netbirdDiagnosticCancellation", true).put("overlayProviderHealth", true)
                result.put("localConfigControl",io.syn443.android.BuildConfig.DEBUG)
                if (result.optString("reason") == "policy_waiting_restart_budget" && result.optBoolean("desiredOn")) {
                    result.put("policyRetryAt", Recovery.replacementReadyAt(store.checkpoint(result), System.currentTimeMillis()))
                }
                val os=LifecycleAccess.policy(context)
                val overlay = OverlaySnapshot.forStatus(result.optLong("generation", -1), result.optLong("networkEpoch", -1), result.opt("desiredOn") == true, result.opt("engineActive") == true)
                result.put("netbird", overlay).put("policy", RuntimePolicies(context).status()).put("routeHealth",RouteSnapshot.view(result)).put("osPolicy",os)
                result.put("internetChecks",PolicyChecks.internetView(result.optLong("generation"),result.optLong("networkEpoch"),
                    result.getJSONObject("policy").optLong("activationGeneration"),result.optBoolean("engineActive") && result.optBoolean("desiredOn")))
                result.put("policyChecks",PolicyChecks.view(result.optLong("generation"),result.optLong("networkEpoch"),
                    result.getJSONObject("policy").optLong("activationGeneration"),result.optBoolean("engineActive")))
                // Legacy fields must not expose the old persisted sample as current.
                for(key in listOf("alwaysOn","lockdown"))result.put(key,if(os.optBoolean("known"))os.getBoolean(key) else org.json.JSONObject.NULL)
            }
            Bundle().apply { putBoolean("ok", true); putString("json", result.toString()) }
        } catch (_: Exception) {
            Bundle().apply { putBoolean("ok", false); putString("error", "command_rejected") }
        }
    }
    override fun query(uri: Uri, projection: Array<out String>?, selection: String?, selectionArgs: Array<out String>?, sortOrder: String?): Cursor? = null
    override fun getType(uri: Uri): String? =
        if (!io.syn443.android.BuildConfig.DEBUG) null else when (uri.toString()) {
            "content://io.syn443.control/support-bundle-session" -> "application/vnd.syn443.bundle-session-v1"
            "content://io.syn443.control/overlay-status" -> "application/vnd.syn443.overlay-status-v1"
            else -> null
        }
    override fun insert(uri: Uri, values: ContentValues?): Uri? = null
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?) = 0
    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<out String>?) = 0
}
