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
    companion object { @Volatile var explicitConnectInProcess = false }
    private var initialized=false
    @Synchronized private fun initializeUnlocked() {
        if(initialized)return
        check(LifecycleAccess.unlocked(checkNotNull(context)))
        val store = StateStore.get(checkNotNull(context))
        OsIntentGate.observe(checkNotNull(context), store)
        if (store.checkpoint().desiredOn) store.event(if (store.read().optBoolean("resumeRequired")) "NeedsAction" else "Recovering", if (store.read().optBoolean("resumeRequired")) "explicit_resume_required" else "controller_recreated", store.read().optLong("networkEpoch"))
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
            initializeUnlocked()
            val store = StateStore.get(context)
            when (method) {
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
                "auth-cancel" -> {
                    try {store.serialized {
                        store.update {store.put(it,Recovery.command(store.checkpoint(it),false));OsIntentGate.command(context,it,false);it.put("phase","Off")}
                        LoginController.get(context).cancel()
                    }} finally {context.startService(Intent(context,TunnelService::class.java).setAction(TunnelService.RECONCILE))}
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
                    require(RuntimePolicies(context).managed())
                    if (store.checkpoint().desiredOn) requestReconcile(context, store, method)
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
                    require(method !in setOf("fault-java", "fault-native") || (store.checkpoint().desiredOn && store.read().optBoolean("engineActive")))
                    context.startService(Intent(context, TunnelService::class.java).setAction(method))
                }
                "netbird-diagnose" -> {
                    require(store.checkpoint().desiredOn)
                    context.startService(Intent(context, TunnelService::class.java).setAction(method))
                }
                "routes-status" -> return Bundle().apply {putBoolean("ok",true);putString("json",RouteSnapshot.view(store.read()).toString())}
                "routes-check", "routes-cancel" -> {
                    require(store.checkpoint().desiredOn && store.read().optBoolean("engineActive"))
                    require(arg==null || (method=="routes-check" && Regex("route-[1-9][0-9]?").matches(arg)))
                    require(method!="routes-check" || RouteSnapshot.accepts(arg))
                    context.startService(Intent(context,TunnelService::class.java).setAction(method).also {if(arg!=null)it.putExtra("routeId",arg)})
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
                result.put("localConfigControl",io.syn443.android.BuildConfig.DEBUG)
                val os=LifecycleAccess.policy(context)
                result.put("netbird", OverlaySnapshot.read()).put("policy", RuntimePolicies(context).status()).put("routeHealth",RouteSnapshot.view(result)).put("osPolicy",os)
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
    override fun getType(uri: Uri): String? = null
    override fun insert(uri: Uri, values: ContentValues?): Uri? = null
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?) = 0
    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<out String>?) = 0
}
