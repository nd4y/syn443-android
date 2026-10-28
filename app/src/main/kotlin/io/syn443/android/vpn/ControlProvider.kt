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
    override fun onCreate(): Boolean {
        val store = StateStore.get(checkNotNull(context))
        OsIntentGate.observe(checkNotNull(context), store)
        if (store.checkpoint().desiredOn) store.event(if (store.read().optBoolean("resumeRequired")) "NeedsAction" else "Recovering", if (store.read().optBoolean("resumeRequired")) "explicit_resume_required" else "controller_recreated", store.read().optLong("networkEpoch"))
        LoginController.get(checkNotNull(context)).recover()
        return true
    }
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
        val store = StateStore.get(context)
        return try {
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
                "auth-status" -> return Bundle().apply {putBoolean("ok",true);putString("json",LoginController.get(context).status().toString())}
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
            if (method == "status") result.put("netbird", OverlaySnapshot.read()).put("policy", RuntimePolicies(context).status())
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
