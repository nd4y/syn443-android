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
    override fun onCreate(): Boolean {
        val store = StateStore.get(checkNotNull(context))
        if (store.checkpoint().desiredOn) store.event("Recovering", "controller_recreated", store.read().optLong("networkEpoch"))
        return true
    }
    override fun call(method: String, arg: String?, extras: Bundle?): Bundle {
        val context = checkNotNull(context)
        val caller = Binder.getCallingUid()
        require(caller == Process.myUid() || (io.syn443.android.BuildConfig.DEBUG && caller == 2000)) { "unauthorized caller" }
        val store = StateStore.get(context)
        return try {
            when (method) {
                "status", "logs" -> Unit
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
                    store.update { store.put(it, Recovery.command(store.checkpoint(it), on)); it.put("phase", if (on) "Connecting" else "Off") }
                    val intent = Intent(context, TunnelService::class.java).setAction(TunnelService.RECONCILE)
                    if (on) context.startForegroundService(intent) else context.startService(intent)
                }
                "resume" -> {
                    require(store.checkpoint().desiredOn) { "newer Stop wins" }
                    context.startForegroundService(Intent(context, TunnelService::class.java).setAction(TunnelService.RECONCILE))
                }
                "fault-crash", "fault-hang" -> {
                    require(io.syn443.android.BuildConfig.DEBUG && caller == 2000)
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
                else -> error("unknown command")
            }
            val result = store.read()
            if (method == "status") result.put("netbird", OverlaySnapshot.read())
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
