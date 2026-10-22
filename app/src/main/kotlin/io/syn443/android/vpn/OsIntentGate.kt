package io.syn443.android.vpn

import android.app.PendingIntent
import android.app.AlarmManager
import android.content.Context
import android.content.Intent
import android.provider.Settings
import android.os.SystemClock
import org.json.JSONObject

/** System-owned marker survives process death, but is cancelled by package Force stop.
 * A far-future, inexact NON_WAKEUP alarm retains the token: ActivityManager's
 * PendingIntent map alone holds weak references. It never restarts VPN or wakes
 * the device. AndroidX WorkManager uses a similar long-lived alarm sentinel. */
object OsIntentGate {
    private const val RETAIN_MS = 3650L * 24 * 60 * 60 * 1000
    private fun retain(context: Context) {
        val pending = checkNotNull(marker(context, true))
        context.getSystemService(AlarmManager::class.java).set(AlarmManager.ELAPSED_REALTIME,
            SystemClock.elapsedRealtime() + RETAIN_MS, pending)
    }
    private fun boot(context: Context) = Settings.Global.getInt(context.contentResolver, Settings.Global.BOOT_COUNT, -1).also { require(it >= 0) }
    private fun marker(context: Context, create: Boolean): PendingIntent? = PendingIntent.getBroadcast(context, 4431,
        Intent(context, BootReceiver::class.java).setAction("io.syn443.USER_INTENT_MARKER"),
        PendingIntent.FLAG_IMMUTABLE or if (create) PendingIntent.FLAG_UPDATE_CURRENT else PendingIntent.FLAG_NO_CREATE)
    fun command(context: Context, value: JSONObject, on: Boolean) {
        if (on) retain(context) else marker(context, false)?.let {
            context.getSystemService(AlarmManager::class.java).cancel(it); it.cancel()
        }
        value.put("intentBoot", boot(context)).put("resumeRequired", false)
    }
    fun observe(context: Context, store: StateStore) {
        store.update { value ->
            if (value.optBoolean("desiredOn") && value.optInt("intentBoot", -1) == boot(context) && marker(context, false) == null)
                value.put("resumeRequired", true)
        }
    }
    fun allowed(context: Context, store: StateStore): Boolean {
        val value = store.read()
        return !value.optBoolean("resumeRequired") && value.optInt("intentBoot", -1) == boot(context) && marker(context, false) != null
    }
    fun bootTrigger(context: Context, store: StateStore, action: String): Boolean {
        var accepted = false
        store.update { value ->
            if (value.optBoolean("desiredOn") && !value.optBoolean("resumeRequired")) {
                val newBoot = value.optInt("intentBoot", -1) != boot(context)
                if ((action == Intent.ACTION_BOOT_COMPLETED && newBoot) || marker(context, false) != null) {
                    retain(context); value.put("intentBoot", boot(context)); accepted = true
                } else value.put("resumeRequired", true)
            }
        }
        return accepted
    }
}
