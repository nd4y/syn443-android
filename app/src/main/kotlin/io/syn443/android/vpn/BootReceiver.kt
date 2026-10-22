package io.syn443.android.vpn

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED && intent.action != Intent.ACTION_MY_PACKAGE_REPLACED) return
        val store = StateStore.get(context)
        if (!store.checkpoint().desiredOn) return
        if (store.read().optBoolean("resumeRequired")) return
        if (!OsIntentGate.bootTrigger(context, store, checkNotNull(intent.action))) return
        runCatching { context.startForegroundService(Intent(context, TunnelService::class.java).setAction(TunnelService.RECONCILE)) }
            .onFailure { store.event("NeedsAction", "os_start_restricted", store.read().optLong("networkEpoch")) }
    }
}
