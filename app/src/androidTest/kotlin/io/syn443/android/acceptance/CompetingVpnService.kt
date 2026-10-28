package io.syn443.android.acceptance

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import java.io.File

/** Independent UID/TUN owner in the test APK, never included in the client APK. */
class CompetingVpnService : VpnService() {
    private var tun: ParcelFileDescriptor? = null
    private fun mark(value: String) = File(noBackupFilesDir, "competing-vpn-state").writeText(value)
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val manager = checkNotNull(getSystemService(NotificationManager::class.java))
        manager.createNotificationChannel(NotificationChannel("acceptance", "VPN acceptance test", NotificationManager.IMPORTANCE_LOW))
        startForeground(41, Notification.Builder(this, "acceptance")
            .setSmallIcon(android.R.drawable.ic_dialog_info).setContentTitle("SYN443 temporary VPN test").build())
        if (tun == null) {
            tun = Builder().setSession("SYN443 acceptance fixture").addAddress("192.0.2.2", 32)
                .addRoute("198.51.100.0", 24).establish()
        }
        mark(if (tun != null) "active" else "unavailable")
        if (tun == null) stopSelf()
        return START_NOT_STICKY
    }
    override fun onRevoke() { tun?.close(); tun = null; mark("off"); stopSelf(); super.onRevoke() }
    override fun onDestroy() { tun?.close(); tun = null; mark("off"); super.onDestroy() }
}
