package io.syn443.android.acceptance;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Intent;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/** Independent test-UID TUN owner; SDK/Java only, never in the client APK. */
public final class CompetingVpnService extends VpnService {
    private ParcelFileDescriptor tun;
    private void mark(String value) {
        try (FileOutputStream output = new FileOutputStream(new File(getNoBackupFilesDir(), "competing-vpn-state"))) {
            output.write(value.getBytes(StandardCharsets.US_ASCII));
        } catch (IOException error) { throw new IllegalStateException("Fixture state unavailable", error); }
    }
    @Override public int onStartCommand(Intent intent, int flags, int id) {
        NotificationManager manager = getSystemService(NotificationManager.class);
        if (manager == null) throw new IllegalStateException("Notification service unavailable");
        manager.createNotificationChannel(new NotificationChannel("acceptance", "VPN acceptance test", NotificationManager.IMPORTANCE_LOW));
        startForeground(41, new Notification.Builder(this, "acceptance")
            .setSmallIcon(android.R.drawable.ic_dialog_info).setContentTitle("SYN443 temporary VPN test").build());
        if (tun == null) tun = new Builder().setSession("SYN443 acceptance fixture")
            .addAddress("192.0.2.2", 32).addRoute("198.51.100.0", 24).establish();
        mark(tun == null ? "unavailable" : "active");
        if (tun == null) stopSelf();
        return START_NOT_STICKY;
    }
    private void release() {
        if (tun != null) { try { tun.close(); } catch (IOException ignored) { } tun = null; }
        mark("off");
    }
    @Override public void onRevoke() { release(); stopSelf(); super.onRevoke(); }
    @Override public void onDestroy() { release(); super.onDestroy(); }
}
