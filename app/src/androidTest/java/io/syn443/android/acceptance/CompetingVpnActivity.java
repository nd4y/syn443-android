package io.syn443.android.acceptance;

import android.app.Activity;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

/** A separate APK process cannot inherit Kotlin classes from the target app. */
@SuppressWarnings("deprecation")
public final class CompetingVpnActivity extends Activity {
    @Override public void onCreate(Bundle saved) {
        super.onCreate(saved);
        if ("ranchu".equals(Build.HARDWARE) || "goldfish".equals(Build.HARDWARE)) {
            if (getIntent().getBooleanExtra("ci-stop", false)) { stopPeer(); finish(); return; }
            if (getIntent().getBooleanExtra("ci-start", false)) {
                if (VpnService.prepare(this) != null) throw new IllegalStateException("Emulator consent missing");
                startPeer(); finish(); return;
            }
        }
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(32, 64, 32, 32);
        TextView info = new TextView(this);
        info.setText("Temporary SYN443 VPN handover test. Only documentation-network addresses are routed. Stop the test when finished.");
        root.addView(info);
        Button start = new Button(this);
        start.setText("Start acceptance VPN");
        start.setOnClickListener(v -> {
            Intent consent = VpnService.prepare(this);
            if (consent == null) startPeer(); else startActivityForResult(consent, 41);
        });
        root.addView(start);
        Button stop = new Button(this);
        stop.setText("Stop acceptance VPN");
        stop.setOnClickListener(v -> stopPeer());
        root.addView(stop);
        setContentView(root);
    }
    private void startPeer() { startForegroundService(new Intent(this, CompetingVpnService.class)); }
    private void stopPeer() { stopService(new Intent(this, CompetingVpnService.class)); }
    @Override public void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        if (request == 41 && result == RESULT_OK) startPeer();
    }
}
