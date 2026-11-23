package io.syn443.android.acceptance;

import android.Manifest;
import android.app.Activity;
import android.content.ContentProviderClient;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ProviderInfo;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Process;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/** Ordinary UID and SDK only. This Activity is shipped solely in the Android test APK. */
public final class ForeignOperatorActivity extends Activity {
    private static final String TARGET = "io.syn443.android";
    private static final String READ = "io.syn443.operator.read";
    private static final String CONTROL = "io.syn443.control";
    private boolean started;

    @Override protected void onPostResume() {
        super.onPostResume();
        if (started) return;
        started = true;
        if (!"ranchu".equals(Build.HARDWARE) && !"goldfish".equals(Build.HARDWARE)) {
            finish();
            return;
        }
        new Thread(() -> {
            try {
                verify();
                result("denied");
            } catch (Exception | AssertionError failure) {
                result("unexpected");
            } finally {
                runOnUiThread(this::finish);
            }
        }).start();
    }

    @SuppressWarnings("deprecation")
    private void verify() throws Exception {
        PackageInfo target = getPackageManager().getPackageInfo(TARGET, PackageManager.GET_PROVIDERS);
        ApplicationInfo app = target.applicationInfo;
        if (!"io.syn443.android.test".equals(getPackageName())
                || Process.myUid() == app.uid || Process.myUid() < Process.FIRST_APPLICATION_UID
                || checkSelfPermission(Manifest.permission.DUMP) != PackageManager.PERMISSION_DENIED
                || (app.flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0 || target.providers == null) {
            throw new AssertionError("Ordinary caller and release target are required");
        }
        boolean readFound = false;
        boolean privateFound = false;
        for (ProviderInfo provider : target.providers) {
            if (READ.equals(provider.authority)) {
                readFound = provider.exported;
            }
            if (CONTROL.equals(provider.authority)) {
                privateFound = !provider.exported;
            }
        }
        if (!readFound || !privateFound) throw new AssertionError("Both installed providers are required");
        for (String method : new String[]{"status", "logs", "auth-status", "routes-status"}) {
            requireDenied(READ, method, false);
        }
        for (String method : new String[]{"status", "config-plan-file", "bundle-collect"}) {
            requireDenied(CONTROL, method, true);
        }
    }

    private void requireDenied(String authority, String method, boolean mayBeHidden) throws Exception {
        Uri uri = Uri.parse("content://" + authority);
        try (ContentProviderClient client = getContentResolver().acquireUnstableContentProviderClient(uri)) {
            if (client == null && mayBeHidden) return;
            if (client == null) throw new AssertionError("Exported provider missing");
            client.call(method, null, null);
        } catch (SecurityException expected) {
            return;
        }
        throw new AssertionError("Provider returned to an unprivileged caller");
    }

    private void result(String value) {
        File file = new File(getNoBackupFilesDir(), "foreign-operator-result");
        try (FileOutputStream out = new FileOutputStream(file)) {
            out.write(value.getBytes(StandardCharsets.US_ASCII));
        } catch (IOException failure) {
            throw new IllegalStateException("Cannot record fixture result", failure);
        }
    }
}
