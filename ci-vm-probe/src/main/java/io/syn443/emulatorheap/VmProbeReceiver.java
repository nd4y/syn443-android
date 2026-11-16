package io.syn443.emulatorheap;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.Process;
import android.os.SystemClock;

/** Explicit CI fixture only. It reads no app state, files, credentials or network. */
public final class VmProbeReceiver extends BroadcastReceiver {
    @Override public void onReceive(Context context, Intent intent) {
        if (!BuildConfig.DEBUG || !("ranchu".equals(Build.HARDWARE) || "goldfish".equals(Build.HARDWARE))
                || !"io.syn443.emulatorheap".equals(context.getPackageName())
                || intent == null || !"io.syn443.emulatorheap.MEASURE".equals(intent.getAction())
                || intent.getData() != null || intent.getExtras() != null) {
            setResult(1, "{\"schemaVersion\":1,\"error\":\"fixture_unavailable\"}", null);
            return;
        }
        Runtime vm = Runtime.getRuntime();
        try {
            String data = VmMemorySnapshot.encode(vm.maxMemory(), vm.totalMemory(), vm.freeMemory(),
                    Process.myPid(), SystemClock.uptimeMillis());
            setResult(0, data, null);
        } catch (RuntimeException failure) {
            setResult(1, "{\"schemaVersion\":1,\"error\":\"invalid_snapshot\"}", null);
        }
    }
}
