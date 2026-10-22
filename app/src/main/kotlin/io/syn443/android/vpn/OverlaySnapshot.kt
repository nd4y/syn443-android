package io.syn443.android.vpn

import android.os.SystemClock
import org.json.JSONObject

/** Controller RAM only. Peer identifiers must never enter durable event logs. */
object OverlaySnapshot {
    private var payload: String? = null
    private var received = 0L
    @Synchronized fun update(raw: String) {
        require(raw.length <= 65_536)
        JSONObject(raw)
        payload = raw
        received = SystemClock.elapsedRealtime()
    }
    @Synchronized fun clear() { payload = null; received = 0 }
    @Synchronized fun read(): JSONObject = payload?.let {
        JSONObject(it).put("snapshotAgeMs", SystemClock.elapsedRealtime() - received)
    } ?: JSONObject().put("phase", "Unknown")
}
