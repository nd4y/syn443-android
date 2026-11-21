package io.syn443.android.vpn

import android.os.SystemClock
import io.syn443.android.support.ReadyConfig
import org.json.JSONObject

/** Controller RAM only. Peer identifiers must never enter durable event logs. */
object OverlaySnapshot {
    private var payload: String? = null
    private var received = 0L
    @Synchronized fun update(raw: String) {
        require(raw.length <= 65_536)
        require(raw.toByteArray(Charsets.UTF_8).size <= 65_536)
        require(NetBirdPresentation.validUnicode(raw))
        JSONObject(raw)
        payload = raw
        received = SystemClock.elapsedRealtime()
    }
    @Synchronized fun clear() { payload = null; received = 0 }
    @Synchronized fun read(): JSONObject = payload?.let {
        JSONObject(it).put("snapshotAgeMs", SystemClock.elapsedRealtime() - received)
    } ?: JSONObject().put("phase", "Unknown")

    internal fun forStatus(generation: Long, desiredOn: Boolean, engineReady: Boolean): JSONObject {
        val before = ReadyConfig.current
        val report = read()
        val declaration = before?.netBirdFor(generation, desiredOn, engineReady)
        return withProfile(report, if (before === ReadyConfig.current) declaration else null)
    }

    internal fun withProfile(report: JSONObject, declaration: Boolean?): JSONObject {
        if (declaration == false && report.opt("active") != true) {
            return JSONObject().put("phase", "Off").put("active", false).put("configuredInRunningProfile", false)
        }
        val consistent = declaration != false
        return report.put("configuredInRunningProfile", if (consistent && declaration != null) declaration else JSONObject.NULL)
    }
}
