package io.syn443.android.vpn

import android.os.SystemClock
import io.syn443.android.support.ReadyConfig
import org.json.JSONObject

/** Controller RAM only. Peer identifiers must never enter durable event logs. */
object OverlaySnapshot {
    private var payload: String? = null
    private var received = 0L
    private var generation = -1L
    private var epoch = -1L
    private var boundaryWall = System.currentTimeMillis()
    private var boundaryElapsed = SystemClock.elapsedRealtime()

    @Synchronized fun update(raw: String, generation: Long, epoch: Long) {
        require(raw.length <= 65_536)
        require(raw.toByteArray(Charsets.UTF_8).size <= 65_536)
        require(NetBirdPresentation.validUnicode(raw))
        JSONObject(raw)
        payload = raw
        received = SystemClock.elapsedRealtime()
        this.generation = generation
        this.epoch = epoch
    }

    @Synchronized fun clear() {
        payload = null
        received = 0
        generation = -1
        epoch = -1
        boundaryWall = System.currentTimeMillis()
        boundaryElapsed = SystemClock.elapsedRealtime()
    }
    @Synchronized fun read(): JSONObject = payload?.let {
        JSONObject(it).put("snapshotAgeMs", SystemClock.elapsedRealtime() - received)
    } ?: JSONObject().put("phase", "Unknown")

    @Synchronized internal fun forStatus(generation: Long, epoch: Long, desiredOn: Boolean, engineReady: Boolean): JSONObject {
        val before = ReadyConfig.current
        val report = read()
        val declaration = before?.netBirdFor(generation, desiredOn, engineReady)
        val result = withProfile(report, if (before === ReadyConfig.current) declaration else null)
        if (result.opt("configuredInRunningProfile") == true) {
            val current = this.generation == generation && this.epoch == epoch && epoch >= 0
            val elapsed = SystemClock.elapsedRealtime()
            val state = if (current) NetBirdConnectionState.from(result,
                elapsed - received, System.currentTimeMillis(), boundaryWall, elapsed - boundaryElapsed)
                else NetBirdConnectionState.UNKNOWN
            result.put("connectionState", state.name)
        }
        return result
    }

    internal fun withProfile(report: JSONObject, declaration: Boolean?): JSONObject {
        if (declaration == false && report.opt("active") != true) {
            return JSONObject().put("phase", "Off").put("active", false).put("configuredInRunningProfile", false)
        }
        val consistent = declaration != false
        return report.put("configuredInRunningProfile", if (consistent && declaration != null) declaration else JSONObject.NULL)
    }
}
