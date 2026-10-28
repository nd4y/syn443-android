package io.syn443.android.vpn

import android.app.ActivityManager
import android.content.Context
import android.os.Build
import org.json.JSONArray
import org.json.JSONObject

/** On-demand OS metadata only. Never request descriptions, traces or tombstones. */
object EngineExitDiagnostics {
    internal data class Observation(val pid: Int, val process: String, val reason: Int, val status: Int, val at: Long)
    fun snapshot(context: Context, queryPid: Int? = null): JSONObject {
        if (Build.VERSION.SDK_INT < 30) return empty("unsupported")
        return render("${context.packageName}:engine", System.currentTimeMillis(), queryPid) {
            checkNotNull(context.getSystemService(ActivityManager::class.java))
                .getHistoricalProcessExitReasons(context.packageName, queryPid ?: 0, 32).map {
                    Observation(it.pid, it.processName, it.reason, it.status, it.timestamp)
                }
        }
    }
    private fun empty(state: String) = JSONObject().put("schemaVersion", 1).put("state", state).put("exits", JSONArray())
    internal fun render(process: String, now: Long, queryPid: Int? = null, source: () -> List<Observation>): JSONObject {
        val result = empty("available")
        return try {
            require(now >= 0 && (queryPid == null || queryPid > 0))
            val observations = source()
            require(observations.size <= 32)
            val records = observations.filter { it.pid > 0 && it.process == process &&
                (queryPid == null || it.pid == queryPid) && it.at in 1..now }
                .sortedByDescending { it.at }.take(4)
            val output = result.getJSONArray("exits")
            records.forEach {
                val kind = when (it.reason) {
                    4 -> "java_crash"
                    5 -> "native_crash"
                    2 -> "signal"
                    1 -> "self_exit"
                    3 -> "low_memory"
                    8, 10, 11, 15, 16 -> "os_request"
                    6 -> "anr"
                    else -> "other"
                }
                val entry = JSONObject().put("kind", kind).put("at", it.at)
                if ((it.reason in 1..2 || it.reason == 5) && it.status in 0..255) entry.put("status", it.status)
                output.put(entry)
            }
            result
        } catch (_: Exception) { empty("unavailable") }
    }
}
