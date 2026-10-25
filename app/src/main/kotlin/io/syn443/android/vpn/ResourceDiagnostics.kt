package io.syn443.android.vpn

import android.app.ActivityManager
import android.content.Context
import android.os.Process
import android.os.SystemClock
import android.system.Os
import android.system.OsConstants
import io.syn443.observability.Availability
import io.syn443.observability.ProcCounters
import io.syn443.observability.Reading
import io.syn443.observability.ResourceSampler
import io.syn443.observability.Role
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.nio.file.Files

/** On-demand proc counters only. Never contacts the engine Binder or changes VPN state. */
class ResourceDiagnostics(private val context: Context) {
    private val sampler = ResourceSampler { role -> read(role) }

    private fun bounded(file: File, limit: Int = 16_384): String = file.inputStream().use {
        val bytes = ByteArray(limit + 1)
        var size = 0
        while (size < bytes.size) {
            val count = it.read(bytes, size, bytes.size - size)
            if (count < 0) break
            check(count > 0)
            size += count
        }
        require(size <= limit)
        bytes.copyOf(size).toString(Charsets.UTF_8)
    }

    private fun read(role: Role): Reading {
        val name = context.packageName + if (role == Role.ENGINE) ":engine" else ":controller"
        val pid = if (role == Role.CONTROLLER) Process.myPid() else {
            val manager = context.getSystemService(ActivityManager::class.java)
            val processes = manager.runningAppProcesses ?: return Reading(Availability.UNAVAILABLE)
            processes.firstOrNull { it.uid == Process.myUid() && it.processName == name }?.pid
                ?: return Reading(Availability.NOT_RUNNING)
        }
        val directory = File("/proc/$pid")
        fun command() = bounded(File(directory, "cmdline"), 256).trimEnd('\u0000')
        require(command() == name)
        val hz = Os.sysconf(OsConstants._SC_CLK_TCK)
        val before = ProcCounters.parse(bounded(File(directory, "stat")), bounded(File(directory, "status")), null, pid, Process.myUid(), hz)
        val fds = runCatching {
            Files.newDirectoryStream(File(directory, "fd").toPath()).use { entries ->
                var count = 0
                for (ignored in entries) { count++; require(count <= 4096) }
                count
            }
        }.getOrNull()
        val after = ProcCounters.parse(bounded(File(directory, "stat")), bounded(File(directory, "status")), fds, pid, Process.myUid(), hz)
        if (before.identity != after.identity || command() != name) return Reading(Availability.PROCESS_CHANGED)
        return Reading(Availability.AVAILABLE, after)
    }

    fun snapshot(): JSONObject {
        val uptime = SystemClock.uptimeMillis()
        val report = sampler.sample(SystemClock.elapsedRealtime(), uptime)
        val processes = JSONArray()
        for (observation in report.processes) {
            val counters = observation.reading.counters
            val window = observation.window
            processes.put(JSONObject().put("role", observation.role.name.lowercase())
                .put("state", observation.reading.state.name.lowercase())
                .put("cpuTimeMs", counters?.cpuMs ?: JSONObject.NULL)
                .put("rssBytes", counters?.rssBytes ?: JSONObject.NULL)
                .put("threads", counters?.threads ?: JSONObject.NULL)
                .put("fileDescriptors", counters?.fds ?: JSONObject.NULL)
                .put("window", JSONObject().put("state", window.state)
                    .put("elapsedMs", window.elapsedMs ?: JSONObject.NULL).put("awakeMs", window.awakeMs ?: JSONObject.NULL)
                    .put("cpuMs", window.cpuMs ?: JSONObject.NULL).put("cpuPermille", window.cpuPermille ?: JSONObject.NULL)))
        }
        return JSONObject().put("schemaVersion", 1).put("sampledElapsedMs", report.elapsedMs)
            .put("sampledUptimeMs", report.uptimeMs).put("sampleAgeMs", report.ageMs).put("cached", report.cached)
            .put("minIntervalMs", ResourceSampler.MIN_INTERVAL_MS).put("processes", processes)
    }
}
