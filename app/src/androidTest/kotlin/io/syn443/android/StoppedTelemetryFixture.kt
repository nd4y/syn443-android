package io.syn443.android

import android.app.job.JobScheduler
import android.content.Context
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.SystemClock
import androidx.work.NetworkType
import androidx.work.WorkManager
import io.syn443.android.vpn.StoppedTelemetryWorker
import org.json.JSONObject
import java.util.concurrent.TimeUnit

/** Disposable Actions emulator only. Return the OS job number, never enrollment data. */
internal object StoppedTelemetryFixture {
    fun optInStopAndLocateJob(context: Context): Bundle {
        val uri = Uri.parse("content://io.syn443.control")
        fun call(method: String, arg: String? = null) = checkNotNull(context.contentResolver.call(uri,method,arg,null))
            .also { check(it.getBoolean("ok")) }
        fun state(method: String) = JSONObject(checkNotNull(call(method).getString("json")))
        val auth = state("auth-status")
        check(auth.getBoolean("telemetryAvailable") && !auth.getBoolean("telemetryEnabled") && state("status").getBoolean("desiredOn"))
        call("auth-telemetry", auth.getLong("generation").toString() + ":true")
        call("disconnect")
        val work = WorkManager.getInstance(context)
        val scheduler = checkNotNull(context.getSystemService(JobScheduler::class.java))
        val deadline = SystemClock.elapsedRealtime() + 25_000
        do {
            val active = work.getWorkInfosByTag(StoppedTelemetryWorker::class.java.name).get(3,TimeUnit.SECONDS).filter { !it.state.isFinished }
            check(active.size <= 1)
            val item = active.singleOrNull()
            if (item != null) {
                check(item.periodicityInfo?.repeatIntervalMillis == 900_000L && item.initialDelayMillis == 900_000L)
                check(item.constraints.requiredNetworkType == NetworkType.UNMETERED)
                val jobs = if (Build.VERSION.SDK_INT >= 34) scheduler.pendingJobsInAllNamespaces
                    else mapOf("" to scheduler.allPendingJobs)
                for ((namespace, list) in jobs) {
                    val job = list.singleOrNull {
                        it.service.packageName == context.packageName && it.service.className.endsWith(".SystemJobService") &&
                            it.extras.getString("EXTRA_WORK_SPEC_ID") == item.id.toString()
                    } ?: continue
                    val name = namespace.orEmpty()
                    check(name.isEmpty() || name.matches(Regex("[A-Za-z0-9_.-]{1,80}")))
                    return Bundle().apply { putString("job", job.id.toString()); putString("namespace", name) }
                }
            }
            SystemClock.sleep(100)
        } while (SystemClock.elapsedRealtime() < deadline)
        error("Scheduled telemetry work unavailable")
    }
}
