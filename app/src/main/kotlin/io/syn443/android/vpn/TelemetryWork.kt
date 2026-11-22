package io.syn443.android.vpn

import android.app.Application
import android.content.Context
import androidx.work.BackoffPolicy
import androidx.work.Configuration
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkerParameters
import androidx.work.multiprocess.RemoteCoroutineWorker
import androidx.work.multiprocess.RemoteListenableWorker
import androidx.work.multiprocess.RemoteWorkerService
import androidx.work.multiprocess.RemoteWorkManager
import androidx.work.workDataOf
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.withTimeoutOrNull

class TelemetryWorkApplication : Application(), Configuration.Provider {
    override val workManagerConfiguration: Configuration
        get() = Configuration.Builder().setDefaultProcessName(packageName).build()
}

internal object TelemetryWork {
    const val CONSENT = "consent"
    private var scheduledSession: String? = null
    private val sessionFormat = Regex("[A-Za-z0-9_-]{43}")
    enum class VpnState { STOPPED, ACTIVE, UNKNOWN }

    fun vpnState(state: org.json.JSONObject): VpnState {
        if (state.opt("desiredOn") == true) return VpnState.ACTIVE
        if (state.opt("engineStateKnown") != true || state.optLong("generation", -1) < 0) return VpnState.UNKNOWN
        return when {
            state.opt("engineActive") == true -> VpnState.ACTIVE
            state.opt("desiredOn") == false && state.opt("engineActive") == false -> VpnState.STOPPED
            else -> VpnState.UNKNOWN
        }
    }

    fun valid(session: String?) = session != null && sessionFormat.matches(session)
    fun name(session: String) = "technical-telemetry-" + session

    @Synchronized fun schedule(context: Context, session: String) {
        require(valid(session))
        if (scheduledSession == session) return
        val input = workDataOf(
            CONSENT to session,
            RemoteListenableWorker.ARGUMENT_PACKAGE_NAME to context.packageName,
            RemoteListenableWorker.ARGUMENT_CLASS_NAME to RemoteWorkerService::class.java.name,
        )
        val work = PeriodicWorkRequestBuilder<StoppedTelemetryWorker>(15, TimeUnit.MINUTES)
            .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.UNMETERED).build())
            .setInitialDelay(15, TimeUnit.MINUTES)
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 15, TimeUnit.MINUTES)
            .setInputData(input).build()
        val enqueued = RemoteWorkManager.getInstance(context).enqueueUniquePeriodicWork(name(session), ExistingPeriodicWorkPolicy.KEEP, work)
        scheduledSession = session
        enqueued.addListener({
            if (runCatching { enqueued.get() }.isFailure) synchronized(this) {
                if (scheduledSession == session) scheduledSession = null
            }
        }, java.util.concurrent.Executor { it.run() })
    }

    @Synchronized fun cancel(context: Context, session: String) {
        if (scheduledSession == session) scheduledSession = null
        if (valid(session)) RemoteWorkManager.getInstance(context).cancelUniqueWork(name(session))
    }
}

class StoppedTelemetryWorker(context: Context, parameters: WorkerParameters) : RemoteCoroutineWorker(context, parameters) {
    override suspend fun doRemoteWork(): Result {
        val session = inputData.getString(TelemetryWork.CONSENT) ?: return Result.failure()
        if (!TelemetryWork.valid(session) || Application.getProcessName() != applicationContext.packageName + ":controller") return Result.failure()
        if (!LifecycleAccess.unlocked(applicationContext)) return Result.retry()
        val controller = LoginController.get(applicationContext)
        if (!controller.ownsTelemetrySchedule(session)) {
            TelemetryWork.cancel(applicationContext, session)
            return Result.success()
        }
        val settled = withTimeoutOrNull(75_000) { controller.deliverStoppedTelemetry(session) }
        return if (settled == true) Result.success() else Result.retry()
    }
}
