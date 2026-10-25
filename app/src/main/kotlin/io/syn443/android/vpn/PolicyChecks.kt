package io.syn443.android.vpn

import io.syn443.health.CheckJob
import io.syn443.health.NetworkProbe
import io.syn443.health.ProbePool
import io.syn443.policy.Check

/** Process-wide worker cap also applies to cancelled jobs and later service generations. */
class PolicyChecks(synthetic: Boolean = false) {
    private val job = CheckJob(pool, NetworkProbe(synthetic), { android.os.SystemClock.elapsedRealtime() })
    fun cancel() = job.cancel()
    fun run(checks: List<Check>) = job.run(checks)
    val failure get() = job.failure
    companion object { private val pool = ProbePool() }
}
