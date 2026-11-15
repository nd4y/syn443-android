package io.syn443.android.vpn

import io.syn443.health.CheckJob
import io.syn443.health.NetworkProbe
import io.syn443.health.ProbePool
import io.syn443.policy.Check
import org.json.JSONArray
import org.json.JSONObject

/** Process-wide worker cap also applies to cancelled jobs and later service generations. */
class PolicyChecks(synthetic: Boolean = false) {
    private val job = CheckJob(pool, NetworkProbe(synthetic, resolve = AndroidProbeResolver()::resolveAll), { android.os.SystemClock.elapsedRealtime() })
    fun cancel() = job.cancel()
    fun run(checks: List<Check>) = job.run(checks)
    val failure get() = job.failure
    val failureStage get() = job.failureStage
    companion object {
        private val pool = ProbePool()
        private val results = PolicyCheckSnapshot()
        internal fun record(batch: io.syn443.health.Batch, intent: Long, network: Long, activation: Long) = results.record(batch,intent,network,activation)
        internal fun invalidate() = results.invalidate()
        internal fun view(intent: Long, network: Long, activation: Long, active: Boolean) = results.read(intent,network,activation,active)
        private var sampledAt = -30_000L
        private var cached = ""
        /** Explicit DEBUG diagnostics only: fixed worker names and stack symbols, never values/targets. */
        @Synchronized fun diagnostics(): JSONObject {
            check(io.syn443.android.BuildConfig.DEBUG)
            val now=android.os.SystemClock.elapsedRealtime()
            if(cached.isNotEmpty() && now-sampledAt in 0L until 30_000L)return JSONObject(cached).put("cached",true)
            val threads=JSONArray()
            Thread.getAllStackTraces().entries.filter {it.key.name=="syn443-policy-probe"}.take(2).forEach {(thread,frames)->
                threads.put(JSONObject().put("state",thread.state.name).put("frames",JSONArray(frames.take(12).map {
                    JSONObject().put("class",it.className.take(160)).put("method",it.methodName.take(80))
                })))
            }
            val result=JSONObject().put("schemaVersion",1).put("sampledElapsedMs",now).put("minIntervalMs",30_000)
                .put("cached",false).put("pool",JSONObject(pool.counters())).put("threads",threads)
            cached=result.toString();sampledAt=now
            return result
        }
    }
}
