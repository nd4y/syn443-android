package io.syn443.android.vpn

import io.syn443.health.Batch
import org.json.JSONArray
import org.json.JSONObject

/** Last fenced batch in RAM. Reading does not run probes or make stale evidence current. */
internal class PolicyCheckSnapshot(private val clock: () -> Long = { android.os.SystemClock.elapsedRealtime() }) {
    private var sample: String? = null
    private var ownerCurrent = false
    @Synchronized fun record(batch: Batch, intent: Long, network: Long, activation: Long) {
        require(intent >= 0 && network >= 0 && activation >= 0)
        require(batch.observations.size in 1..8 && batch.observations.map { it.outcome } == batch.outcomes)
        sample = JSONObject().put("sampledElapsedMs", clock()).put("intentGeneration", intent)
            .put("networkEpoch", network).put("activationGeneration", activation)
            .put("checks", JSONArray(batch.observations.mapIndexed { index, value ->
                JSONObject().put("index", index).put("outcome", value.outcome.name)
                    .put("stage", value.stage?.name ?: JSONObject.NULL)
                    .put("failure", value.failure?.name ?: JSONObject.NULL)
            })).toString()
        ownerCurrent = true
    }
    @Synchronized fun invalidate() { ownerCurrent = false }
    @Synchronized fun read(intent: Long, network: Long, activation: Long, active: Boolean): JSONObject {
        val value = sample?.let(::JSONObject)
        val age = value?.let { clock() - it.getLong("sampledElapsedMs") }
        val current = ownerCurrent && active && value != null && age != null && age in 0L..30_000L && value.getLong("intentGeneration") == intent &&
            value.getLong("networkEpoch") == network && value.getLong("activationGeneration") == activation
        return JSONObject().put("schemaVersion", 1).put("current", current).put("ageMs", age?.takeIf { it >= 0 } ?: JSONObject.NULL)
            .put("lastBatch", value ?: JSONObject.NULL)
    }
}
