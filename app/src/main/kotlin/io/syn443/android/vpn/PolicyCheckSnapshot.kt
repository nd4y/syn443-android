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
                    .also { row -> value.dnsResult?.let { row.put("dnsResult",it.name) } }
            })).toString()
        ownerCurrent = true
    }
    @Synchronized fun invalidate() { ownerCurrent = false }
    /** Historical export only. No caller-supplied authority can mark it current. */
    @Synchronized internal fun passiveSnapshot(): JSONObject {
        val value = sample?.let(::JSONObject)
        val age = value?.let { clock() - it.getLong("sampledElapsedMs") }
        return JSONObject().put("schemaVersion", 1).put("current", JSONObject.NULL)
            .put("ageMs", age?.takeIf { it >= 0 } ?: JSONObject.NULL)
            .put("lastBatch", value ?: JSONObject.NULL)
    }
    @Synchronized fun read(intent: Long, network: Long, activation: Long, active: Boolean): JSONObject {
        val value = sample?.let(::JSONObject)
        val age = value?.let { clock() - it.getLong("sampledElapsedMs") }
        val current = ownerCurrent && active && value != null && age != null && age in 0L..30_000L && value.getLong("intentGeneration") == intent &&
            value.getLong("networkEpoch") == network && value.getLong("activationGeneration") == activation
        return JSONObject().put("schemaVersion", 1).put("current", current).put("ageMs", age?.takeIf { it >= 0 } ?: JSONObject.NULL)
            .put("lastBatch", value ?: JSONObject.NULL)
    }
}

/** Render only fresh, typed DNS evidence. Endpoints and arbitrary response values stay out of the UI. */
internal fun internetDnsFailures(snapshot:JSONObject?):List<String> {
    if (snapshot == null || snapshot.opt("current") != true) return emptyList()
    val rows=snapshot.optJSONObject("lastBatch")?.optJSONArray("checks") ?: return emptyList()
    if (rows.length() !in 1..8) return emptyList()
    return buildList {
        for (i in 0 until rows.length()) {
            val row=rows.optJSONObject(i) ?: continue
            if (row.optString("stage")!="RESOLVE" || row.optString("outcome")!="FAIL") continue
            val detail=when (row.optString("failure")) {
                "TIMEOUT" -> "истекло время ожидания"
                "DNS" -> when(row.optString("dnsResult")) {
                    "NXDOMAIN" -> "имя не существует (NXDOMAIN)"
                    "SERVFAIL" -> "сбой DNS-сервера (SERVFAIL)"
                    "REFUSED" -> "DNS-сервер отклонил запрос (REFUSED)"
                    "NO_ADDRESSES" -> "ответ без IP-адресов (NOERROR)"
                    "OTHER_RCODE" -> "сервер вернул другую ошибку DNS"
                    "RESOLVER_ERROR" -> "ошибка системного резолвера"
                    else -> "не удалось разрешить имя"
                }
                else -> continue
            }
            add("DNS, проверка ${i+1}: $detail")
        }
    }
}
