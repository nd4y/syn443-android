package io.syn443.android.support

import io.syn443.health.Outcome
import io.syn443.recovery.RouteState
import java.util.Locale
import org.json.JSONArray
import org.json.JSONObject

/** Fresh allowlist projection. Unknown subtrees are never serialized, walked or
 * copied. No labels, addresses, targets, identities, config or free text leave it. */
object DiagnosticProjection {
    private const val MAX_SAFE = 9_007_199_254_740_991L
    private const val MAX_ROWS = 64
    private val phases = setOf("Off", "NeedsLogin", "NeedsPermission", "NeedsUnlock", "NeedsAction", "NoNetwork",
        "Portal", "Detecting", "Connecting", "Online", "Degraded", "Recovering", "BlockedByPolicy")
    // Same closed lifecycle codes as the bounded syn443ctl diagnostic projection.
    private val eventCodes = setOf(
        "awaiting_identity_release", "captive_portal", "configuration_invalid", "configuration_or_capability_invalid",
        "controller_recreated", "dns_resolution_failed", "dns_timeout", "explicit_resume_required",
        "health_policy_not_authorized", "managed_route_recheck", "native_bind_failed", "native_binding_died",
        "native_binding_timeout", "native_died", "native_disconnected", "native_handshake_failed", "native_ipc_failed",
        "native_late_start", "native_lease_update_failed", "native_null_binding", "native_progress_timeout",
        "native_restart_budget", "native_start", "native_start_failed", "network_changed", "network_unavailable",
        "network_update_failed", "overlay_credentials_pending", "overlay_material_changed", "policy_baseline_degraded",
        "policy_checks_unavailable", "policy_gate_pending", "policy_lease_time_or_scope_invalid", "policy_rollback",
        "policy_store_unavailable", "policy_waiting_restart_budget", "required_https_ok",
        "required_route_unverified_or_failed", "retry_scheduled", "start_failed", "tcp_timeout", "tls_failed",
        "tls_timeout", "transport_eof", "user_stop", "vpn_permission_required", "vpn_permission_revoked",
    )
    private val version = Regex("[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}(?:-[a-z][a-z0-9-]{0,63})?")
    private val routeStates = RouteState.entries.map { it.name.lowercase(Locale.ROOT) }.toSet()
    private val outcomes = Outcome.entries.map { it.name }.toSet()
    private val peerStates = setOf("connected", "connecting", "disconnected", "unknown")
    private val resultStates = setOf("queued", "checking", "reply", "no_reply", "cancelled", "invalid_target", "unknown", "limit")
    private val diagnosticStates = setOf("idle", "preparing", "running", "completed", "partial", "cancelled", "unavailable", "no_peers")

    fun project(state: JSONObject, overlay: JSONObject?, checks: JSONObject?, exits: JSONObject?,
        versionName: String, versionCode: Int, sdk: Int, physicalLink: JSONObject? = null): List<DiagnosticArchive.Component> {
        val versions = if (versionName.length <= 96 && version.matches(versionName) && versionCode > 0 && sdk in 1..9999)
            json(DiagnosticArchive.Name.VERSIONS, document().put("versionName", versionName).put("versionCode", versionCode).put("sdk", sdk))
        else missing(DiagnosticArchive.Name.VERSIONS, DiagnosticArchive.Reason.INVALID_SOURCE, DiagnosticArchive.State.ERROR)
        val capabilities = json(DiagnosticArchive.Name.CAPABILITIES, document().put("collection", "offline_allowlist_projection")
            .put("maxEvents", MAX_ROWS).put("effectiveConfig", "ready_engine_projection").put("nativeStacks", "unsupported"))
        return listOf(versions, capabilities,
            missing(DiagnosticArchive.Name.EFFECTIVE_CONFIG),
            json(DiagnosticArchive.Name.HEALTH, health(state, physicalLink)), events(state),
            observation(DiagnosticArchive.Name.CHECKS, checks?.let(::checkProjection)),
            observation(DiagnosticArchive.Name.OVERLAY, overlay?.let(::overlayProjection)),
            exits?.let { json(DiagnosticArchive.Name.CRASHES, crashes(it)) } ?: missing(DiagnosticArchive.Name.CRASHES),
            missing(DiagnosticArchive.Name.NATIVE_STACKS, DiagnosticArchive.Reason.UNSUPPORTED))
    }

    // The schema marker alone carries no observation. Explicit false values
    // and measured empty collections are evidence and remain available.
    private fun observation(name: DiagnosticArchive.Name, value: JSONObject?): DiagnosticArchive.Component =
        if (value != null && value.length() > 1) json(name, value) else missing(name)

    private fun document() = JSONObject().put("schemaVersion", 1)
    private fun integer(value: Any?): Long? = when (value) {
        is Int -> value.toLong()
        is Long -> value
        is Short -> value.toLong()
        is Byte -> value.toLong()
        else -> null
    }?.takeIf { it in 0..MAX_SAFE }
    private fun numbers(source: JSONObject, target: JSONObject, vararg names: String) {
        for (name in names) integer(source.opt(name))?.let { target.put(name, it) }
    }
    private fun booleans(source: JSONObject, target: JSONObject, vararg names: String) {
        for (name in names) (source.opt(name) as? Boolean)?.let { target.put(name, it) }
    }
    private fun known(source: JSONObject, name: String, allowed: Set<String>): String? =
        (source.opt(name) as? String)?.takeIf { it in allowed }
    private fun health(source: JSONObject, link: JSONObject?): JSONObject = document().also { value ->
        value.put("phase", known(source, "phase", phases) ?: "unknown")
        value.put("reason", known(source, "reason", eventCodes) ?: "unknown")
        numbers(source, value, "generation", "networkEpoch", "activationGeneration", "eventSequence", "attempt")
        booleans(source, value, "desiredOn", "engineActive", "resumeRequired")
        if (source.opt("desiredOn") == true && link != null) {
            known(link, "transport", setOf("WIFI", "CELLULAR", "OTHER"))?.let { transport ->
                val safe = JSONObject().put("transport", transport)
                booleans(link, safe, "ipv4Address", "ipv4Default", "ipv6Address", "ipv6Default")
                if (transport == "WIFI") known(link, "homeProof", setOf("verified", "unconfirmed"))?.let { safe.put("homeProof", it) }
                value.put("physicalLink", safe)
            }
        }
        (source.opt("policy") as? JSONObject)?.let { policy ->
            val safe = JSONObject()
            numbers(policy, safe, "activationGeneration")
            if (safe.length() > 0) value.put("policy", safe)
        }
        (source.opt("routeHealth") as? JSONObject)?.let { routes ->
            val safe = JSONObject()
            booleans(routes, safe, "running", "requiredReady")
            counts(routes.opt("routes"), "state", routeStates)?.let { safe.put("counts", it) }
            value.put("routeHealth", safe)
        }
    }
    private fun events(source: JSONObject): DiagnosticArchive.Component {
        val input = source.opt("events") as? JSONArray ?: return missing(DiagnosticArchive.Name.EVENTS)
        val output = StringBuilder()
        for (index in (input.length() - MAX_ROWS).coerceAtLeast(0) until input.length()) {
            val row = input.opt(index) as? JSONObject ?: continue
            val phase = known(row, "phase", phases) ?: continue
            val safe = JSONObject().put("phase", phase).put("code", known(row, "code", eventCodes) ?: "redacted")
            numbers(row, safe, "at", "elapsed", "sequence", "intentGeneration", "networkEpoch")
            output.append(safe.toString()).append('\n')
        }
        return bytes(DiagnosticArchive.Name.EVENTS, output.toString().toByteArray(Charsets.UTF_8))
    }
    private fun checkProjection(source: JSONObject): JSONObject = document().also { value ->
        booleans(source, value, "current")
        numbers(source, value, "ageMs")
        (source.opt("lastBatch") as? JSONObject)?.let { batch ->
            val safe = JSONObject()
            numbers(batch, safe, "sampledElapsedMs", "intentGeneration", "networkEpoch", "activationGeneration")
            counts(batch.opt("checks"), "outcome", outcomes)?.let { safe.put("counts", it) }
            if (safe.length() > 0) value.put("lastBatch", safe)
        }
    }
    private fun overlayProjection(source: JSONObject): JSONObject = document().also { value ->
        booleans(source, value, "active")
        numbers(source, value, "snapshotAgeMs", "sampled_at_ms")
        known(source, "mode", setOf("direct", "vless"))?.let { value.put("mode", it) }
        (source.opt("peer_state") as? JSONObject)?.let { peers ->
            val safe = JSONObject()
            // A replacement owner can explicitly invalidate the old header.
            if (!peers.has("connection_unknown") || peers.opt("connection_unknown") == false)
                booleans(peers, safe, "management_connected", "signal_connected")
            booleans(peers, safe, "connection_unknown", "metadata_unknown")
            if (!peers.has("metadata_unknown") || peers.opt("metadata_unknown") == false)
                counts(peers.opt("peers"), "state", peerStates)?.let { safe.put("counts", it) }
            if (safe.length() > 0) value.put("peer_state", safe)
        }
        (source.opt("diagnostics") as? JSONObject)?.let { diagnostics ->
            val safe = JSONObject()
            booleans(diagnostics, safe, "stale", "metadata_unknown")
            known(diagnostics, "state", diagnosticStates)?.let { safe.put("state", it) }
            if (!diagnostics.has("metadata_unknown") || diagnostics.opt("metadata_unknown") == false)
                counts(diagnostics.opt("results"), "state", resultStates)?.let { safe.put("counts", it) }
            if (safe.length() > 0) value.put("diagnostics", safe)
        }
    }
    private fun crashes(source: JSONObject): JSONObject = document().also { value ->
        val state = known(source, "state", setOf("available", "unsupported", "unavailable"))
        value.put("state", state ?: "unknown")
        if (state == "available") (source.opt("exits") as? JSONArray)?.let { rows ->
            val result = JSONArray()
            for (index in 0 until minOf(rows.length(), 4)) {
                val row = rows.opt(index) as? JSONObject ?: continue
                val kind = known(row, "kind", setOf("java_crash", "native_crash", "signal", "self_exit", "low_memory", "os_request", "anr", "other")) ?: continue
                val at = integer(row.opt("at"))?.takeIf { it > 0 } ?: continue
                val safe = JSONObject().put("kind", kind).put("at", at)
                if (kind in setOf("signal", "self_exit", "native_crash"))
                    integer(row.opt("status"))?.takeIf { it <= 255 }?.let { safe.put("status", it) }
                result.put(safe)
            }
            value.put("exits", result)
        }
    }
    private fun counts(raw: Any?, field: String, allowed: Set<String>): JSONObject? {
        val rows = raw as? JSONArray ?: return null
        val inspected = minOf(rows.length(), MAX_ROWS)
        val counts = JSONObject()
        var unknown = 0
        for (index in 0 until inspected) {
            val row = rows.opt(index) as? JSONObject
            val state = row?.let { known(it, field, allowed) }
            if (state == null) unknown++ else counts.put(state, counts.optInt(state) + 1)
        }
        return JSONObject().put("reported", rows.length()).put("inspected", inspected)
            .put("unknown", unknown).put("states", counts)
    }
    private fun missing(name: DiagnosticArchive.Name, reason: DiagnosticArchive.Reason = DiagnosticArchive.Reason.UNAVAILABLE,
        state: DiagnosticArchive.State = DiagnosticArchive.State.MISSING) = DiagnosticArchive.Component(name, null, state, reason)
    private fun json(name: DiagnosticArchive.Name, value: JSONObject) = bytes(name, value.toString().toByteArray(Charsets.UTF_8))
    private fun bytes(name: DiagnosticArchive.Name, value: ByteArray): DiagnosticArchive.Component =
        if (value.size <= DiagnosticArchive.MAX_COMPONENT)
            DiagnosticArchive.Component(name, value, DiagnosticArchive.State.AVAILABLE, DiagnosticArchive.Reason.PROJECTION_ONLY)
        else missing(name, DiagnosticArchive.Reason.OVER_LIMIT, DiagnosticArchive.State.ERROR)
}
