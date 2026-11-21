package io.syn443.android.vpn

import io.syn443.decision.NetworkMode
import io.syn443.policy.NetworkModePolicy
import java.util.UUID
import org.json.JSONArray
import org.json.JSONObject

/** Only the VPN controller holds a choice. Restart or loss of link continuity retires it. */
internal class ManagedNetworkMode {
    data class Scope(val generation: Long, val epoch: Long, val engine: String, val contentHash: String, val authority: String, val boot: Int)
    data class View(val scope: Scope, val effective: NetworkMode, val source: String, val allowed: List<NetworkMode>,
                    val maxMinutes: Int, val until: Long, val validUntil: Long, val stamp: String) {
        fun json() = JSONObject().put("effective", effective.name).put("source", source)
            .put("allowed", JSONArray(allowed.map { it.name })).put("maxMinutes", maxMinutes)
            .put("until", until).put("stamp", stamp)
    }

    private var scope: Scope? = null
    private var selected: NetworkMode? = null
    private var expires = 0L
    private var stamp = UUID.randomUUID().toString()
    private var previousOptions = emptyList<NetworkMode>()

    fun clear() {
        scope = null
        selected = null
        expires = 0
        previousOptions = emptyList()
        stamp = UUID.randomUUID().toString()
    }

    fun observe(current: Scope, policy: NetworkModePolicy?, detected: NetworkMode, now: Long, lease: Long): View? {
        if (now < 0 || now >= lease) { clear(); return null }
        if (current != scope) { clear(); scope = current }
        val usable = when (detected) {
            NetworkMode.HOME_WIFI -> listOf(NetworkMode.WIFI, NetworkMode.HOME_WIFI)
            NetworkMode.WIFI -> listOf(NetworkMode.WIFI)
            NetworkMode.CELLULAR, NetworkMode.CELLULAR_RESTRICTED -> listOf(NetworkMode.CELLULAR, NetworkMode.CELLULAR_RESTRICTED)
            NetworkMode.UNKNOWN -> emptyList()
        }
        val allowed = usable.filter { it.name in policy?.userModes.orEmpty() }
        if (previousOptions != allowed || selected != null && (now >= expires || selected !in allowed)) {
            if (now >= expires || selected !in allowed) { selected = null; expires = 0 }
            previousOptions = allowed
            stamp = UUID.randomUUID().toString()
        }
        val preferred = usable.find { it.name == policy?.preferredMode }
        val source = if (selected != null) "manual" else if (preferred != null) "assigned" else "automatic"
        val until = if (selected == null) 0L else minOf(lease, expires)
        return View(current, selected ?: preferred ?: detected, source, allowed, policy?.maxOverrideMinutes ?: 0,
                    until, if (until > 0) until else lease, stamp)
    }

    fun choose(view: View, expectedStamp: String, name: String, minutes: Int, now: Long): Boolean {
        if (scope != view.scope || stamp != view.stamp || stamp != expectedStamp || now < 0 || now >= view.validUntil) return false
        if (name == "AUTO") {
            if (minutes != 0 || selected == null) return false
            selected = null; expires = 0
        } else {
            val choice = view.allowed.find { it.name == name } ?: return false
            if (minutes !in 1..view.maxMinutes || now > Long.MAX_VALUE - minutes*60_000L) return false
            selected = choice; expires = now + minutes*60_000L
        }
        stamp = UUID.randomUUID().toString()
        return true
    }
}
