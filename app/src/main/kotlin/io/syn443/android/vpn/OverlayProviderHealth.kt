package io.syn443.android.vpn

import android.content.Context
import org.json.JSONObject

/** A provider-wide control connection does not establish a data path to any particular peer. */
internal object OverlayProviderHealth {
    private val providers = setOf("netbird", "tailscale", "zerotier")

    fun supports(provider: String?) = provider != null && provider in providers

    fun live(context: Context, provider: String): JSONObject = read(provider) {
        val state = LifecycleAccess.engineStatus(context, StateStore.get(context).read())
        OverlaySnapshot.forStatus(state.optLong("generation", -1), state.optLong("networkEpoch", -1),
            state.opt("desiredOn") == true, state.opt("engineActive") == true)
    }

    fun netBirdState(snapshot: JSONObject): NetBirdConnectionState {
        if (snapshot.opt("configuredInRunningProfile") != true) return NetBirdConnectionState.UNKNOWN
        return NetBirdConnectionState.entries.firstOrNull { it.name == snapshot.opt("connectionState") }
            ?: NetBirdConnectionState.UNKNOWN
    }

    fun read(provider: String, snapshot: () -> JSONObject): JSONObject {
        require(supports(provider))
        val result = JSONObject().put("schemaVersion", 1).put("provider", provider)
        if (provider != "netbird") return result.put("implementation", "not_implemented")

        val overlay = snapshot()
        val configured = overlay.opt("configuredInRunningProfile") as? Boolean
        val connection = netBirdState(overlay)
        val control = when (connection) {
            NetBirdConnectionState.DIRECT, NetBirdConnectionState.VLESS, NetBirdConnectionState.CONTROL -> "connected"
            NetBirdConnectionState.NO_MANAGEMENT -> "management_unavailable"
            NetBirdConnectionState.NO_SIGNAL -> "signal_unavailable"
            NetBirdConnectionState.NO_CONTROL -> "unavailable"
            NetBirdConnectionState.STARTING -> "starting"
            NetBirdConnectionState.RECOVERING -> "recovering"
            NetBirdConnectionState.NEEDS_ACTION -> "needs_action"
            NetBirdConnectionState.OFF -> "off"
            NetBirdConnectionState.UNKNOWN -> "unknown"
        }
        val transport = when (connection) {
            NetBirdConnectionState.DIRECT -> "direct"
            NetBirdConnectionState.VLESS -> "vless"
            else -> "unknown"
        }
        return result.put("implementation", "available").put("configured", configured ?: JSONObject.NULL)
            .put("control", control).put("controlTransport", transport)
    }
}
