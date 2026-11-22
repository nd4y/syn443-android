package io.syn443.android.vpn

import org.json.JSONObject

/** Compact status for the primary screen. Neither control channel proves peer reachability. */
internal enum class NetBirdConnectionState(val label: String) {
    UNKNOWN("NetBird · ждём свежие данные"),
    STARTING("NetBird подключается"),
    RECOVERING("NetBird восстанавливает соединение"),
    NEEDS_ACTION("Для подключения NetBird требуется действие"),
    OFF("NetBird остановлен"),
    NO_CONTROL("NetBird · сервер управления и сигнализация недоступны"),
    NO_MANAGEMENT("NetBird · сервер управления недоступен"),
    NO_SIGNAL("NetBird · сигнализация недоступна"),
    DIRECT("NetBird напрямую · управление и сигнализация доступны"),
    VLESS("NetBird через VLESS · управление и сигнализация доступны"),
    CONTROL("NetBird · управление и сигнализация доступны");

    companion object {
        private const val FRESH_MS = 25_000L

        fun from(report: JSONObject, receivedAge: Long, nowWall: Long,
                 boundaryWall: Long, boundaryAge: Long): NetBirdConnectionState {
            if (receivedAge !in 0..FRESH_MS || boundaryAge < receivedAge) return UNKNOWN
            val active = report.opt("active")
            if (active == false && report.opt("phase") == "Off") return OFF
            if (active != true) return UNKNOWN
            when (report.opt("phase")) {
                "Configured", "Starting" -> return STARTING
                "Recovering" -> return RECOVERING
                "NeedsAction" -> return NEEDS_ACTION
                "Started" -> Unit
                else -> return UNKNOWN
            }
            val peer = report.optJSONObject("peer_state") ?: return UNKNOWN
            val sample = NetBirdPresentation.sampledAt(peer) ?: return UNKNOWN
            if (sample <= boundaryWall || sample > nowWall || nowWall - sample !in 0..minOf(FRESH_MS, boundaryAge) ||
                peer.opt("active") != true || peer.opt("connection_unknown") != false) return UNKNOWN
            val management = peer.opt("management_connected") as? Boolean ?: return UNKNOWN
            val signal = peer.opt("signal_connected") as? Boolean ?: return UNKNOWN
            if (!management && !signal) return NO_CONTROL
            if (!management) return NO_MANAGEMENT
            if (!signal) return NO_SIGNAL
            val mode = peer.opt("mode")
            if (mode != report.opt("mode")) return CONTROL
            return when (mode) {
                "direct" -> DIRECT
                "vless" -> VLESS
                else -> CONTROL
            }
        }
    }
}
