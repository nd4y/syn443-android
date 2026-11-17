package io.syn443.android.vpn

import java.time.Instant
import org.json.JSONArray
import org.json.JSONObject

/** Bounded display values only. None of these fields establish route health. */
internal object NetBirdPresentation {
    data class Row(val fqdn: String?, val ip: String?, val state: String,
        val relayed: Boolean?, val rttMs: Long?, val truncated: Boolean) {
        override fun toString() = "NetBirdRow([redacted])"
    }
    data class View(val page: Int, val total: Int, val retained: Int, val shown: Int,
        val omitted: Int, val pages: Int, val request: String) {
        override fun toString() = "NetBirdView([redacted])"
    }
    data class Section(val rows: List<Row>, val view: View?, val reported: Int?) {
        override fun toString() = "NetBirdSection([redacted])"
    }
    data class Coverage(val total: Int, val planned: Int, val checked: Int, val unprobed: Int, val omitted: Int) {
        val complete: Boolean get() = checked == total && planned == total && unprobed == 0 && omitted == 0
        override fun toString() = "NetBirdCoverage([redacted])"
    }
    data class Report(val active: Boolean?, val phase: String, val mode: String?, val proxy: String?,
        val management: Boolean?, val signal: Boolean?, val canDiagnose: Boolean, val stale: Boolean,
        val reason: String?, val failure: String?, val peers: Section, val diagnostics: Section,
        val diagnosticState: String, val coverage: Coverage?, val diagnosticStale: Boolean?) {
        val connection: String get() = "Cloud: ${management?.toString() ?: "н/д"}; signal: ${signal?.toString() ?: "н/д"}"
        val transport: String get() = when (mode) {
            "direct" -> "Подключение напрямую; relay используется как резерв"
            "vless" -> "Через VLESS: ${proxy ?: "ожидание"}"
            else -> "Способ подключения: неизвестно"
        }
        val diagnosticLabel: String get() = when (diagnosticState) {
            "preparing" -> "Получение списка пиров"
            "no_peers" -> if (coverage?.total == 0) "Нет пиров для проверки. После подключения список может ещё обновляться." else "Нет данных о пирах для проверки"
            "running" -> "Выполняется"
            "completed" -> if (coverage?.complete == true) "Завершена" else "Завершена; полный охват не подтверждён"
            "partial" -> "Частичная"
            "cancelled" -> "Отменена"
            "unavailable" -> "Недоступна"
            else -> "Нет данных"
        }
        override fun toString() = "NetBirdReport([redacted])"
    }
    internal fun validUnicode(value: String): Boolean {
        var index = 0
        while (index < value.length) {
            val char = value[index++]
            if (char.isHighSurrogate()) {
                if (index >= value.length || !value[index++].isLowSurrogate()) return false
            } else if (char.isLowSurrogate()) return false
        }
        return true
    }
    private fun text(raw: Any?, max: Int): String? = (raw as? String)?.takeIf {
        it.toByteArray(Charsets.UTF_8).size <= max && validUnicode(it) && it.none { char -> char < ' ' || char == '\u007f' }
    }
    private fun bool(owner: JSONObject?, field: String) = owner?.opt(field) as? Boolean
    private fun count(owner: JSONObject?, field: String): Int? = when (val value = owner?.opt(field)) {
        is Int -> value.takeIf { it >= 0 }
        is Long -> value.takeIf { it in 0..Int.MAX_VALUE.toLong() }?.toInt()
        else -> null
    }
    private fun view(owner: JSONObject?, length: Int?): View? {
        if (owner?.has("metadata_unknown") == true && bool(owner, "metadata_unknown") != false) return null
        val value = owner?.opt("view") as? JSONObject ?: return null
        if (value.keys().asSequence().toSet() != setOf("page", "page_size", "total", "retained", "shown", "omitted", "pages", "request")) return null
        val page = count(value, "page") ?: return null
        if (count(value, "page_size") != 16) return null
        val total = count(value, "total") ?: return null
        val retained = count(value, "retained") ?: return null
        val shown = count(value, "shown") ?: return null
        val omitted = count(value, "omitted") ?: return null
        val pages = count(value, "pages") ?: return null
        val request = text(value.opt("request"), 64)?.takeIf { it.all { char -> char.code in 32..126 } } ?: return null
        if (retained > 1024 || retained > total || omitted != total - retained || pages != (retained + 15) / 16 ||
            page !in 0..63 || (pages == 0 && page != 0) || (pages > 0 && page >= pages) ||
            shown != minOf(16, maxOf(0, retained - page * 16)) || shown != length || shown > 16) return null
        return View(page, total, retained, shown, omitted, pages, request)
    }
    private fun section(owner: JSONObject?, name: String, diagnostics: Boolean): Section {
        val values = owner?.opt(name) as? JSONArray
        val rows = ArrayList<Row>(16)
        if (values != null) for (index in 0 until minOf(16, values.length())) {
            val row = values.opt(index) as? JSONObject
            val known = if (diagnostics) setOf("queued", "checking", "reply", "no_reply", "cancelled", "invalid_target", "limit")
                else setOf("connected", "connecting", "disconnected")
            val state = (row?.opt("state") as? String)?.takeIf { it in known } ?: "неизвестно"
            val rtt = if (state == "reply") count(row, "rtt_ms")?.takeIf { it <= 30_000 }?.toLong() else null
            val ip = if (row?.has("ip_valid") == true && bool(row, "ip_valid") != true) null else text(row?.opt("ip"), 64)?.takeIf { it.isNotEmpty() }
            rows += Row(text(row?.opt("fqdn"), 96)?.takeIf { it.isNotEmpty() }, ip, state,
                bool(row, "relayed"), rtt, bool(row, "fqdn_truncated") == true)
        }
        val validRows = values != null && values.length() <= 16 && (0 until values.length()).all { values.opt(it) is JSONObject }
        return Section(java.util.Collections.unmodifiableList(rows), if (validRows) view(owner, values?.length()) else null, values?.length())
    }
    private fun coverage(owner: JSONObject?, view: View?): Coverage? {
        val value = owner?.opt("coverage") as? JSONObject ?: return null
        if (view == null || value.keys().asSequence().toSet() != setOf("total", "planned", "checked", "unprobed", "omitted")) return null
        val total = count(value, "total") ?: return null
        val planned = count(value, "planned") ?: return null
        val checked = count(value, "checked") ?: return null
        val unprobed = count(value, "unprobed") ?: return null
        val omitted = count(value, "omitted") ?: return null
        if (total != view.total || omitted != view.omitted || planned > view.retained || checked > planned || unprobed != total - checked) return null
        return Coverage(total, planned, checked, unprobed, omitted)
    }
    fun read(overlay: JSONObject, nowWallMs: Long = System.currentTimeMillis()): Report {
        val state = overlay.opt("peer_state") as? JSONObject
        val connectionUnknown = state?.has("connection_unknown") == true && bool(state, "connection_unknown") != false
        val diagnostics = overlay.opt("diagnostics") as? JSONObject
        val peers = section(state, "peers", false)
        val results = section(diagnostics, "results", true)
        val modeRaw = if (overlay.has("mode")) overlay.opt("mode") else state?.opt("mode")
        val mode = (modeRaw as? String)?.takeIf { it in setOf("direct", "vless") }?.takeUnless {
            state?.has("mode") == true && state.opt("mode") != it
        }
        val age = when (val raw = overlay.opt("snapshotAgeMs")) { is Int -> raw.toLong(); is Long -> raw; else -> null }
        val sampled = text(state?.opt("sampled_at"), 64)?.let { runCatching { Instant.parse(it).toEpochMilli() }.getOrNull() }
        val stale = age == null || age !in 0..25_000 || sampled == null || sampled > nowWallMs || nowWallMs - sampled !in 0..25_000
        val phase = text(overlay.opt("phase"), 48)?.takeIf { it.matches(Regex("[A-Za-z][A-Za-z0-9_]{0,47}")) } ?: "неизвестно"
        val reason = text(overlay.opt("reason"), 64)?.takeIf { it.matches(Regex("[a-z][a-z0-9_]{0,63}")) }
        val failure = text(overlay.opt("last_failure"), 64)?.takeIf { it.matches(Regex("[a-z][a-z0-9_]{0,63}")) }
        return Report(bool(overlay, "active"), phase, mode, text(state?.opt("selected_proxy"), 96)?.takeIf { it.isNotEmpty() },
            if (connectionUnknown) null else bool(state, "management_connected"),
            if (connectionUnknown) null else bool(state, "signal_connected"),
            !connectionUnknown && bool(overlay, "active") == true && bool(state, "active") == true, stale, reason, failure, peers, results,
            (diagnostics?.opt("state") as? String)?.takeIf { it in setOf("preparing", "no_peers", "running", "completed", "partial", "cancelled", "unavailable") } ?: "unknown",
            coverage(diagnostics, results.view), bool(diagnostics, "stale"))
    }
}
