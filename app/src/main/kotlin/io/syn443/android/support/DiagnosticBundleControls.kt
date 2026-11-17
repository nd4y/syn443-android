package io.syn443.android.support

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import org.json.JSONObject

/** Closed presentation only. No raw JSON, names, paths, grant IDs, or free text. */
@Composable
internal fun DiagnosticBundleControls(
    value: JSONObject, busy: Boolean, message: String, collect: () -> Unit, refresh: () -> Unit,
    cancel: () -> Unit, export: () -> Unit, cancelling: Boolean = false,
) {
    val state = value.opt("state") as? String
    val ready = validBundlePreview(value)
    val active = state in setOf("collecting", "busy")
    Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text("Диагностика", style = MaterialTheme.typography.headlineMedium, modifier = Modifier.testTag("bundle-title"))
        Text("Сбор использует сохранённое состояние. Новые сетевые проверки не запускаются.")
        Text(when (state) {
            "collecting", "busy" -> "Сбор продолжается"
            "ready" -> if (ready) "Архив готов" else "Некорректные сведения об архиве"
            "cancelled" -> "Сбор отменён"
            "expired" -> "Срок доступа к архиву истёк"
            "failed" -> "Не удалось собрать архив"
            "not_found" -> "Архив больше недоступен"
            else -> "Архив ещё не собран"
        }, Modifier.testTag("bundle-state"))
        if (ready) {
            Text("Размер: ${value.getInt("bytes")} байт", Modifier.testTag("bundle-size"))
            val manifest = value.getJSONObject("manifest")
            Text(if (manifest.getBoolean("complete")) "Все источники доступны" else "Часть источников недоступна или очищена",
                Modifier.testTag("bundle-completeness"))
            val rows = manifest.optJSONArray("components")
            for (index in 0 until minOf(rows?.length() ?: 0, 9)) {
                val row = rows?.optJSONObject(index) ?: continue
                val name = row.opt("name") as? String ?: continue
                val title = names[name] ?: continue
                val description = when (row.opt("state")) {
                    "available" -> "очищенные данные"
                    "truncated" -> "ограниченный объём"
                    "missing" -> "источник недоступен"
                    "error" -> "ошибка источника"
                    else -> "состояние неизвестно"
                }
                Text("$title: $description", Modifier.testTag("bundle-component-$index"))
            }
        }
        Text("В SYN443 не отправлен", Modifier.testTag("bundle-not-sent"))
        Text("Очищенный архив всё ещё может содержать сведения о работе сети. Экспорт выполняется отдельно.")
        if (message.isNotEmpty()) Text(message, Modifier.testTag("bundle-message"))
        Button(onClick = collect, enabled = !busy && !active, modifier = Modifier.testTag("bundle-collect")) { Text("Собрать архив") }
        TextButton(onClick = refresh, enabled = !busy && state != null && state != "idle", modifier = Modifier.testTag("bundle-refresh")) { Text("Обновить состояние") }
        TextButton(onClick = cancel, enabled = !cancelling && (active || (!busy && ready)), modifier = Modifier.testTag("bundle-cancel")) {
            Text(if (active) "Отменить сбор" else "Удалить доступ к архиву")
        }
        Button(onClick = export, enabled = !busy && ready, modifier = Modifier.testTag("bundle-export")) { Text("Экспортировать ZIP") }
        if (busy) LinearProgressIndicator(Modifier.fillMaxWidth().testTag("bundle-working"))
    }
}

internal fun validBundlePreview(value: JSONObject): Boolean {
    if (value.opt("state") != "ready" || !(value.opt("id") as? String).orEmpty().matches(Regex("[a-f0-9]{32}")) ||
        !(value.opt("sha256") as? String).orEmpty().matches(Regex("[a-f0-9]{64}"))) return false
    fun number(row: JSONObject, key: String): Long? = when (val raw = row.opt(key)) {
        is Int -> raw.toLong()
        is Long -> raw
        else -> null
    }
    val archiveBytes = number(value, "bytes") ?: return false
    if (archiveBytes !in 1L..524_288L) return false
    val manifest = value.optJSONObject("manifest") ?: return false
    if (manifest.opt("schemaVersion") != 1 || manifest.opt("product") != "SYN443" || manifest.opt("complete") !is Boolean) return false
    val rows = manifest.optJSONArray("components") ?: return false
    if (rows.length() != names.size) return false
    val seen = mutableSetOf<String>()
    var total = 0L
    var complete = true
    for (index in 0 until rows.length()) {
        val row = rows.optJSONObject(index) ?: return false
        val name = row.opt("name") as? String ?: return false
        if (name !in names || !seen.add(name)) return false
        val state = row.opt("state")
        val reason = row.opt("reason")
        if (state !in setOf("available", "missing", "error", "truncated") || reason !in setOf("none", "unavailable", "unsupported", "over_limit", "invalid_source", "io_error", "projection_only")) return false
        val size = number(row, "bytes") ?: return false
        if (size !in 0L..65_536L) return false
        total += size
        if (total > 262_144) return false
        if (state in setOf("available", "truncated")) {
            if (!(row.opt("sha256") as? String).orEmpty().matches(Regex("[a-f0-9]{64}"))) return false
        } else if (size != 0L || row.opt("sha256") != JSONObject.NULL) return false
        complete = complete && state == "available" && reason == "none"
    }
    return manifest.getBoolean("complete") == complete
}

private val names = mapOf(
    "versions.json" to "Версии", "capabilities.json" to "Возможности", "effective-config.json" to "Конфигурация",
    "health.json" to "Состояние VPN", "events.jsonl" to "События", "checks.json" to "Проверки",
    "overlay.json" to "NetBird", "crashes.json" to "Завершения процесса", "native-stacks.json" to "Нативные стеки",
)
