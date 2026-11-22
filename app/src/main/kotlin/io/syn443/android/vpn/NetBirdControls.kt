package io.syn443.android.vpn

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.material3.Button
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import java.util.UUID
import kotlinx.coroutines.delay
import org.json.JSONObject

private data class NetBirdViewRequest(val id: String, val page: Int) {
    override fun toString() = "NetBirdViewRequest([redacted])"
}

/** Cached status and explicit bounded view commands only. Paging never starts
 * diagnostics or reads the provider SDK from the UI. */
@Composable
internal fun NetBirdControls(overlay: JSONObject, command: (String, String?) -> Unit) {
    if (overlay.opt("configuredInRunningProfile") == false && overlay.opt("active") != true) {
        Text("В текущей конфигурации VPN нет NetBird", Modifier.testTag("netbird-profile-absent"))
        return
    }
    val model = NetBirdPresentation.read(overlay)
    var peerPending by remember { mutableStateOf<NetBirdViewRequest?>(null) }
    var diagnosticPending by remember { mutableStateOf<NetBirdViewRequest?>(null) }
    var peerTimeout by remember { mutableStateOf(false) }
    var diagnosticTimeout by remember { mutableStateOf(false) }
    LaunchedEffect(peerPending?.id) {
        val request = peerPending ?: return@LaunchedEffect
        delay(8_000)
        if (peerPending?.id == request.id) { peerPending = null; peerTimeout = true }
    }
    LaunchedEffect(diagnosticPending?.id) {
        val request = diagnosticPending ?: return@LaunchedEffect
        delay(8_000)
        if (diagnosticPending?.id == request.id) { diagnosticPending = null; diagnosticTimeout = true }
    }
    LaunchedEffect(model.peers.view?.request, peerPending?.id) {
        if (peerPending != null && model.peers.view?.request == peerPending?.id) peerPending = null
    }
    LaunchedEffect(model.diagnostics.view?.request, diagnosticPending?.id) {
        if (diagnosticPending != null && model.diagnostics.view?.request == diagnosticPending?.id) diagnosticPending = null
    }
    fun request(section: String, page: Int) {
        if (page !in 0..63) return
        if (section == "peers" && peerPending != null || section == "diagnostics" && diagnosticPending != null) return
        val pending = NetBirdViewRequest(UUID.randomUUID().toString(), page)
        if (section == "peers") { peerPending = pending; peerTimeout = false }
        else { diagnosticPending = pending; diagnosticTimeout = false }
        command("netbird-view", JSONObject().put("kind", "overlay-view").put("section", section)
            .put("page", page).put("request", pending.id).toString())
    }
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Text("NetBird: ${model.phase}", Modifier.testTag("netbird-status"))
        if (model.active == null) Text("Состояние модуля: неизвестно")
        else if (!model.active) Text("Модуль NetBird не активен")
        Text(model.transport, Modifier.testTag("netbird-transport"))
        Text(model.connection, Modifier.testTag("netbird-connection"))
        if (model.stale) Text("Статус NetBird устарел или ещё не получен")
        model.reason?.let { Text("NetBird: $it") }
        model.failure?.let { Text("Ошибка NetBird: $it") }
        if (model.failureTruncated == true) Text("Сообщение об ошибке ограничено", Modifier.testTag("netbird-failure-truncated"))
        TextButton(onClick = { command("status", null) }, modifier = Modifier.testTag("netbird-refresh")) {
            Text("Обновить статус NetBird")
        }
        NetBirdSection("peers", "Пиры", model.peers, peerPending != null, peerTimeout,
            { page -> request("peers", page) })
        Text("Наличие пира не подтверждает доступность приложения.")
        for ((index, row) in model.peers.rows.withIndex()) {
            Text("${row.fqdn ?: "н/д"} ${row.ip ?: "н/д"}: ${row.state}, " + when (row.relayed) {
                true -> "relay"
                false -> "direct/ожидание"
                null -> "путь н/д"
            } + if (row.truncated) " (имя сокращено)" else "", Modifier.testTag("netbird-peer-$index"),
                maxLines = 3, overflow = TextOverflow.Ellipsis)
        }
        Button(onClick = { command("netbird-diagnose", null) }, enabled = model.canDiagnose,
            modifier = Modifier.testTag("netbird-diagnose")) { Text("Проверить пиры NetBird") }
        model.cancellableJob?.let { jobId ->
            TextButton(onClick = { command("netbird-cancel", jobId) }, modifier = Modifier.testTag("netbird-cancel")) {
                Text("Отменить проверку пиров")
            }
        }
        Text("Проверка пиров: ${model.diagnosticLabel}", Modifier.testTag("netbird-diagnostic-state"))
        if (model.diagnosticStale == true) Text("Результат проверки относится к предыдущей сети")
        val coverage = model.coverage
        Text(if (coverage == null) "Охват проверки неизвестен" else
            "Проверено ${coverage.checked} из ${coverage.total}; запланировано ${coverage.planned}; не проверено ${coverage.unprobed}; вне кэша ${coverage.omitted}",
            Modifier.testTag("netbird-coverage"))
        NetBirdSection("diagnostics", "Результаты", model.diagnostics, diagnosticPending != null, diagnosticTimeout,
            { page -> request("diagnostics", page) })
        for ((index, row) in model.diagnostics.rows.withIndex()) {
            Text("${row.fqdn ?: "н/д"}: ${if (row.state == "limit") "не проверен (лимит)" else row.state}, ${row.rttMs?.toString() ?: "н/д"} мс" +
                if (row.truncated) " (имя сокращено)" else "", Modifier.testTag("netbird-result-$index"),
                maxLines = 3, overflow = TextOverflow.Ellipsis)
        }
    }
}

@Composable
private fun NetBirdSection(section: String, title: String, value: NetBirdPresentation.Section,
    pending: Boolean, timedOut: Boolean, request: (Int) -> Unit) {
    val view = value.view
    val counts = if (view == null) "$title: н/д; показано ${value.rows.size}; общий охват неизвестен" else
        "$title: ${view.total}; показано ${view.shown}; в памяти ${view.retained}; вне кэша ${view.omitted}"
    Text(counts, Modifier.testTag("netbird-$section-counts"))
    if (view == null && value.reported != null) Text("Получено строк: ${value.reported}; вывод ограничен 16 строками. Метаданные страниц не подтверждены.")
    if (view != null) Text("Страница ${if (view.pages == 0) 0 else view.page + 1} из ${view.pages}")
    Row {
        TextButton(onClick = { request(checkNotNull(view).page - 1) },
            enabled = !pending && view != null && view.page > 0, modifier = Modifier.testTag("netbird-$section-prev")) { Text("Назад") }
        TextButton(onClick = { request(checkNotNull(view).page + 1) },
            enabled = !pending && view != null && view.page + 1 < view.pages, modifier = Modifier.testTag("netbird-$section-next")) { Text("Далее") }
    }
    if (pending) Text("Ожидание страницы", Modifier.testTag("netbird-$section-pending"))
    if (timedOut) Text("Время ожидания страницы истекло. При необходимости повторите запрос вручную.", Modifier.testTag("netbird-$section-timeout"))
}
