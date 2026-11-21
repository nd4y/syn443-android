package io.syn443.android.chat

import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import org.json.JSONObject

/** Projection for deliberate user-to-administrator messages. Never copy free text from status. */
internal data class SupportIncident(val clientId: String, val message: String) {
    companion object {
        private val phases = mapOf(
            "Off" to "отключён", "NeedsLogin" to "нужен вход", "NeedsPermission" to "нужно разрешение VPN",
            "NeedsUnlock" to "нужна разблокировка", "NeedsAction" to "требуется действие",
            "NoNetwork" to "нет сети", "Portal" to "требуется вход в сеть", "Detecting" to "определение сети",
            "Starting" to "запуск", "Connecting" to "подключение", "Online" to "на связи",
            "Degraded" to "частичная доступность", "Recovering" to "восстановление",
            "Blocked" to "блокировка политикой", "BlockedByPolicy" to "блокировка политикой",
        )

        fun capture(status: JSONObject?, id: String = ChatLimits.id()): SupportIncident {
            require(id.matches(Regex("[0-9a-f]{32}")))
            val intent = when (status?.opt("desiredOn")) { true -> "включить"; false -> "выключить"; else -> "неизвестно" }
            val phase = status?.opt("phase") as? String
            val running = status?.opt("engineStateKnown") == true && status?.opt("engineActive") == true
            val label = if (phase in setOf("Online", "Degraded") && (!running || status?.opt("desiredOn") != true)) null else phase?.let(phases::get)
            val policy = status?.optJSONObject("policy")
            fun revision(name: String): String {
                val value = policy?.opt(name)
                val integer = when (value) { is Int -> value.toLong(); is Long -> value; else -> null }
                return integer?.takeIf { it in 1L..9_007_199_254_740_991L }?.toString() ?: "неизвестна"
            }
            val routes = status?.optJSONObject("routeHealth")?.optJSONArray("routes")
            var fresh = 0
            var failed = 0
            var stale = 0
            val causes = sortedSetOf<String>()
            if (running && status?.opt("desiredOn") == true && routes != null && routes.length() <= 1024) {
                for (index in 0 until routes.length()) {
                    val route = routes.optJSONObject(index) ?: continue
                    when (route.opt("state")) {
                        "working" -> fresh++
                        "failed" -> {
                            failed++
                            val layer = when (route.opt("reason")) {
                                "dial_failed", "outbound_unavailable" -> "транспорт"
                                "tls_failed" -> "TLS"
                                "ssh_banner_mismatch" -> "SSH"
                                "request_failed", "response_failed", "http_response_mismatch" -> "HTTP"
                                "exit_evidence_invalid", "exit_ip_mismatch", "exit_country_mismatch" -> "проверка выхода"
                                "check_timeout" -> "тайм-аут проверки"
                                else -> null
                            }
                            if (layer != null) causes += layer
                        }
                        "stale" -> stale++
                    }
                }
            }
            val evidence = if (fresh + failed + stale == 0) "нет подтверждений" else
                "работают $fresh, с ошибкой $failed, устарели $stale"
            val incidentId = "SYN-" + id.take(12)
            return SupportIncident(id, listOf(
                "Обращение $incidentId", "Намерение VPN - $intent",
                "Состояние при создании - " + (label ?: "неизвестно"),
                "Проверки маршрутов при создании - $evidence",
                "Слой сбоя - " + causes.joinToString(", ").ifEmpty { "не установлен" },
                "Активная версия политики - " + revision("activeRevision"),
                "Последняя рабочая версия политики - " + revision("lastKnownGoodRevision"),
            ).joinToString("\n"))
        }
    }
}

@Composable
internal fun IncidentPreview(report: SupportIncident?, saving: Boolean, error: String?, canSubmit: Boolean = true, submit: () -> Unit, dismiss: () -> Unit) {
    AlertDialog(
        onDismissRequest = { if (!saving) dismiss() },
        title = { Text("Сообщить о проблеме") },
        text = { Text(listOfNotNull(report?.message ?: if (error == null) "Получаем состояние устройства" else null, error).joinToString("\n\n"),
            Modifier.testTag("incident-preview")) },
        confirmButton = { TextButton(enabled = report != null && !saving && canSubmit, onClick = submit,
            modifier = Modifier.testTag("incident-submit")) { Text("Отправить администратору") } },
        dismissButton = { TextButton(enabled = !saving, onClick = dismiss, modifier = Modifier.testTag("incident-cancel")) { Text("Отмена") } },
    )
}
