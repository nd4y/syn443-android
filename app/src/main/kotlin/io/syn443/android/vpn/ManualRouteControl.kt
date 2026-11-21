package io.syn443.android.vpn

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.LocalSaveableStateRegistry
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.window.SecureFlagPolicy
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch
import org.json.JSONObject

private val fields = listOf("domain" to "Домен", "address" to "IP-адрес", "application" to "Приложение (имя пакета)",
    "network" to "Транспорт (TCP или UDP)", "port" to "Порт", "dnsType" to "Тип запроса DNS")

@Composable
internal fun ManualRouteControl(health: JSONObject? = null, explain: suspend (String) -> ManualRouteAnswer?) {
    var open by remember { mutableStateOf(false) }
    TextButton(onClick = { open = true }, modifier = Modifier.testTag("manual-route-open")) {
        Text("Объяснить маршрут")
    }
    if (!open) return
    AlertDialog(
        onDismissRequest = { open = false },
        properties = DialogProperties(securePolicy = SecureFlagPolicy.SecureOn),
        title = { Text("Проверка правил на устройстве") },
        text = {
            CompositionLocalProvider(LocalSaveableStateRegistry provides null) {
                ManualRouteFields(health, explain)
            }
        },
        confirmButton = { TextButton(onClick = { open = false }) { Text("Закрыть") } },
    )
}

@Composable
private fun ManualRouteFields(health: JSONObject?, explain: suspend (String) -> ManualRouteAnswer?) {
    val inputs = remember { mutableStateMapOf<String, String>() }
    var generation by remember { mutableLongStateOf(0) }
    var result by remember { mutableStateOf<ManualRouteAnswer?>(null) }
    var busy by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    Column(Modifier.heightIn(max = 500.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Text("Введите домен, IP-адрес или пакет приложения. Для уточнения можно заполнить несколько полей. Проверка использует текущую конфигурацию на телефоне.")
        for ((key, label) in fields) {
            OutlinedTextField(
                value = inputs[key].orEmpty(),
                onValueChange = { value ->
                    if (value.length <= 255) {
                        inputs[key] = value
                        generation++
                        result = null
                    }
                },
                label = { Text(label) }, singleLine = true,
                modifier = Modifier.fillMaxWidth().testTag("manual-route-" + key),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, autoCorrectEnabled = false),
            )
        }
        Button(onClick = {
            val query = JSONObject()
            inputs.forEach { (key, value) -> if (value.isNotBlank()) query.put(key, value.trim()) }
            val raw = query.toString()
            if (runCatching { LocalRouteQuery.parse(raw) }.isFailure) {
                result = ManualRouteAnswer("Проверьте введённые значения.")
            } else {
                val ticket = generation
                busy = true
                scope.launch {
                    try {
                        val answer = explain(raw)
                        if (ticket == generation) result = answer ?: ManualRouteAnswer("Разрешённая конфигурация недоступна.")
                    } catch (e: CancellationException) {
                        throw e
                    } catch (_: Exception) {
                        if (ticket == generation) result = ManualRouteAnswer("Не удалось проверить конфигурацию.")
                    } finally {
                        busy = false
                    }
                }
            }
        }, enabled = !busy && listOf("domain", "address", "application").any { !inputs[it].isNullOrBlank() },
            modifier = Modifier.testTag("manual-route-run")) { Text(if (busy) "Проверяем…" else "Проверить") }
        result?.let { answer ->
            Text(answer.description, Modifier.testTag("manual-route-result").semantics { liveRegion = LiveRegionMode.Polite })
            if (answer.outbound != null) Text(answer.measurement(health) ?: "Для этого маршрута нет свежего подтверждённого пути.",
                Modifier.testTag("manual-route-measurement"))
        }
    }
}
