package io.syn443.android.chat

import androidx.compose.foundation.layout.Column
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import org.json.JSONObject

private val incidentReference = Regex("SYN-[0-9a-f]{12}")

internal fun incidentResult(reference: String, response: JSONObject): String {
    require(incidentReference.matches(reference) && response.opt("reference") == reference)
    return when (response.opt("state")) {
        "missing" -> { require(!response.has("report")); "Обращение не найдено." }
        "ambiguous" -> { require(!response.has("report")); "Номер совпал у нескольких обращений. Уточните диалог у пользователя." }
        "found" -> {
            val report = response.getJSONObject("report")
            val text = report.opt("text") as? String ?: throw ChatFailure("INVALID_REPLY")
            require(text.lineSequence().first() == "Обращение $reference" && ChatLimits.text(text))
            val seconds = when (val value = report.opt("createdAt")) {
                is Long -> value
                is Int -> value.toLong()
                else -> throw ChatFailure("INVALID_REPLY")
            }
            require(seconds in 1..253402300799L)
            val date = java.text.DateFormat.getDateTimeInstance().format(java.util.Date(seconds * 1000))
            "$text\nПолучено $date"
        }
        else -> throw ChatFailure("INVALID_REPLY")
    }
}

@Composable
internal fun AdminIncidentLookup(fetch: suspend (String) -> JSONObject) {
    var reference by remember { mutableStateOf("") }
    var result by remember { mutableStateOf("") }
    var request by remember { mutableStateOf<Job?>(null) }
    var busy by remember { mutableStateOf(false) }
    var generation by remember { mutableLongStateOf(0L) }
    val scope = rememberCoroutineScope()
    Column {
        OutlinedTextField(reference, { value ->
            request?.cancel()
            request = null
            busy = false
            generation++
            reference = value.take(64)
            result = ""
        }, label = { Text("Номер обращения") }, singleLine = true, modifier = Modifier.testTag("incident-reference"))
        TextButton(enabled = !busy && incidentReference.matches(reference), onClick = {
            val expected = reference
            val attempt = ++generation
            result = ""
            busy = true
            request = scope.launch {
                try {
                    val found = incidentResult(expected, fetch(expected))
                    if (attempt == generation && reference == expected) result = found
                } catch (cancelled: CancellationException) { throw cancelled }
                catch (error: Exception) {
                    if (attempt == generation) result = when ((error as? ChatFailure)?.code) {
                        "ACCESS_DENIED", "REAUTHENTICATE", "SESSION_EXPIRED" -> "Проверьте вход и права администратора."
                        else -> "Поиск временно недоступен."
                    }
                } finally {
                    if (attempt == generation) busy = false
                }
            }
        }, modifier = Modifier.testTag("incident-find")) { Text("Найти обращение") }
        if (result.isNotEmpty()) Text(result, Modifier.testTag("incident-result"))
    }
}
