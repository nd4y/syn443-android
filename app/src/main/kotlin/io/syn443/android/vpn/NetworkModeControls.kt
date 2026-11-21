package io.syn443.android.vpn

import android.os.SystemClock
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.input.KeyboardType
import org.json.JSONObject

private val networkModeLabels = mapOf(
    "WIFI" to "Обычный Wi-Fi", "HOME_WIFI" to "Домашний Wi-Fi", "CELLULAR" to "Мобильная сеть",
    "CELLULAR_RESTRICTED" to "Мобильная сеть с белым списком", "UNKNOWN" to "Другая сеть",
)

@Composable
internal fun NetworkModeControls(report: JSONObject?, choose: (String, String, Int) -> Unit) {
    if (report == null) return
    val name = networkModeLabels[report.optString("effective")] ?: return
    val stamp = report.optString("stamp")
    val source = report.optString("source")
    val origin = when (source) {
        "manual" -> "Выбрано вручную"
        "assigned" -> "Назначено администратором"
        "automatic" -> "Определено автоматически"
        else -> return
    }
    val remaining = report.optLong("until") - SystemClock.elapsedRealtime()
    if (source == "manual" && remaining <= 0) return
    val suffix = if (source == "manual") " · ещё ${(remaining+59_999)/60_000} мин." else ""
    Text("$name · $origin$suffix", Modifier.testTag("effective-network-mode"))
    val permissions = report.optJSONArray("allowed") ?: return
    val allowed = (0 until permissions.length()).map { permissions.optString(it) }.filter { it in networkModeLabels && it != "UNKNOWN" }
    val maximum = report.optInt("maxMinutes")
    if (allowed.isEmpty() || maximum !in 1..1440 || stamp.length != 36) return
    var open by remember(stamp) { mutableStateOf(false) }
    var selected by remember(stamp) { mutableStateOf(allowed.first()) }
    var minutes by remember(stamp) { mutableStateOf(minOf(15, maximum).toString()) }
    TextButton(onClick={open=true}, modifier=Modifier.testTag("choose-network-mode")) { Text("Изменить режим сети") }
    if (!open) return
    val duration = minutes.toIntOrNull()?.takeIf { it in 1..maximum }
    AlertDialog(onDismissRequest={open=false}, title={Text("Временный режим сети")}, text={
        Column {
            Text("Выбор действует до смены сети или окончания срока.")
            for (mode in allowed) {
                TextButton(onClick={selected=mode}, modifier=Modifier.testTag("mode-choice-$mode")) {
                    Text(if (selected == mode) "✓ ${networkModeLabels.getValue(mode)}" else networkModeLabels.getValue(mode))
                }
            }
            OutlinedTextField(value=minutes, onValueChange={ if(it.length<=4 && it.all { c->c in '0'..'9' }) minutes=it },
                label={Text("Срок в минутах (1-$maximum)")}, isError=duration==null,
                keyboardOptions=KeyboardOptions(keyboardType=KeyboardType.Number), singleLine=true, modifier=Modifier.testTag("mode-duration"))
            if (source=="manual") TextButton(onClick={open=false;choose(stamp,"AUTO",0)}) { Text("Снять ручной выбор") }
        }
    }, dismissButton={TextButton(onClick={open=false}) {Text("Отмена")}},
    confirmButton={TextButton(enabled=duration!=null,onClick={duration?.let {open=false;choose(stamp,selected,it)}},
        modifier=Modifier.testTag("mode-confirm")) {Text("Применить")}})
}
