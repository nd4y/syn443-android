package io.syn443.android.vpn

import android.app.Activity
import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.net.VpnService
import android.util.Base64
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.material3.Button
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.core.net.toUri
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.LifecycleOwner
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import kotlinx.coroutines.launch
import org.json.JSONObject

private val controlUri = "content://io.syn443.control".toUri()

@Composable
fun VpnControls(connectFromTile: Boolean = false) {
    val context = LocalContext.current
    var status by remember { mutableStateOf(JSONObject()) }
    var message by remember { mutableStateOf("") }
    val scope = rememberCoroutineScope()
    val lifecycle = (context as LifecycleOwner).lifecycle
    var visible by remember { mutableStateOf(lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) }
    DisposableEffect(lifecycle) {
        val observer = LifecycleEventObserver { _, _ -> visible = lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED) }
        lifecycle.addObserver(observer)
        onDispose { lifecycle.removeObserver(observer) }
    }
    fun command(method: String, arg: String? = null) {
        val result = context.contentResolver.call(controlUri, method, arg, null)
        message = if (result?.getBoolean("ok") == true) "Команда принята" else "Не удалось выполнить команду"
    }
    val notifications = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        if (!granted) message = "VPN работает, но уведомления отключены в Android"
    }
    fun askNotifications() {
        if (Build.VERSION.SDK_INT >= 33 && ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED)
            notifications.launch(Manifest.permission.POST_NOTIFICATIONS)
    }
    val consent = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == Activity.RESULT_OK) { command("resume"); askNotifications() } else message = "Нужно разрешение Android на VPN"
    }
    val importer = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) {
            scope.launch {
                val bytes = withContext(Dispatchers.IO) { runCatching {
                    context.contentResolver.openInputStream(uri)?.use { input ->
                        val buffer = ByteArray(262_145)
                        var size = 0
                        while (size < buffer.size) {
                            val count = input.read(buffer, size, buffer.size - size)
                            if (count < 0) break
                            check(count > 0) { "input made no progress" }
                            size += count
                        }
                        buffer.copyOf(size)
                    }
                }.getOrNull() }
                if (bytes != null && bytes.size <= 262_144) command("import", Base64.encodeToString(bytes, Base64.NO_WRAP))
                else message = "Не удалось прочитать конфигурацию"
            }
        }
    }
    LaunchedEffect(visible) {
        while (visible) {
            val raw = withContext(Dispatchers.IO) { runCatching { context.contentResolver.call(controlUri, "status", null, null)?.getString("json") }.getOrNull() }
            if (raw != null) status = JSONObject(raw)
            delay(1_000)
        }
    }
    fun requestConnect() {
        message = ""
        command("connect")
        val intent = VpnService.prepare(context)
        if (intent != null) consent.launch(intent) else askNotifications()
    }
    LaunchedEffect(connectFromTile) { if (connectFromTile) requestConnect() }
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text("VPN: " + if (status.optBoolean("desiredOn")) "включён пользователем" else "выключен", Modifier.testTag("vpn-intent"))
        if (status.optBoolean("testHealth")) Text("ТЕСТОВЫЙ СТЕНД: синтетический HTTP, проверка TLS не выполняется")
        Text(when (status.optString("phase")) {
            "Online" -> "Работает"
            "NoNetwork" -> "Ожидание сети"
            "Recovering" -> "Восстанавливаем соединение"
            "Connecting" -> "Подключаемся"
            "NeedsPermission", "NeedsAction" -> "Требуется действие пользователя"
            else -> "Отключён"
        }, Modifier.testTag("vpn-status"))
        if (status.optString("reason").isNotEmpty()) Text("Диагностика: " + status.optString("reason"))
        val overlay = status.optJSONObject("netbird")
        if (overlay?.optBoolean("active") == true) {
            val peerState = overlay.optJSONObject("peer_state") ?: JSONObject()
            val age = overlay.optLong("snapshotAgeMs", Long.MAX_VALUE)
            val sampledAge = runCatching { System.currentTimeMillis() - java.time.Instant.parse(peerState.getString("sampled_at")).toEpochMilli() }.getOrDefault(Long.MAX_VALUE)
            Text("NetBird: ${overlay.optString("phase", "Unknown")}", Modifier.testTag("netbird-status"))
            Text(if (overlay.optString("mode") == "direct") "Подключение напрямую; relay используется как резерв" else
                "Через VLESS: ${peerState.optString("selected_proxy", "ожидание")}")
            Text("Cloud: ${peerState.optBoolean("management_connected")}; signal: ${peerState.optBoolean("signal_connected")}")
            if (age > 25_000 || sampledAge !in 0..25_000) Text("Статус NetBird устарел или ещё не получен")
            if (overlay.optString("reason").isNotEmpty()) Text("NetBird: ${overlay.optString("reason")}")
            val peers = peerState.optJSONArray("peers")
            Text("Пиры: ${peers?.length() ?: 0}. Наличие пира не подтверждает доступность приложения.")
            if (peers != null) for (i in 0 until minOf(peers.length(), 128)) {
                val peer = peers.getJSONObject(i)
                Text("${peer.optString("fqdn")} ${peer.optString("ip")}: ${peer.optString("state")}, " +
                    if (peer.optBoolean("relayed")) "relay" else "direct/ожидание")
            }
            Button(onClick = { command("netbird-diagnose") }, enabled = peerState.optBoolean("active")) { Text("Проверить пиры NetBird") }
            val diagnostics = overlay.optJSONObject("diagnostics")
            if (diagnostics != null) {
                Text("Проверка пиров: ${diagnostics.optString("state")}")
                if (diagnostics.optBoolean("stale")) Text("Результат проверки относится к предыдущей сети")
                val results = diagnostics.optJSONArray("results")
                if (results != null) for (i in 0 until minOf(results.length(), 128)) {
                    val result = results.getJSONObject(i)
                    Text("${result.optString("fqdn")}: ${result.optString("state")}, ${result.optLong("rtt_ms")} мс")
                }
            }
        }
        val next = status.optLong("nextWallMs")
        if (status.optBoolean("desiredOn") && next > System.currentTimeMillis()) Text("Повтор не ранее чем через ${(next - System.currentTimeMillis()) / 1_000} с, при доступной сети")
        Button(onClick = { requestConnect() }, modifier = Modifier.testTag("vpn-connect")) { Text("Подключиться") }
        Button(onClick = { command("disconnect") }, modifier = Modifier.testTag("vpn-disconnect")) { Text("Отключить") }
        Button(onClick = { importer.launch(arrayOf("application/json", "text/plain")) }, enabled = !status.optBoolean("desiredOn")) { Text("Импорт конфигурации движка") }
        Text("M1: прямой путь или импортированные профили. Регистрация и управляемый provisioning ещё не реализованы.")
        if (message.isNotEmpty()) Text(message)
    }
}
