package io.syn443.android.vpn

import android.app.Activity
import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.net.VpnService
import android.util.Base64
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
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
fun VpnControls(consentGeneration: Long = -1, account: @Composable (Boolean) -> Unit = {}) {
    val context = LocalContext.current
    var status by remember { mutableStateOf(JSONObject()) }
    var statusAvailable by remember { mutableStateOf<Boolean?>(null) }
    var message by remember { mutableStateOf("") }
    var detailsOpen by rememberSaveable { mutableStateOf(false) }
    var resources by remember { mutableStateOf<JSONObject?>(null) }
    var resourcesBusy by remember { mutableStateOf(false) }
    var exits by remember { mutableStateOf<JSONObject?>(null) }
    var exitsBusy by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    val lifecycle = (context as LifecycleOwner).lifecycle
    var visible by remember { mutableStateOf(lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) }
    DisposableEffect(lifecycle) {
        val observer = LifecycleEventObserver { _, _ -> visible = lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED) }
        lifecycle.addObserver(observer)
        onDispose { lifecycle.removeObserver(observer) }
    }
    val displayedCheckContext=status.optJSONObject("routeHealth")?.optString("checkContext").orEmpty()
    fun command(method: String, arg: String? = null): Bundle? {
        val extras=if(method=="routes-check" && arg!=null) Bundle().apply {putString("checkContext",displayedCheckContext)} else null
        val result = runCatching { context.contentResolver.call(controlUri, method, arg, extras) }.getOrNull()
        val accepted = result?.takeIf { it.getBoolean("ok") }
        message = when {
            accepted == null -> "Не удалось выполнить команду"
            method == "policy-refresh" -> {
                val reply=accepted.getString("json")?.let { runCatching { JSONObject(it) }.getOrNull() }
                if(reply?.opt("admitted")==false) "Проверка уже выполняется или выполнялась недавно"
                else "Запрошено обновление политики"
            }
            method == "routes-check" && arg != null -> "Запрошена проверка маршрута"
            else -> ""
        }
        return accepted
    }
    fun updateIntent(reply: Bundle) {
        val accepted = reply.getString("json")?.let { runCatching { JSONObject(it) }.getOrNull() } ?: return
        val generation = accepted.optLong("generation", -1)
        if (generation >= status.optLong("generation", -1) && accepted.has("desiredOn")) {
            status = JSONObject(status.toString())
                .put("generation", generation)
                .put("desiredOn", accepted.getBoolean("desiredOn"))
                .put("phase", accepted.optString("phase"))
                .put("reason", accepted.optString("reason"))
        }
    }
    val notifications = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        if (!granted) message = "Уведомления VPN отключены в Android"
    }
    fun askNotifications() {
        if (Build.VERSION.SDK_INT >= 33 && ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED)
            notifications.launch(Manifest.permission.POST_NOTIFICATIONS)
    }
    val consent = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            if (command("resume") != null) askNotifications()
        } else message = "Нужно разрешение Android на VPN"
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
        // Opening UI is never Connect, including after an Android Force stop.
        if (visible) withContext(Dispatchers.IO) { runCatching {
            val raw = context.contentResolver.call(controlUri, "status", null, null)?.getString("json")
            if (raw != null) context.contentResolver.call(controlUri, "foreground-open", JSONObject(raw).optLong("generation").toString(), null)
        } }
        while (visible) {
            val current = withContext(Dispatchers.IO) { runCatching {
                context.contentResolver.call(controlUri, "status", null, null)?.getString("json")?.let(::JSONObject)
            }.getOrNull() }
            statusAvailable = current != null
            if (current != null && (current.isNull("generation") || current.optLong("generation") >= status.optLong("generation", -1))) {
                status = current
            }
            delay(1_000)
        }
    }
    fun requestConnect() {
        val accepted = command("connect")
        if (accepted == null) {
            message = "Подключение недоступно. Проверьте вход и конфигурацию VPN."
            return
        }
        updateIntent(accepted)
        val intent = VpnService.prepare(context)
        if (intent != null) consent.launch(intent) else askNotifications()
    }
    LaunchedEffect(consentGeneration) {
        if (consentGeneration >= 0) {
            val raw = withContext(Dispatchers.IO) { context.contentResolver.call(controlUri, "status", null, null)?.getString("json") }
            if (raw != null) {
                val current = JSONObject(raw)
                if (current.optBoolean("desiredOn") && current.optLong("generation") == consentGeneration)
                    VpnService.prepare(context)?.let { consent.launch(it) }
            }
        }
    }
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        val desiredOn = if (status.isNull("desiredOn")) null else status.optBoolean("desiredOn")
        val phase = status.optString("phase")
        val reason = status.optString("reason")
        val portal = statusAvailable == true && phase == "NoNetwork" && reason == "captive_portal"
        val policy = status.optJSONObject("policy")
        val accountPolicyBlocked = policy?.let { it.optString("source") == "account" && it.optString("phase") == "blocked" } == true
        Text(when (desiredOn) {
            true -> "VPN включён"
            false -> "VPN выключен"
            null -> "VPN"
        }, Modifier.testTag("vpn-intent"), style = MaterialTheme.typography.titleMedium)
        VpnStatusSummary(status, statusAvailable, accountPolicyBlocked)
        if (statusAvailable==true && desiredOn==true) NetworkModeControls(status.optJSONObject("physicalLink")?.optJSONObject("modeSelection")) { stamp, mode, minutes ->
            command("network-mode","$stamp|$mode|$minutes")
        }
        VpnPrimaryAction(
            desiredOn = desiredOn,
            connectEnabled = statusAvailable == true && !accountPolicyBlocked,
            onConnect = ::requestConnect,
            onStop = { command("disconnect")?.let(::updateIntent) },
        )
        TextButton(onClick = {
            context.startActivity(android.content.Intent(context, io.syn443.android.chat.SupportActivity::class.java)
                .putExtra(io.syn443.android.chat.SupportActivity.REPORT_PROBLEM, true)
                .addFlags(android.content.Intent.FLAG_ACTIVITY_REORDER_TO_FRONT or android.content.Intent.FLAG_ACTIVITY_SINGLE_TOP))
        }, modifier = Modifier.testTag("report-problem")) { Text("Сообщить о проблеме") }
        if (statusAvailable == true && desiredOn == true) {
            if (phase == "NeedsPermission") TextButton(onClick = {
                val intent = VpnService.prepare(context)
                if (intent != null) consent.launch(intent)
                else if (command("resume") != null) askNotifications()
            }) { Text("Разрешить VPN") }
            if (phase == "NeedsAction" && (status.optBoolean("resumeRequired") || reason == "os_start_restricted"))
                TextButton(onClick = ::requestConnect) { Text("Возобновить подключение") }
        }
        if(portal) {
            Text(if(status.optJSONObject("osPolicy")?.optBoolean("lockdown")==true)
                "Android блокирует подключения без VPN. Если системный вход в Wi-Fi недоступен, выберите другую сеть или обратитесь к администратору."
            else "Откройте системное уведомление о входе в Wi-Fi. SYN443 продолжит подключение после входа.",
                Modifier.testTag("wifi-portal-help"))
        }
        val next = maxOf(status.optLong("nextWallMs"), status.optLong("policyRetryAt"))
        if (statusAvailable == true && desiredOn == true && next > System.currentTimeMillis())
            Text("Повтор не ранее чем через ${(next - System.currentTimeMillis()) / 1_000} с, при доступной сети")
        if (message.isNotEmpty()) Text(message, Modifier.semantics { liveRegion = LiveRegionMode.Polite })
        account(statusAvailable==true && phase=="Off" && desiredOn==false &&
            status.optBoolean("engineStateKnown") && !status.optBoolean("engineActive"))
        TextButton(
            onClick = { detailsOpen = !detailsOpen },
            modifier = Modifier.testTag("vpn-details").semantics {
                stateDescription = if (detailsOpen) "Раскрыто" else "Свёрнуто"
            },
        ) { Text(if (detailsOpen) "Скрыть диагностику" else "Маршруты и диагностика") }
        if (detailsOpen) {
            if (statusAvailable == true && desiredOn == true) PhysicalLinkDetails(status.optJSONObject("physicalLink"))
            if (statusAvailable == true && desiredOn == true) {
                for (detail in internetDnsFailures(status.optJSONObject("internetChecks"))) Text(detail)
            }
            if (status.optBoolean("testHealth")) Text("ТЕСТОВЫЙ СТЕНД: синтетический HTTP, проверка TLS не выполняется")
            if (status.optString("reason").isNotEmpty()) Text("Диагностика: " + status.optString("reason"))
            if (policy?.optBoolean("managed") == true) {
                Text("Политика: ${policy.optString("phase")}", Modifier.testTag("policy-status"))
                Text("Желаемая: ${policy.optString("desiredRevision", "-")}; активная: ${policy.optString("activeRevision", "-")}; рабочая: ${policy.optString("lastKnownGoodRevision", "-")}")
                if (policy.optString("reason").isNotEmpty()) Text("Политика: ${policy.optString("reason")}")
                Button(enabled=status.optBoolean("desiredOn") || policy.optString("source")=="account",
                    onClick = { command("policy-refresh") }) { Text("Проверить обновление политики") }
            }
            val overlay = status.optJSONObject("netbird")
            if (overlay != null) NetBirdControls(overlay) { method, arg -> command(method, arg) }
            RouteControls(status){method,arg->command(method,arg)}
            if (visible && statusAvailable == true) {
                key(status.optString("configRevision"), status.optLong("generation"), status.optLong("networkEpoch"),
                    policy?.optString("source"), policy?.optString("phase"), policy?.optString("activeRevision"),
                    policy?.optString("desiredRevision"), policy?.optString("activationGeneration")) {
                    ManualRouteControl(status.optJSONObject("routeHealth")) { query ->
                        withContext(Dispatchers.IO) {
                            context.contentResolver.call(controlUri, "route-explain", query, null)
                                ?.takeIf { it.getBoolean("ok") }?.let { reply ->
                                    reply.getString("description")?.let { ManualRouteAnswer(it, reply.getString("outbound"), reply.getString("revision")) }
                                }
                        }
                    }
                }
            }
            Button(onClick = {
                resourcesBusy = true
                scope.launch {
                    resources = withContext(Dispatchers.IO) { runCatching {
                        val result = context.contentResolver.call(controlUri, "resources", null, null)
                        check(result?.getBoolean("ok") == true)
                        JSONObject(checkNotNull(result?.getString("json")))
                    }.getOrNull() }
                    resourcesBusy = false
                    if (resources == null) message = "Не удалось получить показатели ресурсов"
                }
            }, enabled = !resourcesBusy, modifier = Modifier.testTag("resource-refresh")) { Text("Измерить ресурсы") }
            resources?.let { snapshot ->
                Text("Ресурсы: снимок по запросу, без фонового сбора", Modifier.testTag("resource-status"))
                Text("Возраст при запросе: ${snapshot.optLong("sampleAgeMs")} мс. CPU: 100% = одно логическое ядро. Это не замер батареи.")
                val processes = snapshot.getJSONArray("processes")
                for (i in 0 until processes.length()) {
                    val process = processes.getJSONObject(i)
                    val role = if (process.getString("role") == "controller") "Контроллер" else "Движок"
                    if (process.getString("state") != "available") Text("$role: показатели недоступны (${process.getString("state")})")
                    else {
                        val rss = if (process.isNull("rssBytes")) "н/д" else "${process.getLong("rssBytes") / 1_048_576} MiB"
                        val window = process.getJSONObject("window")
                        val cpu = if (window.isNull("cpuPermille")) "нужно два измерения с интервалом от 30 с" else "${window.getLong("cpuPermille") / 10.0}% за ${window.getLong("elapsedMs") / 1000} с"
                        Text("$role: RSS $rss; CPU $cpu; потоки ${process.opt("threads")}; дескрипторы ${process.opt("fileDescriptors")}")
                    }
                }
            }
            Button(onClick = {
                if (Build.VERSION.SDK_INT < 30) {
                    exits = EngineExitDiagnostics.snapshot(context)
                } else {
                    exitsBusy = true
                    scope.launch {
                        exits = withContext(Dispatchers.IO) { runCatching {
                            val result = context.contentResolver.call(controlUri, "engine-exits", null, null)
                            check(result?.getBoolean("ok") == true)
                            JSONObject(checkNotNull(result?.getString("json")))
                        }.getOrElse { EngineExitDiagnostics.unavailable() } }
                        exitsBusy = false
                    }
                }
            }, enabled = !exitsBusy, modifier = Modifier.testTag("exit-refresh")) { Text("Причины завершения VPN") }
            exits?.let { report ->
                val entries = report.getJSONArray("exits")
                val heading = when (report.optString("state")) {
                    "unsupported" -> "Эта версия Android не предоставляет историю завершений"
                    "unavailable" -> "История завершений временно недоступна"
                    else -> if (entries.length() == 0) "Завершения движка не зарегистрированы" else "Последние завершения движка"
                }
                Text(heading, Modifier.testTag("exit-status"))
                for (i in 0 until entries.length()) {
                    val item = entries.getJSONObject(i)
                    val reason = when (item.optString("kind")) {
                        "native_crash" -> "Авария VPN-движка"
                        "java_crash" -> "Ошибка процесса VPN"
                        "signal" -> "Завершение сигналом ОС"
                        "self_exit" -> "Процесс завершился самостоятельно"
                        "low_memory" -> "Недостаточно памяти"
                        "anr" -> "Процесс не отвечал"
                        "os_request" -> "Завершён системой или пользователем"
                        else -> "Другая причина"
                    }
                    val date = java.text.DateFormat.getDateTimeInstance().format(java.util.Date(item.getLong("at")))
                    Text("$date: $reason")
                }
            }
            Button(onClick = { importer.launch(arrayOf("application/json", "text/plain")) }, enabled = statusAvailable == true && desiredOn == false && policy?.optBoolean("managed") != true) { Text("Импорт конфигурации движка") }
        }
    }
}

@Composable
internal fun VpnStatusSummary(status: JSONObject, available: Boolean?, accountPolicyBlocked: Boolean) {
    val known = status.optBoolean("engineStateKnown")
    val active = status.optBoolean("engineActive")
    val phase = status.optString("phase")
    val checking = "Проверяем состояние VPN"
    val label = when {
        available == null -> checking
        !available -> "Состояние VPN временно недоступно"
        phase == "NeedsUnlock" -> "Нужно разблокировать телефон"
        status.opt("desiredOn") == false -> when {
            known && active -> "Останавливаем VPN"
            !known -> checking
            accountPolicyBlocked -> "Ожидаем конфигурацию от сервера"
            else -> "Отключён"
        }
        status.opt("desiredOn") != true -> checking
        else -> when (phase) {
            "Online" -> if (known && active) "Работает" else checking
            "Degraded" -> if (known && active) "Частично работает" else checking
            "BlockedByPolicy", "Blocked" -> "Доступ ограничен политикой"
            "NoNetwork" -> if (status.optString("reason") == "captive_portal") "Войдите в сеть Wi-Fi" else "Ожидание сети"
            "Recovering" -> "Восстанавливаем соединение"
            "Starting", "Connecting" -> "Подключаемся"
            "NeedsPermission" -> "Нужно разрешение Android на VPN"
            "NeedsAction" -> "Требуется действие пользователя"
            "NeedsLogin" -> "Требуется вход в аккаунт"
            else -> checking
        }
    }
    Text(label, Modifier.testTag("vpn-status").semantics { liveRegion = LiveRegionMode.Polite })
    if (available == true && status.opt("desiredOn") == true && known && active &&
        phase in setOf("Online", "Degraded", "Recovering")) {
        val overlay = status.optJSONObject("netbird")
        if (overlay?.opt("configuredInRunningProfile") == true) {
            val summary = NetBirdConnectionState.entries.firstOrNull { it.name == overlay.opt("connectionState") }
                ?: NetBirdConnectionState.UNKNOWN
            Text(summary.label, Modifier.testTag("vpn-netbird-summary").semantics { liveRegion = LiveRegionMode.Polite })
        }
    }
}

@Composable
internal fun VpnPrimaryAction(desiredOn: Boolean?, connectEnabled: Boolean, onConnect: () -> Unit, onStop: () -> Unit) {
    if (desiredOn == true) {
        Button(onClick = onStop, modifier = Modifier.fillMaxWidth().testTag("vpn-disconnect")) { Text("Отключить") }
    } else {
        Button(onClick = onConnect, enabled = desiredOn == false && connectEnabled,
            modifier = Modifier.fillMaxWidth().testTag("vpn-connect")) { Text("Подключиться") }
    }
}
