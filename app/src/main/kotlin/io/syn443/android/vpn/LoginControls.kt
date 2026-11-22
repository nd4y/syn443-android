package io.syn443.android.vpn

import android.content.Intent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.core.net.toUri
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.LifecycleOwner
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject

@Composable fun LoginControls(vpnStopped:Boolean) {
    val context=LocalContext.current;val scope=rememberCoroutineScope()
    val uri=remember {"content://io.syn443.control".toUri()}
    var status by remember {mutableStateOf(JSONObject())}
    var message by remember {mutableStateOf("")}
    var launchGeneration by remember {mutableStateOf<Long?>(null)}
    var launchAfterRevision by remember {mutableStateOf<Long?>(null)}
    val lifecycle=(context as LifecycleOwner).lifecycle
    var visible by remember {mutableStateOf(lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED))}
    DisposableEffect(lifecycle) {
        val observer=LifecycleEventObserver {_,_->visible=lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)}
        lifecycle.addObserver(observer);onDispose {lifecycle.removeObserver(observer)}
    }
    suspend fun command(method:String,arg:String?=null)=withContext(Dispatchers.IO) {
        runCatching {context.contentResolver.call(uri,method,arg,null)}.getOrNull()
    }
    LaunchedEffect(visible) {
        if(visible)while(true) {
            val result=command("auth-status")
            status=runCatching {JSONObject(result?.getString("json")?:"{}")} .getOrDefault(JSONObject())
            val awaitingPermit=needsForegroundRenewal(status.optString("phase"),status.optString("reason"),status.optJSONObject("assignedPolicy"))
            if((awaitingPermit || status.optString("phase") in setOf("PROVISIONING","INVITING","ENROLLING")) && !status.optBoolean("busy") &&
                lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) {
                command("auth-poll",status.optLong("generation",-1).toString())
            }
            delay(1000)
        }
    }
    val phase=status.optString("phase");val generation=status.optLong("generation",-1)
    val revision=status.optLong("intentRevision",-1)
    val canReauthenticate=status.optBoolean("canReauthenticate")
    val reason=status.optString("reason")
    val panelConfigured=status.optBoolean("controlPanelConfigured")
    LaunchedEffect(visible,generation,panelConfigured) {
        if(visible && panelConfigured)while(lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)) {
            val admitted=command("auth-admin-poll",generation.toString())?.getBoolean("admitted")==true
            delay(if(admitted)60_000 else 5_000)
        }
    }
    LaunchedEffect(visible,generation,revision,status.optBoolean("browserReady"),launchGeneration,launchAfterRevision) {
        if(visible && launchGeneration==generation && status.optBoolean("browserReady") &&
            (launchAfterRevision?.let {revision>it} ?: true)) {
            val url=command("auth-browser",generation.toString())?.getString("url")
            if(url!=null && launchGeneration==generation)runCatching {context.startActivity(Intent(Intent.ACTION_VIEW,url.toUri()).addCategory(Intent.CATEGORY_BROWSABLE))}
                .onFailure {message="Не удалось открыть браузер. Нажмите «Продолжить вход»."}
            launchGeneration=null;launchAfterRevision=null
        }
    }
    if(status.optBoolean("configured") || phase !in setOf("","SIGNED_OUT"))Column(verticalArrangement=Arrangement.spacedBy(8.dp)) {
        Text("Вход в SYN443",Modifier.testTag("auth-title"))
        if(phase=="INVITING" && status.optString("pairCode").isNotEmpty())Text("Код сверки с администратором: "+status.optString("pairCode"),Modifier.testTag("invite-pair-code"))
        Text(when(phase) {
            "SIGNED_OUT"->"Выполните вход через Keycloak"
            "RESERVED"->"Подготовка защищённого входа"
            "INVITING"->when(status.optString("inviteState")){"pending_approval"->"Ожидается подтверждение администратора";"provisioning"->"Подтверждено. Подготавливается конфигурация";else->"Ручная привязка устройства"}
            "BROWSER"->"Вход продолжается в браузере"
            "EXCHANGING","AUTHENTICATED","CLEANUP","ENROLLING"->"Проверка доступа и регистрация устройства"
            "PROVISIONING"->"Устройство зарегистрировано. Ожидается конфигурация от сервера."
            "POLICY_CACHED"->if(status.optJSONObject("assignedPolicy")?.let {it.optBoolean("candidateValidated") || it.optBoolean("runtimeAuthorized")}==true)
                "Конфигурация получена и проверена." else "Ожидаем действующую конфигурацию."
            "REFRESHING"->"Обновление защищённой сессии"
            "NEEDS_REAUTH"->when {
                canReauthenticate->"Войдите в тот же аккаунт Keycloak. Привязка устройства сохранится."
                status.optBoolean("registrationMayExist")->"Обратитесь к администратору, чтобы восстановить доступ к этому устройству."
                else->"Отмените незавершённый вход и начните его снова."
            }
            "RETIRING"->"Завершение сессии и удаление локальных ключей"
            else->"Данные входа недоступны. VPN заблокирован до восстановления."
        },Modifier.testTag("auth-phase"))
        if(reason.isNotEmpty() && (phase!="NEEDS_REAUTH" || canReauthenticate && reason!="SESSION_EXPIRED"))Text(when(reason) {
            "PENDING"->"Сервер ещё готовит конфигурацию."
            "TRANSPORT"->"Сервер управления недоступен. Проверьте сеть и повторите попытку."
            "ACCESS_DENIED"->"Доступ ограничен. Обратитесь к администратору."
            "SESSION_EXPIRED"->"Сессия истекла. Действующая офлайн-политика сохраняется до своего срока. Для обновления нужен вход."
            else->"Операция не завершена."
        })
        if(phase=="SIGNED_OUT")Button(enabled=!status.optBoolean("busy"),onClick={scope.launch {
            if(command("auth-start",generation.toString())?.getBoolean("ok")==true)launchGeneration=generation+1
            else message="Не удалось начать вход. Сначала остановите VPN."
        }},modifier=Modifier.testTag("auth-start")) {Text("Войти")}
        if(canReauthenticate && !vpnStopped)
            Text("Отключите VPN, чтобы открыть Keycloak. После входа подключите VPN снова.",Modifier.testTag("auth-reauth-stop-required"))
        if(canReauthenticate)Button(enabled=vpnStopped && !status.optBoolean("busy"),onClick={scope.launch {
            if(command("auth-reauth","$generation:$revision")?.getBoolean("ok")==true) {
                launchAfterRevision=revision;launchGeneration=generation;message=""
            } else message="Не удалось начать повторный вход. Повторите попытку."
        }},modifier=Modifier.testTag("auth-reauth")) {Text(if(phase=="BROWSER")"Начать вход заново" else "Войти снова через Keycloak")}
        if(phase=="BROWSER")Button(enabled=status.optBoolean("browserReady") && (!canReauthenticate || vpnStopped),onClick={
            launchAfterRevision=null;launchGeneration=generation
        },modifier=Modifier.testTag("auth-open")) {Text("Продолжить вход")}
        val awaitingPermit=needsForegroundRenewal(phase,reason,status.optJSONObject("assignedPolicy"))
        if(phase !in setOf("SIGNED_OUT","BLOCKED","BROWSER","NEEDS_REAUTH") && (phase!="POLICY_CACHED" || reason.isNotEmpty() || awaitingPermit))
            TextButton(enabled=!status.optBoolean("busy"),onClick={scope.launch {
            if(command("auth-retry",generation.toString())?.getBoolean("ok")!=true)message="Не удалось повторить операцию."
            else message=""
        }},modifier=Modifier.testTag("auth-retry")) {Text(if(awaitingPermit)"Обновить конфигурацию" else "Повторить")}
        AccountExitControls(visible, phase, generation, revision, status.optBoolean("registrationMayExist", true)) {
            launchGeneration=null
            launchAfterRevision=null
            scope.launch {
                val accepted=command("auth-reviewed-cancel","$generation:$revision")?.getBoolean("ok")==true
                message=if(accepted) "" else "Не удалось подтвердить выход. Проверьте текущее состояние и повторите попытку."
            }
        }
        if(status.optInt("cleanupPending")>0)Text("Очистка регистрации на сервере продолжится после нового входа в тот же аккаунт.")
        AdminEntryControls(phase in setOf("POLICY_CACHED","REFRESHING"),status.optBoolean("controlPanelAvailable"),
            status.optBoolean("busy")) {
            if(lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED))runCatching {
                context.startActivity(Intent(context,io.syn443.android.admin.AdminActivity::class.java))
            }.onFailure {message="Не удалось открыть администрирование."}
        }
        val telemetryEnabled=status.optBoolean("telemetryEnabled")
        if(status.optBoolean("telemetryAvailable") || telemetryEnabled) {
            Text("Техническая телеметрия помогает разбирать сбои VPN. Отправляются коды событий, состояние VPN, версия приложения и тип сети без истории сайтов, адресов и учётных данных. Сводка состояния доступна вашему администратору. Её можно отключить этой кнопкой.")
            Button(enabled=!status.optBoolean("busy"),onClick={scope.launch {
                val reply=command("auth-telemetry","$generation:${!telemetryEnabled}")
                if(reply?.getBoolean("ok")!=true)message="Не удалось изменить настройку телеметрии."
            }},modifier=Modifier.testTag("auth-technical-telemetry")) {
                Text(if(telemetryEnabled)"Отключить телеметрию" else "Разрешить телеметрию")
            }
        }
        if(message.isNotEmpty())Text(message)
    }
}

@Composable
internal fun AccountExitControls(
    visible:Boolean, phase:String, generation:Long, revision:Long, registrationMayExist:Boolean, onExit:()->Unit
) {
    if (!visible || generation < 0 || revision < 0 || phase in setOf("", "SIGNED_OUT", "RETIRING", "BLOCKED")) return
    var reviewing by remember(generation, revision, registrationMayExist) { mutableStateOf(false) }
    TextButton(
        onClick={ if (registrationMayExist) reviewing=true else onExit() },
        modifier=Modifier.testTag("auth-cancel")
    ) { Text(if (registrationMayExist) "Выйти и отвязать устройство" else "Отменить вход") }
    if (reviewing) AlertDialog(
        onDismissRequest={reviewing=false},
        title={Text("Отвязать это устройство?")},
        text={Text("VPN отключится. SYN443 удалит с телефона сессию и ключи этой привязки. Чтобы подключиться снова, потребуется зарегистрировать устройство.")},
        confirmButton={ TextButton(onClick={reviewing=false; onExit()}, modifier=Modifier.testTag("auth-confirm-unlink")) {
            Text("Отвязать устройство")
        } },
        dismissButton={ TextButton(onClick={reviewing=false}, modifier=Modifier.testTag("auth-keep-binding")) {
            Text("Оставить привязку")
        } }
    )
}
