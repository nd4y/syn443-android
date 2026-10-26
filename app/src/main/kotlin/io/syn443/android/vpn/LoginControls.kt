package io.syn443.android.vpn

import android.content.Intent
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
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.LifecycleOwner
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject

@Composable fun LoginControls() {
    val context=LocalContext.current;val scope=rememberCoroutineScope()
    val uri=remember {"content://io.syn443.control".toUri()}
    var status by remember {mutableStateOf(JSONObject())}
    var message by remember {mutableStateOf("")}
    var launchGeneration by remember {mutableStateOf<Long?>(null)}
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
            delay(1000)
        }
    }
    val phase=status.optString("phase");val generation=status.optLong("generation",-1)
    LaunchedEffect(visible,generation,status.optBoolean("browserReady"),launchGeneration) {
        if(visible && launchGeneration==generation && status.optBoolean("browserReady")) {
            val url=command("auth-browser",generation.toString())?.getString("url")
            if(url!=null && launchGeneration==generation)runCatching {context.startActivity(Intent(Intent.ACTION_VIEW,url.toUri()).addCategory(Intent.CATEGORY_BROWSABLE))}
                .onFailure {message="Не удалось открыть браузер. Нажмите «Продолжить вход»."}
            launchGeneration=null
        }
    }
    if(status.optBoolean("configured") || phase !in setOf("","SIGNED_OUT"))Column(verticalArrangement=Arrangement.spacedBy(8.dp)) {
        Text("Вход в SYN443",Modifier.testTag("auth-title"))
        Text(when(phase) {
            "SIGNED_OUT"->"Выполните вход через Keycloak"
            "RESERVED"->"Подготовка защищённого входа"
            "BROWSER"->"Вход продолжается в браузере"
            "EXCHANGING","AUTHENTICATED","CLEANUP","ENROLLING"->"Проверка доступа и регистрация устройства"
            "PROVISIONING","POLICY_CACHED"->"Устройство зарегистрировано. Подключение выданной политики ещё не доступно в этой версии."
            "NEEDS_REAUTH"->"Нужен повторный вход. Завершите текущую сессию и войдите снова."
            "RETIRING"->"Завершение сессии и удаление локальных ключей"
            else->"Данные входа недоступны. VPN заблокирован до восстановления."
        },Modifier.testTag("auth-phase"))
        if(status.optString("reason").isNotEmpty())Text("Операция не завершена. Можно повторить попытку или завершить сессию.")
        if(phase=="SIGNED_OUT")Button(enabled=!status.optBoolean("busy"),onClick={scope.launch {
            if(command("auth-start",generation.toString())?.getBoolean("ok")==true)launchGeneration=generation+1
            else message="Не удалось начать вход. Сначала остановите VPN."
        }},modifier=Modifier.testTag("auth-start")) {Text("Войти")}
        if(phase=="BROWSER")Button(enabled=status.optBoolean("browserReady"),onClick={launchGeneration=generation},modifier=Modifier.testTag("auth-open")) {Text("Продолжить вход")}
        if(phase !in setOf("SIGNED_OUT","BLOCKED","BROWSER"))Button(enabled=!status.optBoolean("busy"),onClick={scope.launch {
            command("auth-retry",generation.toString())
        }},modifier=Modifier.testTag("auth-retry")) {Text("Повторить")}
        if(phase!="SIGNED_OUT")Button(onClick={launchGeneration=null;scope.launch {
            if(command("auth-cancel")?.getBoolean("ok")!=true)message="Завершение не подтверждено. Повторите попытку."
        }},modifier=Modifier.testTag("auth-cancel")) {Text("Завершить сессию")}
        if(status.optInt("cleanupPending")>0)Text("Очистка регистрации на сервере продолжится после нового входа в тот же аккаунт.")
        if(message.isNotEmpty())Text(message)
    }
}
