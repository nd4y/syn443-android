package io.syn443.android.admin

import android.os.Bundle
import android.os.SystemClock
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.LifecycleOwner
import io.syn443.android.vpn.AdminPanelBrowser
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

class AdminActivity:ComponentActivity() {
    override fun onCreate(savedInstanceState:Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {MaterialTheme(colorScheme=darkColorScheme()) {Surface(Modifier.fillMaxSize()) {
            val bridge=remember {ResolverAdminUiBridge(applicationContext.contentResolver)}
            AdminRoute(bridge)
        }}}
    }
}

/** Immutable RAM presentation only. No saved state contains privileged bodies. */
internal data class AdminUiModel(val status:AdminUiStatus=AdminUiStatus(),val working:Boolean=false,
    val page:AdminDevicesPage?=null,val after:String="",val selected:String="",
    val configuration:AdminDocument?=null,val runtime:AdminDocument?=null,
    val showConfiguration:Boolean=false,val showRuntime:Boolean=false,val message:String="") {
    override fun toString()="AdminUiModel([redacted])"
}
internal data class AdminUiActions(val login:()->Unit={},val browser:()->Unit={},val logout:()->Unit={},
    val refresh:()->Unit={},val page:(String)->Unit={},val select:(String)->Unit={},val web:()->Unit={},
    val toggleConfiguration:()->Unit={},val toggleRuntime:()->Unit={})

@Composable private fun AdminRoute(bridge:AdminUiBridge) {
    val context=LocalContext.current
    val lifecycle=(context as LifecycleOwner).lifecycle
    val scope=rememberCoroutineScope()
    val toolbar=MaterialTheme.colorScheme.surface.toArgb()
    val navigation=MaterialTheme.colorScheme.background.toArgb()
    var model by remember {mutableStateOf(AdminUiModel())}
    var visible by remember {mutableStateOf(lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED))}
    var operation by remember {mutableStateOf<Job?>(null)}
    var sequence by remember {mutableStateOf(0L)}
    fun current(ticket:Long,generation:Long?=null)=visible && sequence==ticket &&
        (generation==null || model.status.generation==generation)
    fun execute(cancelExisting:Boolean=false,block:suspend (Long)->Unit) {
        if(operation?.isActive==true && !cancelExisting)return
        if(cancelExisting)operation?.cancel()
        sequence++
        val ticket=sequence
        operation=scope.launch {
            model=model.copy(working=true,message="")
            try {block(ticket)}
            catch(e:CancellationException){throw e}
            catch(e:Exception) {if(current(ticket)) {
                val code=(e as? AdminUiFailure)?.code?:"UNAVAILABLE"
                model=if(code in setOf("REAUTHENTICATE","SESSION_EXPIRED","ACCOUNT_CHANGED"))
                    AdminUiModel(status=model.status.copy(phase=AdminUiPhase.REAUTHENTICATE,busy=false,reason=code),
                        working=true,message=adminErrorText(code))
                else if(model.status.phase==AdminUiPhase.INITIALIZING)
                    AdminUiModel(status=model.status.copy(phase=AdminUiPhase.UNAVAILABLE,busy=false),
                        working=true,message=adminErrorText(code))
                else model.copy(message=adminErrorText(code))
            }}
            finally {if(sequence==ticket){model=model.copy(working=false);operation=null}}
        }
    }
    suspend fun status(ticket:Long):AdminUiStatus {
        val next=bridge.status()
        if(!current(ticket))throw CancellationException()
        model=if(next.generation!=model.status.generation || next.phase!=AdminUiPhase.AUTHENTICATED)
            AdminUiModel(status=next,working=true)
        else model.copy(status=next)
        return next
    }
    suspend fun loadPage(ticket:Long,generation:Long,after:String) {
        val page=bridge.devices(generation,after)
        if(current(ticket,generation) && model.status.phase==AdminUiPhase.AUTHENTICATED)
            model=model.copy(page=page,after=after,selected="",configuration=null,runtime=null,
                showConfiguration=false,showRuntime=false)
    }
    suspend fun refresh(ticket:Long,load:Boolean=true) {
        val started=SystemClock.elapsedRealtime()
        var next=status(ticket)
        while(next.busy || next.phase in setOf(AdminUiPhase.INITIALIZING,AdminUiPhase.STARTING)) {
            if(SystemClock.elapsedRealtime()-started !in 0..59_999)throw AdminUiFailure("UNAVAILABLE")
            delay(1000)
            next=status(ticket)
        }
        if(load && next.phase==AdminUiPhase.AUTHENTICATED)loadPage(ticket,next.generation,"")
    }
    DisposableEffect(lifecycle) {
        val observer=LifecycleEventObserver {_,_->
            visible=lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)
            if(!visible) {
                sequence++;operation?.cancel();operation=null
                model=AdminUiModel(status=model.status)
            }
        }
        lifecycle.addObserver(observer)
        onDispose {sequence++;operation?.cancel();lifecycle.removeObserver(observer)}
    }
    LaunchedEffect(visible) {if(visible)execute {refresh(it)}}
    val actions=AdminUiActions(
        login={execute {ticket->
            val observed=status(ticket)
            if(!bridge.login(observed.generation))throw AdminUiFailure("BUSY")
            refresh(ticket)
        }},
        browser={val generation=model.status.generation;execute {ticket->
            val launch=bridge.browser(generation) // one fresh, one-use handoff per explicit tap.
            val observed=status(ticket)
            if(current(ticket,generation) && observed.phase==AdminUiPhase.BROWSER && !observed.busy) {
                if(!launch.fresh(SystemClock.elapsedRealtime()))throw AdminUiFailure("UNAVAILABLE")
                try {AdminLoginBrowser.open(context,launch,toolbar,navigation)}
                catch(_:Exception){throw AdminUiFailure("BROWSER_UNAVAILABLE")}
            } else throw AdminUiFailure("REAUTHENTICATE")
        }},
        logout={val generation=model.status.generation;execute(cancelExisting=true) {ticket->
            if(!bridge.logout(generation))throw AdminUiFailure("BUSY")
            refresh(ticket,load=false)
        }},
        refresh={execute {refresh(it)}},
        page={after->val generation=model.status.generation;execute {ticket->loadPage(ticket,generation,after)}},
        select={device->val generation=model.status.generation;execute {ticket->
            model=model.copy(selected=device,configuration=null,runtime=null,showConfiguration=false,showRuntime=false)
            val configuration=bridge.document(generation,AdminReadAction.CONFIGURATION,device)
            if(!current(ticket,generation))throw CancellationException()
            model=model.copy(configuration=configuration)
            val runtime=bridge.document(generation,AdminReadAction.RUNTIME,device)
            if(current(ticket,generation))model=model.copy(runtime=runtime)
        }},
        web={execute {ticket->
            val url=bridge.webPanel()
            if(current(ticket)) {
                try {AdminPanelBrowser.open(context,url,toolbar,navigation)}
                catch(_:Exception){throw AdminUiFailure("BROWSER_UNAVAILABLE")}
            }
        }},
        toggleConfiguration={model=model.copy(showConfiguration=!model.showConfiguration)},
        toggleRuntime={model=model.copy(showRuntime=!model.showRuntime)},
    )
    AdminScreen(model,actions)
}

@Composable internal fun AdminScreen(model:AdminUiModel,actions:AdminUiActions) {
    val status=model.status
    val busy=model.working || status.busy
    val authenticated=status.phase==AdminUiPhase.AUTHENTICATED
    LazyColumn(Modifier.fillMaxSize().safeDrawingPadding().padding(horizontal=20.dp).testTag("admin-content"),
        verticalArrangement=Arrangement.spacedBy(12.dp),contentPadding=PaddingValues(vertical=20.dp)) {
        item {Text("Администрирование",Modifier.testTag("admin-title"),style=MaterialTheme.typography.headlineMedium)}
        item {Text(when(status.phase) {
            AdminUiPhase.INITIALIZING->"Проверка административной сессии"
            AdminUiPhase.SIGNED_OUT->"Нужен отдельный вход администратора"
            AdminUiPhase.STARTING->"Подготовка защищённого входа"
            AdminUiPhase.BROWSER->"Завершите вход и подтверждение доступа в браузере"
            AdminUiPhase.AUTHENTICATED->"Административный вход подтверждён"
            AdminUiPhase.REAUTHENTICATE->"Административная сессия истекла. Войдите снова."
            AdminUiPhase.UNAVAILABLE->"Административная сессия недоступна"
        },Modifier.testTag("admin-status"))}
        if(status.phase in setOf(AdminUiPhase.SIGNED_OUT,AdminUiPhase.REAUTHENTICATE))
            item {Button(actions.login,enabled=!busy,modifier=Modifier.testTag("admin-login")) {Text("Войти как администратор")}}
        if(status.phase==AdminUiPhase.BROWSER)
            item {Button(actions.browser,enabled=!busy,modifier=Modifier.testTag("admin-browser")) {Text("Продолжить вход в браузере")}}
        if(status.phase !in setOf(AdminUiPhase.INITIALIZING,AdminUiPhase.SIGNED_OUT))
            item {TextButton(actions.logout,modifier=Modifier.testTag("admin-logout")) {Text("Выйти из административной сессии")}}
        item {Row(horizontalArrangement=Arrangement.spacedBy(8.dp)) {
            TextButton(actions.refresh,enabled=!model.working,modifier=Modifier.testTag("admin-refresh")) {Text("Обновить")}
            TextButton(actions.web,enabled=!busy,modifier=Modifier.testTag("admin-full-web")) {Text("Полная веб-панель")}
        }}
        if(busy)item {LinearProgressIndicator(Modifier.fillMaxWidth().testTag("admin-progress"))}
        if(model.message.isNotEmpty())item {Text(model.message,Modifier.testTag("admin-error"),color=MaterialTheme.colorScheme.error)}
        else if(status.reason.isNotEmpty())item {Text(adminErrorText(status.reason),Modifier.testTag("admin-reason"))}
        if(authenticated) {
            item {HorizontalDivider();Text("Доступные устройства",Modifier.testTag("admin-devices-title"),style=MaterialTheme.typography.titleLarge)}
            item {Text("Права проверяются сервером. Отчёт о применении политики не является проверкой соединения.")}
            if(model.page==null)item {Text("Список устройств ещё не загружен.",Modifier.testTag("admin-devices-unknown"))}
            else if(model.page.devices.isEmpty())item {Text("У вас нет доступных устройств.",Modifier.testTag("admin-devices-empty"))}
            items(model.page?.devices.orEmpty(),key={"device-"+it.id}) {device->
                OutlinedButton(onClick={actions.select(device.id)},enabled=!busy,modifier=Modifier.fillMaxWidth().testTag("admin-device-"+device.id)) {
                    Column(Modifier.fillMaxWidth(),verticalArrangement=Arrangement.spacedBy(4.dp)) {
                        Text(device.id,fontFamily=FontFamily.Monospace)
                        Text("Выданная политика: ${device.policyRevision}; желаемая ревизия: ${device.desiredRevision}")
                        Text(device.report)
                    }
                }
            }
            if(model.page!=null)item {Row(horizontalArrangement=Arrangement.spacedBy(8.dp)) {
                if(model.after.isNotEmpty())TextButton(onClick={actions.page("")},enabled=!busy,modifier=Modifier.testTag("admin-devices-first")) {Text("В начало списка")}
                if(model.page.next.isNotEmpty())Button(onClick={actions.page(model.page.next)},enabled=!busy,modifier=Modifier.testTag("admin-devices-next")) {Text("Следующие устройства")}
            }}
            if(model.selected.isNotEmpty()) {
                item {HorizontalDivider();Text("Устройство: "+model.selected,Modifier.testTag("admin-selected"),style=MaterialTheme.typography.titleMedium)}
                item {Text("Конфигурация",style=MaterialTheme.typography.titleMedium)}
                if(model.configuration==null)item {Text("Конфигурация ещё не получена.",Modifier.testTag("admin-config-unknown"))}
                else {
                    item {Text(model.configuration.summary,Modifier.testTag("admin-config-summary"))}
                    item {TextButton(actions.toggleConfiguration,modifier=Modifier.testTag("admin-config-toggle")) {Text(if(model.showConfiguration)"Скрыть конфигурацию" else "Показать конфигурацию целиком")}}
                    if(model.showConfiguration)itemsIndexed(model.configuration.chunks) {index,chunk->
                        SelectionContainer {Text(chunk,Modifier.testTag("admin-config-chunk-$index"),fontFamily=FontFamily.Monospace,style=MaterialTheme.typography.bodySmall)}
                    }
                }
                item {Text("Последний отчёт устройства",style=MaterialTheme.typography.titleMedium)}
                if(model.runtime==null)item {Text("Текущее состояние неизвестно: отчёт ещё не получен.",Modifier.testTag("admin-runtime-unknown"))}
                else {
                    item {Text(model.runtime.summary,Modifier.testTag("admin-runtime-summary"))}
                    item {TextButton(actions.toggleRuntime,modifier=Modifier.testTag("admin-runtime-toggle")) {Text(if(model.showRuntime)"Скрыть отчёт" else "Показать последний отчёт")}}
                    if(model.showRuntime)itemsIndexed(model.runtime.chunks) {index,chunk->
                        SelectionContainer {Text(chunk,Modifier.testTag("admin-runtime-chunk-$index"),fontFamily=FontFamily.Monospace,style=MaterialTheme.typography.bodySmall)}
                    }
                }
            }
        }
    }
}
