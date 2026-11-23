package io.syn443.android.admin

import io.syn443.android.Syn443Theme
import android.os.Bundle
import android.os.SystemClock
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalFocusManager
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
        setContent {Syn443Theme {Surface(Modifier.fillMaxSize()) {
            val bridge=remember {ResolverAdminUiBridge(applicationContext.contentResolver)}
            AdminRoute(bridge)
        }}}
    }
}

/** Immutable RAM presentation only. No saved state contains privileged bodies. */
internal data class AdminUiModel(val status:AdminUiStatus=AdminUiStatus(),val working:Boolean=false,
    val page:AdminDevicesPage?=null,val after:String="",val selected:String="",
    val configuration:AdminDocument?=null,val runtime:AdminDocument?=null,
    val showConfiguration:Boolean=false,val showRuntime:Boolean=false,val message:String="",val editor:AdminEditorModel?=null,
    val comparison:AdminComparisonModel?=null,val searchText:String="",val activePrefix:String="") {
    override fun toString()="AdminUiModel([redacted])"
}
internal data class AdminUiActions(val login:()->Unit={},val browser:()->Unit={},val logout:()->Unit={},
    val refresh:()->Unit={},val page:(String)->Unit={},val select:(String)->Unit={},val web:()->Unit={},
    val toggleConfiguration:()->Unit={},val toggleRuntime:()->Unit={},val edit:()->Unit={},
    val typePrefix:(String)->Unit={},val search:(String)->Unit={})

@Composable internal fun AdminRoute(bridge:AdminUiBridge) {
    val context=LocalContext.current
    val focusManager = LocalFocusManager.current
    val lifecycle=(context as LifecycleOwner).lifecycle
    val scope=rememberCoroutineScope()
    val toolbar=MaterialTheme.colorScheme.surface.toArgb()
    val navigation=MaterialTheme.colorScheme.background.toArgb()
    var model by remember {mutableStateOf(AdminUiModel())}
    var visible by remember(lifecycle, bridge) { mutableStateOf(false) }
    var foregroundSession by remember(lifecycle, bridge) { mutableLongStateOf(0L) }
    var operation by remember {mutableStateOf<Job?>(null)}
    var sequence by remember {mutableStateOf(0L)}
    fun current(ticket:Long,generation:Long?=null)=visible && sequence==ticket &&
        (generation==null || model.status.generation==generation)
    fun execute(cancelExisting:Boolean=false,block:suspend (Long)->Unit) {
        if (!visible || (operation?.isActive == true && !cancelExisting)) return
        if(cancelExisting)operation?.cancel()
        sequence++
        val ticket=sequence
        operation=scope.launch {
            model=model.copy(working=true,message="",editor=model.editor?.withBusy(true),comparison=model.comparison?.withBusy(true))
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
                else model.copy(message=adminErrorText(code),editor=model.editor?.withFailure(code),comparison=model.comparison?.withFailure(code))
            }}
            finally {if(sequence==ticket){model=model.copy(working=false,editor=model.editor?.withBusy(false),comparison=model.comparison?.withBusy(false));operation=null}}
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
    suspend fun loadPage(ticket:Long,generation:Long,after:String,prefix:String) {
        val page=bridge.devices(generation,after,prefix)
        if(current(ticket,generation) && model.status.phase==AdminUiPhase.AUTHENTICATED)
            model=model.copy(page=page,after=after,activePrefix=prefix,selected="",configuration=null,runtime=null,
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
        if(load && next.phase==AdminUiPhase.AUTHENTICATED)loadPage(ticket,next.generation,"",model.activePrefix)
    }
    DisposableEffect(lifecycle, bridge) {
        fun retireVisibleSession() {
            visible = false
            sequence++
            operation?.cancel()
            operation = null
            model = AdminUiModel(status = model.status)
        }

        val observer = LifecycleEventObserver { _, event ->
            when (event) {
                Lifecycle.Event.ON_START -> if (!visible) {
                    foregroundSession++
                    visible = true
                    // Reopen the inventory even when STOP and START occur between frames.
                    execute { ticket -> refresh(ticket) }
                }
                Lifecycle.Event.ON_STOP, Lifecycle.Event.ON_DESTROY -> if (visible) retireVisibleSession()
                else -> Unit
            }
        }
        lifecycle.addObserver(observer)
        onDispose {
            lifecycle.removeObserver(observer)
            retireVisibleSession()
        }
    }
    fun editCommand(kind:io.syn443.android.vpn.AdminEditorCoordinator.Kind,pages:List<String> = emptyList(),
        review:String="",deadline:Long=0,comparisonBinding:String="",operationBinding:String="") {
        val captured=model.editor?:return
        val generation=model.status.generation
        execute {ticket->
            val command=io.syn443.android.vpn.AdminEditorCoordinator.Command(kind,captured.device,captured.documentBinding,
                captured.localRevision,pages,review,deadline,comparisonBinding,operationBinding)
            val next=bridge.editor(generation,command)
            if(current(ticket,generation) && model.editor?.documentBinding==captured.documentBinding)
                model=model.copy(editor=if(kind==io.syn443.android.vpn.AdminEditorCoordinator.Kind.CLOSE && next.localRevision==0L)null else next,comparison=null)
        }
    }
    fun comparisonCommand(kind:io.syn443.android.vpn.AdminEditorCoordinator.ComparisonKind,
        section:AdminComparisonSection=AdminComparisonSection.CONFLICTS,offset:Int=0,row:String="",
        side:AdminComparisonSide=AdminComparisonSide.BASE,page:Int=0,choice:String="",binding:String?=null) {
        val captured=model.editor?:return
        val generation=model.status.generation
        val expected=binding ?:model.comparison?.binding ?:captured.comparisonBinding
        execute {ticket->
            val command=io.syn443.android.vpn.AdminEditorCoordinator.ComparisonCommand(kind,captured.device,captured.documentBinding,
                captured.localRevision,if(kind==io.syn443.android.vpn.AdminEditorCoordinator.ComparisonKind.LOAD)"" else expected,
                section,offset,row,side,page,choice)
            val next=bridge.comparison(generation,command)
            if(current(ticket,generation) && model.editor?.documentBinding==captured.documentBinding)model=model.copy(comparison=next)
        }
    }
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
        page={after->val generation=model.status.generation;val prefix=model.activePrefix
            execute {ticket->loadPage(ticket,generation,after,prefix)}},
        typePrefix={text->if(text.length<=64)model=model.copy(searchText=text)},
        search={prefix->
            if(prefix.isEmpty() || AdminWire.id.matches(prefix)) {
                focusManager.clearFocus()
                val generation=model.status.generation
                execute {ticket->
                    model=model.copy(searchText=prefix,activePrefix=prefix,after="",page=null,selected="",
                        configuration=null,runtime=null,showConfiguration=false,showRuntime=false)
                    loadPage(ticket,generation,"",prefix)
                }
            }
        },
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
        edit={val selected=model.selected;val generation=model.status.generation;execute {ticket->
            val next=bridge.editor(generation,io.syn443.android.vpn.AdminEditorCoordinator.Command(
                io.syn443.android.vpn.AdminEditorCoordinator.Kind.OPEN,device=selected))
            if(current(ticket,generation))model=model.copy(editor=next)
        }},
    )
    val editor=model.editor
    val comparison=model.comparison
    if (!visible) return
    if (editor == null) key(foregroundSession) {
        // A retained search field or lazy-list position belongs to the previous visit.
        AdminScreen(model, actions)
    }
    else if(comparison!=null)AdminComparisonScreen(comparison,AdminComparisonActions(
        page={section,offset->comparisonCommand(io.syn443.android.vpn.AdminEditorCoordinator.ComparisonKind.PAGE,section,offset)},
        detail={row,side,page->comparisonCommand(io.syn443.android.vpn.AdminEditorCoordinator.ComparisonKind.DETAIL,comparison.section,
            comparison.offset,row,side,page)},
        choose={row,choice->comparisonCommand(io.syn443.android.vpn.AdminEditorCoordinator.ComparisonKind.RESOLVE,comparison.section,
            comparison.offset,row,choice=choice)},
        apply={binding,revision->if(revision==model.editor?.localRevision)editCommand(io.syn443.android.vpn.AdminEditorCoordinator.Kind.REBASE,comparisonBinding=binding)},
        back={model=model.copy(comparison=null)},
        reload={comparisonCommand(io.syn443.android.vpn.AdminEditorCoordinator.ComparisonKind.LOAD)},web=actions.web))
    else AdminEditorScreen(editor,AdminEditorActions(
        saveLocal={editCommand(io.syn443.android.vpn.AdminEditorCoordinator.Kind.SAVE_LOCAL,it)},
        saveDraft={editCommand(io.syn443.android.vpn.AdminEditorCoordinator.Kind.SAVE_DRAFT)},
        preview={editCommand(io.syn443.android.vpn.AdminEditorCoordinator.Kind.PREVIEW)},
        publish={binding,deadline->editCommand(io.syn443.android.vpn.AdminEditorCoordinator.Kind.PUBLISH,review=binding,deadline=deadline)},
        poll={editCommand(io.syn443.android.vpn.AdminEditorCoordinator.Kind.POLL)},
        retryExact={editCommand(io.syn443.android.vpn.AdminEditorCoordinator.Kind.RETRY_EXACT)},
        checkOutcome={editCommand(io.syn443.android.vpn.AdminEditorCoordinator.Kind.CHECK_OUTCOME,operationBinding=model.editor?.operationBinding?:"")},
        sealPending={binding->editCommand(io.syn443.android.vpn.AdminEditorCoordinator.Kind.SEAL_PENDING,operationBinding=binding)},
        comparison={comparisonCommand(io.syn443.android.vpn.AdminEditorCoordinator.ComparisonKind.LOAD)},
        rebase={comparisonCommand(io.syn443.android.vpn.AdminEditorCoordinator.ComparisonKind.LOAD)},
        viewComparison={comparisonCommand(io.syn443.android.vpn.AdminEditorCoordinator.ComparisonKind.PAGE,
            section=AdminComparisonSection.DIFF,binding=editor.comparisonBinding)},
        login={val generation=model.status.generation;model=model.copy(editor=null);execute {ticket->
            if(!bridge.logout(generation))throw AdminUiFailure("BUSY")
            refresh(ticket,load=false)
            val observed=status(ticket)
            if(!bridge.login(observed.generation))throw AdminUiFailure("BUSY")
            refresh(ticket)
        }},
        web=actions.web,back={model=model.copy(editor=null,comparison=null)},close={editCommand(io.syn443.android.vpn.AdminEditorCoordinator.Kind.CLOSE)}))
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
            item {Text("Показаны последние полученные данные. Для нового чтения нажмите «Обновить». Права проверяются сервером. Отчёт о применении политики не является проверкой соединения.")}
            item {
                OutlinedTextField(model.searchText,actions.typePrefix,singleLine=true,enabled=!busy,
                    keyboardOptions=KeyboardOptions(keyboardType=KeyboardType.Ascii,imeAction=ImeAction.Search),
                    keyboardActions=KeyboardActions(onSearch={
                        if(!busy && AdminWire.id.matches(model.searchText))actions.search(model.searchText)
                    }),label={Text("Начало ID устройства")},modifier=Modifier.fillMaxWidth().testTag("admin-prefix"))
                Row(horizontalArrangement=Arrangement.spacedBy(8.dp)) {
                    Button(onClick={actions.search(model.searchText)},enabled=!busy && AdminWire.id.matches(model.searchText),
                        modifier=Modifier.testTag("admin-search")) {Text("Найти")}
                    if(model.activePrefix.isNotEmpty() || model.searchText.isNotEmpty())
                        TextButton(onClick={actions.search("")},enabled=!busy,modifier=Modifier.testTag("admin-search-reset")) {
                            Text("Все устройства")
                        }
                }
                if(model.activePrefix.isNotEmpty())Text("Поиск по началу ID «${model.activePrefix}»")
            }
            if(model.page==null)item {Text("Список устройств ещё не загружен.",Modifier.testTag("admin-devices-unknown"))}
            else if(model.page.devices.isEmpty())item {Text(if(model.activePrefix.isEmpty())"У вас нет доступных устройств." else "Совпадений среди доступных устройств нет.",Modifier.testTag("admin-devices-empty"))}
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
                item {OutlinedButton(actions.edit,enabled=!busy,modifier=Modifier.testTag("admin-edit-configuration")) {Text("Редактировать конфигурацию")}}
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
