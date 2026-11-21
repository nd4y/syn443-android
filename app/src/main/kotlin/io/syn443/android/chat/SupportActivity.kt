package io.syn443.android.chat

import android.content.Intent
import io.syn443.identity.ChatRefreshGate
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.ui.unit.dp
import androidx.core.net.toUri
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

class SupportActivity:ComponentActivity() {
    companion object { internal const val REPORT_PROBLEM = "io.syn443.reportProblem" }
    private var incidentRequested by mutableStateOf(false)

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        if (intent.getBooleanExtra(REPORT_PROBLEM, false)) incidentRequested = true
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putBoolean(REPORT_PROBLEM, incidentRequested)
    }

    override fun onCreate(savedInstanceState:Bundle?) {super.onCreate(savedInstanceState)
        incidentRequested = savedInstanceState?.getBoolean(REPORT_PROBLEM) ?: intent.getBooleanExtra(REPORT_PROBLEM, false)
        var prepared by mutableStateOf(false)
        // Install the root during onCreate. Cache preparation must not attach a
        // new Compose root later, after the resumed window has begun drawing.
        // Keep chat operations behind preparation so cleanup cannot delete a
        // file created by this instance of the screen.
        setContent {MaterialTheme(colorScheme=darkColorScheme()) {Surface(Modifier.fillMaxSize()) {
            if(prepared)SupportChat(incidentRequested) { incidentRequested = false }
            else Column(Modifier.fillMaxSize().safeDrawingPadding().padding(16.dp)) {
                Text("Подготовка чата",Modifier.testTag("chat-preparing"))
            }
        }}}
        // Only private chat preparation files from an interrupted UI operation.
        // Durable drafts/parts live in the encrypted no-backup SQL store.
        lifecycleScope.launch {
            withContext(Dispatchers.IO) {cacheDir.listFiles()?.filter {it.isFile && it.name.startsWith("chat-") && (it.name.endsWith(".input") || it.name.endsWith(".output") || it.name.startsWith("chat-download-"))}?.take(256)?.forEach {it.delete()}}
            prepared=true
        }
    }
}
private fun JSONArray.objects()=(0 until length()).map {getJSONObject(it)}
private fun chatCode(e:Exception):String = (e as? ChatFailure)?.code?.takeIf {it in setOf(
    "ACCOUNT_CHANGED","REAUTHENTICATE","SESSION_EXPIRED","ACCESS_DENIED","THROTTLED","BUSY",
    "MEDIA_UNSUPPORTED","TRANSPORT","INVALID_REPLY","UNAVAILABLE","CANCELLED","CONFLICT","PENDING",
)} ?: "UNAVAILABLE"
private fun chatError(e:Exception,queued:Boolean)=when(chatCode(e)) {
    "ACCOUNT_CHANGED","REAUTHENTICATE","SESSION_EXPIRED"->"Сессия завершена. Войдите снова."
    "ACCESS_DENIED"->"Нет доступа к этому диалогу."
    "THROTTLED"->"Сервер занят. Повторим подключение позже."
    "BUSY"->"Клиент выполняет другую операцию. Повторим позже."
    "MEDIA_UNSUPPORTED"->AttachmentProblem.UNSUPPORTED_MEDIA.message
    else->if(queued)"Сообщение сохранено на устройстве. Отправку можно повторить."
        else "Чат временно недоступен. Повторим подключение."
}
private fun refreshResult(e:Exception)=when(chatCode(e)) {
    "ACCOUNT_CHANGED","REAUTHENTICATE","SESSION_EXPIRED","ACCESS_DENIED"->ChatRefreshGate.Result.AUTHORITY_REQUIRED
    "THROTTLED"->ChatRefreshGate.Result.THROTTLED
    "BUSY"->ChatRefreshGate.Result.BUSY
    else->ChatRefreshGate.Result.TRANSIENT_FAILURE
}

@Composable private fun SupportChat(incidentRequested: Boolean, closeIncident: () -> Unit) {
    val context=LocalContext.current;val scope=rememberCoroutineScope();val mutex=remember {Mutex()}
    val lifecycle=(context as LifecycleOwner).lifecycle
    var visible by remember {mutableStateOf(lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED))}
    var operation by remember {mutableStateOf<Job?>(null)}
    var generation by remember {mutableStateOf(-1L)}
    var client by remember {mutableStateOf<ChatClient?>(null)}
    var store by remember {mutableStateOf<ChatOutbox?>(null)}
    var admin by remember {mutableStateOf(false)}
    var conversation by remember {mutableStateOf("")}
    var attachmentProblem by remember(generation, conversation) { mutableStateOf<AttachmentProblem?>(null) }
    var inbox by remember {mutableStateOf(ChatInboxWindow())}
    var messages by remember {mutableStateOf(ChatMessageWindow())}
    var peerRead by remember {mutableStateOf(0L)}
    var pending by remember {mutableStateOf(emptyList<Pair<String,JSONObject>>())}
    var text by remember { mutableStateOf(TextFieldValue()) }
    var files by remember {mutableStateOf(emptyList<JSONObject>())}
    var status by remember {mutableStateOf("Подключение к поддержке")}
    var nextAttempt by remember {mutableStateOf(0L)}
    var refreshGate by remember {mutableStateOf(ChatRefreshGate())}
    var refreshRunning by remember {mutableStateOf(false)}
    var connectionProblem by remember {mutableStateOf(false)}
    var manualRefresh by remember {mutableStateOf(false)}
    var refreshNonce by remember {mutableStateOf(0L)}
    var retryReady by remember {mutableStateOf(false)}
    var download by remember {mutableStateOf<JSONObject?>(null)}
    var incidentPreview by remember { mutableStateOf<SupportIncident?>(null) }
    var incidentOwner by remember { mutableStateOf(-1L) }
    var incidentError by remember { mutableStateOf<String?>(null) }
    var incidentNotice by remember(generation) { mutableStateOf("") }
    var unaddressed by remember(generation) { mutableStateOf(emptyList<String>()) }
    var incidentSaving by remember { mutableStateOf(false) }
    fun currentIncidentOwner(): Long {
        val auth = context.contentResolver.call("content://io.syn443.control".toUri(), "auth-status", null, null)
            ?.getString("json")?.let(::JSONObject) ?: return -1
        return if (auth.optString("phase") in setOf("PROVISIONING", "POLICY_CACHED", "REFRESHING"))
            auth.optLong("generation", -1) else -1
    }
    LaunchedEffect(incidentRequested) {
        incidentPreview = null
        incidentError = null
        incidentOwner = -1
        if (incidentRequested) {
            val (owner, report) = withContext(Dispatchers.IO) {
                val owner = runCatching(::currentIncidentOwner).getOrDefault(-1L)
                val status = runCatching { context.contentResolver.call("content://io.syn443.control".toUri(),
                    "status", null, null)?.getString("json")?.let(::JSONObject) }.getOrNull()
                owner to if (owner >= 0) SupportIncident.capture(status) else null
            }
            incidentOwner = owner
            incidentPreview = report
            if (owner < 0) incidentError = "Для обращения войдите в SYN443."
        }
    }
    val busy=operation?.isActive==true
    DisposableEffect(lifecycle) {
        val observer=LifecycleEventObserver {_,_->
            visible=lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)
            if(!visible)operation?.cancel()
        }
        lifecycle.addObserver(observer);onDispose {lifecycle.removeObserver(observer);operation?.cancel()}
    }
    LaunchedEffect(store) {
        val current=store
        try {awaitCancellation()}
        finally {withContext(NonCancellable+Dispatchers.IO) {current?.close()}}
    }
    fun run(block:suspend ()->Unit) {
        if(operation?.isActive==true)return
        operation=scope.launch {
            try {mutex.withLock {block()}}
            catch(e:CancellationException) {throw e}
            catch(e:Exception) {
                if(io.syn443.android.BuildConfig.DEBUG)android.util.Log.w("SYN443Chat","operation_failed/"+chatCode(e))
                status=chatError(e,pending.isNotEmpty());nextAttempt=android.os.SystemClock.elapsedRealtime()+60_000
            }
            finally {operation=null}
        }
    }
    fun selectConversation(id: String) {
        conversation = id
        messages = ChatMessageWindow()
        peerRead = 0L
        download = null
        pending = emptyList()
    }
    fun currentDrafts(drafts: List<Pair<String, JSONObject>>) = pendingInConversation(drafts,conversation)
    suspend fun refreshInbox(older: Boolean) {
        val api = client ?: return
        if (!admin || conversation.isNotEmpty()) return
        val previous = inbox
        val (before, beforeId) = previous.request(older) ?: return
        val query = JSONObject().put("before", before).put("beforeId", beforeId)
        val page = (api.call("inbox", query) as JSONArray).objects()
        if (api === client && admin && conversation.isEmpty() && previous === inbox)
            inbox = previous.accept(page, older)
    }
    suspend fun refresh(move: HistoryMove = HistoryMove.POLL) {
        val api=client?:return
        val id=conversation
        if(id.isEmpty())return
        val previous = messages
        loadChatMessagePage(id, previous, move,
            fetch = { api.objectCall("messages", it) },
            current = { client === api && conversation == id && messages === previous },
            visible = { visible },
            publish = { page, read -> messages = page; peerRead = read },
            acknowledge = { api.call("read", it) })
    }
    suspend fun sendPending(id:String) {
        val api=requireNotNull(client);val db=requireNotNull(store)
        val delivered = ChatTransfer.send(api,db,id) {status=it}
        if (incidentNotice.contains("SYN-" + id.take(12)) && delivered.opt("clientId") == id)
            incidentNotice = "Обращение SYN-" + id.take(12) + " доставлено."

        pending=currentDrafts(withContext(Dispatchers.IO) {db.drafts()})
        status="Отправлено";refresh()
    }
    val save=rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) {uri->
        val attachment=download;download=null
        if(uri!=null && attachment!=null)run {
            val temporary=File(context.cacheDir,"chat-download-${ChatLimits.id()}")
            try {
                ChatTransfer.download(requireNotNull(client),attachment,temporary) {status=it}
                withContext(Dispatchers.IO) {context.contentResolver.openOutputStream(uri,"wt").use {out->requireNotNull(out);temporary.inputStream().use {it.copyTo(out)}}}
                status="Файл сохранён"
            } finally {temporary.delete()}
        }
    }
    fun prepare(uri:android.net.Uri,compress:Boolean) {run {
        require(files.size<4)
        attachmentProblem = null
        val previousStatus = status
        val file = try {
            ChatMedia.prepare(context,uri,compress) {status=it}.use { prepared ->
                withContext(Dispatchers.IO) {
                    val owner = currentCoroutineContext()
                    requireNotNull(store).importFile(prepared.file,prepared.name,prepared.mime,prepared.kind) {owner.ensureActive()}
                }
            }
        } catch (cancelled: CancellationException) {
            status = previousStatus
            throw cancelled
        } catch (error: Exception) {
            attachmentProblem = AttachmentProblem.from(error) ?: throw error
            status = previousStatus
            return@run
        }
        files = files + file
        status="Файл подготовлен"
    }}
    val document=rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) {uri->if(uri!=null)prepare(uri,false)}
    val media=rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) {uri->if(uri!=null)prepare(uri,true)}
    LaunchedEffect(visible,refreshNonce) {
        if(visible)while(true) {
            try {mutex.withLock {
                val login=withContext(Dispatchers.IO) {JSONObject(context.contentResolver.call("content://io.syn443.control".toUri(),"auth-status",null,null)?.getString("json")?:"{}")}
                val next=login.optLong("generation",-1)
                if(login.optString("phase") !in setOf("PROVISIONING","POLICY_CACHED","REFRESHING")) {
                    generation= -1;client=null;store=null;selectConversation("");inbox=ChatInboxWindow();files=emptyList();text=TextFieldValue();admin=false
                    refreshGate=ChatRefreshGate();connectionProblem=false;manualRefresh=false
                    status="Для чата войдите в SYN443 на главном экране."
                } else {
                    if(generation!=next) {
                        selectConversation("");files=emptyList();text=TextFieldValue();inbox=ChatInboxWindow();admin=false
                        client=null;store=null;generation=next;refreshGate=ChatRefreshGate()
                    }
                    val gate=refreshGate
                    val ticket=gate.begin(android.os.SystemClock.elapsedRealtime(),manualRefresh)
                    manualRefresh=false
                    if(ticket!=null) {
                        refreshRunning=true
                        try {
                            if(client==null || store==null) {
                                val opened=withContext(NonCancellable+Dispatchers.IO) {ChatOutbox(context,next)}
                                try {currentCoroutineContext().ensureActive()}
                                catch(e:CancellationException) {withContext(NonCancellable+Dispatchers.IO) {opened.close()};throw e}
                                store=opened;client=ChatClient(context,next)
                            }
                            // Keep the generation-bound queue visible while the server is unavailable.
                            val local = withContext(Dispatchers.IO) { requireNotNull(store).drafts() }
                            unaddressed = local.filter { it.second.opt("incident") == true && it.second.opt("conversation") == "" }.map { it.first }
                            pending=currentDrafts(local)
                            val own=requireNotNull(client).objectCall("self")
                            val permittedAdmin=own.getBoolean("admin")
                            if(admin && !permittedAdmin) {selectConversation("");inbox=ChatInboxWindow();files=emptyList();text=TextFieldValue()}
                            admin=permittedAdmin
                            val ownId = own.getJSONObject("conversation").getString("id")
                            withContext(Dispatchers.IO) { requireNotNull(store).bindOwnIncidents(own) }
                            unaddressed = emptyList()
                            if(!admin)conversation=ownId
                            if(admin && conversation.isEmpty() && !inbox.historical) refreshInbox(false)
                            refresh()
                            val eligible=withContext(Dispatchers.IO) {requireNotNull(store).drafts()}.filter { (_, draft) ->
                                val target = draft.getString("conversation")
                                target.isNotEmpty() && if (draft.opt("incident") == true) target == ownId else admin || target == conversation
                            }
                            pending=currentDrafts(eligible)
                            if(eligible.isNotEmpty() && android.os.SystemClock.elapsedRealtime()>=nextAttempt) {
                                nextAttempt=android.os.SystemClock.elapsedRealtime()+30_000
                                sendPending(eligible.first().first)
                            } else status=if(admin && conversation.isEmpty())"Выберите диалог" else "На связи"
                            connectionProblem=false
                            gate.complete(ticket,ChatRefreshGate.Result.SUCCESS,android.os.SystemClock.elapsedRealtime())
                        } catch(e:CancellationException) {
                            gate.complete(ticket,ChatRefreshGate.Result.CANCELLED,android.os.SystemClock.elapsedRealtime());throw e
                        } catch(e:Exception) {
                            gate.complete(ticket,refreshResult(e),android.os.SystemClock.elapsedRealtime());throw e
                        } finally {refreshRunning=false}
                    }
                }
            }} catch(e:CancellationException) {throw e}
            catch(e:Exception) {
                if(io.syn443.android.BuildConfig.DEBUG)android.util.Log.w("SYN443Chat","refresh_failed/"+chatCode(e))
                connectionProblem=true;status=chatError(e,pending.isNotEmpty())
                nextAttempt=android.os.SystemClock.elapsedRealtime()+60_000
            }
            retryReady=refreshGate.manualReady(android.os.SystemClock.elapsedRealtime())
            delay(10_000)
        }
    }
    if (incidentRequested) {
        val sameOwner = incidentOwner >= 0 && generation == incidentOwner
        val db = store
        val report = incidentPreview
        IncidentPreview(report, incidentSaving,
            incidentError ?: if (incidentOwner >= 0 && generation >= 0 && !sameOwner) "Учётная запись изменилась." else null,
            canSubmit = sameOwner && db != null, submit = {
                if (!incidentSaving && sameOwner && db != null && report != null) {
                    val submittedOwner = incidentOwner
                    incidentSaving = true
                    scope.launch {
                        try {
                            withContext(Dispatchers.IO) {
                                check(currentIncidentOwner() == submittedOwner)
                                db.queueIncident(report)
                            }
                            if (generation == submittedOwner && db === store) {
                                unaddressed = (unaddressed + report.clientId).distinct()
                                incidentNotice = "Обращение SYN-" + report.clientId.take(12) +
                                    " сохранено. Чат отправит его при подключении."
                                closeIncident()
                                manualRefresh = true
                                refreshNonce++
                            }
                        } catch (cancelled: CancellationException) { throw cancelled }
                        catch (_: Exception) { incidentError = "Сохранить обращение не удалось. Попробуйте ещё раз." }
                        finally { incidentSaving = false }
                    }
                }
            }, dismiss = closeIncident)
    }
    Column(Modifier.fillMaxSize().safeDrawingPadding().imePadding().padding(16.dp),verticalArrangement=Arrangement.spacedBy(8.dp)) {
        Text("Чат с администратором",style=MaterialTheme.typography.headlineSmall,modifier=Modifier.testTag("chat-title"))
        Text(status,Modifier.testTag("chat-status"))
        if (incidentNotice.isNotEmpty()) Text(incidentNotice, Modifier.testTag("incident-queued"))
        for (id in unaddressed) {
            if (!incidentNotice.contains("SYN-" + id.take(12)))
                Text("Ожидает подключения - обращение SYN-" + id.take(12), Modifier.testTag("incident-offline"))
        }

        if(connectionProblem)TextButton(
            onClick={manualRefresh=true;refreshNonce++},
            enabled=retryReady && !busy && !refreshRunning,
            modifier=Modifier.testTag("chat-retry"),
        ) {Text("Повторить подключение")}
        Text("Сообщения доступны администраторам сервиса. Файлы до 25 МБ.",style=MaterialTheme.typography.bodySmall)
        if (visible && admin && conversation.isEmpty()) client?.let { api -> key(api) {
            AdminIncidentLookup { ref -> api.objectCall("incident/lookup", JSONObject().put("reference", ref)) }
        } }
        if(admin) {
            Row(horizontalArrangement=Arrangement.spacedBy(8.dp)) {
                Button(onClick={selectConversation(""); run { if (!inbox.historical) refreshInbox(false) }},
                    enabled=conversation.isNotEmpty() && !busy && !refreshRunning && text.text.isBlank() && text.composition == null && files.isEmpty()) {Text("Все диалоги")}
                Text("Администратор")
            }
        }
        LazyColumn(Modifier.weight(1f).fillMaxWidth(),verticalArrangement=Arrangement.spacedBy(8.dp)) {
            if(admin && conversation.isEmpty()) {
                if(inbox.historical)item {TextButton(onClick={run {refreshInbox(false)}},enabled=!busy && !refreshRunning) {Text("К началу списка диалогов")}}
                items(inbox.rows,key={it.getString("id")}) {row->
                    Button(onClick={selectConversation(row.getString("id"));run {refresh(HistoryMove.LATEST)}},enabled=!busy && !refreshRunning) {
                        Text("Пользователь ${row.getString("owner").take(10)}"+if(row.getLong("lastSeq")>row.getLong("readSeq"))" - новые сообщения" else "")
                    }
                }
                if(inbox.olderAvailable)item {Button(onClick={run {refreshInbox(true)}},enabled=!busy && !refreshRunning) {Text("Следующие диалоги")}}
            } else {
                if(messages.olderAvailable)item {TextButton(onClick={run {refresh(HistoryMove.OLDER)}},enabled=!busy && !refreshRunning) {Text("Предыдущие сообщения")}}
                items(messages.rows,key={it.getString("id")}) {msg->
                    Card(Modifier.fillMaxWidth()) {Column(Modifier.padding(12.dp)) {
                        Text(if(msg.getString("senderRole")=="admin")"Администратор" else "Пользователь",style=MaterialTheme.typography.labelMedium)
                        SelectionContainer {Text(msg.getString("text"))}
                        for(file in msg.getJSONArray("attachments").objects())TextButton(onClick={download=file;save.launch(file.getString("name"))},enabled=!busy) {Text("Сохранить: ${file.getString("name")} (${file.getLong("size")/1024} КБ)")}
                        Text(java.text.DateFormat.getDateTimeInstance(java.text.DateFormat.SHORT,java.text.DateFormat.SHORT).format(java.util.Date(msg.getLong("createdAt")*1000))+
                            if(msg.getLong("sequence")<=peerRead)" - прочитано" else "",style=MaterialTheme.typography.labelSmall)
                    }}
                }
                if(messages.newerAvailable)item {
                    ChatHistoryNavigation(enabled=!busy && !refreshRunning, onMove={move->run {refresh(move)}})
                }
            }
            items(pending,key={it.first}) {(id,draft)->
                Card {Column(Modifier.padding(8.dp)) {
                    Text("Ожидает отправки: ${draft.getString("text").take(80)}")
                    Row {TextButton(onClick={run {sendPending(id)}},enabled=!busy) {Text("Повторить")}
                        TextButton(onClick={run {withContext(Dispatchers.IO) {requireNotNull(store).removeDraft(id);for(file in draft.getJSONArray("files").objects())store!!.removeFile(file.getString("localId"))};pending=currentDrafts(withContext(Dispatchers.IO) {store!!.drafts()})}},enabled=!busy) {Text("Удалить попытку")}}
                }}
            }
        }
        if(client!=null && conversation.isNotEmpty()) {
            for(file in files)TextButton(onClick={run {withContext(Dispatchers.IO) {store!!.removeFile(file.getString("localId"))};files=files-file}},enabled=!busy) {Text("${file.getString("name")} - убрать")}
            attachmentProblem?.let { ChatAttachmentNotice(it) }
            ChatComposer(text, { text = it }, busy, files.size,
                pickMedia = { media.launch(arrayOf("image/*","video/*")) },
                pickDocument = { document.launch(arrayOf("*/*")) },
                send = { message ->
                    val selected = conversation
                    val owner = generation
                    val attachments = files.toList()
                    run {
                        if (conversation != selected || generation != owner || text.composition != null ||
                            text.text != message || files != attachments) return@run
                        val id = ChatLimits.id()
                        val draft = JSONObject().put("conversation",selected).put("text",message).put("files",JSONArray(attachments))
                        withContext(Dispatchers.IO) { requireNotNull(store).saveDraft(id,draft) }
                        text = TextFieldValue(); files = emptyList()
                        pending = currentDrafts(withContext(Dispatchers.IO) { requireNotNull(store).drafts() })
                        sendPending(id)
                    }
                })
        }
        if(busy || refreshRunning)TextButton(onClick={if(busy)operation?.cancel() else refreshNonce++}) {Text("Отменить операцию")}
    }
}

@Composable
internal fun ChatComposer(
    value: TextFieldValue, change: (TextFieldValue) -> Unit, busy: Boolean, fileCount: Int,
    pickMedia: () -> Unit, pickDocument: () -> Unit, send: (String) -> Unit,
) {
    val valid = ChatLimits.text(value.text)
    val composing = value.composition != null
    OutlinedTextField(
        value, { if (it.text.length <= ChatLimits.maxTextUnits) change(it) },
        label = { Text("Сообщение") }, maxLines = 4, enabled = !busy,
        isError = !composing && !valid,
        supportingText = if (!composing && !valid) {
            { Text("Проверьте символы и сократите сообщение до 4096 символов.") }
        } else null,
        modifier = Modifier.fillMaxWidth().testTag("chat-text"),
    )
    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
        TextButton(onClick = pickMedia, enabled = !busy && fileCount < 4) { Text("Фото / видео") }
        TextButton(onClick = pickDocument, enabled = !busy && fileCount < 4) { Text("Файл") }
        Button(
            onClick = { send(value.text) },
            enabled = !busy && !composing && valid && (value.text.isNotBlank() || fileCount > 0),
            modifier = Modifier.testTag("chat-send"),
        ) { Text("Отправить") }
    }
}

@Composable internal fun ChatAttachmentNotice(problem: AttachmentProblem) {
    Text(problem.message, color = MaterialTheme.colorScheme.error,
        modifier = Modifier.testTag("chat-attachment-problem").semantics { liveRegion = LiveRegionMode.Polite })
}

@Composable internal fun ChatHistoryNavigation(enabled: Boolean, onMove: (HistoryMove) -> Unit) {
    Column {
        TextButton(onClick = { onMove(HistoryMove.NEWER) }, enabled = enabled) { Text("Следующие сообщения") }
        TextButton(onClick = { onMove(HistoryMove.LATEST) }, enabled = enabled) { Text("К последним сообщениям") }
    }
}
