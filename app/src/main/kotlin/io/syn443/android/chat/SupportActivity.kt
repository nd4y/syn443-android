package io.syn443.android.chat

import android.content.Intent
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
    override fun onCreate(savedInstanceState:Bundle?) {super.onCreate(savedInstanceState)
        // Only private chat preparation files from an interrupted UI operation.
        // Durable drafts/parts live in the encrypted no-backup SQL store.
        lifecycleScope.launch {
            withContext(Dispatchers.IO) {cacheDir.listFiles()?.filter {it.isFile && it.name.startsWith("chat-") && (it.name.endsWith(".input") || it.name.endsWith(".output") || it.name.startsWith("chat-download-"))}?.take(256)?.forEach {it.delete()}}
            setContent {MaterialTheme(colorScheme=darkColorScheme()) {Surface(Modifier.fillMaxSize()) {SupportChat()}}}
        }
    }
}
private fun JSONArray.objects()=(0 until length()).map {getJSONObject(it)}
private fun chatError(e:Exception)=when((e as? ChatFailure)?.code) {
    "ACCOUNT_CHANGED","REAUTHENTICATE"->"Сессия завершена. Войдите снова."
    "ACCESS_DENIED"->"Нет доступа к этому диалогу."
    "THROTTLED"->"Сервер занят. Повторим через минуту."
    "BUSY"->"Клиент выполняет другую операцию. Повторим позже."
    "MEDIA_UNSUPPORTED"->"Не удалось сжать видео. Выберите другой файл или отправьте оригинал до 25 МБ."
    else->"Операция не завершена. Сообщение в очереди можно отправить повторно."
}

@Composable private fun SupportChat() {
    val context=LocalContext.current;val scope=rememberCoroutineScope();val mutex=remember {Mutex()}
    val lifecycle=(context as LifecycleOwner).lifecycle
    var visible by remember {mutableStateOf(lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED))}
    var operation by remember {mutableStateOf<Job?>(null)}
    var generation by remember {mutableStateOf(-1L)}
    var client by remember {mutableStateOf<ChatClient?>(null)}
    var store by remember {mutableStateOf<ChatOutbox?>(null)}
    var admin by remember {mutableStateOf(false)}
    var conversation by remember {mutableStateOf("")}
    var inbox by remember {mutableStateOf(emptyList<JSONObject>())}
    var messages by remember {mutableStateOf(emptyList<JSONObject>())}
    var peerRead by remember {mutableStateOf(0L)}
    var pending by remember {mutableStateOf(emptyList<Pair<String,JSONObject>>())}
    var text by remember {mutableStateOf("")}
    var files by remember {mutableStateOf(emptyList<JSONObject>())}
    var status by remember {mutableStateOf("Подключение к поддержке")}
    var nextAttempt by remember {mutableStateOf(0L)}
    var download by remember {mutableStateOf<JSONObject?>(null)}
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
                if(io.syn443.android.BuildConfig.DEBUG)android.util.Log.w("SYN443Chat","operation_failed/"+e.javaClass.simpleName)
                status=chatError(e);nextAttempt=android.os.SystemClock.elapsedRealtime()+60_000
            }
            finally {operation=null}
        }
    }
    suspend fun refresh(older:Boolean=false) {
        val api=client?:return
        if(conversation.isEmpty())return
        val request=JSONObject().put("conversation",conversation).put("before",if(older)messages.firstOrNull()?.getLong("sequence")?:0L else 0L).put("after",if(older)0L else messages.lastOrNull()?.getLong("sequence")?:0L)
        val response=api.objectCall("messages",request)
        messages=(messages+response.getJSONArray("messages").objects()).distinctBy {it.getString("id")}.sortedBy {it.getLong("sequence")}.takeLast(200)
        peerRead=response.getLong("peerRead")
        if(visible && !older && messages.isNotEmpty())api.call("read",JSONObject().put("conversation",conversation).put("sequence",messages.last().getLong("sequence")))
    }
    suspend fun sendPending(id:String) {
        val api=requireNotNull(client);val db=requireNotNull(store)
        ChatTransfer.send(api,db,id) {status=it}
        pending=withContext(Dispatchers.IO) {db.drafts()};status="Отправлено";refresh()
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
        val prepared=ChatMedia.prepare(context,uri,compress) {status=it}
        try {files=files+withContext(Dispatchers.IO) {
            val owner=currentCoroutineContext()
            requireNotNull(store).importFile(prepared.file,prepared.name,prepared.mime,prepared.kind) {owner.ensureActive()}
        }}
        finally {prepared.close()}
        status="Файл подготовлен"
    }}
    val document=rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) {uri->if(uri!=null)prepare(uri,false)}
    val media=rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) {uri->if(uri!=null)prepare(uri,true)}
    LaunchedEffect(visible) {
        if(visible)while(true) {
            try {mutex.withLock {
                val login=withContext(Dispatchers.IO) {JSONObject(context.contentResolver.call("content://io.syn443.control".toUri(),"auth-status",null,null)?.getString("json")?:"{}")}
                val next=login.optLong("generation",-1)
                if(login.optString("phase") !in setOf("PROVISIONING","POLICY_CACHED","REFRESHING")) {
                    generation= -1;client=null;store=null;messages=emptyList();inbox=emptyList();pending=emptyList();files=emptyList();text="";conversation="";admin=false
                    status="Для чата войдите в SYN443 на главном экране."
                } else {
                    if(generation!=next || client==null || store==null) {
                        messages=emptyList();conversation="";files=emptyList();text="";inbox=emptyList();pending=emptyList();admin=false
                        val opened=withContext(NonCancellable+Dispatchers.IO) {ChatOutbox(context,next)}
                        try {currentCoroutineContext().ensureActive()}
                        catch(e:CancellationException) {withContext(NonCancellable+Dispatchers.IO) {opened.close()};throw e}
                        store=opened;generation=next;client=ChatClient(context,next)
                    }
                    val own=requireNotNull(client).objectCall("self")
                    val permittedAdmin=own.getBoolean("admin")
                    if(admin && !permittedAdmin) {conversation="";messages=emptyList();inbox=emptyList();files=emptyList();text=""}
                    admin=permittedAdmin
                    if(!admin)conversation=own.getJSONObject("conversation").getString("id")
                    if(admin)inbox=(requireNotNull(client).call("inbox",JSONObject().put("before",0).put("beforeId","")) as JSONArray).objects()
                    refresh()
                    pending=withContext(Dispatchers.IO) {requireNotNull(store).drafts()}.filter {admin || it.second.getString("conversation")==conversation}
                    if(pending.isNotEmpty() && android.os.SystemClock.elapsedRealtime()>=nextAttempt) {
                        nextAttempt=android.os.SystemClock.elapsedRealtime()+30_000
                        sendPending(pending.first().first)
                    } else status=if(admin && conversation.isEmpty())"Выберите диалог" else "На связи"
                }
            }} catch(e:CancellationException) {throw e}
            catch(e:Exception) {status=chatError(e);nextAttempt=android.os.SystemClock.elapsedRealtime()+60_000}
            delay(10_000)
        }
    }
    Column(Modifier.fillMaxSize().safeDrawingPadding().imePadding().padding(16.dp),verticalArrangement=Arrangement.spacedBy(8.dp)) {
        Text("Чат с администратором",style=MaterialTheme.typography.headlineSmall,modifier=Modifier.testTag("chat-title"))
        Text(status,Modifier.testTag("chat-status"))
        Text("Сообщения доступны администраторам сервиса. Файлы до 25 МБ.",style=MaterialTheme.typography.bodySmall)
        if(admin) {
            Row(horizontalArrangement=Arrangement.spacedBy(8.dp)) {
                Button(onClick={conversation="";messages=emptyList()},enabled=!busy && text.isBlank() && files.isEmpty()) {Text("Все диалоги")}
                Text("Администратор")
            }
        }
        LazyColumn(Modifier.weight(1f).fillMaxWidth(),verticalArrangement=Arrangement.spacedBy(8.dp)) {
            if(admin && conversation.isEmpty()) {
                items(inbox,key={it.getString("id")}) {row->
                    Button(onClick={conversation=row.getString("id");messages=emptyList();run {refresh()}},enabled=!busy) {
                        Text("Пользователь ${row.getString("owner").take(10)}"+if(row.getLong("lastSeq")>row.getLong("readSeq"))" - новые сообщения" else "")
                    }
                }
                if(inbox.size>=50)item {Button(onClick={run {
                    val last=inbox.last();val more=(requireNotNull(client).call("inbox",JSONObject().put("before",last.getLong("updatedAt")).put("beforeId",last.getString("id"))) as JSONArray).objects()
                    inbox=(inbox+more).distinctBy {it.getString("id")}.take(200)
                }},enabled=!busy) {Text("Ещё диалоги")}}
            } else {
                if(messages.isNotEmpty())item {TextButton(onClick={run {refresh(true)}},enabled=!busy) {Text("Предыдущие сообщения")}}
                items(messages,key={it.getString("id")}) {msg->
                    Card(Modifier.fillMaxWidth()) {Column(Modifier.padding(12.dp)) {
                        Text(if(msg.getString("senderRole")=="admin")"Администратор" else "Пользователь",style=MaterialTheme.typography.labelMedium)
                        SelectionContainer {Text(msg.getString("text"))}
                        for(file in msg.getJSONArray("attachments").objects())TextButton(onClick={download=file;save.launch(file.getString("name"))},enabled=!busy) {Text("Сохранить: ${file.getString("name")} (${file.getLong("size")/1024} КБ)")}
                        Text(java.text.DateFormat.getDateTimeInstance(java.text.DateFormat.SHORT,java.text.DateFormat.SHORT).format(java.util.Date(msg.getLong("createdAt")*1000))+
                            if(msg.getLong("sequence")<=peerRead)" - прочитано" else "",style=MaterialTheme.typography.labelSmall)
                    }}
                }
            }
            items(pending,key={it.first}) {(id,draft)->
                Card {Column(Modifier.padding(8.dp)) {
                    Text("Ожидает отправки: ${draft.getString("text").take(80)}")
                    Row {TextButton(onClick={run {sendPending(id)}},enabled=!busy) {Text("Повторить")}
                        TextButton(onClick={run {withContext(Dispatchers.IO) {requireNotNull(store).removeDraft(id);for(file in draft.getJSONArray("files").objects())store!!.removeFile(file.getString("localId"))};pending=withContext(Dispatchers.IO) {store!!.drafts()}}},enabled=!busy) {Text("Удалить попытку")}}
                }}
            }
        }
        if(client!=null && conversation.isNotEmpty()) {
            for(file in files)TextButton(onClick={run {withContext(Dispatchers.IO) {store!!.removeFile(file.getString("localId"))};files=files-file}},enabled=!busy) {Text("${file.getString("name")} - убрать")}
            OutlinedTextField(text,{if(ChatLimits.text(it))text=it},label={Text("Сообщение")},maxLines=4,enabled=!busy,modifier=Modifier.fillMaxWidth().testTag("chat-text"))
            Row(horizontalArrangement=Arrangement.spacedBy(6.dp)) {
                TextButton(onClick={media.launch(arrayOf("image/*","video/*"))},enabled=!busy && files.size<4) {Text("Фото / видео")}
                TextButton(onClick={document.launch(arrayOf("*/*"))},enabled=!busy && files.size<4) {Text("Файл")}
                Button(onClick={run {
                    val id=ChatLimits.id();val draft=JSONObject().put("conversation",conversation).put("text",text).put("files",JSONArray(files))
                    withContext(Dispatchers.IO) {requireNotNull(store).saveDraft(id,draft)}
                    text="";files=emptyList();pending=withContext(Dispatchers.IO) {store!!.drafts()};sendPending(id)
                }},enabled=!busy && (text.isNotBlank() || files.isNotEmpty()),modifier=Modifier.testTag("chat-send")) {Text("Отправить")}
            }
        }
        if(busy)TextButton(onClick={operation?.cancel()}) {Text("Отменить операцию")}
    }
}
