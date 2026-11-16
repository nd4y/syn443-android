package io.syn443.android.admin

import android.content.ContentResolver
import android.os.Bundle
import android.os.Looper
import android.os.SystemClock
import androidx.core.net.toUri
import io.syn443.policy.Canonical
import io.syn443.policy.Policy
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.*
import org.json.JSONObject
import java.util.UUID
import java.util.Locale

internal enum class AdminUiPhase { INITIALIZING, SIGNED_OUT, STARTING, BROWSER, AUTHENTICATED, REAUTHENTICATE, UNAVAILABLE }
internal data class AdminUiStatus(val generation:Long=0,val phase:AdminUiPhase=AdminUiPhase.INITIALIZING,
    val busy:Boolean=false,val reason:String="")
internal data class AdminDeviceRow(val id:String,val policyRevision:Long,val desiredRevision:Long,val report:String) {
    override fun toString()="AdminDeviceRow([redacted])"
}
internal data class AdminDevicesPage(val devices:List<AdminDeviceRow>,val next:String,val observedAtMs:Long) {
    override fun toString()="AdminDevicesPage([redacted])"
}
internal data class AdminDocument(val chunks:List<String>,val summary:String) {
    override fun toString()="AdminDocument([redacted])"
}
internal class AdminBrowserLaunch(val url:String,private val expiresAtElapsedMs:Long) {
    init {require(expiresAtElapsedMs>0)}
    fun fresh(now:Long)=now>=0 && now<expiresAtElapsedMs
    override fun toString()="AdminBrowserLaunch([redacted])"
}
internal enum class AdminReadAction(val wire:String) { DEVICES("devices"), CONFIGURATION("configuration"), RUNTIME("runtime") }
internal class AdminUiFailure(code:String):Exception("administrative_operation_failed") {
    val code=code.uppercase(Locale.ROOT)
}

internal fun adminErrorText(code:String)=when(code.uppercase(Locale.ROOT)) {
    "REAUTHENTICATE","SESSION_EXPIRED","ACCOUNT_CHANGED"->"Сессия завершена. Войдите как администратор снова."
    "ACCESS_DENIED"->"Недостаточно прав для этого действия."
    "BUSY"->"Другая операция ещё выполняется. Повторите попытку."
    "TRANSPORT"->"Сервер управления недоступен. Проверьте сеть и повторите попытку."
    "CANCELLED"->"Операция отменена."
    "BROWSER_UNAVAILABLE"->"Не удалось открыть браузер. Проверьте, что он установлен."
    else->"Данные временно недоступны. Обновите состояние и повторите попытку."
}

internal interface AdminUiBridge {
    suspend fun status():AdminUiStatus
    suspend fun login(generation:Long):Boolean
    suspend fun logout(generation:Long):Boolean
    suspend fun browser(generation:Long):AdminBrowserLaunch
    suspend fun callback(raw:String)
    suspend fun devices(generation:Long,after:String=""):AdminDevicesPage
    suspend fun document(generation:Long,action:AdminReadAction,target:String):AdminDocument
    suspend fun webPanel():String
}

/** All RPCs, UTF-8 decoding, JSON work and chunking stay on IO. No credential,
 * operation body or response is logged, persisted or put in an Activity extra. */
internal class ResolverAdminUiBridge(private val resolver:ContentResolver):AdminUiBridge {
    private val uri="content://io.syn443.control".toUri()
    private suspend fun rpc(method:String,arg:String?=null,extras:Bundle?=null):Bundle=withContext(Dispatchers.IO) {
        try {resolver.call(uri,method,arg,extras)?:throw AdminUiFailure("UNAVAILABLE")}
        catch(e:CancellationException){throw e}
        catch(e:AdminUiFailure){throw e}
        catch(_:Exception){throw AdminUiFailure("UNAVAILABLE")}
    }
    override suspend fun status():AdminUiStatus=withContext(Dispatchers.IO) {
        val raw=rpc("admin-status").getString("json")?:throw AdminUiFailure("UNAVAILABLE")
        require(raw.toByteArray(Charsets.UTF_8).size<=4096)
        val value=Canonical.parse(raw).jsonObject
        require(value.keys==setOf("generation","phase","busy","reason"))
        val generation=value.getValue("generation").jsonPrimitive.let {require(!it.isString);it.long}
        require(generation in 0..9_007_199_254_740_991L)
        val phase=value.getValue("phase").jsonPrimitive.let {require(it.isString);AdminUiPhase.valueOf(it.content)}
        val busy=value.getValue("busy").jsonPrimitive.let {require(!it.isString);it.boolean}
        val reason=value.getValue("reason").jsonPrimitive.let {require(it.isString && it.content.length<=64);it.content}
        AdminUiStatus(generation,phase,busy,reason)
    }
    override suspend fun login(generation:Long)=rpc("admin-login",generation.toString()).getBoolean("admitted")
    override suspend fun logout(generation:Long)=rpc("admin-logout",generation.toString()).getBoolean("admitted")
    override suspend fun browser(generation:Long):AdminBrowserLaunch=withContext(Dispatchers.IO) {
        val id=UUID.randomUUID().toString().replace("-","")
        val extras=Bundle().apply {putLong("generation",generation)}
        if(!rpc("admin-browser-start",id,extras).getBoolean("admitted")) {
            val current=status()
            throw AdminUiFailure(if(current.generation!=generation || current.phase!=AdminUiPhase.BROWSER)"REAUTHENTICATE" else "BUSY")
        }
        val started=SystemClock.elapsedRealtime()
        var launch:AdminBrowserLaunch?=null
        try {
            while(SystemClock.elapsedRealtime()-started in 0..29_999) {
                val reply=rpc("admin-browser-result",id,extras)
                val raw=reply.getString("json")?:throw AdminUiFailure("INVALID_REPLY")
                require(raw.toByteArray(Charsets.UTF_8).size<=4096)
                val meta=Canonical.parse(raw).jsonObject
                when(meta.getValue("state").jsonPrimitive.content) {
                    "pending"->delay(1000)
                    "done"->{
                        val url=reply.getString("url")?:throw AdminUiFailure("INVALID_REPLY")
                        val deadline=reply.get("expiresAtElapsedMs")
                        require(deadline is Long)
                        val now=SystemClock.elapsedRealtime()
                        require(deadline>now && deadline-now<=5000)
                        launch=AdminBrowserLaunch(AdminLoginBrowser.checked(url),deadline)
                        break
                    }
                    "failed"->throw AdminUiFailure(meta["reason"]?.jsonPrimitive?.content?:"UNAVAILABLE")
                    "gone"->throw AdminUiFailure("UNAVAILABLE")
                    else->throw AdminUiFailure("INVALID_REPLY")
                }
            }
        } finally {
            withContext(NonCancellable+Dispatchers.IO) {runCatching {rpc("admin-browser-cancel",id,extras)}}
        }
        val ready=launch?:throw AdminUiFailure("UNAVAILABLE")
        if(!ready.fresh(SystemClock.elapsedRealtime()))throw AdminUiFailure("UNAVAILABLE")
        ready
    }
    override suspend fun callback(raw:String) {
        require(raw.length in 1..8192)
        rpc("admin-callback",raw)
    }
    private suspend fun read(generation:Long,action:AdminReadAction,target:String):ByteArray {
        require(generation>=0 && (target.isEmpty() && action==AdminReadAction.DEVICES || AdminWire.id.matches(target)))
        val id=UUID.randomUUID().toString().replace("-","")
        val extras=Bundle().apply {putLong("generation",generation);putString("action",action.wire);putString("target",target)}
        val resultExtras=Bundle().apply {putLong("generation",generation)}
        if(!rpc("admin-read-start",id,extras).getBoolean("admitted")) {
            val current=status()
            throw AdminUiFailure(if(current.generation!=generation || current.phase!=AdminUiPhase.AUTHENTICATED)"REAUTHENTICATE" else "BUSY")
        }
        val started=SystemClock.elapsedRealtime()
        try {
            while(SystemClock.elapsedRealtime()-started in 0..59_999) {
                val reply=rpc("admin-read-result",id,resultExtras)
                val raw=reply.getString("json")?:throw AdminUiFailure("INVALID_REPLY")
                val meta=withContext(Dispatchers.IO) {
                    require(raw.toByteArray(Charsets.UTF_8).size<=4096)
                    Canonical.parse(raw).jsonObject
                }
                when(meta.getValue("state").jsonPrimitive.content) {
                    "pending"->delay(1000)
                    "done"->return (reply.getByteArray("body")?:throw AdminUiFailure("INVALID_REPLY")).also {
                        require(it.size in 1..AdminWire.MAX_BODY)
                    }
                    "failed"->throw AdminUiFailure(meta["reason"]?.jsonPrimitive?.content?:"UNAVAILABLE")
                    "gone"->{
                        val current=status()
                        throw AdminUiFailure(if(current.generation!=generation || current.phase!=AdminUiPhase.AUTHENTICATED)"REAUTHENTICATE" else "UNAVAILABLE")
                    }
                    else->throw AdminUiFailure("INVALID_REPLY")
                }
            }
            throw AdminUiFailure("UNAVAILABLE")
        } finally {
            withContext(NonCancellable+Dispatchers.IO) {runCatching {rpc("admin-read-cancel",id,resultExtras)}}
        }
    }
    override suspend fun devices(generation:Long,after:String)=withContext(Dispatchers.IO) {
        AdminWire.page(read(generation,AdminReadAction.DEVICES,after),after)
    }
    override suspend fun document(generation:Long,action:AdminReadAction,target:String)=withContext(Dispatchers.IO) {
        require(action!=AdminReadAction.DEVICES)
        AdminWire.document(read(generation,action,target),action,target)
    }
    override suspend fun webPanel():String=withContext(Dispatchers.IO) {
        // Ordinary device navigation has its own generation and server hint.
        // Never substitute the separate administrative session generation.
        fun generation(raw:String):Long=Canonical.parse(raw).jsonObject.getValue("generation").jsonPrimitive.long
        val captured=generation(rpc("auth-status").getString("json")?:throw AdminUiFailure("UNAVAILABLE"))
        require(captured>=0)
        fun url(reply:Bundle)=reply.getString("url").takeIf {reply.getBoolean("ok")}
        url(rpc("auth-admin-panel",captured.toString()))?.let {return@withContext it}
        rpc("auth-admin-poll",captured.toString())
        val started=SystemClock.elapsedRealtime()
        while(SystemClock.elapsedRealtime()-started in 0..59_999) {
            delay(1000)
            require(generation(rpc("auth-status").getString("json")?:throw AdminUiFailure("UNAVAILABLE"))==captured)
            url(rpc("auth-admin-panel",captured.toString()))?.let {return@withContext it}
        }
        throw AdminUiFailure("UNAVAILABLE")
    }
}

/** Presentation-only decoder. The controller/core independently validates API
 * authority and DTOs; this layer keeps raw configuration text intact. */
internal object AdminWire {
    const val MAX_BODY=524288
    val id=Regex("[A-Za-z0-9_-]{1,64}")
    private fun text(raw:ByteArray):String {
        check(Looper.myLooper()!=Looper.getMainLooper())
        require(raw.size in 1..MAX_BODY)
        return Policy.utf8(raw)
    }
    fun page(raw:ByteArray,after:String):AdminDevicesPage {
        val value=Canonical.parse(text(raw)).jsonObject
        require(value.keys==setOf("devices","next","observedAtMs"))
        fun number(value:JsonElement):Long=value.jsonPrimitive.let {require(!it.isString);it.long}.also {require(it in 0..9_007_199_254_740_991L)}
        val rows=value.getValue("devices").jsonArray
        require(rows.size<=32)
        val devices=rows.map {entry->
            val row=entry.jsonObject
            require(row.keys==setOf("device","policyRevision","desiredRevision","report"))
            val device=row.getValue("device").jsonPrimitive.let {require(it.isString);it.content}
            require(id.matches(device) && device>after)
            val report=row.getValue("report").jsonObject.getValue("state").jsonPrimitive.let {require(it.isString);it.content}
            val label=when(report) {
                "reported"->"Получен отчёт о применении"
                "historical"->"Исторический отчёт о применении"
                "awaiting_report"->"Ожидается отчёт о применении"
                "not_issued"->"Политика ещё не выдана"
                else->"Состояние применения неизвестно"
            }
            AdminDeviceRow(device,number(row.getValue("policyRevision")),number(row.getValue("desiredRevision")),label)
        }
        require(devices.map {it.id}.distinct().size==devices.size && devices.zipWithNext().all {it.first.id<it.second.id})
        val next=value.getValue("next").jsonPrimitive.let {require(it.isString);it.content}
        require(next.isEmpty() || devices.size==32 && next==devices.last().id)
        return AdminDevicesPage(devices.toList(),next,number(value.getValue("observedAtMs")))
    }
    fun document(raw:ByteArray,action:AdminReadAction,target:String):AdminDocument {
        require(action!=AdminReadAction.DEVICES && id.matches(target))
        val text=text(raw)
        val root=JSONObject(text)
        require(root.get("device") is String && root.getString("device")==target)
        val summary=if(action==AdminReadAction.CONFIGURATION)
            "Конфигурация сервера. Применение политики не подтверждает текущее соединение."
        else when(root.optString("state")) {
            "recent"->"Последний отчёт устройства: недавний. Текущее соединение не проверялось."
            "stale"->"Последний отчёт устройства устарел. Текущее состояние неизвестно."
            else->"Отчёт устройства отсутствует. Текущее состояние неизвестно."
        }
        val chunks=ArrayList<String>();var at=0
        while(at<text.length) {
            var end=minOf(at+2048,text.length)
            if(end<text.length && text[end-1].isHighSurrogate() && text[end].isLowSurrogate())end--
            chunks+=text.substring(at,end);at=end
        }
        require(chunks.size<=512)
        return AdminDocument(chunks.toList(),summary)
    }
}
