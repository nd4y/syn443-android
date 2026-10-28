package io.syn443.android.chat

import android.content.Context
import android.os.Bundle
import androidx.core.net.toUri
import kotlinx.coroutines.*
import org.json.JSONObject
import org.json.JSONTokener
import java.security.MessageDigest
import java.util.UUID

class ChatFailure(val code:String):Exception(code)
object ChatLimits {
    const val file=25*1024*1024
    const val chunk=256*1024
    fun id()=UUID.randomUUID().toString().replace("-","")
    fun hash(bytes:ByteArray)=MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") {"%02x".format(it)}
    fun text(value:String):Boolean=value.codePointCount(0,value.length)<=4096 && value.toByteArray().size<=16384 && '\u0000' !in value
}

/** No credentials cross Binder. Cancellation closes only this operation, never the VPN. */
class ChatClient(private val context:Context,val generation:Long) {
    private val endpoint="content://io.syn443.control".toUri()
    suspend fun call(action:String,body:JSONObject=JSONObject()):Any=withContext(Dispatchers.IO) {
        val id=ChatLimits.id();val args=Bundle().apply {putLong("generation",generation);putString("action",action);putString("body",body.toString())}
        try {
            if(context.contentResolver.call(endpoint,"chat-start",id,args)?.getBoolean("ok")!=true)throw ChatFailure("BUSY")
            withTimeout(55_000) {
                while(true) {
                    ensureActive()
                    val raw=context.contentResolver.call(endpoint,"chat-result",id,args)?.getString("json")?:throw ChatFailure("UNAVAILABLE")
                    val result=JSONObject(raw)
                    when(result.getString("state")) {
                        "done"->return@withTimeout JSONTokener(result.getString("body")).nextValue()
                        "failed"->throw ChatFailure(result.getString("reason"))
                        "gone"->throw ChatFailure("ACCOUNT_CHANGED")
                    }
                    delay(80)
                }
                @Suppress("UNREACHABLE_CODE") Unit
            }
        } finally {withContext(NonCancellable) {runCatching {context.contentResolver.call(endpoint,"chat-cancel",id,null)}}}
    }
    suspend fun objectCall(action:String,body:JSONObject=JSONObject())=call(action,body) as JSONObject
}
