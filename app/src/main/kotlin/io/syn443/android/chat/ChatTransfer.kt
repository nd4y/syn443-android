package io.syn443.android.chat

import android.util.Base64
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.security.MessageDigest

object ChatTransfer {
    /** Caller persists the draft before sending. Retry uses the exact same IDs and bytes. */
    suspend fun send(client:ChatClient,store:ChatOutbox,id:String,progress:(String)->Unit):JSONObject {
        val draft=withContext(Dispatchers.IO) {requireNotNull(store.draft(id))}
        val attachments=JSONArray();val local=draft.getJSONArray("files")
        for(i in 0 until local.length()) {
            val info=local.getJSONObject(i);val request=JSONObject(info.toString()).apply {remove("localId");put("conversation",draft.getString("conversation"))}
            val status=client.objectCall("uploads/begin",request)
            val attachment=status.getJSONObject("attachment");val upload=attachment.getString("id")
            require(attachment.getString("sha256")==info.getString("sha256") && attachment.getLong("size")==info.getLong("size"))
            if(!status.getBoolean("complete")) {
                val present=status.getJSONArray("parts").let {a->(0 until a.length()).map {a.getInt(it)}.toSet()}
                val count=((info.getLong("size")+ChatLimits.chunk-1)/ChatLimits.chunk).toInt()
                for(part in 0 until count) {
                    if(part !in present) {
                        val bytes=withContext(Dispatchers.IO) {store.chunk(info.getString("localId"),part)}
                        client.call("uploads/part",JSONObject().put("upload",upload).put("part",part).put("data",Base64.encodeToString(bytes,Base64.NO_WRAP)).put("sha256",ChatLimits.hash(bytes)))
                    }
                    progress("Файл ${i+1}/${local.length()}: ${(part+1)*100/count}%")
                }
                client.call("uploads/complete",JSONObject().put("upload",upload))
            }
            attachments.put(upload)
        }
        val result=client.objectCall("send",JSONObject().put("conversation",draft.getString("conversation")).put("clientId",id).put("text",draft.getString("text")).put("attachments",attachments))
        withContext(Dispatchers.IO) {
            store.removeDraft(id)
            for(i in 0 until local.length())store.removeFile(local.getJSONObject(i).getString("localId"))
        }
        return result
    }
    suspend fun download(client:ChatClient,attachment:JSONObject,target:File,progress:(String)->Unit) {
        val size=attachment.getLong("size");require(size in 1..ChatLimits.file.toLong())
        val hash=MessageDigest.getInstance("SHA-256")
        try {withContext(Dispatchers.IO) {
            target.outputStream().use {out->
                val count=((size+ChatLimits.chunk-1)/ChatLimits.chunk).toInt()
                for(part in 0 until count) {
                    ensureActive()
                    val result=client.objectCall("download",JSONObject().put("attachment",attachment.getString("id")).put("part",part))
                    val data=Base64.decode(result.getString("data"),Base64.NO_WRAP)
                    require(data.size==minOf(ChatLimits.chunk.toLong(),size-part.toLong()*ChatLimits.chunk).toInt() && ChatLimits.hash(data)==result.getString("sha256"))
                    hash.update(data);out.write(data);withContext(Dispatchers.Main) {progress("Скачивание: ${(part+1)*100/count}%")}
                }
            }
            require(hash.digest().joinToString("") {"%02x".format(it)}==attachment.getString("sha256"))
        }} catch(e:Exception) {target.delete();throw e}
    }
}
