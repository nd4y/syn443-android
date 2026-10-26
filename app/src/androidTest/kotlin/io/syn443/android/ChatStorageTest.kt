package io.syn443.android

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.media.ExifInterface
import androidx.core.content.FileProvider
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.syn443.android.chat.*
import kotlinx.coroutines.runBlocking
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.io.RandomAccessFile

@RunWith(AndroidJUnit4::class)
class ChatStorageTest {
    private val context=ApplicationProvider.getApplicationContext<Context>()
    private fun name()="test-"+ChatLimits.id()
    private inline fun fixture(block:(String)->Unit) {
        val name=name();try {block(name)} finally {ChatOutbox.erase(context,name);context.deleteDatabase(File(context.noBackupFilesDir,"$name.db").path)}
    }
    private fun draft()=JSONObject().put("conversation","a".repeat(32)).put("text","synthetic confidential message").put("files",JSONArray())
    @Test fun chatSqlOutboxPersistsCiphertextAndFencesAccountGeneration()=fixture {name->
        val id=ChatLimits.id()
        ChatOutbox(context,7,name).use {it.saveDraft(id,draft())}
        ChatOutbox(context,7,name).use {assertEquals(draft().toString(),it.draft(id).toString());assertEquals(1,it.drafts().size)}
        val bytes=File(context.noBackupFilesDir,"$name.db").readBytes().toString(Charsets.ISO_8859_1)
        assertFalse(bytes.contains("synthetic confidential"));assertFalse(bytes.contains("conversation"))
        ChatOutbox(context,8,name).use {assertTrue(it.drafts().isEmpty());assertNull(it.draft(id))}
        ChatOutbox(context,7,name).use {assertTrue(it.drafts().isEmpty())}
    }
    @Test fun chatSqlChunksPreserveTwentyFiveMiBAndRejectOversize()=fixture {name->
        val file=File(context.cacheDir,"chat-test-${ChatLimits.id()}")
        try {
            val part=ByteArray(ChatLimits.chunk) {(it%251).toByte()};file.outputStream().use {out->repeat(100) {out.write(part)}}
            ChatOutbox(context,1,name).use {store->
                val info=store.importFile(file,"synthetic.bin","application/octet-stream","file")
                assertEquals(ChatLimits.file.toLong(),info.getLong("size"))
                repeat(100) {assertArrayEquals(part,store.chunk(info.getString("localId"),it))}
                store.removeFile(info.getString("localId"));assertTrue(runCatching {store.chunk(info.getString("localId"),0)}.isFailure)
                RandomAccessFile(file,"rw").use {it.setLength(ChatLimits.file.toLong()+1)}
                assertTrue(runCatching {store.importFile(file,"large.bin","application/octet-stream","file")}.isFailure)
            }
        } finally {file.delete()}
    }
    @Test fun chatOutboxQuotaAndLogoutEraseTheOwnedKey()=fixture {name->
        val ids=List(8){ChatLimits.id()}
        ChatOutbox(context,1,name).use {store->
            ids.forEach {store.saveDraft(it,draft())};store.saveDraft(ids.first(),draft().put("text","updated"))
            assertTrue(runCatching {store.saveDraft(ChatLimits.id(),draft())}.isFailure)
            store.removeDraft(ids.first());assertEquals(7,store.drafts().size)
            ChatOutbox.erase(context,name);assertTrue(store.drafts().isEmpty())
            assertTrue(runCatching {store.saveDraft(ids.first(),draft())}.isFailure)
        }
    }
    @Test fun chatPhotoCompressionAppliesOrientationAndStripsGps()=runBlocking {
        val dir=File(context.cacheDir,"chat-test").apply {mkdirs()};val input=File(dir,"source-${ChatLimits.id()}.jpg")
        try {
            val bitmap=Bitmap.createBitmap(640,480,Bitmap.Config.ARGB_8888)
            try {bitmap.eraseColor(android.graphics.Color.BLUE);input.outputStream().use {bitmap.compress(Bitmap.CompressFormat.JPEG,95,it)}} finally {bitmap.recycle()}
            ExifInterface(input.path).apply {setAttribute(ExifInterface.TAG_ORIENTATION,"6");setAttribute(ExifInterface.TAG_GPS_LATITUDE,"0/1,6/1,0/1");setAttribute(ExifInterface.TAG_GPS_LATITUDE_REF,"N");saveAttributes()}
            ChatMedia.prepare(context,FileProvider.getUriForFile(context,"io.syn443.chat.fixture",input),true) {}.use {output->
                assertEquals("image/jpeg",output.mime);assertTrue(output.file.length() in 1..ChatLimits.file.toLong())
                val result=BitmapFactory.decodeFile(output.file.path);try {assertEquals(480,result.width);assertEquals(640,result.height)} finally {result.recycle()}
                assertNull(ExifInterface(output.file.path).getAttribute(ExifInterface.TAG_GPS_LATITUDE))
            }
        } finally {input.delete()}
    }
    @Test fun chatTextAndDocumentBoundariesDoNotAcceptInvalidMedia()=runBlocking {
        assertTrue(ChatLimits.text("😀".repeat(4096)));assertFalse(ChatLimits.text("😀".repeat(4097)));assertFalse(ChatLimits.text("bad\u0000text"))
        val dir=File(context.cacheDir,"chat-test").apply {mkdirs()};val input=File(dir,"bad-${ChatLimits.id()}.jpg")
        try {input.writeText("not an image");val uri=FileProvider.getUriForFile(context,"io.syn443.chat.fixture",input)
            assertTrue(runCatching {ChatMedia.prepare(context,uri,true) {}}.isFailure)
            ChatMedia.prepare(context,uri,false) {}.use {assertEquals("file",it.kind);assertEquals("not an image",it.file.readText())}
        } finally {input.delete()}
    }
}
