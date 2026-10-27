package io.syn443.android

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.media.ExifInterface
import androidx.core.content.FileProvider
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.syn443.android.chat.*
import kotlinx.coroutines.*
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
    @Test fun chatRestartReclaimsUnsentFilesButPreservesDraftAttachments()=fixture {name->
        val file=File(context.cacheDir,"chat-test-${ChatLimits.id()}").apply {writeText("synthetic document")}
        try {
            var kept="";var orphan=""
            ChatOutbox(context,1,name).use {store->
                val info=store.importFile(file,"kept.txt","text/plain","file");kept=info.getString("localId")
                orphan=store.importFile(file,"orphan.txt","text/plain","file").getString("localId")
                store.saveDraft(ChatLimits.id(),draft().put("files",JSONArray().put(info)))
            }
            ChatOutbox(context,1,name).use {store->
                assertEquals("synthetic document",store.chunk(kept,0).toString(Charsets.UTF_8))
                assertTrue(runCatching {store.chunk(orphan,0)}.isFailure)
            }
        } finally {file.delete()}
    }
    @Test fun chatCancelledImportRollsBackPartialSqlAndCanBeRetried()=fixture {name->
        val file=File(context.cacheDir,"chat-test-${ChatLimits.id()}").apply {writeBytes(ByteArray(ChatLimits.chunk*3){37})}
        try {ChatOutbox(context,1,name).use {store->
            var checks=0
            assertThrows(CancellationException::class.java) {store.importFile(file,"cancelled.bin","application/octet-stream","file") {if(++checks==3)throw CancellationException()}}
            val snapshot=File(context.noBackupFilesDir,"$name.db")
            android.database.sqlite.SQLiteDatabase.openDatabase(snapshot.path,null,android.database.sqlite.SQLiteDatabase.OPEN_READONLY).use {db->
                for(table in listOf("files","chunks"))db.rawQuery("SELECT count(*) FROM $table",null).use {c->c.moveToFirst();assertEquals(0,c.getInt(0))}
            }
            val info=store.importFile(file,"retry.bin","application/octet-stream","file")
            assertEquals(file.length(),info.getLong("size"));assertEquals(37,store.chunk(info.getString("localId"),2)[0].toInt())
        }} finally {file.delete()}
    }
    private fun videoFixture():File {
        val dir=File(context.cacheDir,"chat-test").apply {mkdirs()}
        return File(dir,"source-${ChatLimits.id()}.mp4").also {file->
            androidx.test.platform.app.InstrumentationRegistry.getInstrumentation().context.assets.open("chat-fixture.mp4").use {input->file.outputStream().use {input.copyTo(it)}}
        }
    }
    @Test fun chatVideoCompressionProducesBoundedMp4AndStripsLocation()=runBlocking {
        val input=videoFixture()
        try {
            ChatMedia.prepare(context,FileProvider.getUriForFile(context,"io.syn443.chat.fixture",input),true) {}.use {output->
                assertEquals("video/mp4",output.mime);assertEquals("video",output.kind)
                assertTrue(output.file.length() in 1..ChatLimits.file.toLong());assertTrue(output.file.length()<input.length())
                android.media.MediaMetadataRetriever().use {r->
                    r.setDataSource(output.file.path)
                    assertTrue(r.extractMetadata(android.media.MediaMetadataRetriever.METADATA_KEY_VIDEO_WIDTH)!!.toInt()<=1280)
                    assertTrue(r.extractMetadata(android.media.MediaMetadataRetriever.METADATA_KEY_VIDEO_HEIGHT)!!.toInt()<=720)
                    assertNull(r.extractMetadata(android.media.MediaMetadataRetriever.METADATA_KEY_LOCATION))
                }
                val extractor=android.media.MediaExtractor()
                try {
                    extractor.setDataSource(output.file.path)
                    val types=(0 until extractor.trackCount).map {extractor.getTrackFormat(it).getString(android.media.MediaFormat.KEY_MIME)}
                    assertTrue(types.contains("video/avc"));assertTrue(types.contains("audio/mp4a-latm"))
                } finally {extractor.release()}
            }
        } finally {input.delete()}
    }
    @Test fun chatCancellingActiveVideoExportRemovesPrivateTemporaryFiles()=runBlocking {
        val input=videoFixture()
        fun temporary()=context.cacheDir.listFiles().orEmpty().filter {it.name.startsWith("chat-") && (it.name.endsWith(".input") || it.name.endsWith(".output"))}.map {it.name}.toSet()
        val before=temporary();var started=false
        try {
            val job=launch {
                ChatMedia.prepare(context,FileProvider.getUriForFile(context,"io.syn443.chat.fixture",input),true) {value->
                    if(value.contains("0%")) {started=true;cancel()}
                }.close()
            }
            withTimeout(30_000) {job.join()};assertTrue(started);assertTrue(job.isCancelled);assertEquals(before,temporary())
        } finally {input.delete()}
    }
}
