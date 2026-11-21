package io.syn443.android

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteFullException
import android.graphics.Bitmap
import android.system.ErrnoException
import android.system.OsConstants
import androidx.core.content.FileProvider
import androidx.test.core.app.ApplicationProvider
import io.syn443.android.chat.AttachmentProblem
import io.syn443.android.chat.ChatFailure
import io.syn443.android.chat.ChatLimits
import io.syn443.android.chat.ChatMedia
import io.syn443.android.chat.ChatOutbox
import java.io.File
import java.io.IOException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test

class AttachmentStorageFailureTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()

    private fun scratch() = context.cacheDir.listFiles().orEmpty()
        .filter { it.name.startsWith("chat-") && (it.extension == "input" || it.extension == "output") }.toSet()

    @Test fun failedWritePreservesSourceAndReleasesScratchBeforeRetry() = runBlocking {
        val dir = File(context.cacheDir, "chat-test").apply { mkdirs() }
        val source = File(dir, "source-${ChatLimits.id()}.jpg")
        try {
            val bitmap = Bitmap.createBitmap(24, 32, Bitmap.Config.ARGB_8888)
            try { source.outputStream().use { assertTrue(bitmap.compress(Bitmap.CompressFormat.JPEG, 90, it)) } }
            finally { bitmap.recycle() }
            val original = source.readBytes()
            val uri = FileProvider.getUriForFile(context, "io.syn443.chat.fixture", source)
            val before = scratch()
            val noSpace = IOException("synthetic write", ErrnoException("write", OsConstants.ENOSPC))
            val failed = runCatching { ChatMedia.prepare(context, uri, true) { throw noSpace }.use {} }.exceptionOrNull()
            assertSame(noSpace, failed)
            assertEquals(AttachmentProblem.STORAGE_FULL, AttachmentProblem.from(noSpace))
            assertEquals(before, scratch())
            // An unchecked failure also unwinds temporary ownership before it propagates.
            val abrupt = AssertionError("synthetic interrupted pipeline")
            assertSame(abrupt, runCatching { ChatMedia.prepare(context, uri, true) { throw abrupt }.use {} }.exceptionOrNull())
            assertEquals(before, scratch())
            ChatMedia.prepare(context, uri, true) {}.use { assertEquals("image/jpeg", it.mime); assertTrue(it.file.length() > 0) }
            assertArrayEquals(original, source.readBytes())
            assertEquals(before, scratch())
        } finally { source.delete() }
    }

    @Test fun boundedOutboxFullRollsBackPartialFileAndAllowsRetry() {
        val name = "test-${ChatLimits.id()}"
        val path = File(context.noBackupFilesDir, "$name.db")
        val source = File(context.cacheDir, "attachment-${ChatLimits.id()}.bin")
        val contents = ByteArray(ChatLimits.chunk + 17) { (it % 97).toByte() }
        try {
            source.writeBytes(contents)
            ChatOutbox(context, 7, name).use { outbox ->
                var calls = 0
                val full = SQLiteFullException("synthetic SQLITE_FULL")
                val result = runCatching {
                    outbox.importFile(source, "fixture.bin", "application/octet-stream", "file") {
                        // The third cancellation check follows the first encrypted chunk insert.
                        if (++calls == 3) throw full
                    }
                }
                assertSame(full, result.exceptionOrNull())
                assertEquals(AttachmentProblem.STORAGE_FULL, AttachmentProblem.from(full))
                SQLiteDatabase.openDatabase(path.path, null, SQLiteDatabase.OPEN_READONLY).use { read ->
                    for (table in listOf("files","chunks")) {
                        read.rawQuery("SELECT COUNT(*) FROM $table", null).use { rows ->
                            assertTrue(rows.moveToFirst()); assertEquals(0, rows.getInt(0))
                        }
                    }
                }
                val file = outbox.importFile(source, "fixture.bin", "application/octet-stream", "file")
                val id = file.getString("localId")
                assertArrayEquals(contents, outbox.chunk(id, 0) + outbox.chunk(id, 1))
                assertArrayEquals(contents, source.readBytes())
            }
        } finally {
            source.delete()
            ChatOutbox.erase(context, name)
            context.deleteDatabase(path.path)
        }
    }

    @Test fun localStorageAndUnsupportedCodecAreDistinctFromNetworkAndCancellation() {
        assertEquals(AttachmentProblem.STORAGE_FULL, AttachmentProblem.from(ErrnoException("write", OsConstants.EDQUOT)))
        assertEquals(AttachmentProblem.STORAGE_FULL, AttachmentProblem.from(ChatFailure("MEDIA_STORAGE_FULL")))
        assertEquals(AttachmentProblem.UNSUPPORTED_MEDIA, AttachmentProblem.from(ChatFailure("MEDIA_UNSUPPORTED")))
        assertNull(AttachmentProblem.from(IOException("untrusted text mentions ENOSPC")))
        assertNull(AttachmentProblem.from(CancellationException("cancel").apply { initCause(SQLiteFullException()) }))
    }
}
