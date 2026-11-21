package io.syn443.android.chat

import android.database.sqlite.SQLiteFullException
import android.system.ErrnoException
import android.system.OsConstants
import kotlinx.coroutines.CancellationException

internal enum class AttachmentProblem(val message: String) {
    STORAGE_FULL("На устройстве не хватает места. Освободите место и добавьте файл ещё раз."),
    UNSUPPORTED_MEDIA("Не удалось сжать видео. Выберите другой файл или отправьте оригинал до 25 МБ.");

    companion object {
        fun from(error: Throwable): AttachmentProblem? {
            if (error is CancellationException) return null
            var cause: Throwable? = error
            val seen = java.util.Collections.newSetFromMap(java.util.IdentityHashMap<Throwable, Boolean>())
            while (cause != null && seen.add(cause)) {
                if (cause is SQLiteFullException ||
                    cause is ErrnoException && (cause.errno == OsConstants.ENOSPC || cause.errno == OsConstants.EDQUOT) ||
                    cause is ChatFailure && cause.code == "MEDIA_STORAGE_FULL"
                ) return STORAGE_FULL
                cause = cause.cause
            }
            return if (error is ChatFailure && error.code == "MEDIA_UNSUPPORTED") UNSUPPORTED_MEDIA else null
        }
    }
}
