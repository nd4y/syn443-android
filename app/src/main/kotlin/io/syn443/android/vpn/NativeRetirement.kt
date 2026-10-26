package io.syn443.android.vpn

import android.app.ActivityManager
import android.content.Context
import android.os.Process
import java.io.File
import java.io.RandomAccessFile

/** Used on the identity worker. Neither an Off label nor a released lock alone proves exit. */
internal object NativeRetirement {
    fun released(context:Context):Boolean = runCatching {
        fun alive()=checkNotNull(context.getSystemService(ActivityManager::class.java).runningAppProcesses)
            .any {it.uid==Process.myUid() && it.processName=="${context.packageName}:engine"}
        if(alive())return false
        RandomAccessFile(File(context.noBackupFilesDir,"engine-owner.lock"),"rw").use {file->
            file.channel.tryLock()?.use {!alive()} ?: false
        }
    }.getOrDefault(false)
}
