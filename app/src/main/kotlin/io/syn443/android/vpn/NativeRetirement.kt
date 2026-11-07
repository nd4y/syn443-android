package io.syn443.android.vpn

import android.app.ActivityManager
import android.content.Context
import android.os.Process
import java.io.File
import java.io.RandomAccessFile

/** Used on the identity worker. Neither an Off label nor a released lock alone proves exit. */
internal object NativeRetirement {
    fun released(context:Context):Boolean = withReleased(context){true}
    /** Hold the same lock through cleanup. Checking then releasing it before
     * deleting SDK keys would allow a newly created host to acquire them. */
    fun withReleased(context:Context,block:()->Boolean):Boolean = runCatching {
        fun alive()=checkNotNull(context.getSystemService(ActivityManager::class.java).runningAppProcesses)
            .any {it.uid==Process.myUid() && it.processName=="${context.packageName}:engine"}
        if(alive())return false
        RandomAccessFile(File(context.noBackupFilesDir,"engine-owner.lock"),"rw").use {file->
            file.channel.tryLock()?.use {if(alive())false else block() && !alive()} ?: false
        }
    }.getOrDefault(false)
}
