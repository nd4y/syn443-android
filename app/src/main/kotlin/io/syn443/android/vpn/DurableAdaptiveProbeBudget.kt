package io.syn443.android.vpn

import android.content.Context
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.provider.Settings
import android.system.Os
import android.system.OsConstants
import android.util.AtomicFile
import io.syn443.android.BuildConfig
import io.syn443.decision.AdaptiveProbeBudget
import io.syn443.decision.Decision
import io.syn443.policy.Canonical
import io.syn443.policy.Policy
import kotlinx.serialization.json.*
import java.io.File
import java.io.FileOutputStream
import java.nio.channels.FileChannel
import java.nio.channels.FileLock
import java.nio.file.Files
import java.util.concurrent.ArrayBlockingQueue

/** A single lifetime actor owns both disk and the mutable budget. There is no
 * worker replacement, polling, timer, reset, route identity or network I/O. */
internal class DurableAdaptiveProbeBudget private constructor(
    private val context:Context,private val mainHandler:Handler,private val test:TestOptions?
):AdaptiveStartAdmission {
    constructor(context:Context,mainHandler:Handler):this(context.applicationContext,mainHandler,null)

    internal enum class IoStage { BEFORE_FILE_SYNC, BEFORE_DIRECTORY_SYNC, BEFORE_READBACK }
    private class TestOptions(val namespace:String,val clock:()->Long,val bootCount:()->Int,val io:(IoStage)->Unit)
    private data class Envelope(val bootCount:Int,val checkpoint:AdaptiveProbeBudget.Checkpoint)
    private data class Preview(val checkpoint:AdaptiveProbeBudget.Checkpoint?=null,val storageFailed:Boolean=false)
    private data class Request(val routine:Boolean,val callback:(AdaptiveStartAdmission.Result)->Unit)
    init {require(mainHandler.looper==Looper.getMainLooper())}
    private val guard=Any()
    private val requests=ArrayBlockingQueue<Request>(1)
    @Volatile private var preview=Preview()
    @Volatile private var busy=true
    @Volatile private var closing=false
    private val worker=Thread(::runActor,"syn443-adaptive-admission").apply {isDaemon=true;start()}

    companion object {
        private const val LIMIT=16_384
        private val testNamespace=Regex("test-[a-f0-9]{32}")
        // Avoid opening a second descriptor for the same file in this JVM:
        // closing it can release another channel's process-scoped OS lock.
        private val processOwners=HashSet<String>()
        internal fun isolatedForTest(context:Context,namespace:String,mainHandler:Handler,
            clock:()->Long,bootCount:()->Int,io:(IoStage)->Unit={}):DurableAdaptiveProbeBudget {
            require(BuildConfig.DEBUG && testNamespace.matches(namespace))
            return DurableAdaptiveProbeBudget(context,mainHandler,TestOptions(namespace,clock,bootCount,io))
        }
        private fun workerOnly() {
            check(Looper.myLooper()!=Looper.getMainLooper() && !Thread.currentThread().name.startsWith("Binder:"))
        }
        private fun integer(value:JsonElement):Long {
            val primitive=value.jsonPrimitive
            require(!primitive.isString)
            return requireNotNull(primitive.longOrNull)
        }
        private fun boolean(value:JsonElement):Boolean {
            val primitive=value.jsonPrimitive
            require(!primitive.isString)
            return requireNotNull(primitive.booleanOrNull)
        }
        private fun decode(bytes:ByteArray):Envelope {
            require(bytes.size in 1..LIMIT)
            val root=Canonical.parse(Policy.utf8(bytes)).jsonObject
            require(root.keys==setOf("version","bootCount","checkpoint") && integer(root.getValue("version"))==1L)
            val boot=integer(root.getValue("bootCount"));require(boot in 0..Int.MAX_VALUE.toLong())
            val cp=root.getValue("checkpoint").jsonObject
            require(cp.keys==setOf("observedAtMs","clockSealed","entries"))
            val entries=cp.getValue("entries").jsonArray.map {raw->
                val entry=raw.jsonObject;require(entry.keys==setOf("ageMs","routine"))
                AdaptiveProbeBudget.Entry(integer(entry.getValue("ageMs")),boolean(entry.getValue("routine")))
            }
            return Envelope(boot.toInt(),AdaptiveProbeBudget.Checkpoint(integer(cp.getValue("observedAtMs")),
                boolean(cp.getValue("clockSealed")),entries))
        }
        private fun encode(value:Envelope):ByteArray=Canonical.encode(buildJsonObject {
            put("version",1);put("bootCount",value.bootCount)
            put("checkpoint",buildJsonObject {
                put("observedAtMs",value.checkpoint.observedAtMs);put("clockSealed",value.checkpoint.clockSealed)
                put("entries",buildJsonArray {value.checkpoint.entries.forEach {entry->add(buildJsonObject {
                    put("ageMs",entry.ageMs);put("routine",entry.routine)
                })}})
            })
        }).toByteArray(Charsets.UTF_8).also {require(it.size in 1..LIMIT)}
    }

    private fun clock()=test?.clock?.invoke() ?: SystemClock.elapsedRealtime()
    private fun bootCount():Int {
        workerOnly()
        return (test?.bootCount?.invoke() ?: Settings.Global.getInt(context.contentResolver,Settings.Global.BOOT_COUNT,-1))
            .also {require(it>=0)}
    }
    override fun canStart(nowMs:Long,routine:Boolean):Boolean {
        val saved=preview
        if(closing || busy || saved.storageFailed || saved.checkpoint==null)return false
        return try {AdaptiveProbeBudget.restore(saved.checkpoint,nowMs,true).canStart(nowMs,routine)}catch(_:Exception){false}
    }
    override fun invalidated()=preview.checkpoint?.clockSealed==true
    override fun currentTimeMs()=clock()
    override fun routineCadence(groupCount:Int)=AdaptiveProbeBudget().routineCadence(groupCount)
    override fun request(nowMs:Long,routine:Boolean,callback:(AdaptiveStartAdmission.Result)->Unit):Boolean=synchronized(guard) {
        if(nowMs !in 0..Decision.MAX_TIME || closing || busy || preview.storageFailed || preview.checkpoint==null)return@synchronized false
        busy=true
        if(!requests.offer(Request(routine,callback))) {busy=false;return@synchronized false}
        true
    }

    private fun deliver(request:Request,committed:Boolean,observedAt:Long,latest:Long) {
        mainHandler.post {
            val actual=try {clock()}catch(_:Exception){-1L}
            val allowed=committed && !closing && !preview.storageFailed && !invalidated() &&
                actual in observedAt..latest && actual in 0..Decision.MAX_TIME
            try {request.callback(AdaptiveStartAdmission.Result(allowed,actual,latest))}catch(_:Exception) { /* No retry or effect. */ }
        }
    }
    private fun runActor() {
        workerOnly()
        var storage:Store?=null
        var budget:AdaptiveProbeBudget?=null
        try {
            val boot=bootCount();val now=clock()
            storage=Store();val saved=storage.load()
            val live=AdaptiveProbeBudget.restore(saved?.checkpoint ?: AdaptiveProbeBudget().checkpoint(),now,
                saved!=null && saved.bootCount==boot)
            budget=live
            val cp=live.checkpoint();preview=Preview(cp)
            if(saved==null || saved.bootCount!=boot || cp.clockSealed && !saved.checkpoint.clockSealed)
                storage.write(Envelope(boot,cp))
            synchronized(guard) {busy=false}
            while(!closing) {
                val request=try {requests.take()}catch(_:InterruptedException) {if(closing)break else continue}
                var allowed=false;var observed=0L;var latest=0L
                try {
                    if(!closing) {
                        require(bootCount()==boot)
                        observed=clock()
                        latest=if(observed in 0..Decision.MAX_TIME-AdaptiveProbeBudget.MAX_HANDOFF_MS)
                            observed+AdaptiveProbeBudget.MAX_HANDOFF_MS else observed
                        val wasSealed=live.invalidated()
                        val reserved=live.reserve(observed,request.routine,latest)
                        val next=live.checkpoint();preview=Preview(next)
                        if(reserved || next.clockSealed && !wasSealed)storage.write(Envelope(boot,next))
                        allowed=reserved
                    }
                }catch(_:Exception) {preview=Preview(live.checkpoint(),true)}
                finally {
                    try {deliver(request,allowed,observed,latest)}finally {synchronized(guard) {busy=false}}
                }
            }
        }catch(_:Exception) {preview=Preview(budget?.checkpoint() ?: preview.checkpoint,true)}
        finally {
            try {storage?.close()}finally {synchronized(guard) {busy=false}}
        }
    }

    /** Test shutdown cannot reset the ledger and joins the actual actor before
     * an isolated fixture may remove its exact owned files. No production close. */
    internal fun shutdownForTest() {
        require(test!=null && BuildConfig.DEBUG)
        workerOnly();check(Thread.currentThread()!==worker)
        synchronized(guard) {closing=true}
        worker.interrupt();worker.join(10_000);check(!worker.isAlive)
    }
    internal fun busyForTest():Boolean {require(test!=null);return busy}

    private inner class Store {
        private val directory=File(context.noBackupFilesDir,test?.let {"probe-admission-"+it.namespace} ?: "probe-admission")
        private val atomic=AtomicFile(File(directory,"adaptive-v1.json"))
        private val lockFile=File(directory,"owner.lock")
        private var lockStream:FileOutputStream?=null
        private var channel:FileChannel?=null
        private var owner:FileLock?=null
        private var createdDirectory=false
        private var processOwner:String?=null
        private fun regular(file:File)=file.isFile && !Files.isSymbolicLink(file.toPath())
        private fun footprint():Set<String> {
            require(directory.isDirectory && !Files.isSymbolicLink(directory.toPath()))
            val allowed=setOf("adaptive-v1.json","adaptive-v1.json.bak","adaptive-v1.json.new","owner.lock")
            val names=HashSet<String>()
            Files.newDirectoryStream(directory.toPath()).use {files->for(path in files) {
                require(names.size<4)
                val file=path.toFile()
                require(file.name in allowed && names.add(file.name) && regular(file) && file.length()<=LIMIT)
            }}
            require(!lockFile.exists() || lockFile.length()==0L)
            return names
        }
        fun load():Envelope? {
            workerOnly()
            val fresh=!directory.exists()
            if(fresh) {require(directory.mkdir());createdDirectory=true}
            footprint()
            val key=directory.canonicalPath
            synchronized(processOwners) {require(processOwners.size<32 && processOwners.add(key))}
            processOwner=key
            if(!lockFile.exists())require(lockFile.createNewFile())
            require(regular(lockFile) && lockFile.length()==0L)
            lockStream=FileOutputStream(lockFile,true);channel=lockStream?.channel
            owner=requireNotNull(channel?.tryLock())
            footprint()
            if(fresh) {
                require(footprint()==setOf("owner.lock"))
                return null
            }
            require(atomic.baseFile.exists() || File(atomic.baseFile.path+".bak").exists())
            return decode(read())
        }
        private fun read():ByteArray {
            workerOnly();footprint()
            return atomic.openRead().use {input->
                val size=input.channel.size();require(size in 1L..LIMIT.toLong())
                val bytes=ByteArray(size.toInt());var offset=0
                while(offset<bytes.size) {val count=input.read(bytes,offset,bytes.size-offset);require(count>0);offset+=count}
                require(input.read()==-1);bytes
            }
        }
        fun write(value:Envelope) {
            workerOnly();check(owner?.isValid==true);footprint()
            val bytes=encode(value);var output:FileOutputStream?=null
            try {
                output=atomic.startWrite();output.write(bytes);output.flush()
                test?.io?.invoke(IoStage.BEFORE_FILE_SYNC);output.fd.sync()
                atomic.finishWrite(output);output=null
                test?.io?.invoke(IoStage.BEFORE_DIRECTORY_SYNC)
                syncDirectory(directory)
                // Persist the first directory entry as well as its contents:
                // losing a newly-created directory must not forgive a start.
                if(createdDirectory) {syncDirectory(requireNotNull(directory.parentFile));createdDirectory=false}
                test?.io?.invoke(IoStage.BEFORE_READBACK)
                val persisted=read();require(persisted.contentEquals(bytes) && decode(persisted)==value)
            }catch(failure:Exception) {
                output?.let {atomic.failWrite(it)}
                throw failure
            }
        }
        private fun syncDirectory(value:File) {
            val descriptor=Os.open(value.absolutePath,OsConstants.O_RDONLY or OsConstants.O_DIRECTORY or OsConstants.O_CLOEXEC,0)
            try {Os.fsync(descriptor)}finally {Os.close(descriptor)}
        }
        fun close() {
            workerOnly()
            try {try {owner?.release()}finally {try {channel?.close()}finally {lockStream?.close()}}}
            finally {processOwner?.let {key->synchronized(processOwners) {check(processOwners.remove(key))}};processOwner=null}
        }
    }
}
