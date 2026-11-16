package io.syn443.android.vpn

import android.content.Context
import android.os.Looper
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import io.syn443.policy.Canonical
import io.syn443.policy.Policy
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

internal enum class AdminKeyStorageFailure { WRONG_THREAD, INVALID, STALE, CORRUPT, UNAVAILABLE }
internal class AdminKeyStorageException(val reason:AdminKeyStorageFailure):Exception(reason.name)
@Serializable internal enum class AdminKeyPhase { SIGNED_OUT, RESERVED, BROWSER, AUTHENTICATED, RETIRING }
@Serializable internal data class AdminKeyRecord(val version:Int=1,val revision:Long=0,val generation:Long=0,
    val phase:AdminKeyPhase=AdminKeyPhase.SIGNED_OUT,val alias:String="") {
    override fun toString()="AdminKeyRecord(phase=$phase, [redacted])"
}

/** One controller-process owner journal. It stores no credentials and never retires a key itself. */
internal class AdminKeyJournal private constructor(context:Context,private val namespace:String,
    private val encryptionAlias:String) {
    constructor(context:Context,namespace:String="admin-login-v1"):this(context,namespace,"syn443-admin-store-v1")
    companion object {
        private const val maximum=9_007_199_254_740_991L
        private const val plainLimit=4096
        private const val frameLimit=plainLimit+29
        private val lock=Any()
        /** Isolated emulator storage only. Production always uses its fixed, separate AES alias. */
        internal fun isolatedForTest(context:Context,namespace:String,encryptionAlias:String):AdminKeyJournal {
            require(io.syn443.android.BuildConfig.DEBUG && android.os.Build.HARDWARE in setOf("ranchu","goldfish") &&
                namespace.matches(Regex("test-[a-z0-9-]{1,43}")) &&
                encryptionAlias.matches(Regex("syn443-admin-store-test-[A-Za-z0-9_-]{43}")))
            return AdminKeyJournal(context,namespace,encryptionAlias)
        }
        private fun worker() {
            if(Looper.myLooper()==Looper.getMainLooper() || Thread.currentThread().name.startsWith("Binder:"))
                throw AdminKeyStorageException(AdminKeyStorageFailure.WRONG_THREAD)
        }
        private fun valid(record:AdminKeyRecord) {
            require(record.version==1 && record.revision in 0..maximum && record.generation in 0..maximum)
            require(if(record.phase==AdminKeyPhase.SIGNED_OUT)record.alias.isEmpty() else AdminKey.ownedAlias(record.alias))
        }
        private fun transition(expected:AdminKeyRecord,next:AdminKeyRecord) {
            valid(expected);valid(next)
            require(expected.revision<maximum && next.revision==expected.revision+1)
            when {
                expected.phase==AdminKeyPhase.SIGNED_OUT && next.phase==AdminKeyPhase.RESERVED ->
                    require(expected.generation<maximum && next.generation==expected.generation+1)
                expected.phase==AdminKeyPhase.RESERVED && next.phase==AdminKeyPhase.BROWSER ||
                    expected.phase==AdminKeyPhase.BROWSER && next.phase==AdminKeyPhase.AUTHENTICATED ->
                    require(next.generation==expected.generation && next.alias==expected.alias)
                expected.phase in setOf(AdminKeyPhase.RESERVED,AdminKeyPhase.BROWSER,AdminKeyPhase.AUTHENTICATED) && next.phase==AdminKeyPhase.RETIRING ->
                    require(expected.generation<maximum && next.generation==expected.generation+1 && next.alias==expected.alias)
                expected.phase==AdminKeyPhase.RETIRING && next.phase==AdminKeyPhase.SIGNED_OUT ->
                    require(next.generation==expected.generation)
                else -> throw IllegalArgumentException("admin_key_transition_invalid")
            }
        }
    }
    private val directory:File
    private val file:AtomicFile
    init {
        require(namespace.matches(Regex("[a-z0-9-]{1,48}")))
        directory=File(context.noBackupFilesDir,"admin-login/$namespace")
        file=AtomicFile(File(directory,"owner.bin"))
    }
    private fun aad()="SYN443-ADMIN-KEY-JOURNAL-1\n$namespace".toByteArray(Charsets.US_ASCII)
    private fun key(create:Boolean):SecretKey {
        val store=KeyStore.getInstance("AndroidKeyStore").apply {load(null)}
        if(store.containsAlias(encryptionAlias))return checkNotNull(store.getKey(encryptionAlias,null) as? SecretKey)
        check(create)
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,"AndroidKeyStore").apply {
            init(KeyGenParameterSpec.Builder(encryptionAlias,KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setUserAuthenticationRequired(false).build())
        }.generateKey()
    }
    private fun bytes():ByteArray=file.openRead().use {input ->
        val size=input.channel.size()
        require(size in 30L..frameLimit.toLong())
        val value=ByteArray(size.toInt());var offset=0;var complete=false
        try {
            while(offset<value.size) {val count=input.read(value,offset,value.size-offset);require(count>0);offset+=count}
            require(input.read()==-1);complete=true;value
        }finally {if(!complete)value.fill(0)}
    }
    private fun decode(plain:ByteArray):AdminKeyRecord {
        require(plain.size in 1..plainLimit)
        val root=Canonical.parse(Policy.utf8(plain)).jsonObject
        require(root.keys==setOf("version","revision","generation","phase","alias"))
        for(name in listOf("version","revision","generation")) {
            val value=root.getValue(name).jsonPrimitive;require(!value.isString && value.longOrNull!=null)
        }
        for(name in listOf("phase","alias"))require(root.getValue(name).jsonPrimitive.isString)
        return Canonical.json.decodeFromJsonElement<AdminKeyRecord>(root).also(::valid)
    }
    private fun readLocked():AdminKeyRecord {
        if(!directory.exists())return AdminKeyRecord()
        try {
            require(directory.isDirectory)
            // A lone .new or an empty/foreign directory is not a fresh install.
            require(file.baseFile.exists() || File(file.baseFile.path+".bak").exists())
            val encrypted=bytes()
            val plain=try {
                require(encrypted[0]==1.toByte())
                Cipher.getInstance("AES/GCM/NoPadding").run {
                    init(Cipher.DECRYPT_MODE,key(false),GCMParameterSpec(128,encrypted.copyOfRange(1,13)))
                    updateAAD(aad());doFinal(encrypted.copyOfRange(13,encrypted.size))
                }
            }finally {encrypted.fill(0)}
            return try {decode(plain)}finally {plain.fill(0)}
        }catch(_:Exception) {throw AdminKeyStorageException(AdminKeyStorageFailure.CORRUPT)}
    }
    fun read():AdminKeyRecord {
        worker()
        return synchronized(lock) {readLocked()}
    }
    /** Exact CAS on an immutable record. A tombstone remains recoverable until explicit owned retirement. */
    fun commit(expected:AdminKeyRecord,next:AdminKeyRecord):AdminKeyRecord {
        worker()
        try {transition(expected,next)}catch(_:Exception) {throw AdminKeyStorageException(AdminKeyStorageFailure.INVALID)}
        return synchronized(lock) {
            if(readLocked()!=expected)throw AdminKeyStorageException(AdminKeyStorageFailure.STALE)
            val plain=Canonical.encode(Canonical.parse(Canonical.json.encodeToString(next))).toByteArray(Charsets.UTF_8)
            var encrypted:ByteArray?=null
            try {
                require(plain.size in 1..plainLimit)
                val frame=Cipher.getInstance("AES/GCM/NoPadding").run {
                    init(Cipher.ENCRYPT_MODE,key(true));updateAAD(aad());require(iv.size==12);byteArrayOf(1)+iv+doFinal(plain)
                }
                encrypted=frame
                check(directory.isDirectory || directory.mkdirs())
                val output=file.startWrite()
                try {output.write(frame);file.finishWrite(output)}catch(error:Exception) {file.failWrite(output);throw error}
                check(readLocked()==next)
                next
            }catch(error:AdminKeyStorageException) {throw error}
            catch(_:Exception) {throw AdminKeyStorageException(AdminKeyStorageFailure.UNAVAILABLE)}
            finally {plain.fill(0);encrypted?.fill(0)}
        }
    }
}
