package io.syn443.android.vpn

import android.content.Context
import android.os.Looper
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import io.syn443.identity.Identity
import io.syn443.identity.LoginIntent
import io.syn443.identity.LoginPhase
import io.syn443.identity.LoginRecovery
import io.syn443.identity.AssignmentState
import io.syn443.identity.AssignmentIdentity
import io.syn443.policy.Policy
import kotlinx.serialization.encodeToString
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

enum class LoginStorageFailure { STALE, UNAVAILABLE, CORRUPT, WRONG_THREAD }
class LoginStorageException(val reason:LoginStorageFailure):Exception(reason.name)

/**
 * Public intent is the cancellation fence. Crypto runs outside its short lock; only bounded
 * AtomicFile writes hold it. Intent is committed before its referenced ciphertext. An interrupted
 * pair therefore fails closed, rather than replaying a credential from the previous revision.
 * One process owns this journal, like StateStore; it must not be opened by a native host process.
 */
class LoginJournal(context:Context,private val namespace:String="device-login-v1") {
    companion object {
        private const val maximum=65_536
        private const val assignmentMaximum=2_097_152
        private const val keyAlias="syn443-auth-store-v1"
        private val intentLock=Any()
        private val cryptoLock=Any()
        private fun worker() {
            if(Looper.myLooper()==Looper.getMainLooper() || Thread.currentThread().name.startsWith("Binder:"))
                throw LoginStorageException(LoginStorageFailure.WRONG_THREAD)
        }
        private inline fun <T> guarded(block:()->T):T = try {block()}
            catch(e:LoginStorageException) {throw e}
            catch(_:Exception) {throw LoginStorageException(LoginStorageFailure.UNAVAILABLE)}
        private fun key(create:Boolean):SecretKey = synchronized(cryptoLock) {
            val store=KeyStore.getInstance("AndroidKeyStore").apply {load(null)}
            (store.getKey(keyAlias,null) as? SecretKey)?.let {return@synchronized it}
            check(create)
            KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,"AndroidKeyStore").apply {
                init(KeyGenParameterSpec.Builder(keyAlias,KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setUserAuthenticationRequired(false).build())
            }.generateKey()
        }
    }
    private val directory:File
    private val intent:AtomicFile
    private val protected:AtomicFile
    private val assignment:AtomicFile
    init {
        require(namespace.matches(Regex("[a-z0-9-]{1,48}")))
        directory=File(context.noBackupFilesDir,"login/$namespace")
        intent=AtomicFile(File(directory,"intent.json"));protected=AtomicFile(File(directory,"protected.bin"))
        assignment=AtomicFile(File(directory,"assignment.bin"))
    }
    class Prepared internal constructor(internal val generation:Long,internal val authority:String,
        internal val namespace:String,internal val data:ByteArray) : AutoCloseable {
        val hash=Identity.hash(data)
        internal var closed=false
        override fun close() {synchronized(this) {closed=true;data.fill(0)}}
        override fun toString()="PreparedLogin([redacted])"
    }
    private fun exists(file:AtomicFile)=file.baseFile.exists() || File(file.baseFile.path+".bak").exists() || File(file.baseFile.path+".new").exists()
    private fun read(file:AtomicFile,limit:Int):ByteArray = file.openRead().use {input->
        val bytes=ByteArray(limit+1);var count=0
        while(count<bytes.size) {val n=input.read(bytes,count,bytes.size-count);if(n<0)break;check(n>0);count+=n}
        if(count>limit)throw LoginStorageException(LoginStorageFailure.CORRUPT)
        bytes.copyOf(count).also {bytes.fill(0)}
    }
    private fun write(file:AtomicFile,bytes:ByteArray) {
        check(directory.isDirectory || directory.mkdirs())
        val output=file.startWrite()
        try {output.write(bytes);file.finishWrite(output)} catch(e:Exception) {file.failWrite(output);throw e}
    }
    private fun snapshotLocked():LoginIntent {
        if(!exists(intent)) {
            if(exists(protected) || exists(assignment))throw LoginStorageException(LoginStorageFailure.CORRUPT)
            return LoginIntent()
        }
        return try {LoginRecovery.decode(Policy.utf8(read(intent,maximum))).also {
            if(it.phase==LoginPhase.SIGNED_OUT && (exists(protected) || exists(assignment)))throw LoginStorageException(LoginStorageFailure.CORRUPT)
        }}
            catch(_:Exception) {throw LoginStorageException(LoginStorageFailure.CORRUPT)}
    }
    fun snapshot():LoginIntent = guarded {synchronized(intentLock) {snapshotLocked()}}
    fun isCurrent(expected:LoginIntent):Boolean = guarded {synchronized(intentLock) {snapshotLocked()==expected}}
    private fun requireCurrent(expected:LoginIntent) {
        if(snapshotLocked()!=expected)throw LoginStorageException(LoginStorageFailure.STALE)
    }
    private fun aad(generation:Long,authority:String)="SYN443-LOGIN-1\n$namespace\n$generation\n$authority".toByteArray(Charsets.US_ASCII)
    /** No disk mutation. A stale crypto result is disposable and cannot recreate a retired session. */
    fun prepare(expected:LoginIntent,json:String):Prepared = guarded {
        worker();LoginRecovery.validate(expected)
        require(expected.phase !in setOf(LoginPhase.SIGNED_OUT,LoginPhase.RETIRING))
        Identity.objectJSON(json)
        synchronized(intentLock) {requireCurrent(expected)}
        val plain=json.toByteArray(Charsets.UTF_8)
        val cipher=Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.ENCRYPT_MODE,key(true));updateAAD(aad(expected.generation,expected.authority))
        }
        try {Prepared(expected.generation,expected.authority,namespace,byteArrayOf(1)+cipher.iv+cipher.doFinal(plain))}
        finally {plain.fill(0)}
    }
    /** CAS and public metadata only on the controller thread; no Keystore operation under this lock. */
    fun commit(expected:LoginIntent,next:LoginIntent,prepared:Prepared?=null):LoginIntent = guarded {
        val raw=LoginRecovery.encode(next).toByteArray(Charsets.UTF_8);require(raw.size<=maximum)
        require(next.revision==expected.revision+1 && next.generation in expected.generation..expected.generation+1)
        synchronized(intentLock) {
            requireCurrent(expected)
            // Retirement acknowledgement follows successful erasure, including a retry after I/O
            // failure. Cancel itself still persists its generation before attempting erasure.
            if(next.phase==LoginPhase.SIGNED_OUT)eraseLocked()
            if(prepared==null) {
                require(next.protectedHash==expected.protectedHash || next.protectedHash.isEmpty())
                write(intent,raw)
            } else synchronized(prepared) {
                require(!prepared.closed && prepared.generation==next.generation && prepared.authority==next.authority &&
                    prepared.namespace==namespace && prepared.hash==next.protectedHash)
                write(intent,raw)
                write(protected,prepared.data)
            }
            if(next.protectedHash.isEmpty())eraseLocked()
            // AtomicFile.finishWrite logs some platform I/O errors. Independently read back both files.
            if(snapshotLocked()!=next)throw LoginStorageException(LoginStorageFailure.CORRUPT)
            if(next.protectedHash.isNotEmpty() && Identity.hash(read(protected,maximum+29))!=next.protectedHash)
                throw LoginStorageException(LoginStorageFailure.CORRUPT)
            next
        }
    }
    /** Decrypt outside intent lock and fence again after Keystore returns. No stale plaintext escapes. */
    fun readProtected(expected:LoginIntent):String = guarded {
        worker()
        val bytes=synchronized(intentLock) {
            requireCurrent(expected)
            if(expected.protectedHash.isEmpty())throw LoginStorageException(LoginStorageFailure.CORRUPT)
            read(protected,maximum+29).also {
                if(it.size !in 30..maximum+29 || it[0]!=1.toByte() || Identity.hash(it)!=expected.protectedHash)
                    throw LoginStorageException(LoginStorageFailure.CORRUPT)
            }
        }
        val plain=try {
            Cipher.getInstance("AES/GCM/NoPadding").run {
                init(Cipher.DECRYPT_MODE,key(false),GCMParameterSpec(128,bytes.copyOfRange(1,13)))
                updateAAD(aad(expected.generation,expected.authority));doFinal(bytes.copyOfRange(13,bytes.size))
            }
        } catch(_:Exception) {throw LoginStorageException(LoginStorageFailure.CORRUPT)} finally {bytes.fill(0)}
        try {
            synchronized(intentLock) {requireCurrent(expected)}
            Policy.utf8(plain).also {Identity.objectJSON(it)}
        } finally {plain.fill(0)}
    }
    class PreparedAssignment internal constructor(internal val identity:AssignmentIdentity,
        internal val namespace:String,internal val data:ByteArray):AutoCloseable {
        internal var closed=false
        internal val hash=Identity.hash(data)
        override fun close() {synchronized(this) {closed=true;data.fill(0)}}
        override fun toString()="PreparedAssignment([redacted])"
    }
    private fun assignmentIdentity(expected:LoginIntent):AssignmentIdentity {
        LoginRecovery.validate(expected)
        require(expected.phase in setOf(LoginPhase.PROVISIONING,LoginPhase.POLICY_CACHED,LoginPhase.REFRESHING))
        return AssignmentIdentity(expected.authority,expected.generation,expected.deviceId,expected.thumbprint)
    }
    private fun assignmentAad(expected:LoginIntent)=("SYN443-ASSIGNMENT-1\n$namespace\n"+
        "${expected.generation}\n${expected.authority}\n${expected.deviceId}\n${expected.thumbprint}").toByteArray(Charsets.US_ASCII)
    /** Separate bounded ciphertext: activation snapshots must not inflate the credential record. */
    fun prepareAssignment(expected:LoginIntent,value:AssignmentState):PreparedAssignment = guarded {
        worker();val identity=assignmentIdentity(expected);require(value.identity==identity && value.time!=null)
        synchronized(intentLock) {requireCurrent(expected)}
        val plain=Policy.json.encodeToString(value).toByteArray(Charsets.UTF_8)
        try {
            require(plain.size in 1..assignmentMaximum)
            val cipher=Cipher.getInstance("AES/GCM/NoPadding").apply {
                init(Cipher.ENCRYPT_MODE,key(true));updateAAD(assignmentAad(expected))
            }
            PreparedAssignment(identity,namespace,byteArrayOf(1)+cipher.iv+cipher.doFinal(plain))
        } finally {plain.fill(0)}
    }
    /** Caller holds its command fence; the login receipt is committed only after this readback. */
    fun commitAssignment(expected:LoginIntent,prepared:PreparedAssignment) = guarded {synchronized(intentLock) {
        requireCurrent(expected)
        synchronized(prepared) {
            require(!prepared.closed && prepared.namespace==namespace && prepared.identity==assignmentIdentity(expected))
            write(assignment,prepared.data)
            if(Identity.hash(read(assignment,assignmentMaximum+29))!=prepared.hash)throw LoginStorageException(LoginStorageFailure.CORRUPT)
        }
    }}
    fun readAssignment(expected:LoginIntent):AssignmentState? = guarded {
        worker();val identity=assignmentIdentity(expected)
        val bytes=synchronized(intentLock) {
            requireCurrent(expected)
            if(!exists(assignment)) {
                if(expected.policyHash.isNotEmpty())throw LoginStorageException(LoginStorageFailure.CORRUPT)
                return@guarded null
            }
            read(assignment,assignmentMaximum+29).also {
                if(it.size !in 30..assignmentMaximum+29 || it[0]!=1.toByte())throw LoginStorageException(LoginStorageFailure.CORRUPT)
            }
        }
        val plain=try {Cipher.getInstance("AES/GCM/NoPadding").run {
            init(Cipher.DECRYPT_MODE,key(false),GCMParameterSpec(128,bytes.copyOfRange(1,13)))
            updateAAD(assignmentAad(expected));doFinal(bytes.copyOfRange(13,bytes.size))
        }} catch(_:Exception) {throw LoginStorageException(LoginStorageFailure.CORRUPT)} finally {bytes.fill(0)}
        try {
            val text=Policy.utf8(plain)
            val value=try {Policy.json.decodeFromString<AssignmentState>(text).also {
                require(it.identity==identity && it.time!=null && Policy.json.encodeToString(it)==text)
            }} catch(_:Exception) {throw LoginStorageException(LoginStorageFailure.CORRUPT)}
            synchronized(intentLock) {requireCurrent(expected)};value
        } finally {plain.fill(0)}
    }
    private fun eraseLocked() {
        protected.delete();assignment.delete()
        check(!exists(protected) && !exists(assignment))
    }
    /** Retry erasure after a persisted Cancel; retirement cannot be acknowledged until it succeeds. */
    fun eraseRetired(expected:LoginIntent):Boolean = guarded {synchronized(intentLock) {
        requireCurrent(expected);require(expected.phase in setOf(LoginPhase.RETIRING,LoginPhase.SIGNED_OUT))
        eraseLocked();true
    }}
}
