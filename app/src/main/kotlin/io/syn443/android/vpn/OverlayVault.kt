package io.syn443.android.vpn

import android.content.Context
import android.os.Looper
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import io.syn443.identity.*
import io.syn443.policy.Canonical
import io.syn443.policy.Policy
import kotlinx.serialization.encodeToString
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Controller-process only. One durable operation precedes all network/native
 * effects. Each grant has its own nonexportable Keystore key. Neither this class
 * nor a caller-controlled path can read, adopt or remove operator SDK state.
 * The authorization/clock callbacks read immutable or volatile controller views
 * only; they must never acquire command/UI locks or perform network/crypto work. */
internal class OverlayVault(context:Context,private val namespace:String,
    private val isAuthorized:(OverlayEnrollment)->Boolean,private val trustedUpperMs:()->Long,private val area:String="managed-overlay-v1") {
    companion object {
        private val filesLock=Any()
        private val keysLock=Any()
        private fun worker() {
            if(Looper.myLooper()==Looper.getMainLooper() || Thread.currentThread().name.startsWith("Binder:"))
                throw LoginStorageException(LoginStorageFailure.WRONG_THREAD)
        }
        private inline fun<T> guarded(block:()->T):T=try{block()}
            catch(e:LoginStorageException){throw e}
            catch(_:Exception){throw LoginStorageException(LoginStorageFailure.UNAVAILABLE)}
    }
    private val directory:File
    private val ledger:AtomicFile
    private val cipherFile:AtomicFile
    init {
        require(namespace.startsWith("managed-netbird/") && namespace.removePrefix("managed-netbird/").let {it.length==43 && Policy.decode64(it).size==32})
        require(area=="managed-overlay-v1" || io.syn443.android.BuildConfig.DEBUG && area.matches(Regex("test-[a-z0-9-]{1,40}")))
        val hash=Identity.hash(namespace.toByteArray(Charsets.US_ASCII))
        directory=File(context.noBackupFilesDir,"overlay/$area/$hash")
        ledger=AtomicFile(File(directory,"ledger.json"));cipherFile=AtomicFile(File(directory,"credential.bin"))
    }
    private fun exists(f:AtomicFile)=listOf("",".bak",".new").any {File(f.baseFile.path+it).exists()}
    private fun read(f:AtomicFile,limit:Int):ByteArray=f.openRead().use {input->
        val buffer=ByteArray(limit+1);var n=0
        try {
            while(n<buffer.size){val count=input.read(buffer,n,buffer.size-n);if(count<0)break;check(count>0);n+=count}
            if(n>limit)throw LoginStorageException(LoginStorageFailure.CORRUPT)
            buffer.copyOf(n)
        }finally {buffer.fill(0)}
    }
    private fun write(f:AtomicFile,bytes:ByteArray) {
        check(directory.isDirectory || directory.mkdirs());val output=f.startWrite()
        try{output.write(bytes);f.finishWrite(output)}catch(e:Exception){f.failWrite(output);throw e}
        if(!read(f,bytes.size).contentEquals(bytes))throw LoginStorageException(LoginStorageFailure.CORRUPT)
    }
    private fun snapshotLocked():OverlayEnrollment? {
        if(!exists(ledger)) {
            if(exists(cipherFile))throw LoginStorageException(LoginStorageFailure.CORRUPT)
            return null
        }
        return try {
            val raw=Policy.utf8(read(ledger,8192));Canonical.parse(raw)
            Canonical.json.decodeFromString<OverlayEnrollment>(raw).also {
                OverlayEnrollments.validate(it);require(it.operation.namespace==namespace)
            }
        }catch(_:Exception){throw LoginStorageException(LoginStorageFailure.CORRUPT)}
    }
    fun snapshot():OverlayEnrollment?=guarded{synchronized(filesLock){snapshotLocked()}}
    private fun current(expected:OverlayEnrollment,authorize:Boolean=true) {
        if(snapshotLocked()!=expected || authorize && !isAuthorized(expected))throw LoginStorageException(LoginStorageFailure.STALE)
    }
    private fun commitLocked(expected:OverlayEnrollment,next:OverlayEnrollment,authorize:Boolean=true):OverlayEnrollment {
        current(expected,authorize);OverlayEnrollments.validate(next)
        require(next.revision==expected.revision+1 && next.operation==expected.operation && next.identityTag==expected.identityTag && next.bindingTag==expected.bindingTag && next.loginGeneration==expected.loginGeneration)
        val raw=Canonical.json.encodeToString(next).toByteArray(Charsets.UTF_8);require(raw.size<=8192)
        write(ledger,raw);if(snapshotLocked()!=next)throw LoginStorageException(LoginStorageFailure.CORRUPT)
        return next
    }
    fun reserve(binding:OverlayCredentialBinding,generation:Long):OverlayEnrollment=guarded{
        worker();val proposed=OverlayEnrollments.reserve(binding,generation)
        synchronized(filesLock){
            val previous=snapshotLocked()
            if(previous!=null){OverlayEnrollments.requireAuthorized(previous,binding,generation);current(previous);previous}
            else {
                if(!isAuthorized(proposed))throw LoginStorageException(LoginStorageFailure.STALE)
                write(ledger,Canonical.json.encodeToString(proposed).toByteArray(Charsets.UTF_8))
                check(snapshotLocked()==proposed);proposed
            }
        }
    }
    private fun alias(expected:OverlayEnrollment)="syn443-overlay-"+Identity.hash((area+"\n"+expected.identityTag+"\n"+expected.operation.operationId).toByteArray(Charsets.US_ASCII))
    private fun aad(expected:OverlayEnrollment)=("SYN443-OVERLAY-1\n"+area+"\n"+namespace+"\n"+expected.identityTag+"\n"+expected.bindingTag+"\n"+expected.operation.body()).toByteArray(Charsets.US_ASCII)
    private fun key(expected:OverlayEnrollment,create:Boolean):SecretKey=synchronized(keysLock){
        synchronized(filesLock){current(expected)}
        val store=KeyStore.getInstance("AndroidKeyStore").apply{load(null)};val alias=alias(expected)
        (store.getKey(alias,null) as? SecretKey)?.let{return@synchronized it}
        if(!create)throw LoginStorageException(LoginStorageFailure.CORRUPT)
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,"AndroidKeyStore").apply{
            init(KeyGenParameterSpec.Builder(alias,KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setUserAuthenticationRequired(false).build())
        }.generateKey()
    }
    class Prepared internal constructor(internal val expected:OverlayEnrollment,internal val bytes:ByteArray,internal val until:Long):AutoCloseable {
        internal var closed=false
        override fun close(){synchronized(this){closed=true;bytes.fill(0)}}
        override fun toString()="PreparedOverlayCredential([redacted])"
    }
    fun prepare(expected:OverlayEnrollment,envelope:String,binding:OverlayCredentialBinding,roots:Map<String,String>,lowerMs:Long,upperMs:Long):Prepared=guarded{
        worker();require(expected.phase==OverlayPhase.RESERVED);OverlayEnrollments.requireAuthorized(expected,binding,expected.loginGeneration)
        synchronized(filesLock){current(expected)}
        val until=OverlayCredentials.verify(envelope,roots,binding,lowerMs,upperMs).use{it.expiresMs}
        val plain=envelope.toByteArray(Charsets.US_ASCII)
        try {
            val cipher=Cipher.getInstance("AES/GCM/NoPadding").apply{init(Cipher.ENCRYPT_MODE,key(expected,true));updateAAD(aad(expected))}
            val bytes=byteArrayOf(1)+cipher.iv+cipher.doFinal(plain)
            try{synchronized(filesLock){current(expected);require(until>maxOf(upperMs,trustedUpperMs()))};Prepared(expected,bytes,until)}catch(e:Exception){bytes.fill(0);throw e}
        }finally {plain.fill(0)}
    }
    fun cache(prepared:Prepared):OverlayEnrollment=guarded{
        worker();synchronized(filesLock){synchronized(prepared){
            require(!prepared.closed);val expected=prepared.expected;current(expected)
            require(prepared.until>trustedUpperMs())
            val next=OverlayEnrollments.cached(expected,Identity.hash(prepared.bytes),prepared.until)
            // The operation already exists. A crash before the ledger commit
            // leaves RESERVED and safely refetches the same server operation.
            write(cipherFile,prepared.bytes);commitLocked(expected,next)
        }}
    }
    fun credential(expected:OverlayEnrollment,binding:OverlayCredentialBinding,roots:Map<String,String>,lowerMs:Long,upperMs:Long):OverlaySetupSecret=guarded{
        worker();OverlayEnrollments.requireAuthorized(expected,binding,expected.loginGeneration)
        require(expected.phase in setOf(OverlayPhase.CACHED,OverlayPhase.ENROLLING) && expected.credentialUntilMs>maxOf(upperMs,trustedUpperMs()))
        val bytes=synchronized(filesLock){current(expected);read(cipherFile,16_413).also {
            if(it.size !in 30..16_413 || it[0]!=1.toByte() || Identity.hash(it)!=expected.protectedHash)throw LoginStorageException(LoginStorageFailure.CORRUPT)
        }}
        val plain=try {Cipher.getInstance("AES/GCM/NoPadding").run {
            init(Cipher.DECRYPT_MODE,key(expected,false),GCMParameterSpec(128,bytes.copyOfRange(1,13)));updateAAD(aad(expected));doFinal(bytes.copyOfRange(13,bytes.size))
        }}catch(e:LoginStorageException){throw e}catch(_:Exception){throw LoginStorageException(LoginStorageFailure.CORRUPT)}finally{bytes.fill(0)}
        try {
            val secret=OverlayCredentials.verify(Policy.utf8(plain),roots,binding,lowerMs,upperMs)
            try{synchronized(filesLock){current(expected);require(secret.expiresMs>trustedUpperMs())};secret}catch(e:Exception){secret.close();throw e}
        }finally{plain.fill(0)}
    }
    fun enrolling(expected:OverlayEnrollment)=guarded{worker();synchronized(filesLock){commitLocked(expected,OverlayEnrollments.enrolling(expected))}}
    /** Only the controller's confirmed native-registration event may call this. */
    fun registered(expected:OverlayEnrollment,evidence:String)=guarded{worker();synchronized(filesLock){commitLocked(expected,OverlayEnrollments.registered(expected,evidence))}}
    private fun eraseKey(expected:OverlayEnrollment)=synchronized(keysLock){
        val store=KeyStore.getInstance("AndroidKeyStore").apply{load(null)};store.deleteEntry(alias(expected));check(!store.containsAlias(alias(expected)))
    }
    private fun eraseCipher(){cipherFile.delete();File(cipherFile.baseFile.path+".new").let{if(it.exists())check(it.delete())};check(!exists(cipherFile))}
    fun eraseRegistered(expected:OverlayEnrollment):OverlayEnrollment=guarded{
        worker();val erasing=synchronized(filesLock){commitLocked(expected,OverlayEnrollments.erasing(expected))}
        eraseKey(erasing)
        synchronized(filesLock){current(erasing);eraseCipher();commitLocked(erasing,OverlayEnrollments.erased(erasing))}
    }
    fun acknowledged(expected:OverlayEnrollment)=guarded{worker();synchronized(filesLock){commitLocked(expected,OverlayEnrollments.acknowledged(expected))}}
    /** Bounded public cancellation fence only. It never waits for Keystore/SDK. */
    fun retiring(expected:OverlayEnrollment)=guarded{synchronized(filesLock){commitLocked(expected,OverlayEnrollments.retiring(expected),false)}}
    /** retireOwnedIdentity must hold/confirm native ownership release and erase
     * only this namespace. A pending/unconfirmed release never closes retirement. */
    fun finishRetirement(expected:OverlayEnrollment,retireOwnedIdentity:()->Boolean):Boolean=guarded{
        worker();synchronized(filesLock){current(expected,false)};require(expected.phase==OverlayPhase.RETIRING)
        if(!retireOwnedIdentity())return@guarded false
        eraseKey(expected)
        synchronized(filesLock){current(expected,false);eraseCipher();commitLocked(expected,OverlayEnrollments.retired(expected),false)};true
    }
}
