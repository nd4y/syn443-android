package io.syn443.android.vpn

import android.content.Context
import android.os.Looper
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.file.Files
import java.security.KeyStore
import java.security.MessageDigest
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

internal enum class AdminEditorStorageFailure {
    WRONG_THREAD, INVALID, NOT_FOUND, OWNER_MISMATCH, STALE, ALREADY_EXISTS, PENDING, CORRUPT, UNAVAILABLE
}
internal class AdminEditorStorageException(val reason:AdminEditorStorageFailure):Exception(reason.name)
private fun editorWorker() {
    if(Looper.myLooper()==Looper.getMainLooper() || Thread.currentThread().name.startsWith("Binder:"))
        throw AdminEditorStorageException(AdminEditorStorageFailure.WRONG_THREAD)
}

internal data class AdminEditorOwner(val serviceHash:String,val actor:String,val deviceId:String,val draftId:String) {
    override fun toString()="AdminEditorOwner([redacted])"
}

/** Stable request and opaque value-only replay metadata; neither restores credentials or HTTP authority. */
internal class AdminEditorPending internal constructor(val action:String,val requestId:String,body:ByteArray,replayContext:ByteArray) {
    init {editorWorker()}
    private val ownedBody=body.also {require(it.size in 1..AdminEditorStore.MAX_TEXT)}.copyOf()
    private val ownedReplayContext=replayContext.also {require(it.size in 1..AdminEditorStore.MAX_REPLAY_CONTEXT)}.copyOf()
    val body:ByteArray get()=ownedBody.copyOf()
    val replayContext:ByteArray get()=ownedReplayContext.copyOf()
    val bodySha256:String=MessageDigest.getInstance("SHA-256").digest(ownedBody).joinToString("") {"%02x".format(it.toInt() and 255)}
    override fun equals(other:Any?)=other is AdminEditorPending && action==other.action && requestId==other.requestId &&
        ownedBody.contentEquals(other.ownedBody) && ownedReplayContext.contentEquals(other.ownedReplayContext)
    override fun hashCode()=31*(31*(31*action.hashCode()+requestId.hashCode())+ownedBody.contentHashCode())+
        ownedReplayContext.contentHashCode()
    override fun toString()="AdminEditorPending([redacted])"
}

internal class AdminEditorRecord internal constructor(val revision:Long,val owner:AdminEditorOwner,
    proposal:ByteArray,val pending:AdminEditorPending?=null,val closed:Boolean=false) {
    val version:Int get()=1
    private val ownedProposal=proposal.also {require(it.size<=AdminEditorStore.MAX_TEXT)}.copyOf()
    val proposal:ByteArray get()=ownedProposal.copyOf()
    override fun equals(other:Any?)=other is AdminEditorRecord && revision==other.revision && owner==other.owner &&
        closed==other.closed && ownedProposal.contentEquals(other.ownedProposal) && pending==other.pending
    override fun hashCode()=31*(31*(31*(31*revision.hashCode()+owner.hashCode())+closed.hashCode())+
        ownedProposal.contentHashCode())+(pending?.hashCode() ?: 0)
    override fun toString()="AdminEditorRecord([redacted])"
}

/**
 * One installation's encrypted editor, independent of device/admin credentials.
 * All disk and Keystore operations belong to an existing worker. The store owns
 * no executor/network and is not HTTP, account, signature or publication authority.
 * Proposal text may be incomplete: retaining it grants no permission to submit it.
 *
 * A prepared envelope must be considered possibly sent, including after a lost
 * acknowledgement or restart. Only explicit matching resolution can remove it.
 * Logout/process death do not erase the editor. A closed tombstone retains the
 * revision and AES key; a later explicit create may assign the next owner.
 * CAS locking is process-local: the future controller must be the sole process
 * owner. This is not a cross-process lock or external anti-rollback proof.
 */
internal class AdminEditorStore private constructor(context:Context,private val namespace:String,
    private val encryptionAlias:String) {
    constructor(context:Context):this(context,"admin-editor-v1","syn443-admin-editor-store-v1")

    companion object {
        internal const val MAX_TEXT=262_144
        internal const val MAX_REPLAY_CONTEXT=8192
        internal const val MAX_PLAIN=2*MAX_TEXT+4096+MAX_REPLAY_CONTEXT+4
        internal const val MAX_FRAME=MAX_PLAIN+29
        private const val MAX_REVISION=9_007_199_254_740_991L
        private const val MAGIC=0x53414531
        private val actions=setOf("layers.draft.put","layers.draft.discard","preview.request","publish")
        private val objectId=Regex("[A-Za-z0-9_-]{1,64}")
        private val requestId=Regex("[A-Za-z0-9_-]{24,128}")
        private val sha256=Regex("[a-f0-9]{64}")
        private val lock=Any()

        /** Synthetic filesystem/AES fixtures cannot target production or physical devices. */
        internal fun isolatedForTest(context:Context,namespace:String,encryptionAlias:String):AdminEditorStore {
            require(io.syn443.android.BuildConfig.DEBUG && android.os.Build.HARDWARE in setOf("ranchu","goldfish") &&
                namespace.matches(Regex("admin-editor-test-[a-f0-9]{32}")) &&
                encryptionAlias.matches(Regex("syn443-admin-editor-test-[A-Za-z0-9_-]{43}")))
            return AdminEditorStore(context,namespace,encryptionAlias)
        }
        private fun worker()=editorWorker()
        private fun hash43(raw:String):Boolean {
            if(!raw.matches(Regex("[A-Za-z0-9_-]{43}")))return false
            val bytes=try {Base64.getUrlDecoder().decode(raw)}catch(_:IllegalArgumentException) {return false}
            return try {bytes.size==32 && Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)==raw}
            finally {bytes.fill(0)}
        }
        private fun valid(owner:AdminEditorOwner) {
            require(hash43(owner.serviceHash) && hash43(owner.actor) && objectId.matches(owner.deviceId) && objectId.matches(owner.draftId))
        }
        private fun utf8(raw:ByteArray,minimum:Int=0,maximum:Int=MAX_TEXT) {
            require(raw.size in minimum..maximum)
            Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(raw))
        }
        private inline fun checked(action:()->Unit) {
            try {action()}catch(_:Exception) {throw AdminEditorStorageException(AdminEditorStorageFailure.INVALID)}
        }
        private fun valid(record:AdminEditorRecord) {
            require(record.revision in 1..MAX_REVISION);valid(record.owner)
            val proposal=record.proposal
            try {utf8(proposal);if(record.closed)require(proposal.isEmpty() && record.pending==null)}finally {proposal.fill(0)}
            record.pending?.let {pending ->
                require(pending.action in actions && requestId.matches(pending.requestId))
                val body=pending.body;val replay=pending.replayContext
                try {utf8(body,1);utf8(replay,1,MAX_REPLAY_CONTEXT)}finally {body.fill(0);replay.fill(0)}
            }
        }
    }

    init {worker()}
    private val directory=File(context.noBackupFilesDir,namespace)
    private val file=AtomicFile(File(directory,"editor.bin"))
    private fun aad()="SYN443-ADMIN-EDITOR-1\n$namespace".toByteArray(Charsets.US_ASCII)
    private fun keyStore()=KeyStore.getInstance("AndroidKeyStore").apply {load(null)}
    private fun key(create:Boolean):SecretKey {
        val store=keyStore()
        if(store.containsAlias(encryptionAlias))return checkNotNull(store.getKey(encryptionAlias,null) as? SecretKey)
        check(create)
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,"AndroidKeyStore").apply {
            init(KeyGenParameterSpec.Builder(encryptionAlias,KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(256)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setUserAuthenticationRequired(false).build())
        }.generateKey()
    }
    private fun encode(record:AdminEditorRecord):ByteArray {
        valid(record)
        val proposal=record.proposal;val body=record.pending?.body;val replay=record.pending?.replayContext
        val buffer=ByteArrayOutputStream(proposal.size+(body?.size ?: 0)+(replay?.size ?: 0)+516)
        try {
            DataOutputStream(buffer).use {output ->
                fun text(value:String) {val bytes=value.toByteArray(Charsets.US_ASCII);output.writeInt(bytes.size);output.write(bytes)}
                output.writeInt(MAGIC);output.writeInt(1);output.writeLong(record.revision);output.writeByte(if(record.closed)1 else 0)
                text(record.owner.serviceHash);text(record.owner.actor);text(record.owner.deviceId);text(record.owner.draftId)
                output.writeInt(proposal.size);output.write(proposal)
                output.writeByte(if(record.pending==null)0 else 1)
                record.pending?.let {pending ->
                    text(pending.action);text(pending.requestId);output.writeInt(checkNotNull(body).size);output.write(body)
                    output.writeInt(checkNotNull(replay).size);output.write(replay)
                }
            }
            return buffer.toByteArray().also {require(it.size<=MAX_PLAIN)}
        }finally {proposal.fill(0);body?.fill(0);replay?.fill(0)}
    }
    private fun decode(plain:ByteArray):AdminEditorRecord {
        require(plain.size in 1..MAX_PLAIN)
        DataInputStream(ByteArrayInputStream(plain)).use {input ->
            fun bytes(maximum:Int,minimum:Int=0):ByteArray {
                val length=input.readInt()
                require(length in minimum..maximum && length<=input.available())
                return ByteArray(length).also {input.readFully(it)}
            }
            fun text(maximum:Int,minimum:Int=1):String {
                val raw=bytes(maximum,minimum)
                return try {
                    require(raw.all {it.toInt() in 0..127});raw.toString(Charsets.US_ASCII)
                }finally {raw.fill(0)}
            }
            require(input.readInt()==MAGIC && input.readInt()==1)
            val revision=input.readLong();val closed=input.readUnsignedByte();require(closed in 0..1)
            val owner=AdminEditorOwner(text(43,43),text(43,43),text(64),text(64))
            val proposal=bytes(MAX_TEXT);var body:ByteArray?=null;var replay:ByteArray?=null
            try {
                val present=input.readUnsignedByte();require(present in 0..1)
                val pending=if(present==0)null else {
                    val action=text(32);val id=text(128,24);body=bytes(MAX_TEXT,1);replay=bytes(MAX_REPLAY_CONTEXT,1)
                    AdminEditorPending(action,id,checkNotNull(body),checkNotNull(replay))
                }
                require(input.read()==-1)
                return AdminEditorRecord(revision,owner,proposal,pending,closed==1).also(::valid)
            }finally {proposal.fill(0);body?.fill(0);replay?.fill(0)}
        }
    }
    /** Null means pristine only when both namespace and exact AES alias are absent. */
    private fun readLocked():AdminEditorRecord? {
        try {
            if(!directory.exists()) {
                require(!Files.isSymbolicLink(directory.toPath()) && !keyStore().containsAlias(encryptionAlias))
                return null
            }
            require(directory.isDirectory && !Files.isSymbolicLink(directory.toPath()))
            val entries=checkNotNull(directory.listFiles())
            require(entries.isNotEmpty() && entries.all {it.name in setOf("editor.bin","editor.bin.bak") &&
                it.isFile && !Files.isSymbolicLink(it.toPath())})
            require(file.baseFile.exists() || File(file.baseFile.path+".bak").exists())
            // A known .bak may restore the committed owner. A .new or foreign
            // entry is rejected above before AtomicFile can delete it.
            val encrypted=file.openRead().use {input ->
                val length=input.channel.size();require(length in 30L..MAX_FRAME.toLong())
                val bytes=ByteArray(length.toInt());var complete=false
                try {
                    var offset=0
                    while(offset<bytes.size) {val count=input.read(bytes,offset,bytes.size-offset);require(count>0);offset+=count}
                    require(input.read()==-1);complete=true;bytes
                }finally {if(!complete)bytes.fill(0)}
            }
            val plain=try {
                require(encrypted[0]==1.toByte())
                Cipher.getInstance("AES/GCM/NoPadding").run {
                    init(Cipher.DECRYPT_MODE,key(false),GCMParameterSpec(128,encrypted.copyOfRange(1,13)))
                    updateAAD(aad());doFinal(encrypted.copyOfRange(13,encrypted.size))
                }
            }finally {encrypted.fill(0)}
            return try {decode(plain)}finally {plain.fill(0)}
        }catch(_:Exception) {throw AdminEditorStorageException(AdminEditorStorageFailure.CORRUPT)}
    }
    private fun writeLocked(next:AdminEditorRecord,createKey:Boolean):AdminEditorRecord {
        val plain=encode(next);var frame:ByteArray?=null
        try {
            if(createKey)check(directory.mkdir())else check(directory.isDirectory)
            val encrypted=Cipher.getInstance("AES/GCM/NoPadding").run {
                init(Cipher.ENCRYPT_MODE,key(createKey));updateAAD(aad());require(iv.size==12)
                byteArrayOf(1)+iv+doFinal(plain)
            }
            frame=encrypted;require(encrypted.size<=MAX_FRAME)
            val output=file.startWrite()
            try {output.write(encrypted);file.finishWrite(output)}catch(error:Exception) {file.failWrite(output);throw error}
            check(readLocked()==next)
            return next
        }catch(_:Exception) {throw AdminEditorStorageException(AdminEditorStorageFailure.UNAVAILABLE)}
        finally {plain.fill(0);frame?.fill(0)}
    }
    private fun current(expected:AdminEditorRecord):AdminEditorRecord {
        val record=readLocked() ?: throw AdminEditorStorageException(AdminEditorStorageFailure.NOT_FOUND)
        if(record.owner!=expected.owner)throw AdminEditorStorageException(AdminEditorStorageFailure.OWNER_MISMATCH)
        if(record!=expected)throw AdminEditorStorageException(AdminEditorStorageFailure.STALE)
        if(record.closed)throw AdminEditorStorageException(AdminEditorStorageFailure.INVALID)
        if(record.revision==MAX_REVISION)throw AdminEditorStorageException(AdminEditorStorageFailure.INVALID)
        return record
    }
    /** Only explicit pristine creation or consumption of an authenticated closed tombstone is allowed. */
    fun create(owner:AdminEditorOwner,proposal:ByteArray):AdminEditorRecord {
        worker();checked {require(proposal.size<=MAX_TEXT)};val owned=proposal.copyOf()
        try {
            checked {valid(owner);utf8(owned)}
            return synchronized(lock) {
                val previous=readLocked()
                if(previous!=null && !previous.closed)throw AdminEditorStorageException(AdminEditorStorageFailure.ALREADY_EXISTS)
                if(previous?.revision==MAX_REVISION)throw AdminEditorStorageException(AdminEditorStorageFailure.INVALID)
                val next=AdminEditorRecord((previous?.revision ?: 0)+1,owner,owned)
                writeLocked(next,previous==null)
            }
        }finally {owned.fill(0)}
    }
    fun load(expectedOwner:AdminEditorOwner):AdminEditorRecord {
        worker();checked {valid(expectedOwner)}
        return synchronized(lock) {
            val record=readLocked() ?: throw AdminEditorStorageException(AdminEditorStorageFailure.NOT_FOUND)
            if(record.owner!=expectedOwner)throw AdminEditorStorageException(AdminEditorStorageFailure.OWNER_MISMATCH)
            record
        }
    }
    /**
     * Discover only the exact verified account's active editor after restart.
     * Pristine storage and that account's closed tombstone return null. Account
     * mismatch is denied before revealing closed, draft, device or pending state.
     * This is a read, with only the existing known AtomicFile backup recovery;
     * it never creates/replaces a record or key and grants no HTTP authority.
     */
    fun recoverOwned(serviceHash:String,actor:String):AdminEditorRecord? {
        worker();checked {require(hash43(serviceHash) && hash43(actor))}
        return synchronized(lock) {
            val record=readLocked() ?: return@synchronized null
            if(record.owner.serviceHash!=serviceHash || record.owner.actor!=actor)
                throw AdminEditorStorageException(AdminEditorStorageFailure.OWNER_MISMATCH)
            if(record.closed)null else record
        }
    }
    fun edit(expected:AdminEditorRecord,proposal:ByteArray):AdminEditorRecord {
        worker();checked {require(proposal.size<=MAX_TEXT)};val owned=proposal.copyOf()
        try {
            checked {valid(expected);utf8(owned)}
            return synchronized(lock) {
                val actual=current(expected)
                if(actual.pending!=null)throw AdminEditorStorageException(AdminEditorStorageFailure.PENDING)
                writeLocked(AdminEditorRecord(actual.revision+1,actual.owner,owned),false)
            }
        }finally {owned.fill(0)}
    }
    /** Durable exact envelope/context first; no retry, replacement or refund is inferred from returning. */
    fun preparePending(expected:AdminEditorRecord,action:String,requestID:String,body:ByteArray,replayContext:ByteArray):AdminEditorRecord {
        worker();checked {require(body.size in 1..MAX_TEXT && replayContext.size in 1..MAX_REPLAY_CONTEXT)}
        val owned=body.copyOf();val replay=replayContext.copyOf()
        try {
            checked {valid(expected);require(action in actions && requestId.matches(requestID));utf8(owned,1);utf8(replay,1,MAX_REPLAY_CONTEXT)}
            return synchronized(lock) {
                val actual=current(expected)
                if(actual.pending!=null)throw AdminEditorStorageException(AdminEditorStorageFailure.PENDING)
                val proposal=actual.proposal
                try {writeLocked(AdminEditorRecord(actual.revision+1,actual.owner,proposal,AdminEditorPending(action,requestID,owned,replay)),false)}
                finally {proposal.fill(0)}
            }
        }finally {owned.fill(0);replay.fill(0)}
    }
    /** Caller verifies the remote result. Matching bytes identify an outcome; this store cannot authenticate it. */
    fun resolve(expected:AdminEditorRecord,requestID:String,bodySha256:String,verifiedSavedProposal:ByteArray):AdminEditorRecord {
        worker();checked {require(verifiedSavedProposal.size<=MAX_TEXT)};val owned=verifiedSavedProposal.copyOf()
        try {
            checked {valid(expected);require(requestId.matches(requestID) && sha256.matches(bodySha256));utf8(owned)}
            return synchronized(lock) {
                val actual=current(expected)
                val pending=actual.pending ?: throw AdminEditorStorageException(AdminEditorStorageFailure.INVALID)
                if(pending.requestId!=requestID || pending.bodySha256!=bodySha256)
                    throw AdminEditorStorageException(AdminEditorStorageFailure.STALE)
                writeLocked(AdminEditorRecord(actual.revision+1,actual.owner,owned),false)
            }
        }finally {owned.fill(0)}
    }
    /** Explicitly abandon only an unsent editor, retaining its monotonic tombstone and AES key. */
    fun close(expected:AdminEditorRecord):AdminEditorRecord {
        worker();checked {valid(expected)}
        return synchronized(lock) {
            val actual=current(expected)
            if(actual.pending!=null)throw AdminEditorStorageException(AdminEditorStorageFailure.PENDING)
            writeLocked(AdminEditorRecord(actual.revision+1,actual.owner,ByteArray(0),closed=true),false)
        }
    }
}
