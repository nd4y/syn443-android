package io.syn443.android

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.test.core.app.ApplicationProvider
import androidx.test.platform.app.InstrumentationRegistry
import io.syn443.android.vpn.AdminEditorOwner
import io.syn443.android.vpn.AdminEditorPending
import io.syn443.android.vpn.AdminEditorRecord
import io.syn443.android.vpn.AdminEditorStorageException
import io.syn443.android.vpn.AdminEditorStorageFailure as Failure
import io.syn443.android.vpn.AdminEditorStore
import io.syn443.identity.Identity
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.Closeable
import java.io.DataOutputStream
import java.io.File
import java.security.KeyStore
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec

/** Real, namespace-isolated AES/AtomicFile tests. No server, controller, identity or VPN commands. */
class AdminEditorStoreTest {
    private class Fixture(sharedAlias:String?=null):Closeable {
        val context=ApplicationProvider.getApplicationContext<Context>()
        val namespace="admin-editor-test-"+UUID.randomUUID().toString().replace("-","")
        val alias=sharedAlias ?: "syn443-admin-editor-test-"+Identity.random()
        val directory=File(context.noBackupFilesDir,namespace)
        val file=File(directory,"editor.bin")
        val owner=AdminEditorOwner(Identity.hash("synthetic service".toByteArray()),Identity.hash("synthetic actor".toByteArray()),"device-a","draft-a")
        init {assumeTrue(BuildConfig.DEBUG && android.os.Build.HARDWARE in setOf("ranchu","goldfish"))}
        private val executor=Executors.newSingleThreadExecutor()
        private val busy=AtomicBoolean(false)
        val foreignIdle=AtomicBoolean(true)
        val extraAliases=mutableListOf<String>()
        fun store()=AdminEditorStore.isolatedForTest(context,namespace,alias)
        fun <T> worker(action:()->T):T {
            check(busy.compareAndSet(false,true))
            val future=try {executor.submit<T> {try {action()}finally {busy.set(false)}}}
            catch(error:Exception) {busy.set(false);throw error}
            return future.get(30,TimeUnit.SECONDS)
        }
        fun encrypt(plain:ByteArray):ByteArray=Cipher.getInstance("AES/GCM/NoPadding").run {
            init(Cipher.ENCRYPT_MODE,keyStore().getKey(alias,null))
            updateAAD("SYN443-ADMIN-EDITOR-1\n$namespace".toByteArray(Charsets.US_ASCII))
            byteArrayOf(1)+iv+doFinal(plain)
        }
        fun generateKey(name:String=alias) {
            check(!keyStore().containsAlias(name))
            KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,"AndroidKeyStore").apply {
                init(KeyGenParameterSpec.Builder(name,KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setKeySize(256)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setUserAuthenticationRequired(false).build())
            }.generateKey()
        }
        override fun close() {
            try {
                // A timed-out actual worker is not permission to delete its key/file.
                check(!busy.get() && foreignIdle.get()) {"fixture_owner_not_confirmed_idle"}
                worker {
                    (extraAliases+alias).forEach {name ->
                        check(name==alias || name.matches(Regex("syn443-editor-sentinel-test-[A-Za-z0-9_-]{43}")))
                        keyStore().deleteEntry(name)
                    }
                    directory.listFiles()?.forEach {entry ->
                        check(entry.name in setOf("editor.bin","editor.bin.bak","editor.bin.new","orphan"))
                        check(entry.isFile && entry.delete())
                    }
                    check(!directory.exists() || directory.delete())
                }
            }finally {executor.shutdownNow();check(executor.awaitTermination(5,TimeUnit.SECONDS))}
        }
    }
    companion object {
        private fun keyStore()=KeyStore.getInstance("AndroidKeyStore").apply {load(null)}
        private fun bytes(value:String)=value.toByteArray(Charsets.UTF_8)
        private fun id()=Identity.random()
        private fun replay()=bytes("synthetic owned replay context")
        /** Deliberately emits authenticated malformed binary without using the Store encoder. */
        private fun plain(owner:AdminEditorOwner,version:Int=1,revision:Long=1,closed:Int=0,proposal:ByteArray=bytes("draft"),
            present:Int=0,action:String="layers.draft.put",request:String=id(),body:ByteArray=bytes("{}"),proposalLength:Int=proposal.size,
            replayContext:ByteArray=replay(),contextLength:Int=replayContext.size):ByteArray {
            val buffer=ByteArrayOutputStream()
            DataOutputStream(buffer).use {output ->
                fun text(raw:String) {val encoded=raw.toByteArray(Charsets.US_ASCII);output.writeInt(encoded.size);output.write(encoded)}
                output.writeInt(0x53414531);output.writeInt(version);output.writeLong(revision);output.writeByte(closed)
                text(owner.serviceHash);text(owner.actor);text(owner.deviceId);text(owner.draftId)
                output.writeInt(proposalLength);output.write(proposal);output.writeByte(present)
                if(present==1) {
                    text(action);text(request);output.writeInt(body.size);output.write(body)
                    output.writeInt(contextLength);output.write(replayContext)
                }
            }
            return buffer.toByteArray()
        }
    }
    private fun failure(expected:Failure,action:()->Unit) {
        val error=assertThrows(AdminEditorStorageException::class.java,action)
        assertEquals(expected,error.reason);assertEquals(expected.name,error.message);assertNull(error.cause)
    }

    @Test fun explicitEditorCreationOwnsUtf8AndCiphertextWithoutCredentialOrKeyMutation() {
        Fixture().use {f -> f.worker {
            val store=f.store()
            failure(Failure.NOT_FOUND) {store.load(f.owner)}
            assertFalse(f.directory.exists());assertFalse(keyStore().containsAlias(f.alias))
            val protected=listOf("syn443-policy-v1","syn443-admin-store-v1","syn443-admin-editor-store-v1")
                .associateWith {keyStore().containsAlias(it)}
            val sentinel="syn443-editor-sentinel-test-"+Identity.random()
            f.extraAliases+=sentinel;f.generateKey(sentinel)
            val challenge=bytes("synthetic independent key challenge")
            val proof=Cipher.getInstance("AES/GCM/NoPadding").run {
                init(Cipher.ENCRYPT_MODE,keyStore().getKey(sentinel,null));iv+doFinal(challenge)
            }
            val input=bytes("Незавершённый редактор: {\"synthetic\":")
            val expected=input.copyOf();val created=store.create(f.owner,input)
            input.fill(0)
            assertEquals(1,created.version);assertEquals(1L,created.revision);assertFalse(created.closed);assertNull(created.pending)
            assertArrayEquals(expected,created.proposal)
            created.proposal.fill(0)
            assertArrayEquals(expected,f.store().load(f.owner).proposal)
            assertFalse(f.file.readBytes().toString(Charsets.ISO_8859_1).contains("synthetic"))
            assertNull(keyStore().getKey(f.alias,null).encoded)
            assertEquals(protected,protected.keys.associateWith {keyStore().containsAlias(it)})
            assertArrayEquals(challenge,Cipher.getInstance("AES/GCM/NoPadding").run {
                init(Cipher.DECRYPT_MODE,keyStore().getKey(sentinel,null),GCMParameterSpec(128,proof.copyOfRange(0,12)))
                doFinal(proof.copyOfRange(12,proof.size))
            })
            for(value in listOf(f.owner.toString(),created.toString())) {
                assertTrue(value.contains("[redacted]"));assertFalse(value.contains(f.owner.actor));assertFalse(value.contains("device-a"))
            }
        }}
    }

    @Test fun pendingEnvelopeSurvivesLostAckAndBlocksEditCloseOrReplacementUntilExactResolution() {
        Fixture().use {f -> f.worker {
            val store=f.store();val created=store.create(f.owner,bytes("old draft"))
            val body=bytes("{\"request\":\"synthetic\"}");val savedBody=body.copyOf();val request=id()
            val context=replay();val savedContext=context.copyOf()
            val held=store.preparePending(created,"layers.draft.put",request,body,context)
            body.fill(0);context.fill(0);held.pending!!.body.fill(0);held.pending.replayContext.fill(0)
            val reopened=f.store().load(f.owner);val pending=checkNotNull(reopened.pending)
            assertEquals(held,reopened);assertEquals(request,pending.requestId);assertArrayEquals(savedBody,pending.body)
            assertArrayEquals(savedContext,pending.replayContext)
            assertTrue(pending.bodySha256.matches(Regex("[a-f0-9]{64}")));assertEquals("AdminEditorPending([redacted])",pending.toString())
            val frame=f.file.readBytes()
            failure(Failure.PENDING) {store.edit(reopened,bytes("unsent replacement"))}
            failure(Failure.PENDING) {store.close(reopened)}
            failure(Failure.PENDING) {store.preparePending(reopened,"layers.draft.put",request,savedBody,savedContext)}
            failure(Failure.PENDING) {store.preparePending(reopened,"layers.draft.put",request,savedBody,bytes("different replay context"))}
            failure(Failure.PENDING) {store.preparePending(reopened,"publish",id(),bytes("other body"),replay())}
            val foreignPending=AdminEditorPending(pending.action,request,savedBody,bytes("different replay context"))
            assertNotEquals(pending,foreignPending)
            val foreignContextRecord=AdminEditorRecord(reopened.revision,reopened.owner,reopened.proposal,foreignPending)
            failure(Failure.STALE) {store.resolve(foreignContextRecord,request,pending.bodySha256,bytes("remote draft"))}
            failure(Failure.ALREADY_EXISTS) {store.create(f.owner.copy(draftId="draft-b"),bytes("other draft"))}
            failure(Failure.STALE) {store.resolve(reopened,id(),pending.bodySha256,bytes("remote draft"))}
            failure(Failure.INVALID) {store.resolve(reopened,request,"G".repeat(64),bytes("remote draft"))}
            val wrongHash=if(pending.bodySha256=="0".repeat(64))"1".repeat(64) else "0".repeat(64)
            failure(Failure.STALE) {store.resolve(reopened,request,wrongHash,bytes("remote draft"))}
            assertArrayEquals(frame,f.file.readBytes())
            assertArrayEquals(savedContext,f.store().load(f.owner).pending!!.replayContext)
            val replacement=bytes("verified saved draft");val expected=replacement.copyOf()
            val resolved=store.resolve(reopened,request,pending.bodySha256,replacement);replacement.fill(0)
            assertEquals(reopened.revision+1,resolved.revision);assertNull(resolved.pending)
            assertArrayEquals(expected,resolved.proposal);assertEquals(resolved,f.store().load(f.owner))
            failure(Failure.STALE) {store.resolve(reopened,request,pending.bodySha256,bytes("replayed result"))}
            failure(Failure.INVALID) {store.resolve(resolved,request,pending.bodySha256,expected)}
            assertEquals(resolved,store.load(f.owner))
        }}
    }

    @Test fun actualConcurrentCasAndForeignOwnersCannotReplaceTheSingleEditor() {
        Fixture().use {f ->
            val original=f.worker {f.store().create(f.owner,bytes("initial"))}
            val start=CountDownLatch(1);val pool=Executors.newFixedThreadPool(2)
            f.foreignIdle.set(false)
            try {
                val results=listOf("writer-a","writer-b").map {value -> pool.submit<Pair<AdminEditorRecord?,Failure?>> {
                    check(start.await(10,TimeUnit.SECONDS))
                    try {f.store().edit(original,bytes(value)) to null}
                    catch(error:AdminEditorStorageException) {null to error.reason}
                }}
                start.countDown();val completed=results.map {it.get(20,TimeUnit.SECONDS)}
                assertEquals(1,completed.count {it.first!=null});assertEquals(listOf(Failure.STALE),completed.mapNotNull {it.second})
                val winner=checkNotNull(completed.single {it.first!=null}.first)
                f.worker {
                    assertEquals(original.revision+1,winner.revision);assertEquals(winner,f.store().load(f.owner))
                    val frame=f.file.readBytes()
                    for(foreign in listOf(f.owner.copy(serviceHash=Identity.hash(bytes("another service"))),
                        f.owner.copy(actor=Identity.hash(bytes("another actor"))),f.owner.copy(deviceId="device-b"),f.owner.copy(draftId="draft-b"))) {
                        failure(Failure.OWNER_MISMATCH) {f.store().load(foreign)}
                        failure(Failure.ALREADY_EXISTS) {f.store().create(foreign,bytes("other"))}
                    }
                    failure(Failure.STALE) {f.store().edit(original,bytes("stale"))}
                    assertArrayEquals(frame,f.file.readBytes())
                }
            }finally {
                start.countDown();pool.shutdownNow()
                val terminated=pool.awaitTermination(10,TimeUnit.SECONDS)
                f.foreignIdle.set(terminated);check(terminated)
            }
        }
    }

    @Test fun ownedRecoveryDiscoversFullDurableDraftAndPendingWithoutIdsOrMutation() {
        Fixture().use {f -> f.worker {
            val store=f.store()
            assertNull(store.recoverOwned(f.owner.serviceHash,f.owner.actor))
            assertFalse(f.directory.exists());assertFalse(keyStore().containsAlias(f.alias))
            val created=store.create(f.owner,bytes("owned unfinished proposal: {"))
            val frame=f.file.readBytes()
            val recovered=checkNotNull(f.store().recoverOwned(f.owner.serviceHash,f.owner.actor))
            assertEquals(created,recovered);assertEquals("device-a",recovered.owner.deviceId)
            assertEquals("draft-a",recovered.owner.draftId);assertFalse(recovered.closed)
            recovered.proposal.fill(0)
            assertEquals(created,f.store().recoverOwned(f.owner.serviceHash,f.owner.actor))
            assertArrayEquals(frame,f.file.readBytes())
            val body=bytes("{\"synthetic\":\"exact pending body\"}");val context=replay();val request=id()
            val held=store.preparePending(recovered,"layers.draft.put",request,body,context)
            val pendingFrame=f.file.readBytes()
            val restored=checkNotNull(f.store().recoverOwned(f.owner.serviceHash,f.owner.actor))
            assertEquals(held,restored);val pending=checkNotNull(restored.pending)
            assertEquals(request,pending.requestId);assertArrayEquals(body,pending.body)
            assertArrayEquals(context,pending.replayContext);assertEquals(held.pending!!.bodySha256,pending.bodySha256)
            restored.proposal.fill(0);pending.body.fill(0);pending.replayContext.fill(0)
            assertEquals(held,f.store().recoverOwned(f.owner.serviceHash,f.owner.actor))
            failure(Failure.PENDING) {store.edit(restored,bytes("cannot replace pending"))}
            failure(Failure.PENDING) {store.close(restored)}
            assertArrayEquals(pendingFrame,f.file.readBytes());assertTrue(keyStore().containsAlias(f.alias))
            val resolved=store.resolve(restored,request,pending.bodySha256,bytes("verified saved proposal"))
            assertEquals(held.revision+1,resolved.revision);assertNull(resolved.pending)
            assertEquals(resolved,f.store().recoverOwned(f.owner.serviceHash,f.owner.actor))
            failure(Failure.STALE) {store.edit(recovered,bytes("stale pre-restart record"))}
        }}
    }

    @Test fun ownedRecoveryRejectsForeignOrNoncanonicalAccountsBeforeExposingTombstoneState() {
        Fixture().use {f -> f.worker {
            val store=f.store();val created=store.create(f.owner,bytes("private owned proposal"))
            val foreignService=Identity.hash(bytes("foreign synthetic service"))
            val foreignActor=Identity.hash(bytes("foreign synthetic actor"))
            fun denied() {
                val frame=f.file.readBytes()
                for((service,actor) in listOf(foreignService to f.owner.actor,f.owner.serviceHash to foreignActor,
                    foreignService to foreignActor)) {
                    failure(Failure.OWNER_MISMATCH) {store.recoverOwned(service,actor)}
                    assertArrayEquals(frame,f.file.readBytes())
                }
                for(invalid in listOf("", "bad", "A".repeat(42)+"B",f.owner.actor+"=")) {
                    failure(Failure.INVALID) {store.recoverOwned(invalid,f.owner.actor)}
                    failure(Failure.INVALID) {store.recoverOwned(f.owner.serviceHash,invalid)}
                    assertArrayEquals(frame,f.file.readBytes())
                }
            }
            denied()
            val pending=store.preparePending(created,"publish",id(),bytes("{\"synthetic\":true}"),replay())
            denied()
            val active=store.resolve(pending,pending.pending!!.requestId,pending.pending.bodySha256,pending.proposal)
            val closed=store.close(active);val closedFrame=f.file.readBytes()
            denied()
            assertNull(store.recoverOwned(f.owner.serviceHash,f.owner.actor))
            assertEquals(closed,store.load(f.owner));assertArrayEquals(closedFrame,f.file.readBytes())
            assertTrue(keyStore().containsAlias(f.alias))
            assertEquals(setOf("editor.bin"),checkNotNull(f.directory.listFiles()).map {it.name}.toSet())
        }}
    }

    @Test fun ownedRecoveryPreservesCorruptFramesAndMissingKeysWithoutResetOrOwnerDisclosure() {
        Fixture().use {f -> f.worker {
            val store=f.store();store.create(f.owner,bytes("durable proposal"));val authentic=f.file.readBytes()
            val malformed=listOf(authentic.copyOf(12),ByteArray(AdminEditorStore.MAX_FRAME+1),
                authentic.copyOf().apply {this[lastIndex]=(this[lastIndex].toInt() xor 1).toByte()},
                f.encrypt(plain(f.owner,present=1,action="roles.grant")))
            for(frame in malformed) {
                f.file.writeBytes(frame)
                failure(Failure.CORRUPT) {store.recoverOwned(f.owner.serviceHash,f.owner.actor)}
                failure(Failure.CORRUPT) {store.recoverOwned(Identity.hash(bytes("unknown service")),Identity.hash(bytes("unknown actor")))}
                failure(Failure.INVALID) {store.recoverOwned("bad",f.owner.actor)}
                assertArrayEquals(frame,f.file.readBytes());assertTrue(keyStore().containsAlias(f.alias))
            }
            f.file.writeBytes(authentic);keyStore().deleteEntry(f.alias)
            failure(Failure.CORRUPT) {store.recoverOwned(f.owner.serviceHash,f.owner.actor)}
            assertFalse(keyStore().containsAlias(f.alias));assertArrayEquals(authentic,f.file.readBytes())
        }}
    }

    @Test fun ownedRecoveryRejectsMainAndBinderBeforeReadingEvenAnInvalidAccount() {
        Fixture().use {f ->
            val store=f.worker {f.store()}
            val created=f.worker {store.create(f.owner,bytes("preserved worker-only proposal"))}
            val frame=f.file.readBytes()
            fun guarded() {
                failure(Failure.WRONG_THREAD) {store.recoverOwned(f.owner.serviceHash,f.owner.actor)}
                failure(Failure.WRONG_THREAD) {store.recoverOwned("bad","bad")}
            }
            InstrumentationRegistry.getInstrumentation().runOnMainSync {guarded()}
            val binder=Executors.newSingleThreadExecutor {action -> Thread(action,"Binder:admin-editor-recovery-fixture")}
            f.foreignIdle.set(false)
            try {binder.submit {guarded()}.get(10,TimeUnit.SECONDS)}
            finally {
                binder.shutdownNow();val terminated=binder.awaitTermination(5,TimeUnit.SECONDS)
                f.foreignIdle.set(terminated);check(terminated)
            }
            f.worker {
                assertEquals(created,store.recoverOwned(f.owner.serviceHash,f.owner.actor))
                assertArrayEquals(frame,f.file.readBytes());assertTrue(keyStore().containsAlias(f.alias))
            }
        }
    }

    @Test fun closedTombstoneAllowsNextOwnerOnlyWithoutPendingAndPreservesRevisionAndAesKey() {
        Fixture().use {f -> f.worker {
            val store=f.store();val first=store.create(f.owner,ByteArray(0))
            val pending=store.preparePending(first,"layers.draft.discard",id(),bytes("{\"synthetic\":true}"),replay())
            failure(Failure.PENDING) {store.close(pending)}
            failure(Failure.ALREADY_EXISTS) {store.create(f.owner.copy(draftId="next"),ByteArray(0))}
            val active=store.resolve(pending,pending.pending!!.requestId,pending.pending.bodySha256,pending.proposal)
            val keyProof=f.encrypt(bytes("same store key"))
            val closed=store.close(active)
            assertEquals(active.revision+1,closed.revision);assertTrue(closed.closed)
            assertEquals(0,closed.proposal.size);assertNull(closed.pending);assertEquals(closed,f.store().load(f.owner))
            assertTrue(f.file.isFile);assertTrue(keyStore().containsAlias(f.alias))
            failure(Failure.INVALID) {store.edit(closed,bytes("revive"))}
            failure(Failure.INVALID) {store.close(closed)}
            val nextOwner=f.owner.copy(deviceId="device-next",draftId="draft-next")
            val next=f.store().create(nextOwner,bytes("new editor"))
            assertEquals(closed.revision+1,next.revision);assertEquals(nextOwner,next.owner);assertFalse(next.closed)
            failure(Failure.OWNER_MISMATCH) {store.load(f.owner)}
            assertEquals(next,store.load(nextOwner))
            assertArrayEquals(bytes("same store key"),Cipher.getInstance("AES/GCM/NoPadding").run {
                init(Cipher.DECRYPT_MODE,keyStore().getKey(f.alias,null),GCMParameterSpec(128,keyProof.copyOfRange(1,13)))
                updateAAD("SYN443-ADMIN-EDITOR-1\n${f.namespace}".toByteArray(Charsets.US_ASCII))
                doFinal(keyProof.copyOfRange(13,keyProof.size))
            })
        }}
    }

    @Test fun textEnvelopeAndEncryptedFrameBoundsRejectBeforeAnyPersistentReplacement() {
        Fixture().use {f -> f.worker {
            val store=f.store();val max=ByteArray(AdminEditorStore.MAX_TEXT) {'x'.code.toByte()}
            val created=store.create(f.owner,max)
            val maxContext=ByteArray(AdminEditorStore.MAX_REPLAY_CONTEXT) {'c'.code.toByte()}
            val held=store.preparePending(created,"publish",id(),max,maxContext)
            assertArrayEquals(max,held.proposal);assertArrayEquals(max,held.pending!!.body)
            assertArrayEquals(maxContext,held.pending.replayContext)
            assertTrue(f.file.length()<=AdminEditorStore.MAX_FRAME)
            assertEquals(held,store.load(f.owner));val authentic=f.file.readBytes()
            for(value in listOf(ByteArray(AdminEditorStore.MAX_TEXT+1),byteArrayOf(0xc3.toByte(),0x28))) {
                failure(Failure.INVALID) {store.edit(held,value)}
                failure(Failure.INVALID) {store.resolve(held,held.pending.requestId,held.pending.bodySha256,value)}
                failure(Failure.INVALID) {store.preparePending(held,"publish",id(),value,replay())}
                assertArrayEquals(authentic,f.file.readBytes())
            }
            for(value in listOf(ByteArray(0),ByteArray(AdminEditorStore.MAX_REPLAY_CONTEXT+1),byteArrayOf(0xc3.toByte(),0x28))) {
                failure(Failure.INVALID) {store.preparePending(held,"publish",id(),bytes("{}"),value)}
                assertArrayEquals(authentic,f.file.readBytes())
            }
            val badFrames=listOf(ByteArray(0),authentic.copyOf(12),authentic.copyOf(29),
                ByteArray(AdminEditorStore.MAX_FRAME+1),authentic.copyOf().apply {this[0]=2},
                authentic.copyOf().apply {this[lastIndex]=(this[lastIndex].toInt() xor 1).toByte()})
            for(frame in badFrames) {
                f.file.writeBytes(frame)
                failure(Failure.CORRUPT) {store.load(f.owner)}
                failure(Failure.CORRUPT) {store.create(f.owner,bytes("cannot reset"))}
                assertArrayEquals(frame,f.file.readBytes());assertTrue(keyStore().containsAlias(f.alias))
            }
        }}
    }

    @Test fun authenticatedBinaryGrammarIsClosedBoundedAndNeverParsesProposalAsJson() {
        Fixture().use {f -> f.worker {
            val store=f.store();store.create(f.owner,bytes("initial"))
            val invalid=listOf(plain(f.owner,version=2),plain(f.owner,revision=0),
                plain(f.owner,revision=9_007_199_254_740_992L),plain(f.owner,closed=2),plain(f.owner,present=2),
                plain(f.owner,closed=1),plain(f.owner,closed=1,proposal=ByteArray(0),present=1),
                plain(f.owner,proposalLength=-1),plain(f.owner,proposalLength=Int.MAX_VALUE),
                plain(f.owner,proposal=byteArrayOf(0xc3.toByte(),0x28)),plain(f.owner)+byteArrayOf(0),
                plain(f.owner.copy(serviceHash="A".repeat(42)+"B")),plain(f.owner.copy(actor="bad")),
                plain(f.owner.copy(deviceId="../device")),plain(f.owner.copy(draftId="")),
                plain(f.owner,present=1,action="roles.grant"),plain(f.owner,present=1,request="x".repeat(23)),
                plain(f.owner,present=1,request="x".repeat(129)),plain(f.owner,present=1,body=ByteArray(0)),
                plain(f.owner,present=1,body=byteArrayOf(0xff.toByte())),
                plain(f.owner,present=1,replayContext=ByteArray(0)),
                plain(f.owner,present=1,replayContext=ByteArray(AdminEditorStore.MAX_REPLAY_CONTEXT+1)),
                plain(f.owner,present=1,replayContext=byteArrayOf(0xff.toByte())),
                plain(f.owner,present=1,contextLength=-1),plain(f.owner,present=1,contextLength=Int.MAX_VALUE),
                plain(f.owner,present=1).dropLast(1).toByteArray())
            for(raw in invalid) {
                val frame=f.encrypt(raw);f.file.writeBytes(frame)
                failure(Failure.CORRUPT) {store.load(f.owner)}
                assertArrayEquals(frame,f.file.readBytes());raw.fill(0)
            }
            val valid=plain(f.owner,proposal=bytes("not JSON: {\"unfinished\":\uD83D\uDE00"))
            f.file.writeBytes(f.encrypt(valid));val record=store.load(f.owner)
            assertArrayEquals(bytes("not JSON: {\"unfinished\":\uD83D\uDE00"),record.proposal)
            val active=store.edit(record,ByteArray(0))
            val beforeInvalid=f.file.readBytes()
            for(action in listOf("roles.grant","", "layers.draft.Put")) {
                failure(Failure.INVALID) {store.preparePending(active,action,id(),bytes("{}"),replay())}
            }
            for(request in listOf("x".repeat(23),"x".repeat(129),"x".repeat(24)+"/")) {
                failure(Failure.INVALID) {store.preparePending(active,"publish",request,bytes("{}"),replay())}
            }
            failure(Failure.INVALID) {store.preparePending(active,"publish",id(),ByteArray(0),replay())}
            for(owner in listOf(f.owner.copy(serviceHash="A".repeat(42)+"B"),f.owner.copy(actor="bad"),
                f.owner.copy(deviceId="../device"),f.owner.copy(draftId=""))) {
                failure(Failure.INVALID) {store.load(owner)}
                failure(Failure.INVALID) {store.create(owner,ByteArray(0))}
            }
            assertArrayEquals(beforeInvalid,f.file.readBytes())
            for(action in listOf("layers.draft.put","layers.draft.discard","preview.request","publish")) {
                val pending=store.preparePending(store.load(f.owner),action,id(),bytes("{}"),replay())
                assertEquals(action,pending.pending!!.action)
                store.resolve(pending,pending.pending.requestId,pending.pending.bodySha256,pending.proposal)
            }
            assertTrue(store.load(f.owner).revision>active.revision)
            for(closed in listOf(0,1)) {
                val limit=f.encrypt(plain(f.owner,revision=9_007_199_254_740_991L,closed=closed,proposal=ByteArray(0)))
                f.file.writeBytes(limit);val last=store.load(f.owner)
                failure(Failure.INVALID) {if(last.closed)store.create(f.owner.copy(draftId="next"),ByteArray(0)) else store.edit(last,ByteArray(0))}
                assertArrayEquals(limit,f.file.readBytes())
            }
        }}
    }

    @Test fun missingAesOrNamespaceOrOrphanNeverCreatesAFreshEditorAndKnownBackupOnlyRecoversCommit() {
        Fixture().use {f -> f.worker {
            val store=f.store();store.create(f.owner,bytes("preserved"));val frame=f.file.readBytes()
            keyStore().deleteEntry(f.alias)
            failure(Failure.CORRUPT) {store.load(f.owner)}
            failure(Failure.CORRUPT) {store.create(f.owner,bytes("reset"))}
            assertFalse(keyStore().containsAlias(f.alias));assertArrayEquals(frame,f.file.readBytes())
        }}
        Fixture().use {f -> f.worker {
            f.generateKey();assertFalse(f.directory.exists())
            failure(Failure.CORRUPT) {f.store().load(f.owner)}
            failure(Failure.CORRUPT) {f.store().create(f.owner,bytes("reset"))}
            assertFalse(f.directory.exists());assertTrue(keyStore().containsAlias(f.alias))
        }}
        for(entry in listOf("empty","editor.bin.new","orphan"))Fixture().use {f -> f.worker {
            assertTrue(f.directory.mkdir())
            val orphan=if(entry=="empty")null else File(f.directory,entry).apply {writeBytes(ByteArray(40))}
            failure(Failure.CORRUPT) {f.store().load(f.owner)}
            failure(Failure.CORRUPT) {f.store().create(f.owner,ByteArray(0))}
            assertFalse(keyStore().containsAlias(f.alias));assertTrue(orphan==null || orphan.isFile)
        }}
        Fixture().use {f -> f.worker {
            val committed=f.store().create(f.owner,bytes("committed owner"));val frame=f.file.readBytes()
            val backup=File(f.directory,"editor.bin.bak").apply {writeBytes(frame)}
            f.file.writeBytes(ByteArray(12))
            assertEquals(committed,f.store().load(f.owner));assertArrayEquals(frame,f.file.readBytes())
            assertFalse(backup.exists())
            backup.writeBytes(frame);assertTrue(f.file.delete())
            assertEquals(committed,f.store().load(f.owner));assertArrayEquals(frame,f.file.readBytes())
            assertFalse(backup.exists())
            File(f.directory,"editor.bin.new").writeBytes(frame)
            failure(Failure.CORRUPT) {f.store().load(f.owner)}
            assertTrue(File(f.directory,"editor.bin.new").isFile)
        }}
    }

    @Test fun namespaceBindingThreadGuardsAndTestFactoryCannotExposeOrResetAnotherEditor() {
        Fixture().use {first -> Fixture(first.alias).use {second ->
            first.worker {first.store().create(first.owner,bytes("private owned proposal"))}
            second.worker {
                assertTrue(second.directory.mkdir());second.file.writeBytes(first.file.readBytes())
                failure(Failure.CORRUPT) {second.store().load(first.owner)}
                failure(Failure.CORRUPT) {second.store().create(first.owner,ByteArray(0))}
            }
            val store=first.store();val record=first.worker {store.load(first.owner)};val frame=first.file.readBytes()
            fun guarded() {
                failure(Failure.WRONG_THREAD) {AdminEditorStore(first.context)}
                failure(Failure.WRONG_THREAD) {first.store()}
                failure(Failure.WRONG_THREAD) {AdminEditorPending("publish",id(),bytes("{}"),replay())}
                failure(Failure.WRONG_THREAD) {store.load(first.owner)}
                failure(Failure.WRONG_THREAD) {store.create(first.owner,ByteArray(0))}
                failure(Failure.WRONG_THREAD) {store.edit(record,ByteArray(0))}
                failure(Failure.WRONG_THREAD) {store.preparePending(record,"publish",id(),bytes("{}"),replay())}
                failure(Failure.WRONG_THREAD) {store.resolve(record,id(),"0".repeat(64),ByteArray(0))}
                failure(Failure.WRONG_THREAD) {store.close(record)}
            }
            InstrumentationRegistry.getInstrumentation().runOnMainSync {guarded()}
            val binder=Executors.newSingleThreadExecutor {action -> Thread(action,"Binder:admin-editor-fixture")}
            try {binder.submit {guarded()}.get(10,TimeUnit.SECONDS)}
            finally {binder.shutdownNow();check(binder.awaitTermination(5,TimeUnit.SECONDS))}
            assertThrows(IllegalArgumentException::class.java) {
                AdminEditorStore.isolatedForTest(first.context,first.namespace,"syn443-admin-editor-store-v1")
            }
            for(namespace in listOf("admin-editor-v1","../foreign","admin-editor-test-invalid")) {
                assertThrows(IllegalArgumentException::class.java) {AdminEditorStore.isolatedForTest(first.context,namespace,first.alias)}
            }
            first.worker {assertEquals(record,store.load(first.owner));assertArrayEquals(frame,first.file.readBytes())}
        }}
    }
}
