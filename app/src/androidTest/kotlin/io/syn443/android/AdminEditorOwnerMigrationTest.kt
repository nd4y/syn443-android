package io.syn443.android

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.platform.app.InstrumentationRegistry
import io.syn443.android.vpn.AdminEditorOwner
import io.syn443.android.vpn.AdminEditorRecord
import io.syn443.android.vpn.AdminEditorStorageException
import io.syn443.android.vpn.AdminEditorStorageFailure as Failure
import io.syn443.android.vpn.AdminEditorStore
import io.syn443.identity.Identity
import org.junit.Assert.*
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
import javax.crypto.spec.GCMParameterSpec

/** Real isolated Keystore/AtomicFile CAS only. No identities, HTTP or VPN commands. */
class AdminEditorOwnerMigrationTest {
    private class Fixture:Closeable {
        val context=ApplicationProvider.getApplicationContext<Context>()
        val namespace="admin-editor-test-"+UUID.randomUUID().toString().replace("-","")
        val alias="syn443-admin-editor-test-"+Identity.random()
        val directory=File(context.noBackupFilesDir,namespace)
        val file=File(directory,"editor.bin")
        val legacy=Identity.hash(bytes("synthetic current full discovery"))
        val stable=Identity.hash(bytes("synthetic stable editor authority"))
        val owner=AdminEditorOwner(legacy,Identity.hash(bytes("synthetic actor")),"device-a","draft-a")
        init {check(BuildConfig.DEBUG && android.os.Build.HARDWARE in setOf("ranchu","goldfish")) {"emulator_fixture_required"}}
        private val executor=Executors.newSingleThreadExecutor()
        private val busy=AtomicBoolean(false)
        val foreignIdle=AtomicBoolean(true)
        fun store()=AdminEditorStore.isolatedForTest(context,namespace,alias)
        fun <T> worker(action:()->T):T {
            check(busy.compareAndSet(false,true))
            val future=try {executor.submit<T> {try {action()}finally {busy.set(false)}}}
            catch(error:Exception) {busy.set(false);throw error}
            return future.get(30,TimeUnit.SECONDS)
        }
        fun encrypt(plain:ByteArray)=Cipher.getInstance("AES/GCM/NoPadding").run {
            init(Cipher.ENCRYPT_MODE,keyStore().getKey(alias,null));updateAAD(aad())
            byteArrayOf(1)+iv+doFinal(plain)
        }
        fun decrypt(frame:ByteArray)=Cipher.getInstance("AES/GCM/NoPadding").run {
            init(Cipher.DECRYPT_MODE,keyStore().getKey(alias,null),GCMParameterSpec(128,frame.copyOfRange(1,13)))
            updateAAD(aad());doFinal(frame.copyOfRange(13,frame.size))
        }
        private fun aad()="SYN443-ADMIN-EDITOR-1\n$namespace".toByteArray(Charsets.US_ASCII)
        override fun close() {
            try {
                check(!busy.get() && foreignIdle.get()) {"fixture_owner_not_confirmed_idle"}
                worker {
                    keyStore().deleteEntry(alias)
                    directory.listFiles()?.forEach {entry->
                        check(entry.name in setOf("editor.bin","editor.bin.bak","editor.bin.new") && entry.isFile)
                        check(entry.delete())
                    }
                    check(!directory.exists() || directory.delete())
                }
            }finally {executor.shutdownNow();check(executor.awaitTermination(5,TimeUnit.SECONDS))}
        }
    }
    companion object {
        private fun bytes(value:String)=value.toByteArray(Charsets.UTF_8)
        private fun keyStore()=KeyStore.getInstance("AndroidKeyStore").apply {load(null)}
        private fun failure(expected:Failure,action:()->Unit) {
            val error=assertThrows(AdminEditorStorageException::class.java,action)
            assertEquals(expected,error.reason);assertNull(error.cause)
        }
        private fun maxRevision(owner:AdminEditorOwner):ByteArray {
            val buffer=ByteArrayOutputStream()
            DataOutputStream(buffer).use {out->
                fun text(value:String) {val raw=bytes(value);out.writeInt(raw.size);out.write(raw)}
                out.writeInt(0x53414531);out.writeInt(1);out.writeLong(9_007_199_254_740_991L);out.writeByte(0)
                text(owner.serviceHash);text(owner.actor);text(owner.deviceId);text(owner.draftId)
                val proposal=bytes("unfinished private proposal: {");out.writeInt(proposal.size);out.write(proposal);out.writeByte(0)
            }
            return buffer.toByteArray()
        }
    }

    @Test fun exactCurrentLegacyMigrationPreservesPendingBytesCasAndExistingAesKey() {
        Fixture().use {f->f.worker {
            val store=f.store();val created=store.create(f.owner,bytes("unfinished private proposal: {"))
            val body=bytes("{\"synthetic\":\"exact original\"}");val replay=bytes("exact synthetic replay context")
            val held=store.preparePending(created,"publish",Identity.random(),body,replay)
            val frame=f.file.readBytes();val keyProof=f.encrypt(bytes("same AES key"))
            val migrated=checkNotNull(f.store().recoverOwned(f.stable,f.owner.actor,f.legacy))
            assertEquals(held.revision+1,migrated.revision);assertEquals(f.owner.copy(serviceHash=f.stable),migrated.owner)
            assertTrue(held.proposal.contentEquals(migrated.proposal));assertFalse(migrated.closed)
            val pending=checkNotNull(migrated.pending);val old=checkNotNull(held.pending)
            assertEquals(old.action,pending.action);assertEquals(old.requestId,pending.requestId);assertEquals(old.bodySha256,pending.bodySha256)
            assertTrue(body.contentEquals(pending.body));assertTrue(replay.contentEquals(pending.replayContext))
            assertFalse(frame.contentEquals(f.file.readBytes()));assertTrue(bytes("same AES key").contentEquals(f.decrypt(keyProof)))
            val after=f.file.readBytes()
            assertEquals(migrated,f.store().recoverOwned(f.stable,f.owner.actor,f.legacy))
            assertTrue(after.contentEquals(f.file.readBytes()))
            failure(Failure.OWNER_MISMATCH){store.load(f.owner)}
            failure(Failure.PENDING){store.edit(migrated,bytes("replace unknown"))}
            failure(Failure.PENDING){store.close(migrated)}
            assertEquals(setOf("editor.bin"),checkNotNull(f.directory.listFiles()).map {it.name}.toSet())
        }}
    }

    @Test fun stableRecoveryAndClosedTombstonesStayReadOnlyUntilAnExplicitNewCreate() {
        Fixture().use {f->f.worker {
            val store=f.store();val owner=f.owner.copy(serviceHash=f.stable)
            val created=store.create(owner,bytes("private proposal"));val frame=f.file.readBytes()
            assertEquals(created,store.recoverOwned(f.stable,owner.actor,f.legacy));assertTrue(frame.contentEquals(f.file.readBytes()))
            val proof=f.encrypt(bytes("same store key"));val closed=store.close(created);val tombstone=f.file.readBytes()
            assertNull(store.recoverOwned(f.stable,owner.actor,f.legacy));assertTrue(tombstone.contentEquals(f.file.readBytes()))
            failure(Failure.OWNER_MISMATCH){store.recoverOwned(f.legacy,owner.actor,f.stable)}
            assertTrue(tombstone.contentEquals(f.file.readBytes()))
            val nextOwner=owner.copy(serviceHash=Identity.random(),deviceId="device-b",draftId="draft-b")
            val next=store.create(nextOwner,ByteArray(0))
            assertEquals(closed.revision+1,next.revision);assertEquals(nextOwner,next.owner)
            assertTrue(bytes("same store key").contentEquals(f.decrypt(proof)))
        }}
    }

    @Test fun unknownPastFloorsForeignActorsAndMissingCurrentProofNeverRebindOrExposePending() {
        Fixture().use {f->f.worker {
            val store=f.store();val created=store.create(f.owner,bytes("owned proposal"))
            val held=store.preparePending(created,"layers.draft.put",Identity.random(),bytes("{}"),bytes("owned context"))
            val frame=f.file.readBytes()
            for((actor,legacy) in listOf(f.owner.actor to "",f.owner.actor to Identity.hash(bytes("different current floor")),Identity.random() to f.legacy)) {
                failure(Failure.OWNER_MISMATCH){store.recoverOwned(f.stable,actor,legacy)}
                assertTrue(frame.contentEquals(f.file.readBytes()))
            }
            for(bad in listOf("bad",f.legacy+"=",f.legacy.dropLast(1)+"B")) {
                failure(Failure.INVALID){store.recoverOwned(f.stable,f.owner.actor,bad)}
                assertTrue(frame.contentEquals(f.file.readBytes()))
            }
            assertEquals(held,store.load(f.owner));assertTrue(keyStore().containsAlias(f.alias))
            failure(Failure.ALREADY_EXISTS){store.create(f.owner.copy(serviceHash=f.stable),ByteArray(0))}
            assertTrue(frame.contentEquals(f.file.readBytes()))
        }}
    }

    @Test fun concurrentRecoveryMigratesOnceAndOldSnapshotsCannotResolveTheNewOwner() {
        Fixture().use {f->
            val held=f.worker {
                val store=f.store();val created=store.create(f.owner,bytes("durable proposal"))
                store.preparePending(created,"publish",Identity.random(),bytes("{}"),bytes("same replay"))
            }
            val pool=Executors.newFixedThreadPool(2);val ready=CountDownLatch(2);val release=CountDownLatch(1)
            f.foreignIdle.set(false)
            try {
                val futures=(1..2).map {pool.submit<AdminEditorRecord> {
                    ready.countDown();check(release.await(10,TimeUnit.SECONDS))
                    checkNotNull(f.store().recoverOwned(f.stable,f.owner.actor,f.legacy))
                }}
                check(ready.await(10,TimeUnit.SECONDS));release.countDown()
                val results=futures.map {it.get(20,TimeUnit.SECONDS)}
                assertEquals(results[0],results[1]);assertEquals(held.revision+1,results[0].revision)
                f.worker {
                    val store=f.store();val migrated=results[0];val frame=f.file.readBytes()
                    failure(Failure.OWNER_MISMATCH){store.edit(held,bytes("stale edit"))}
                    val pending=checkNotNull(held.pending)
                    failure(Failure.OWNER_MISMATCH){store.resolve(held,pending.requestId,pending.bodySha256,held.proposal)}
                    assertEquals(migrated,store.load(migrated.owner));assertTrue(frame.contentEquals(f.file.readBytes()))
                }
            }finally {
                release.countDown();pool.shutdownNow();val stopped=pool.awaitTermination(5,TimeUnit.SECONDS)
                f.foreignIdle.set(stopped);check(stopped)
            }
        }
    }

    @Test fun migrationRejectsWrongThreadsCounterExhaustionCorruptionAndLostAesWithoutReset() {
        Fixture().use {f->
            val store=f.worker {f.store().also {it.create(f.owner,bytes("owned proposal"))}}
            val initial=f.file.readBytes()
            InstrumentationRegistry.getInstrumentation().runOnMainSync {
                failure(Failure.WRONG_THREAD){store.recoverOwned(f.stable,f.owner.actor,f.legacy)}
            }
            val binder=Executors.newSingleThreadExecutor {r->Thread(r,"Binder:editor-migration-test")}
            f.foreignIdle.set(false)
            try {binder.submit {failure(Failure.WRONG_THREAD){store.recoverOwned(f.stable,f.owner.actor,f.legacy)}}.get(10,TimeUnit.SECONDS)}
            finally {binder.shutdownNow();val stopped=binder.awaitTermination(5,TimeUnit.SECONDS);f.foreignIdle.set(stopped);check(stopped)}
            assertTrue(initial.contentEquals(f.file.readBytes()))
            f.worker {
                val max=f.encrypt(maxRevision(f.owner));f.file.writeBytes(max)
                failure(Failure.INVALID){store.recoverOwned(f.stable,f.owner.actor,f.legacy)}
                assertTrue(max.contentEquals(f.file.readBytes()))
                val corrupt=initial.copyOf().apply {this[lastIndex]=(this[lastIndex].toInt() xor 1).toByte()};f.file.writeBytes(corrupt)
                failure(Failure.CORRUPT){store.recoverOwned(f.stable,f.owner.actor,f.legacy)}
                assertTrue(corrupt.contentEquals(f.file.readBytes()))
                f.file.writeBytes(initial);keyStore().deleteEntry(f.alias)
                failure(Failure.CORRUPT){store.recoverOwned(f.stable,f.owner.actor,f.legacy)}
                assertTrue(initial.contentEquals(f.file.readBytes()));assertFalse(keyStore().containsAlias(f.alias))
            }
        }
    }
}
