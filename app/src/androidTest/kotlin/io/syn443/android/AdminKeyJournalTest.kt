package io.syn443.android

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.platform.app.InstrumentationRegistry
import io.syn443.android.vpn.AdminKey
import io.syn443.android.vpn.AdminKeyJournal
import io.syn443.android.vpn.AdminKeyPhase as Phase
import io.syn443.android.vpn.AdminKeyRecord as Record
import io.syn443.android.vpn.AdminKeyStorageException
import io.syn443.android.vpn.AdminKeyStorageFailure
import io.syn443.android.vpn.DeviceKey
import io.syn443.identity.Identity
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.Closeable
import java.io.File
import java.security.KeyStore
import java.security.Signature
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec

/** Real Keystore/AtomicFile fixtures, never a production admin/device identity or synthetic trust root. */
class AdminKeyJournalTest {
    private class Fixture(sharedKey:String?=null):Closeable {
        val context=ApplicationProvider.getApplicationContext<Context>()
        val namespace="test-admin-"+UUID.randomUUID().toString().replace("-","")
        val encryptionAlias=sharedKey ?: "syn443-admin-store-test-"+Identity.random()
        val directory=File(context.noBackupFilesDir,"admin-login/$namespace")
        val file=File(directory,"owner.bin")
        val adminAliases=mutableListOf<String>()
        val deviceAliases=mutableListOf<String>()
        private val executor=Executors.newSingleThreadExecutor()
        init {assumeTrue(BuildConfig.DEBUG && android.os.Build.HARDWARE in setOf("ranchu","goldfish"))}
        fun journal()=AdminKeyJournal.isolatedForTest(context,namespace,encryptionAlias)
        fun <T> worker(action:()->T):T=executor.submit<T> {action()}.get(30,TimeUnit.SECONDS)
        fun alias()=AdminKey.newAlias().also {adminAliases+=it}
        fun reserve(journal:AdminKeyJournal=journal()):Record {
            val initial=journal.read()
            return journal.commit(initial,Record(revision=initial.revision+1,generation=initial.generation+1,
                phase=Phase.RESERVED,alias=alias()))
        }
        override fun close() {
            try {worker {
                adminAliases.forEach(AdminKey::deleteOwned)
                deviceAliases.forEach(DeviceKey::deleteOwned)
                keyStore().deleteEntry(encryptionAlias)
                directory.listFiles()?.forEach {file ->
                    check(file.name in setOf("owner.bin","owner.bin.bak","owner.bin.new","orphan"));check(file.delete())
                }
                check(!directory.exists() || directory.delete())
            }}finally {executor.shutdownNow();check(executor.awaitTermination(5,TimeUnit.SECONDS))}
        }
    }
    companion object {
        private fun keyStore()=KeyStore.getInstance("AndroidKeyStore").apply {load(null)}
    }
    private fun failure(reason:AdminKeyStorageFailure,block:()->Unit) {
        val error=assertThrows(AdminKeyStorageException::class.java,block)
        assertEquals(reason,error.reason);assertEquals(reason.name,error.message);assertNull(error.cause)
    }
    private fun next(record:Record,phase:Phase,generation:Long=record.generation,alias:String=record.alias)=
        record.copy(revision=record.revision+1,generation=generation,phase=phase,alias=alias)

    @Test fun adminOwnershipRetirementDeletesOnlyItsPersistedKeyAndPreservesDeviceSentinel() {
        Fixture().use {f -> f.worker {
            val journal=f.journal()
            assertEquals(Record(),journal.read());assertFalse(f.directory.exists())
            assertFalse(keyStore().containsAlias(f.encryptionAlias))
            val reserved=f.reserve(journal)
            val key=checkNotNull(AdminKey.createIfCurrent(reserved.alias) {journal.read()==reserved})
            val reopened=AdminKey.open(reserved.alias);val public=reopened.publicKey
            val input="synthetic admin request".toByteArray();val signature=reopened.sign(input)
            assertTrue(Signature.getInstance("SHA256withECDSA").run {initVerify(public);update(input);verify(signature)})
            assertNull(keyStore().getKey(reserved.alias,null).encoded)
            assertArrayEquals(key.publicKey.encoded,public.encoded)
            assertFalse(key.toString().contains(reserved.alias));assertFalse(reserved.toString().contains(reserved.alias))
            val sentinel=DeviceKey.create().also {f.deviceAliases+=it.alias}
            val sentinelPublic=sentinel.publicKey.encoded
            val browser=journal.commit(reserved,next(reserved,Phase.BROWSER))
            val active=journal.commit(browser,next(browser,Phase.AUTHENTICATED))
            val retiring=journal.commit(active,next(active,Phase.RETIRING,active.generation+1))
            assertEquals(retiring,f.journal().read());assertNotNull(AdminKey.open(retiring.alias).publicKey)
            assertThrows(IllegalArgumentException::class.java) {AdminKey.deleteOwned(sentinel.alias)}
            AdminKey.deleteOwned(retiring.alias)
            assertThrows(IllegalStateException::class.java) {AdminKey.open(retiring.alias)}
            val signedOut=journal.commit(retiring,next(retiring,Phase.SIGNED_OUT,alias=""))
            assertEquals(signedOut,f.journal().read());assertTrue(signedOut.alias.isEmpty())
            assertArrayEquals(sentinelPublic,DeviceKey.open(sentinel.alias).publicKey.encoded)
            val fresh=f.reserve(journal);assertNotEquals(reserved.alias,fresh.alias)
            assertEquals(signedOut.generation+1,fresh.generation)
        }}
    }

    @Test fun recreatedAdminPhaseRecordsContainNoCredentialsAndRequireExplicitOwnedRetirement() {
        for(phase in listOf(Phase.RESERVED,Phase.BROWSER,Phase.AUTHENTICATED))Fixture().use {f -> f.worker {
            val journal=f.journal();var record=f.reserve(journal)
            if(phase!=Phase.RESERVED) {
                assertNotNull(AdminKey.createIfCurrent(record.alias) {journal.read()==record})
                record=journal.commit(record,next(record,Phase.BROWSER))
                if(phase==Phase.AUTHENTICATED)record=journal.commit(record,next(record,phase))
            }
            val saved=f.file.readBytes();val reopened=f.journal()
            assertEquals(record,reopened.read());assertArrayEquals(saved,f.file.readBytes())
            val plain=Cipher.getInstance("AES/GCM/NoPadding").run {
                init(Cipher.DECRYPT_MODE,keyStore().getKey(f.encryptionAlias,null),GCMParameterSpec(128,saved.copyOfRange(1,13)))
                updateAAD("SYN443-ADMIN-KEY-JOURNAL-1\n${f.namespace}".toByteArray(Charsets.US_ASCII))
                doFinal(saved.copyOfRange(13,saved.size))
            }
            try {
                val fields=org.json.JSONObject(plain.toString(Charsets.UTF_8))
                assertEquals(setOf("version","revision","generation","phase","alias"),fields.keys().asSequence().toSet())
                assertEquals(phase.name,fields.getString("phase"))
                assertFalse(saved.toString(Charsets.ISO_8859_1).contains(record.alias))
            }finally {plain.fill(0)}
            if(phase==Phase.RESERVED)assertThrows(IllegalStateException::class.java) {AdminKey.open(record.alias)}
            else assertNotNull(AdminKey.open(record.alias).publicKey)
            val tombstone=reopened.commit(record,next(record,Phase.RETIRING,record.generation+1))
            assertEquals(record.alias,f.journal().read().alias)
            AdminKey.deleteOwned(tombstone.alias)
            val cleared=reopened.commit(tombstone,next(tombstone,Phase.SIGNED_OUT,alias=""))
            assertEquals(cleared,f.journal().read())
        }}
    }

    @Test fun adminJournalCasRejectsStaleWritersInvalidCountersAliasesAndPhaseShortcuts() {
        Fixture().use {f -> f.worker {
            val first=f.journal();val second=f.journal();val initial=first.read();val reserved=f.reserve(first)
            val encrypted=f.file.readBytes()
            failure(AdminKeyStorageFailure.STALE) {second.commit(initial,reserved)}
            for(invalid in listOf(next(reserved,Phase.AUTHENTICATED),next(reserved,Phase.BROWSER,generation=reserved.generation+1),
                next(reserved,Phase.BROWSER,alias=f.alias()),next(reserved,Phase.SIGNED_OUT,alias=""),
                next(reserved,Phase.RETIRING),next(reserved,Phase.BROWSER).copy(version=2),
                next(reserved,Phase.BROWSER).copy(revision=0),next(reserved,Phase.BROWSER).copy(generation=-1),
                next(reserved,Phase.BROWSER).copy(revision=Long.MAX_VALUE),next(reserved,Phase.BROWSER).copy(alias=""),
                next(reserved,Phase.BROWSER).copy(alias="syn443-dpop-"+Identity.random()))) {
                failure(AdminKeyStorageFailure.INVALID) {second.commit(reserved,invalid)}
                assertArrayEquals(encrypted,f.file.readBytes());assertEquals(reserved,first.read())
            }
            val retiring=first.commit(reserved,next(reserved,Phase.RETIRING,reserved.generation+1))
            failure(AdminKeyStorageFailure.INVALID) {first.commit(retiring,next(retiring,Phase.RESERVED))}
            val out=first.commit(retiring,next(retiring,Phase.SIGNED_OUT,alias=""))
            failure(AdminKeyStorageFailure.INVALID) {first.commit(out,next(out,Phase.SIGNED_OUT))}
            assertEquals(out,second.read())
        }}
    }

    @Test fun adminJournalCiphertextRejectsTamperingTruncationOversizeAndForeignNamespace() {
        Fixture().use {first -> Fixture(first.encryptionAlias).use {second -> first.worker {
            val journal=first.journal();val reserved=first.reserve(journal);val authentic=first.file.readBytes()
            second.worker {second.reserve()}
            second.file.writeBytes(authentic)
            second.worker {
                failure(AdminKeyStorageFailure.CORRUPT) {second.journal().read()}
                failure(AdminKeyStorageFailure.CORRUPT) {second.journal().commit(Record(),Record(revision=1,generation=1,
                    phase=Phase.RESERVED,alias=second.alias()))}
                assertArrayEquals(authentic,second.file.readBytes())
            }
            val malformed=listOf(ByteArray(0),authentic.copyOf(12),authentic.copyOf(29),ByteArray(4096+30),
                authentic.copyOf().apply {this[0]=2},
                authentic.copyOf().apply {this[lastIndex]=(this[lastIndex].toInt() xor 1).toByte()})
            for(frame in malformed) {
                first.file.writeBytes(frame)
                failure(AdminKeyStorageFailure.CORRUPT) {journal.read()}
                failure(AdminKeyStorageFailure.CORRUPT) {journal.commit(Record(),Record(revision=1,generation=1,
                    phase=Phase.RESERVED,alias=first.alias()))}
                assertArrayEquals(frame,first.file.readBytes())
            }
            val valid="""{"version":1,"revision":1,"generation":1,"phase":"RESERVED","alias":"${reserved.alias}"}"""
            for(plain in listOf(valid.replace("\"version\":1","\"version\":1,\"version\":1"),
                valid.replace("\"revision\":1","\"revision\":\"1\""),valid.replace("\"generation\":1","\"generation\":1.0"),
                valid.replace("\"version\":1","\"Version\":1"),valid.replace("\"RESERVED\"","\"UNKNOWN\""),
                valid.replace("\"alias\":\"${reserved.alias}\"","\"alias\":null"),
                valid.dropLast(1)+",\"token\":\"synthetic-forbidden-field\"}")) {
                val frame=Cipher.getInstance("AES/GCM/NoPadding").run {
                    init(Cipher.ENCRYPT_MODE,keyStore().getKey(first.encryptionAlias,null))
                    updateAAD("SYN443-ADMIN-KEY-JOURNAL-1\n${first.namespace}".toByteArray(Charsets.US_ASCII))
                    byteArrayOf(1)+iv+doFinal(plain.toByteArray())
                }
                first.file.writeBytes(frame)
                failure(AdminKeyStorageFailure.CORRUPT) {journal.read()}
                assertArrayEquals(frame,first.file.readBytes())
            }
            first.file.writeBytes(authentic);assertEquals(reserved,journal.read())
        }}}
    }

    @Test fun missingAdminAesKeyAndOrphanedAtomicWritesNeverResetOwnership() {
        Fixture().use {f -> f.worker {
            val journal=f.journal();val reserved=f.reserve(journal);val saved=f.file.readBytes()
            keyStore().deleteEntry(f.encryptionAlias)
            failure(AdminKeyStorageFailure.CORRUPT) {journal.read()}
            failure(AdminKeyStorageFailure.CORRUPT) {journal.commit(reserved,next(reserved,Phase.BROWSER))}
            assertFalse(keyStore().containsAlias(f.encryptionAlias));assertArrayEquals(saved,f.file.readBytes())
        }}
        Fixture().use {f -> f.worker {
            val journal=f.journal();assertEquals(Record(),journal.read());assertTrue(f.directory.mkdirs())
            failure(AdminKeyStorageFailure.CORRUPT) {journal.read()}
            val orphan=File(f.directory,"owner.bin.new").apply {writeBytes(ByteArray(40))}
            failure(AdminKeyStorageFailure.CORRUPT) {journal.read()};assertTrue(orphan.exists())
            assertFalse(keyStore().containsAlias(f.encryptionAlias))
        }}
        Fixture().use {f -> f.worker {
            val journal=f.journal();val reserved=f.reserve(journal);val frame=f.file.readBytes()
            File(f.directory,"owner.bin.bak").writeBytes(frame)
            f.file.writeBytes(ByteArray(12))
            assertEquals(reserved,journal.read()) // AtomicFile restores the last committed owner, never initial state.
        }}
    }

    @Test fun adminKeystoreAndJournalRejectMainBinderWorkAndForeignAliases() {
        Fixture().use {f ->
            assertThrows(IllegalArgumentException::class.java) {
                AdminKeyJournal.isolatedForTest(f.context,f.namespace,"syn443-admin-store-v1")
            }
            assertThrows(IllegalArgumentException::class.java) {
                AdminKeyJournal.isolatedForTest(f.context,"../foreign",f.encryptionAlias)
            }
            val record=f.worker {f.reserve()}
            val key=f.worker {checkNotNull(AdminKey.createIfCurrent(record.alias) {f.journal().read()==record})}
            fun wrongThread() {
                failure(AdminKeyStorageFailure.WRONG_THREAD) {f.journal().read()}
                failure(AdminKeyStorageFailure.WRONG_THREAD) {f.journal().commit(record,next(record,Phase.BROWSER))}
                assertThrows(IllegalStateException::class.java) {AdminKey.createIfCurrent(f.alias()) {false}}
                assertThrows(IllegalStateException::class.java) {AdminKey.open(record.alias)}
                assertThrows(IllegalStateException::class.java) {AdminKey.deleteOwned(record.alias)}
                assertThrows(IllegalStateException::class.java) {key.publicKey}
                assertThrows(IllegalStateException::class.java) {key.sign(byteArrayOf(1))}
            }
            InstrumentationRegistry.getInstrumentation().runOnMainSync {wrongThread()}
            val binder=Executors.newSingleThreadExecutor {r -> Thread(r,"Binder:admin-key-fixture")}
            try {binder.submit {wrongThread()}.get(10,TimeUnit.SECONDS)}
            finally {binder.shutdownNow();assertTrue(binder.awaitTermination(5,TimeUnit.SECONDS))}
            f.worker {
                assertEquals(record,f.journal().read());assertNotNull(AdminKey.open(record.alias).publicKey)
                for(alias in listOf("syn443-policy-v1","syn443-admin-store-v1","syn443-bootstrap-trust-v1",
                    "syn443-dpop-"+Identity.random(),record.alias+"/other")) {
                    assertFalse(AdminKey.ownedAlias(alias))
                    assertThrows(IllegalArgumentException::class.java) {AdminKey.open(alias)}
                    assertThrows(IllegalArgumentException::class.java) {AdminKey.deleteOwned(alias)}
                    assertThrows(IllegalArgumentException::class.java) {AdminKey.createIfCurrent(alias) {true}}
                }
            }
        }
    }

    @Test fun cancelledAdminKeyCreationCannotOutrunPersistedRetirementOrRecreateItsAlias() {
        Fixture().use {f ->
            val record=f.worker {f.reserve()};val current=AtomicBoolean(true)
            val entered=CountDownLatch(1);val release=CountDownLatch(1);val pool=Executors.newFixedThreadPool(2)
            try {
                assertNull(f.worker {AdminKey.createIfCurrent(record.alias) {false}})
                val creating=pool.submit<AdminKey?> {AdminKey.createIfCurrent(record.alias) {
                    val admitted=current.get() && f.journal().read()==record
                    entered.countDown();check(release.await(10,TimeUnit.SECONDS));admitted
                }}
                assertTrue(entered.await(10,TimeUnit.SECONDS));current.set(false)
                val retiring=f.worker {f.journal().commit(record,next(record,Phase.RETIRING,record.generation+1))}
                val deleting=pool.submit {AdminKey.deleteOwned(retiring.alias)}
                release.countDown();assertNotNull(creating.get(20,TimeUnit.SECONDS));deleting.get(20,TimeUnit.SECONDS)
                f.worker {
                    assertEquals(retiring,f.journal().read())
                    assertThrows(IllegalStateException::class.java) {AdminKey.open(record.alias)}
                    assertNull(AdminKey.createIfCurrent(record.alias) {current.get() && f.journal().read()==record})
                    val out=f.journal().commit(retiring,next(retiring,Phase.SIGNED_OUT,alias=""))
                    assertEquals(out,f.journal().read())
                }
            }finally {current.set(false);release.countDown();pool.shutdownNow();assertTrue(pool.awaitTermination(5,TimeUnit.SECONDS))}
        }
    }
}
