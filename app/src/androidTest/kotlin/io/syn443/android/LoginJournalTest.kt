package io.syn443.android

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.syn443.android.vpn.DeviceKey
import io.syn443.android.vpn.LoginJournal
import io.syn443.android.vpn.LoginStorageException
import io.syn443.android.vpn.LoginStorageFailure
import io.syn443.identity.*
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class LoginJournalTest {
    private val context=ApplicationProvider.getApplicationContext<Context>()
    private val bootstrap by lazy {
        val key=KeyPairGenerator.getInstance("EC").apply {initialize(ECGenParameterSpec("secp256r1"))}.generateKeyPair()
        Bootstrap("test","https://identity.example.com/realms/test","test","https://api.example.com",
            mapOf("test" to Base64.getEncoder().encodeToString(key.public.encoded)))
    }
    private class Fixture(val journal:LoginJournal,val directory:File,val name:String)
    private fun fixture():Fixture {
        val name="test-"+UUID.randomUUID().toString()
        return Fixture(LoginJournal(context,name),File(context.noBackupFilesDir,"login/$name"),name)
    }
    private fun withFixture(block:(Fixture)->Unit) {
        val f=fixture()
        try {block(f)} finally {assertTrue(!f.directory.exists() || f.directory.deleteRecursively())}
    }
    private fun reserve(f:Fixture):LoginIntent {
        val s=f.journal.snapshot();return f.journal.commit(s,LoginRecovery.reserve(s,s.generation,bootstrap,DeviceKey.newAlias()))
    }
    private fun browser(f:Fixture):LoginIntent {
        val s=reserve(f)
        return f.journal.prepare(s,"{\"verifier\":\"synthetic-private-value\"}").use {p->
            f.journal.commit(s,LoginRecovery.prepared(s,s.generation,Identity.random(),p.hash),p)
        }
    }
    private fun reason(expected:LoginStorageFailure,block:()->Unit) {
        val e=assertThrows(LoginStorageException::class.java,block)
        assertEquals(expected,e.reason);assertNull(e.cause);assertEquals(expected.name,e.message)
    }
    @Test fun protectedStatePersistsWithoutPlaintextAndCallbackIsConsumedOnce() = withFixture {f->
        val s=browser(f);val reopened=LoginJournal(context,f.name)
        assertEquals(s,reopened.snapshot())
        assertTrue(reopened.readProtected(s).contains("synthetic-private-value"))
        for(file in f.directory.listFiles().orEmpty())assertFalse(file.readBytes().toString(Charsets.UTF_8).contains("synthetic-private-value"))
        val bytes=File(f.directory,"protected.bin").readBytes()
        val consumed=reopened.commit(s,LoginRecovery.consumeCallback(s,s.generation))
        assertArrayEquals(bytes,File(f.directory,"protected.bin").readBytes())
        reason(LoginStorageFailure.STALE) {f.journal.readProtected(s)}
        reason(LoginStorageFailure.STALE) {f.journal.commit(s,LoginRecovery.consumeCallback(s,s.generation))}
        assertTrue(f.journal.readProtected(consumed).contains("synthetic-private-value"))
    }
    @Test fun cancelErasesSecretsAndLateEncryptionCannotResurrectThem() = withFixture {f->
        val s=browser(f)
        f.journal.prepare(s,"{\"token\":\"synthetic-late-token\"}").use {late->
            val retiring=f.journal.commit(s,LoginRecovery.cancel(s,s.generation))
            assertFalse(File(f.directory,"protected.bin").exists())
            assertTrue(f.journal.eraseRetired(retiring));DeviceKey.deleteOwned(s.keyAlias)
            val out=f.journal.commit(retiring,LoginRecovery.retired(retiring,retiring.generation,s.keyAlias,true,true))
            reason(LoginStorageFailure.STALE) {f.journal.commit(s,LoginRecovery.consumeCallback(s,s.generation).copy(protectedHash=late.hash),late)}
            assertEquals(LoginPhase.SIGNED_OUT,LoginJournal(context,f.name).snapshot().phase)
            assertFalse(f.journal.isCurrent(s));assertTrue(f.journal.isCurrent(out))
            reason(LoginStorageFailure.CORRUPT) {f.journal.readProtected(out)}
            assertNull(DeviceKey.createIfCurrent(s.keyAlias) {f.journal.isCurrent(s)})
            assertFalse(File(f.directory,"protected.bin").exists())
        }
    }
    @Test fun interruptedIntentCiphertextPairFailsClosedAndCanStillBeCancelled() = withFixture {f->
        val s=browser(f)
        f.journal.prepare(s,"{\"token\":\"synthetic-replacement\"}").use {p->
            val interrupted=LoginRecovery.consumeCallback(s,s.generation).copy(protectedHash=p.hash)
            File(f.directory,"intent.json").writeText(LoginRecovery.encode(interrupted))
            assertEquals(interrupted,f.journal.snapshot())
            reason(LoginStorageFailure.CORRUPT) {f.journal.readProtected(interrupted)}
            val retiring=f.journal.commit(interrupted,LoginRecovery.cancel(interrupted,interrupted.generation))
            assertTrue(f.journal.eraseRetired(retiring));assertFalse(File(f.directory,"protected.bin").exists())
        }
    }
    @Test fun authenticatedCiphertextCannotBeMovedAcrossNamespaceGenerationOrAuthority() = withFixture {a->
        withFixture {b->
            val s=browser(a);val bytes=File(a.directory,"protected.bin").readBytes()
            assertTrue(b.directory.mkdirs());File(b.directory,"intent.json").writeText(LoginRecovery.encode(s))
            File(b.directory,"protected.bin").writeBytes(bytes)
            reason(LoginStorageFailure.CORRUPT) {b.journal.readProtected(s)}
            for(changed in listOf(s.copy(generation=s.generation+1),s.copy(authority=Identity.random()))) {
                File(a.directory,"intent.json").writeText(LoginRecovery.encode(changed))
                reason(LoginStorageFailure.CORRUPT) {a.journal.readProtected(changed)}
            }
            File(a.directory,"intent.json").writeText(LoginRecovery.encode(s))
            bytes[bytes.lastIndex]=(bytes.last().toInt() xor 1).toByte()
            File(a.directory,"protected.bin").writeBytes(bytes)
            // Even a matching attacker-controlled public hash does not bypass authenticated encryption.
            val tampered=s.copy(protectedHash=Identity.hash(bytes));File(a.directory,"intent.json").writeText(LoginRecovery.encode(tampered))
            reason(LoginStorageFailure.CORRUPT) {a.journal.readProtected(tampered)}
        }
    }
    @Test fun malformedOversizedOrMissingPublicIntentNeverBecomesSignedOut() = withFixture {f->
        browser(f)
        val file=File(f.directory,"intent.json")
        for(raw in listOf("{\"generation\":1,\"generation\":2}","x".repeat(65_537),"[]")) {
            file.writeText(raw);reason(LoginStorageFailure.CORRUPT) {f.journal.snapshot()}
        }
        assertTrue(file.delete());reason(LoginStorageFailure.CORRUPT) {f.journal.snapshot()}
        file.writeText(LoginRecovery.encode(LoginIntent()))
        reason(LoginStorageFailure.CORRUPT) {f.journal.snapshot()}
        assertTrue(file.delete())
        File(f.directory,"protected.bin").delete()
        File(f.directory,"intent.json.new").writeText("interrupted first intent")
        reason(LoginStorageFailure.CORRUPT) {f.journal.snapshot()}
    }
    @Test fun atomicBackupRecoveryAndBoundedCiphertextRejectTruncation() = withFixture {f->
        val s=browser(f);val original=File(f.directory,"intent.json").readBytes()
        File(f.directory,"intent.json.bak").writeBytes(original)
        File(f.directory,"intent.json").writeText("interrupted")
        assertEquals(s,f.journal.snapshot())
        assertFalse(File(f.directory,"intent.json.bak").exists())
        for(bytes in listOf(byteArrayOf(1),ByteArray(65_566))) {
            File(f.directory,"protected.bin").writeBytes(bytes)
            reason(LoginStorageFailure.CORRUPT) {f.journal.readProtected(s)}
        }
    }
    @Test fun cryptoIsWorkerOnlyAndPreparedPayloadsCannotCrossJournalsOrBeReusedAfterClose() = withFixture {a->
        withFixture {b->
            val s=reserve(a);reserve(b)
            InstrumentationRegistry.getInstrumentation().runOnMainSync {
                reason(LoginStorageFailure.WRONG_THREAD) {a.journal.prepare(s,"{}")}
                reason(LoginStorageFailure.WRONG_THREAD) {a.journal.readProtected(s)}
            }
            reason(LoginStorageFailure.UNAVAILABLE) {a.journal.prepare(s,"{\"large\":\""+"x".repeat(65_536)+"\"}")}
            a.journal.prepare(s,"{}").use {p->
                val other=b.journal.snapshot()
                reason(LoginStorageFailure.UNAVAILABLE) {b.journal.commit(other,LoginRecovery.prepared(other,other.generation,Identity.random(),p.hash),p)}
                p.close()
                reason(LoginStorageFailure.UNAVAILABLE) {a.journal.commit(s,LoginRecovery.prepared(s,s.generation,Identity.random(),p.hash),p)}
            }
            assertEquals(s,a.journal.snapshot());assertFalse(File(a.directory,"protected.bin").exists())
            assertThrows(IllegalArgumentException::class.java) {LoginJournal(context,"../escape")}
        }
    }
}
