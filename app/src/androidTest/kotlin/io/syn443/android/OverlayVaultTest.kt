package io.syn443.android

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.syn443.android.vpn.*
import io.syn443.identity.*
import io.syn443.policy.Canonical
import kotlinx.serialization.json.*
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

@RunWith(AndroidJUnit4::class)
class OverlayVaultTest {
    private val context=ApplicationProvider.getApplicationContext<Context>()
    private val now=1_800_000_000_000L
    private inner class Fixture {
        val area="test-"+UUID.randomUUID().toString()
        val key=KeyPairGenerator.getInstance("EC").apply{initialize(ECGenParameterSpec("secp256r1"))}.generateKeyPair()
        val roots=mapOf("fixture-root" to Base64.getEncoder().encodeToString(key.public.encoded))
        val binding=OverlayCredentialBinding(OverlayAddress("fixture",Identity.hash(area.toByteArray()),"device-12345","home","netbird","resource","tenant",1,"https://overlay.example.invalid"),Identity.random(),Identity.random(),1,0,now+120_000)
        val namespace=ManagedOverlay.namespace(binding.address)
        val authorized=AtomicBoolean(true)
        val upper=AtomicLong(now)
        val vault=OverlayVault(context,namespace,{authorized.get()},{upper.get()},area)
        val record=vault.reserve(binding,4)
        val alias="syn443-overlay-"+Identity.hash((area+"\n"+record.identityTag+"\n"+record.operation.operationId).toByteArray(Charsets.US_ASCII))
        val directory=File(context.noBackupFilesDir,"overlay/$area/"+Identity.hash(namespace.toByteArray(Charsets.US_ASCII)))
        val value=UUID.randomUUID().toString()
        val envelope:String
        init {
            val a=binding.address
            val payload=buildJsonObject {
                put("schemaVersion",1);put("audience","syn443-overlay-credential")
                putJsonObject("address") {
                    put("serviceId",a.serviceId);put("ownerTag",a.ownerTag);put("deviceId",a.deviceId);put("overlayId",a.overlayId);put("provider",a.provider);put("resourceId",a.resourceId);put("networkId",a.networkId);put("identityEpoch",a.identityEpoch);put("managementURL",a.managementURL)
                }
                put("keyThumbprint",binding.keyThumbprint);put("reference",binding.reference);put("version",1);put("securityEpoch",0);put("kind","netbird.setup-key");put("issuedAtMs",now);put("notBeforeMs",now);put("expiresMs",now+60_000);put("value",value)
            }
            val header=buildJsonObject{put("alg","ES256");put("kid","fixture-root");put("typ","syn443-overlay-credential+jws")}
            val input=Identity.encode(Canonical.encode(header).toByteArray())+"."+Identity.encode(Canonical.encode(payload).toByteArray())
            envelope=input+"."+Identity.encode(Identity.derToRaw(Signature.getInstance("SHA256withECDSA").run{initSign(key.private);update(input.toByteArray());sign()}))
        }
        fun prepare()=vault.prepare(record,envelope,binding,roots,now,now)
        fun cached()=prepare().use{vault.cache(it)}
        fun reopen()=OverlayVault(context,namespace,{authorized.get()},{upper.get()},area)
        fun store()=KeyStore.getInstance("AndroidKeyStore").apply{load(null)}
        fun cleanup(){
            store().deleteEntry(alias)
            val allowed=File(context.noBackupFilesDir,"overlay/$area").canonicalFile
            check(directory.canonicalFile.parentFile==allowed)
            check(!directory.exists()||directory.deleteRecursively())
            allowed.delete()
        }
    }
    private fun fixture(block:(Fixture)->Unit){val f=Fixture();try{block(f)}finally{f.cleanup()}}
    private fun reason(expected:LoginStorageFailure,block:()->Unit){val e=assertThrows(LoginStorageException::class.java,block);assertEquals(expected,e.reason);assertNull(e.cause)}
    @Test fun perGrantKeyCiphertextAndDurableOperationSurviveProcessObjectsThenEraseBeforeAck()=fixture{f->
        assertFalse(f.store().containsAlias(f.alias));assertEquals(f.record,f.reopen().reserve(f.binding,4))
        val cached=f.cached();assertEquals(OverlayPhase.CACHED,cached.phase)
        assertNull(f.store().getKey(f.alias,null).encoded)
        assertFalse(File(f.directory,"credential.bin").readBytes().toString(Charsets.UTF_8).contains(f.envelope))
        assertFalse(File(f.directory,"ledger.json").readText().contains(f.value))
        val reopened=f.reopen();assertEquals(cached,reopened.snapshot())
        reopened.credential(cached,f.binding,f.roots,now,now).use{secret->secret.useValue{assertEquals(f.value,it.toString(Charsets.US_ASCII))}}
        val starting=reopened.enrolling(cached)
        reopened.credential(starting,f.binding,f.roots,now,now).close()
        val registered=reopened.registered(starting,Identity.hash("synthetic-confirmed-native-identity".toByteArray()))
        val erased=reopened.eraseRegistered(registered)
        assertEquals(OverlayPhase.ERASED,erased.phase);assertFalse(f.store().containsAlias(f.alias));assertFalse(File(f.directory,"credential.bin").exists())
        reason(LoginStorageFailure.UNAVAILABLE){reopened.credential(erased,f.binding,f.roots,now,now)}
        val ack=reopened.acknowledged(erased);assertEquals(ack,f.reopen().snapshot())
        val retiring=reopened.retiring(ack);assertFalse(reopened.finishRetirement(retiring){false});assertEquals(retiring,reopened.snapshot())
        assertTrue(reopened.finishRetirement(retiring){true});assertEquals(OverlayPhase.RETIRED,reopened.snapshot()!!.phase)
    }
    @Test fun cancellationRejectsLateAndQueuedCryptoAndWaitsForConfirmedOwnerRelease()=fixture{f->
        f.prepare().use{prepared->
            f.authorized.set(false)
            val retiring=f.vault.retiring(f.record)
            reason(LoginStorageFailure.STALE){f.vault.cache(prepared)}
            reason(LoginStorageFailure.STALE){f.prepare()}
            assertFalse(File(f.directory,"credential.bin").exists())
            assertFalse(f.vault.finishRetirement(retiring){false})
            assertTrue(f.store().containsAlias(f.alias))
            assertTrue(f.vault.finishRetirement(retiring){true})
            assertFalse(f.store().containsAlias(f.alias))
        }
    }
    @Test fun missingKeyTamperingUnknownJournalAndOrphanCipherNeverResetEnrollment() {
        fixture{f->val cached=f.cached();f.store().deleteEntry(f.alias);reason(LoginStorageFailure.CORRUPT){f.vault.credential(cached,f.binding,f.roots,now,now)};assertEquals(cached,f.vault.snapshot())}
        fixture{f->val cached=f.cached();val file=File(f.directory,"credential.bin");val bytes=file.readBytes();bytes[bytes.lastIndex]=(bytes.last().toInt() xor 1).toByte();file.writeBytes(bytes);reason(LoginStorageFailure.CORRUPT){f.vault.credential(cached,f.binding,f.roots,now,now)}}
        fixture{f->File(f.directory,"ledger.json").writeText("{\"unknown\":true}");reason(LoginStorageFailure.CORRUPT){f.vault.snapshot()};reason(LoginStorageFailure.CORRUPT){f.vault.reserve(f.binding,4)}}
        fixture{f->f.cached();assertTrue(File(f.directory,"ledger.json").delete());reason(LoginStorageFailure.CORRUPT){f.vault.snapshot()}}
    }
    @Test fun interruptedCacheCommitRetainsReservedOperationAndCannotCrossStorageArea()=fixture{f->
        f.prepare().use{prepared->
            File(f.directory,"credential.bin").writeBytes(prepared.bytes)
            assertEquals(f.record,f.reopen().reserve(f.binding,4))
            val cached=f.vault.cache(prepared)
            fixture{other->
                // Same identity/record bytes still cannot acquire the source area's key.
                val foreign=OverlayVault(context,f.namespace,{true},{other.upper.get()},other.area)
                val foreignDirectory=File(context.noBackupFilesDir,"overlay/${other.area}/"+Identity.hash(f.namespace.toByteArray(Charsets.US_ASCII)))
                try {
                    assertTrue(foreignDirectory.mkdirs())
                    File(foreignDirectory,"ledger.json").writeBytes(File(f.directory,"ledger.json").readBytes())
                    File(foreignDirectory,"credential.bin").writeBytes(File(f.directory,"credential.bin").readBytes())
                    assertEquals(cached,foreign.snapshot())
                    reason(LoginStorageFailure.CORRUPT){foreign.credential(cached,f.binding,f.roots,now,now)}
                }finally{assertTrue(foreignDirectory.deleteRecursively())}
            }
        }
    }
    @Test fun aLateCredentialCannotBeCachedOrBorrowedAfterTheTrustedUpperDeadline() {
        fixture{f->f.prepare().use{prepared->f.upper.set(now+60_000);reason(LoginStorageFailure.UNAVAILABLE){f.vault.cache(prepared)};assertEquals(f.record,f.vault.snapshot());assertFalse(File(f.directory,"credential.bin").exists())}}
        fixture{f->val cached=f.cached();f.upper.set(now+60_000);reason(LoginStorageFailure.UNAVAILABLE){f.vault.credential(cached,f.binding,f.roots,now,now)}}
    }
    @Test fun mainThreadCannotEncryptDecryptOrMutateEnrollmentButMayPersistCancellation()=fixture{f->
        val cached=f.cached()
        InstrumentationRegistry.getInstrumentation().runOnMainSync {
            reason(LoginStorageFailure.WRONG_THREAD){f.vault.prepare(f.record,f.envelope,f.binding,f.roots,now,now)}
            reason(LoginStorageFailure.WRONG_THREAD){f.vault.credential(cached,f.binding,f.roots,now,now)}
            reason(LoginStorageFailure.WRONG_THREAD){f.vault.enrolling(cached)}
            f.authorized.set(false);assertEquals(OverlayPhase.RETIRING,f.vault.retiring(cached).phase)
        }
        assertTrue(f.vault.finishRetirement(checkNotNull(f.vault.snapshot())){true})
    }
    @Test fun retiredMetadataIsRemovedOnlyAfterConfirmedCredentialAndSdkErasure()=fixture{f->
        val cached=f.cached();f.authorized.set(false)
        val retiring=f.vault.retiring(cached)
        reason(LoginStorageFailure.UNAVAILABLE){f.vault.removeRetired(retiring)}
        assertFalse(f.vault.finishRetirement(retiring){false});assertTrue(File(f.directory,"credential.bin").isFile)
        assertTrue(f.vault.finishRetirement(retiring){true});val retired=checkNotNull(f.vault.snapshot())
        InstrumentationRegistry.getInstrumentation().runOnMainSync {reason(LoginStorageFailure.WRONG_THREAD){f.vault.removeRetired(retired)}}
        assertTrue(f.vault.removeRetired(retired));assertNull(f.vault.snapshot());assertFalse(f.directory.exists())
    }
}
