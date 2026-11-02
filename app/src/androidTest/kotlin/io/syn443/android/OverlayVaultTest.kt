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
        val envelope:String get()=envelopeFor(binding)
        fun envelopeFor(b:OverlayCredentialBinding,issued:Long=now,setupValue:String=value):String {
            val a=b.address
            val payload=buildJsonObject {
                put("schemaVersion",1);put("audience","syn443-overlay-credential")
                putJsonObject("address") {
                    put("serviceId",a.serviceId);put("ownerTag",a.ownerTag);put("deviceId",a.deviceId);put("overlayId",a.overlayId);put("provider",a.provider);put("resourceId",a.resourceId);put("networkId",a.networkId);put("identityEpoch",a.identityEpoch);put("managementURL",a.managementURL)
                }
                put("keyThumbprint",b.keyThumbprint);put("reference",b.reference);put("version",b.version);put("securityEpoch",b.securityEpoch);put("kind","netbird.setup-key");put("issuedAtMs",issued);put("notBeforeMs",issued);put("expiresMs",issued+60_000);put("value",setupValue)
            }
            val header=buildJsonObject{put("alg","ES256");put("kid","fixture-root");put("typ","syn443-overlay-credential+jws")}
            val input=Identity.encode(Canonical.encode(header).toByteArray())+"."+Identity.encode(Canonical.encode(payload).toByteArray())
            return input+"."+Identity.encode(Identity.derToRaw(Signature.getInstance("SHA256withECDSA").run{initSign(key.private);update(input.toByteArray());sign()}))
        }
        fun prepare()=vault.prepare(record,envelope,binding,roots,now,now)
        fun cached()=prepare().use{vault.cache(it)}
        fun reopen()=OverlayVault(context,namespace,{authorized.get()},{upper.get()},area)
        fun store()=KeyStore.getInstance("AndroidKeyStore").apply{load(null)}
        fun cleanup(){
            store().deleteEntry(alias)
            runCatching{vault.snapshot()}.getOrNull()?.let{current->store().deleteEntry("syn443-overlay-"+Identity.hash((area+"\n"+current.identityTag+"\n"+current.operation.operationId).toByteArray(Charsets.US_ASCII)))}
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
    @Test fun expiredPendingGrantCanBeReplacedOnlyAfterErasureAndServerAckWithoutTouchingSdkIdentity()=fixture{f->
        val old=f.vault.enrolling(f.cached());f.upper.set(now+60_000)
        val sdk=ManagedOverlayStorage(context,f.area).directory(f.namespace)
        check(sdk.mkdirs());val sentinel=File(sdk,"sdk-private-marker");sentinel.writeBytes(byteArrayOf(7,9,11))
        try {
            val fresh=f.binding.copy(reference=Identity.random(),version=2,securityEpoch=1)
            reason(LoginStorageFailure.UNAVAILABLE){f.vault.replaceDiscarded(old,fresh,4,true)}
            InstrumentationRegistry.getInstrumentation().runOnMainSync {reason(LoginStorageFailure.WRONG_THREAD){f.vault.discardUnregistered(old)}}
            val discarded=f.vault.discardUnregistered(old)
            assertEquals(OverlayPhase.DISCARDED,discarded.phase);assertEquals(old.operation,discarded.operation)
            assertFalse(f.store().containsAlias(f.alias));assertFalse(File(f.directory,"credential.bin").exists())
            val reopened=f.reopen();assertEquals(discarded,reopened.snapshot())
            reason(LoginStorageFailure.UNAVAILABLE){reopened.replaceDiscarded(discarded,fresh,4,false)}
            reason(LoginStorageFailure.UNAVAILABLE){reopened.replaceDiscarded(discarded,f.binding,4,true)}
            f.authorized.set(false);reason(LoginStorageFailure.STALE){reopened.replaceDiscarded(discarded,fresh,4,true)}
            f.authorized.set(true);val next=reopened.replaceDiscarded(discarded,fresh,4,true)
            assertEquals(OverlayPhase.RESERVED,next.phase);assertEquals(old.identityTag,next.identityTag)
            assertEquals(next,reopened.reserve(fresh,4));assertNotEquals(old.operation,next.operation)
            reason(LoginStorageFailure.STALE){reopened.enrolling(old)}
            assertArrayEquals(byteArrayOf(7,9,11),sentinel.readBytes())
        }finally {assertTrue(sentinel.delete());assertTrue(sdk.delete())}
    }

    @Test fun managedProvisionerPersistsBeforeFetchAndErasesBeforeIndependentConsumption()=fixture{f->
        var fetches=0;var consumptions=0;var offline=true
        val provisioner=ManagedOverlayProvisioner(f.vault,f.binding,4,f.roots,{f.authorized.get()},{TimeWindow(now,f.upper.get())},
            {op->assertEquals(f.record.operation,op);assertEquals(OverlayPhase.RESERVED,f.vault.snapshot()!!.phase);fetches++;f.envelope},
            {op->assertEquals(f.record.operation,op);assertFalse(f.store().containsAlias(f.alias));assertFalse(File(f.directory,"credential.bin").exists());consumptions++;if(offline)throw java.io.IOException("synthetic lost consumption response")})
        provisioner.prepare()!!.use{secret->secret.useValue{assertEquals(f.value,it.toString(Charsets.US_ASCII))}}
        assertEquals(OverlayPhase.ENROLLING,f.vault.snapshot()!!.phase);assertEquals(1,fetches)
        provisioner.prepare()!!.close();assertEquals(1,fetches)
        val evidence=Identity.random();val erased=provisioner.registered(f.namespace,evidence){true}
        assertEquals(OverlayPhase.ERASED,erased.phase);assertEquals(evidence,erased.identityEvidence)
        assertThrows(java.io.IOException::class.java){provisioner.acknowledge()}
        assertEquals(erased,f.vault.snapshot());assertNull(provisioner.prepare());assertEquals(1,fetches)
        offline=false;val ack=provisioner.acknowledge();assertEquals(OverlayPhase.ACKNOWLEDGED,ack.phase)
        assertEquals(ack,provisioner.acknowledge());assertEquals(2,consumptions)
        assertEquals(ack,provisioner.registered(f.namespace,evidence){true})
        assertThrows(IllegalArgumentException::class.java){provisioner.registered(f.namespace,Identity.random()){true}}
        assertFalse(provisioner.toString().contains(f.binding.reference))
    }
    @Test fun managedProvisionerRenewalRetriesLostAckAndNeverResetsSdkKeys()=fixture{f->
        val old=f.vault.enrolling(f.cached());f.upper.set(now+60_000)
        val fresh=f.binding.copy(reference=Identity.random(),version=2,securityEpoch=1)
        val sdk=ManagedOverlayStorage(context,f.area).directory(f.namespace);check(sdk.mkdirs())
        val sentinel=File(sdk,"sdk-private-marker");sentinel.writeBytes(byteArrayOf(13,15,17))
        var fetches=0;var consumed=0;val operations=mutableListOf<OverlayOperation>();val setupValue=UUID.randomUUID().toString()
        val provisioner=ManagedOverlayProvisioner(f.reopen(),fresh,4,f.roots,{f.authorized.get()},{TimeWindow(f.upper.get(),f.upper.get())},
            {op->fetches++;assertEquals(fresh.reference,op.reference);assertEquals(op,f.vault.snapshot()!!.operation);f.envelopeFor(fresh,now+60_000,setupValue)},
            {op->operations+=op;consumed++;assertEquals(old.operation,op);assertFalse(f.store().containsAlias(f.alias));if(consumed==1)throw java.io.IOException("synthetic lost ACK")})
        try {
            assertThrows(java.io.IOException::class.java){provisioner.prepare()}
            assertEquals(OverlayPhase.DISCARDED,f.vault.snapshot()!!.phase);assertEquals(old.operation,f.vault.snapshot()!!.operation);assertEquals(0,fetches)
            provisioner.prepare()!!.use{secret->secret.useValue{assertEquals(setupValue,it.toString(Charsets.US_ASCII))}}
            assertEquals(listOf(old.operation,old.operation),operations);assertEquals(1,fetches)
            val next=f.vault.snapshot()!!;assertEquals(OverlayPhase.ENROLLING,next.phase);assertEquals(old.identityTag,next.identityTag)
            assertNotEquals(old.operation,next.operation);assertArrayEquals(byteArrayOf(13,15,17),sentinel.readBytes())
            provisioner.prepare()!!.close();assertEquals(1,fetches)
        }finally {assertTrue(sentinel.delete());assertTrue(sdk.delete())}
    }
    @Test fun managedProvisionerRejectsLateFetchAndNativeProofAfterCancellation()=fixture{f->
        var consumptions=0
        val provisioner=ManagedOverlayProvisioner(f.vault,f.binding,4,f.roots,{f.authorized.get()},{TimeWindow(now,now)},
            {f.authorized.set(false);f.envelope},{consumptions++})
        reason(LoginStorageFailure.STALE){provisioner.prepare()};assertEquals(f.record,f.vault.snapshot())
        assertFalse(File(f.directory,"credential.bin").exists());f.authorized.set(true)
        f.vault.enrolling(f.cached())
        val evidence=Identity.random()
        assertThrows(IllegalStateException::class.java){provisioner.registered(f.namespace,evidence){false}}
        assertEquals(OverlayPhase.ENROLLING,f.vault.snapshot()!!.phase)
        var checks=0
        assertThrows(IllegalStateException::class.java){provisioner.registered(f.namespace,evidence){++checks==1}}
        assertEquals(OverlayPhase.REGISTERED,f.vault.snapshot()!!.phase);assertEquals(0,consumptions)
        assertTrue(f.store().containsAlias(f.alias))
        InstrumentationRegistry.getInstrumentation().runOnMainSync {
            reason(LoginStorageFailure.WRONG_THREAD){provisioner.prepare()}
            reason(LoginStorageFailure.WRONG_THREAD){provisioner.registered(f.namespace,evidence){true}}
            reason(LoginStorageFailure.WRONG_THREAD){provisioner.acknowledge()}
        }
        f.authorized.set(false);reason(LoginStorageFailure.STALE){provisioner.acknowledge()}
        assertEquals(0,consumptions)
    }

    private fun managedConfig(b:OverlayCredentialBinding):String {
        val a=b.address
        val metadata=org.json.JSONObject().put("overlayId",a.overlayId).put("resourceId",a.resourceId).put("networkId",a.networkId)
            .put("identityEpoch",a.identityEpoch).put("setupReference",b.reference).put("setupVersion",b.version)
        return org.json.JSONObject().put("outbounds",org.json.JSONArray().put(org.json.JSONObject().put("type","netbird").put("tag","home")
            .put("management_url",a.managementURL).put("managed",metadata))).put("route",org.json.JSONObject().put("final","home")).toString()
    }
    @Test fun waitingMaterialKeepsSignedMetadataAndNeverCreatesCredentialOrSDKStorage()=fixture{f->
        val raw=managedConfig(f.binding);val root=File(context.noBackupFilesDir,f.area)
        val material=OverlayRuntimeMaterial(f.binding,io.syn443.policy.Policy.hash(raw),4,"",null,
            {f.authorized.get()},{TimeWindow(now,f.upper.get())},waiting=true)
        material.use {
            assertTrue(it.available());assertEquals("waiting",it.launchMode)
            EngineConfig.validateAssigned(raw,it)
            val outbound=org.json.JSONObject(EngineConfig.renderManaged(raw,root,it)).getJSONArray("outbounds").getJSONObject(0)
            assertTrue(outbound.getBoolean("credential_pending"));assertFalse(outbound.has("setup_key"));assertFalse(outbound.has("managed"))
            assertEquals(f.namespace,outbound.getString("managed_namespace"))
            assertFalse(File(outbound.getString("state_directory")).exists())
            assertNull(f.vault.snapshot())
            assertThrows(IllegalArgumentException::class.java){EngineConfig.validate(org.json.JSONObject(raw).also{v->v.getJSONArray("outbounds").getJSONObject(0).put("credential_pending",true)}.toString())}
            f.upper.set(f.binding.offlineUntilMs);assertFalse(it.available());f.upper.set(now)
            f.authorized.set(false);assertFalse(it.authorized())
        }
        assertFalse(material.available())
        assertThrows(IllegalArgumentException::class.java){OverlayRuntimeMaterial(f.binding,io.syn443.policy.Policy.hash(raw),4,Identity.random(),null,{true},{TimeWindow(now,now)},waiting=true)}
    }
    @Test fun runtimeMaterialRendersOnlyItsSignedConfigAndLocallyDerivedOwnedDirectory()=fixture{f->
        val raw=managedConfig(f.binding);val hash=io.syn443.policy.Policy.hash(raw)
        val enrolling=f.vault.enrolling(f.cached())
        val secret=f.vault.credential(enrolling,f.binding,f.roots,now,now)
        val material=OverlayRuntimeMaterial(f.binding,hash,4,"",secret,{f.authorized.get()},{TimeWindow(now,f.upper.get())})
        val root=File(context.noBackupFilesDir,f.area)
        try {
            val rendered=org.json.JSONObject(EngineConfig.renderManaged(raw,root,material))
            val outbound=rendered.getJSONArray("outbounds").getJSONObject(0)
            assertEquals(f.value,outbound.getString("setup_key"));assertFalse(outbound.has("managed"))
            assertEquals(f.namespace,outbound.getString("managed_namespace"));assertEquals("direct",outbound.getString("connection_mode"))
            assertEquals(ManagedOverlayStorage(context,f.area).directory(f.namespace).absolutePath,outbound.getString("state_directory"))
            assertFalse(outbound.getString("state_directory").contains("/netbird/"));assertTrue(rendered.getJSONObject("log").getBoolean("disabled"))
            assertEquals(hash,io.syn443.policy.Policy.hash(raw));assertTrue(raw.contains("setupReference"));assertFalse(raw.contains(f.value))
            assertThrows(IllegalArgumentException::class.java){EngineConfig.renderManaged(raw+" ",root,material)}
            assertThrows(IllegalArgumentException::class.java){EngineConfig.render(raw,root)}
            assertThrows(IllegalArgumentException::class.java){EngineConfig.validateAssigned(raw)}
            assertTrue(material.available());f.upper.set(now+60_000);assertFalse(material.available());assertTrue(material.authorized())
            f.upper.set(now+120_000);assertFalse(material.authorized());f.upper.set(now+60_000)
            assertThrows(IllegalStateException::class.java){EngineConfig.renderManaged(raw,root,material)}
            f.upper.set(now);f.authorized.set(false);assertFalse(material.available())
            f.authorized.set(true);material.close();assertFalse(material.available())
            assertThrows(IllegalStateException::class.java){secret.useValue{error("closed material leaked key")}}
            assertFalse(material.toString().contains(f.binding.reference))
        }finally{material.close()}
    }
    @Test fun keylessMaterialCannotAdoptInlineKeysPathsOtherNamespacesOrCoercedMetadata()=fixture{f->
        val evidence=Identity.random();val root=File(context.noBackupFilesDir,f.area)
        val raw=managedConfig(f.binding)
        OverlayRuntimeMaterial(f.binding,io.syn443.policy.Policy.hash(raw),4,evidence,null,{true},{TimeWindow(now,now)}).use{material->
            val outbound=org.json.JSONObject(EngineConfig.renderManaged(raw,root,material)).getJSONArray("outbounds").getJSONObject(0)
            assertFalse(outbound.has("setup_key"));assertEquals(f.namespace,outbound.getString("managed_namespace"))
        }
        val changes:List<(org.json.JSONObject)->Unit> = listOf(
            {it.put("setup_key",UUID.randomUUID().toString())}, {it.put("state_directory",root.absolutePath)},
            {it.put("managed_namespace",f.namespace)}, {it.put("management_url","https://other.example.invalid")},
            {it.getJSONObject("managed").put("networkId","other")}, {it.getJSONObject("managed").put("setupReference",Identity.random())},
            {it.getJSONObject("managed").put("identityEpoch","1")}, {it.getJSONObject("managed").put("setupVersion",1.5)},
            {it.getJSONObject("managed").put("unknown",true)})
        for(change in changes) {
            val top=org.json.JSONObject(raw);change(top.getJSONArray("outbounds").getJSONObject(0));val modified=top.toString()
            OverlayRuntimeMaterial(f.binding,io.syn443.policy.Policy.hash(modified),4,evidence,null,{true},{TimeWindow(now,now)}).use{material->
                assertThrows(IllegalArgumentException::class.java){EngineConfig.renderManaged(modified,root,material)}
            }
        }
        assertThrows(IllegalArgumentException::class.java){OverlayRuntimeMaterial(f.binding,"invalid",4,evidence,null,{true},{TimeWindow(now,now)})}
        assertThrows(IllegalArgumentException::class.java){OverlayRuntimeMaterial(f.binding,io.syn443.policy.Policy.hash(raw),4,"",null,{true},{TimeWindow(now,now)})}
        OverlayRuntimeMaterial(f.binding,io.syn443.policy.Policy.hash(raw),4,evidence,null,{true},{TimeWindow(now,now-1)}).use{assertFalse(it.available())}
    }
}
