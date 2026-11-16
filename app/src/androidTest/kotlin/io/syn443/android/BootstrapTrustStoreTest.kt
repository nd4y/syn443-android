package io.syn443.android

import androidx.test.platform.app.InstrumentationRegistry
import io.syn443.android.vpn.BootstrapTrustStore
import io.syn443.identity.*
import io.syn443.policy.Canonical
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.net.URLEncoder
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import java.util.UUID
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class BootstrapTrustStoreTest {
    private fun pair()=KeyPairGenerator.getInstance("EC").apply {initialize(ECGenParameterSpec("secp256r1"))}.generateKeyPair()
    private fun signed(key:KeyPair,id:String,payload:JsonElement,type:String):String {
        val head=Canonical.encode(buildJsonObject {put("alg","ES256");put("kid",id);put("typ",type)})
        val text=Identity.encode(head.toByteArray())+"."+Identity.encode(Canonical.encode(payload).toByteArray())
        val der=Signature.getInstance("SHA256withECDSA").run {initSign(key.private);update(text.toByteArray());sign()}
        return text+"."+Identity.encode(Identity.derToRaw(der))
    }
    private inner class AdminFixture : java.io.Closeable {
        val context=InstrumentationRegistry.getInstrumentation().targetContext
        val namespace="test-admin-"+UUID.randomUUID().toString().replace("-","").take(20)
        val root=pair()
        val online=pair()
        val anchor=TrustAnchor("admin-fixture-root",Base64.getEncoder().encodeToString(root.public.encoded),1)
        val now=System.currentTimeMillis()/1000
        var lookupNow=now
        val metadata=AdminBootstrap("https://admin-id.example.invalid/realms/control",AdminBootstrap.CLIENT_ID,
            AdminBootstrap.AUDIENCE,"https://admin-api.example.invalid",AdminBootstrap.ASSURANCE_ACR)
        val descriptor=ServiceDescriptor(1,"syn443-client-bootstrap",1,1,"service-a",
            "https://id.example.invalid/realms/device","syn443-android","https://api.example.invalid",
            mapOf("online" to Base64.getEncoder().encodeToString(online.public.encoded)),now,now,now+3600,
            adminBootstrap=metadata)
        val journal=File(context.noBackupFilesDir,"$namespace.bin")
        private val executor=Executors.newSingleThreadExecutor()
        fun store()=BootstrapTrustStore(context,namespace,testAnchor=anchor,testAdminNow={lookupNow})
        fun manifest(value:ServiceDescriptor=descriptor,key:KeyPair=root,id:String=anchor.id)=
            signed(key,id,Canonical.json.encodeToJsonElement(value),"syn443-bootstrap+jws")
        fun caches()=context.noBackupFilesDir.listFiles {file -> file.name.startsWith("$namespace-admin-") && file.name.endsWith(".bin")}
            ?.toList().orEmpty()
        fun worker(action:()->Unit) {executor.submit {action()}.get(30,TimeUnit.SECONDS)}
        override fun close() {
            executor.shutdownNow();check(executor.awaitTermination(5,TimeUnit.SECONDS))
            context.noBackupFilesDir.listFiles {file -> file.name=="$namespace.bin" || file.name.startsWith("$namespace.bin.") || file.name.startsWith("$namespace-admin-")}
                ?.forEach {check(it.delete())}
        }
    }
    @Test fun adminDiscoveryTicketMatchesOneVerifiedSnapshotAndLeavesDeviceJournalUnchanged() {
        assumeTrue(android.os.Build.HARDWARE in setOf("ranchu","goldfish"))
        AdminFixture().use {f -> f.worker {
            val store=f.store();val manifest=f.manifest()
            val bootstrap=store.acceptDefaultDescriptor(manifest)
            val (_,floor)=BootstrapTrust.descriptor(manifest,f.anchor,ServiceFloor(),f.now)
            val direct=checkNotNull(BootstrapTrust.adminDiscovery(manifest,f.anchor,floor,bootstrap,f.now))
            val journal=f.journal.readBytes();val authority=Identity.bootstrapAuthority(bootstrap)
            val root=store.adaptiveAuthorityFingerprint()
            val ticket=checkNotNull(store.adminDiscovery(bootstrap))
            assertEquals(f.metadata,ticket.metadata);assertEquals(direct.binding,ticket.binding)
            assertEquals(ticket.binding,checkNotNull(f.store().adminDiscovery(bootstrap)).binding)
            assertEquals(ticket.metadata,store.adminBootstrap(bootstrap))
            assertEquals(authority,Identity.bootstrapAuthority(bootstrap));assertEquals(root,store.adaptiveAuthorityFingerprint())
            assertArrayEquals(journal,f.journal.readBytes())
            for(detached in listOf(bootstrap.copy(serviceId="service-b"),
                bootstrap.copy(issuer="https://other-id.example.invalid/realms/device"),
                bootstrap.copy(clientId="foreign-device-client"),bootstrap.copy(apiOrigin="https://other-api.example.invalid"),
                bootstrap.copy(controlPanelOrigin="https://other-console.example.invalid"),
                bootstrap.copy(roots=mapOf("foreign-online" to bootstrap.roots.values.single())))) {
                assertNull(store.adminDiscovery(detached));assertArrayEquals(journal,f.journal.readBytes())
            }
        }}
    }
    @Test fun signedAdminRevisionChangesDiscoveryBindingWithoutChangingDeviceIdentity() {
        assumeTrue(android.os.Build.HARDWARE in setOf("ranchu","goldfish"))
        AdminFixture().use {f -> f.worker {
            val store=f.store();val bootstrap=store.acceptDefaultDescriptor(f.manifest())
            val authority=Identity.bootstrapAuthority(bootstrap);val root=store.adaptiveAuthorityFingerprint()
            val first=checkNotNull(store.adminDiscovery(bootstrap))
            // Revision itself belongs to discovery authority, even if both
            // administrative values and the ordinary device projection match.
            val sameValues=f.descriptor.copy(revision=2)
            assertEquals(bootstrap,store.acceptDefaultDescriptor(f.manifest(sameValues)))
            val journal=f.journal.readBytes();val renewed=checkNotNull(store.adminDiscovery(bootstrap))
            assertEquals(first.metadata,renewed.metadata);assertNotEquals(first.binding,renewed.binding)
            assertArrayEquals(journal,f.journal.readBytes())
            val changed=sameValues.copy(revision=3,adminBootstrap=f.metadata.copy(apiOrigin="https://other-admin-api.example.invalid"))
            assertEquals(bootstrap,store.acceptDefaultDescriptor(f.manifest(changed)))
            val current=f.journal.readBytes();val next=checkNotNull(f.store().adminDiscovery(bootstrap))
            assertEquals(changed.adminBootstrap,next.metadata);assertNotEquals(renewed.binding,next.binding)
            assertEquals(authority,Identity.bootstrapAuthority(bootstrap));assertEquals(root,store.adaptiveAuthorityFingerprint())
            assertArrayEquals(current,f.journal.readBytes())
        }}
    }
    @Test fun adminDiscoveryRejectsAbsentRemovedExpiredForeignCorruptAndRetiredRootSnapshots() {
        assumeTrue(android.os.Build.HARDWARE in setOf("ranchu","goldfish"))
        AdminFixture().use {f -> f.worker {
            val store=f.store()
            val bootstrap=store.acceptDefaultDescriptor(f.manifest(f.descriptor.copy(adminBootstrap=null)))
            fun lookup(expected:Bootstrap=bootstrap):AdminDiscovery? {
                val journal=f.journal.readBytes()
                return store.adminDiscovery(expected).also {assertArrayEquals(journal,f.journal.readBytes())}
            }
            assertNull(lookup())
            val withAdmin=f.descriptor.copy(revision=2)
            val manifest=f.manifest(withAdmin)
            assertEquals(bootstrap,store.acceptDefaultDescriptor(manifest))
            assertNotNull(lookup())
            val cache=f.caches().single();val authentic=cache.readBytes();val existing=f.caches().toSet()
            val other=store.acceptDefaultDescriptor(f.manifest(withAdmin.copy(serviceId="service-b")))
            val foreign=(f.caches().toSet()-existing).single()
            foreign.writeBytes(authentic);assertNull(lookup(other)) // same key, wrong service AAD and signed floor.
            val current=f.journal.readBytes()
            cache.writeBytes(authentic.copyOf().apply {this[lastIndex]=(this[lastIndex].toInt() xor 1).toByte()})
            assertNull(lookup())
            assertEquals(bootstrap,store.acceptDefaultDescriptor(manifest));assertArrayEquals(current,f.journal.readBytes())
            cache.writeBytes(ByteArray(8193));assertNull(lookup())
            assertEquals(bootstrap,store.acceptDefaultDescriptor(manifest));assertArrayEquals(current,f.journal.readBytes())
            f.lookupNow=withAdmin.expires
            assertNull(lookup())
            val removed=withAdmin.copy(revision=3,expires=f.now+7200,adminBootstrap=null)
            assertEquals(bootstrap,store.acceptDefaultDescriptor(f.manifest(removed)));assertNull(lookup())
            cache.writeBytes(authentic) // authentic older floor must not be a fallback after removal.
            assertNull(lookup())
            val restored=removed.copy(revision=4,adminBootstrap=f.metadata)
            assertEquals(bootstrap,store.acceptDefaultDescriptor(f.manifest(restored)))
            val beforeRoot=checkNotNull(lookup())
            val next=pair();val nextAnchor=TrustAnchor("admin-fixture-next",Base64.getEncoder().encodeToString(next.public.encoded),2)
            val transition=RootTransition(1,"syn443-root-transition",f.anchor.id,nextAnchor.id,nextAnchor.spki,2,f.now,f.now,f.now+7200)
            val body=Canonical.json.encodeToJsonElement(transition)
            val rotation=RootRotation(signed(f.root,f.anchor.id,body,"syn443-root-transition+jws"),
                signed(next,nextAnchor.id,body,"syn443-root-transition+jws"))
            store.rotate(Canonical.json.encodeToString(rotation));assertNull(lookup())
            val fresh=restored.copy(rootEpoch=2,revision=5)
            assertEquals(bootstrap,store.acceptDefaultDescriptor(f.manifest(fresh,next,nextAnchor.id)))
            val ticket=checkNotNull(lookup());assertEquals(f.metadata,ticket.metadata)
            assertNotEquals(beforeRoot.binding,ticket.binding)
        }}
    }
    @Test fun adminDescriptorCacheIsEncryptedProjectionBoundAndIndependentOfDeviceAuthority() {
        assumeTrue(android.os.Build.HARDWARE in setOf("ranchu","goldfish"))
        AdminFixture().use {f -> f.worker {
            val store=f.store()
            val manifest=f.manifest()
            val bootstrap=store.acceptDefaultDescriptor(manifest)
            val authority=Identity.bootstrapAuthority(bootstrap)
            val journal=f.journal.readBytes()
            val rootIdentity=store.adaptiveAuthorityFingerprint()
            assertEquals(f.metadata,store.adminBootstrap(bootstrap))
            assertEquals(f.metadata,f.store().adminBootstrap(bootstrap))
            val cache=f.caches().single();val bytes=cache.readBytes()
            assertFalse(bytes.toString(Charsets.ISO_8859_1).contains(f.metadata.issuer))
            assertFalse(bytes.toString(Charsets.ISO_8859_1).contains(manifest))
            for(detached in listOf(bootstrap.copy(serviceId="service-b"),bootstrap.copy(issuer="https://other-id.example.invalid/realms/device"),
                bootstrap.copy(clientId="foreign-device-client"),bootstrap.copy(apiOrigin="https://other-api.example.invalid"),
                bootstrap.copy(controlPanelOrigin="https://other-console.example.invalid"),
                bootstrap.copy(roots=mapOf("foreign-online" to bootstrap.roots.values.single())))) {
                assertNull(store.adminBootstrap(detached))
            }
            assertArrayEquals(journal,f.journal.readBytes())
            val changed=f.descriptor.copy(revision=2,adminBootstrap=f.metadata.copy(issuer="https://other-admin.example.invalid/realms/control"))
            val stillDevice=store.acceptDefaultDescriptor(f.manifest(changed))
            assertEquals(bootstrap,stillDevice);assertEquals(authority,Identity.bootstrapAuthority(stillDevice))
            assertEquals(rootIdentity,store.adaptiveAuthorityFingerprint())
            assertEquals(changed.adminBootstrap,store.adminBootstrap(bootstrap))
            val before=f.caches().toSet()
            val other=store.acceptDefaultDescriptor(f.manifest(changed.copy(serviceId="service-b")))
            val otherCache=(f.caches().toSet()-before).single()
            otherCache.writeBytes(cache.readBytes()) // same AES key, foreign service AAD/floor.
            assertNull(store.adminBootstrap(other));assertEquals(changed.adminBootstrap,store.adminBootstrap(bootstrap))
        }}
    }
    @Test fun removedAdminMetadataAndCacheReplayCannotBypassCommittedRevisionOrRetiredRoot() {
        assumeTrue(android.os.Build.HARDWARE in setOf("ranchu","goldfish"))
        AdminFixture().use {f -> f.worker {
            val store=f.store();val first=f.manifest()
            val bootstrap=store.acceptDefaultDescriptor(first)
            val cache=f.caches().single();val old=cache.readBytes()
            val removed=store.acceptDefaultDescriptor(f.manifest(f.descriptor.copy(revision=2,adminBootstrap=null)))
            assertEquals(bootstrap,removed);assertNull(store.adminBootstrap(removed));assertTrue(f.caches().isEmpty())
            val committed=f.journal.readBytes()
            cache.writeBytes(old)
            assertNull(f.store().adminBootstrap(bootstrap));assertArrayEquals(committed,f.journal.readBytes())
            assertTrue(runCatching {store.acceptDefaultDescriptor(first)}.isFailure)
            val fresh=f.manifest(f.descriptor.copy(revision=3))
            assertEquals(bootstrap,store.acceptDefaultDescriptor(fresh));assertEquals(f.metadata,store.adminBootstrap(bootstrap))
            val current=f.journal.readBytes();val cipher=cache.readBytes()
            cache.writeBytes(cipher.copyOf().apply {this[lastIndex]=(this[lastIndex].toInt() xor 1).toByte()})
            assertNull(store.adminBootstrap(bootstrap));assertArrayEquals(current,f.journal.readBytes())
            assertEquals(bootstrap,store.acceptDefaultDescriptor(fresh)) // same-floor cache repair changes no device journal.
            assertArrayEquals(current,f.journal.readBytes());assertEquals(f.metadata,store.adminBootstrap(bootstrap))
            val next=pair();val nextAnchor=TrustAnchor("admin-fixture-next",Base64.getEncoder().encodeToString(next.public.encoded),2)
            val transition=RootTransition(1,"syn443-root-transition",f.anchor.id,nextAnchor.id,nextAnchor.spki,2,f.now,f.now,f.now+3600)
            val body=Canonical.json.encodeToJsonElement(transition)
            val rotation=RootRotation(signed(f.root,f.anchor.id,body,"syn443-root-transition+jws"),
                signed(next,nextAnchor.id,body,"syn443-root-transition+jws"))
            store.rotate(Canonical.json.encodeToString(rotation))
            assertNull(store.adminBootstrap(bootstrap))
            val updated=f.manifest(f.descriptor.copy(rootEpoch=2,revision=4),next,nextAnchor.id)
            assertEquals(bootstrap,store.acceptDefaultDescriptor(updated));assertEquals(f.metadata,store.adminBootstrap(bootstrap))
        }}
    }
    @Test fun adminCacheExpiryAbsenceAndOversizeFailClosedWithoutChangingDeviceJournal() {
        assumeTrue(android.os.Build.HARDWARE in setOf("ranchu","goldfish"))
        AdminFixture().use {f -> f.worker {
            assertTrue(runCatching {BootstrapTrustStore(f.context,f.namespace+"-bad",testAdminNow={f.now})}.isFailure)
            val store=f.store()
            val legacy=store.acceptDefaultDescriptor(f.manifest(f.descriptor.copy(adminBootstrap=null)))
            assertNull(store.adminBootstrap(legacy));assertTrue(f.caches().isEmpty())
            val bootstrap=store.acceptDefaultDescriptor(f.manifest(f.descriptor.copy(revision=2)))
            val before=f.journal.readBytes();val cache=f.caches().single()
            f.lookupNow=f.now-3600 // committed signed issuance floor clamps the fixture clock.
            assertEquals(f.metadata,store.adminBootstrap(bootstrap))
            f.lookupNow=f.descriptor.expires
            assertNull(store.adminBootstrap(bootstrap));assertArrayEquals(before,f.journal.readBytes())
            val renewed=f.manifest(f.descriptor.copy(revision=3,expires=f.now+7200))
            assertEquals(bootstrap,store.acceptDefaultDescriptor(renewed));assertEquals(f.metadata,store.adminBootstrap(bootstrap))
            val active=f.journal.readBytes()
            cache.writeBytes(ByteArray(8193))
            assertNull(store.adminBootstrap(bootstrap));assertArrayEquals(active,f.journal.readBytes())
            assertEquals(bootstrap,store.acceptDefaultDescriptor(renewed));assertArrayEquals(active,f.journal.readBytes())
            assertEquals(f.metadata,store.adminBootstrap(bootstrap))
        }}
    }
    @Test fun installationUpgradeCommitsBothSignaturesAndKeepsTheRevisionFloor() {
        assumeTrue(android.os.Build.HARDWARE in setOf("ranchu","goldfish"))
        val context=InstrumentationRegistry.getInstrumentation().targetContext
        val namespace="test-upgrade-"+UUID.randomUUID().toString().replace("-","").take(20)
        val file=File(context.noBackupFilesDir,"$namespace.bin")
        val freshNamespace="$namespace-new"
        val freshFile=File(context.noBackupFilesDir,"$freshNamespace.bin")
        val oldKey=pair();val nextKey=pair();val online=pair()
        fun spki(key:KeyPair)=Base64.getEncoder().encodeToString(key.public.encoded)
        val old=TrustAnchor("root-old",spki(oldKey),1)
        val next=TrustAnchor("root-new",spki(nextKey),2)
        val now=System.currentTimeMillis()/1000
        fun manifest(anchor:TrustAnchor,key:KeyPair,revision:Long):String {
            val descriptor=ServiceDescriptor(1,"syn443-client-bootstrap",anchor.epoch,revision,"service-a",
                "https://id.example.invalid/realms/test","syn443-android","https://api.example.invalid",
                mapOf("online" to spki(online)),now,now,now+3600)
            return signed(key,anchor.id,Canonical.json.encodeToJsonElement(descriptor),"syn443-bootstrap+jws")
        }
        fun rotation(issued:Long,expiry:Long):RootRotation {
            val transition=RootTransition(1,"syn443-root-transition",old.id,next.id,next.spki,2,issued,issued,expiry)
            val body=Canonical.json.encodeToJsonElement(transition)
            return RootRotation(signed(oldKey,old.id,body,"syn443-root-transition+jws"),
                signed(nextKey,next.id,body,"syn443-root-transition+jws"))
        }
        val prior=InstallationProfile(1,old,manifest(old,oldKey,2))
        val proof=rotation(now,now+3600)
        val upgraded=InstallationProfile(2,next,manifest(next,nextKey,3),InstallationUpgrade(old,proof))
        val expired=InstallationUpgrade(old,rotation(now-3600,now-1))
        val executor=Executors.newSingleThreadExecutor()
        try {
            executor.submit {
                fun store(profile:InstallationProfile)=BootstrapTrustStore(context,namespace,testProfile=profile)
                assertEquals("service-a",store(prior).defaultBootstrap().serviceId)
                val original=file.readBytes()
                for(invalid in listOf(upgraded.copy(upgrade=expired),upgraded.copy(service=prior.service),
                    upgraded.copy(service=manifest(next,nextKey,2)),
                    upgraded.copy(upgrade=InstallationUpgrade(old,proof.copy(next=proof.previous))))) {
                    assertTrue(runCatching {store(invalid).defaultBootstrap()}.isFailure)
                    assertArrayEquals(original,file.readBytes())
                }
                assertEquals("service-a",store(upgraded).defaultBootstrap().serviceId)
                val migrated=file.readBytes()
                assertFalse(original.contentEquals(migrated))
                assertEquals("service-a",store(upgraded).defaultBootstrap().serviceId)
                assertArrayEquals(migrated,file.readBytes())
                assertTrue(runCatching {store(prior).defaultBootstrap()}.isFailure)
                assertArrayEquals(migrated,file.readBytes())
                val refreshed=InstallationProfile(1,next,manifest(next,nextKey,4))
                assertEquals("service-a",store(refreshed).defaultBootstrap().serviceId)
                assertEquals("service-a",BootstrapTrustStore(context,freshNamespace,
                    testProfile=upgraded.copy(upgrade=expired)).defaultBootstrap().serviceId)
            }.get(20,TimeUnit.SECONDS)
        }finally{executor.shutdownNow();file.delete();freshFile.delete()}
    }
    @Test fun floorsPersistAcrossRecreationAndCorruptionNeverResetsToInstallationRoot(){
        assumeTrue(android.os.Build.HARDWARE in setOf("ranchu","goldfish"))
        val context=InstrumentationRegistry.getInstrumentation().targetContext
        val namespace="test-trust-"+UUID.randomUUID().toString().replace("-","").take(20)
        val root=pair();val online=pair();val anchor=TrustAnchor("test-root",Base64.getEncoder().encodeToString(root.public.encoded),1)
        val now=System.currentTimeMillis()/1000
        fun service(revision:Long,trust:TrustAnchor=anchor)=
            ServiceDescriptor(1,"syn443-client-bootstrap",trust.epoch,revision,"service-a","https://id.example.invalid/realms/test","syn443-android","https://api.example.invalid",
                mapOf("online" to Base64.getEncoder().encodeToString(online.public.encoded)),now,now,now+3600)
        fun descriptor(revision:Long,signer:KeyPair=root,trust:TrustAnchor=anchor)=
            signed(signer,trust.id,Canonical.json.encodeToJsonElement(service(revision,trust)),"syn443-bootstrap+jws")
        fun link(revision:Long,signer:KeyPair=root,trust:TrustAnchor=anchor):String {
            val value=service(revision,trust)
            val manifest=descriptor(revision,signer,trust)
            fun url(s:String)=URLEncoder.encode(s,"UTF-8")
            return "syn443://enroll/v1?service=service-a&origin="+url(value.apiOrigin)+"&code="+Identity.random()+"&bootstrap="+url(manifest)
        }
        val executor=Executors.newSingleThreadExecutor()
        try {
            val first=link(1);val second=link(2)
            executor.submit {
                val store=BootstrapTrustStore(context,namespace,anchor)
                assertEquals(service(1).issuer,store.acceptDefaultDescriptor(descriptor(1)).issuer)
                assertEquals(1L,store.preview(first).floor.revision)
                assertEquals(2L,store.accept(second).floor.revision)
                val reopened=BootstrapTrustStore(context,namespace,anchor)
                try {reopened.preview(first);fail("bootstrap rollback accepted")}catch(_:IllegalArgumentException){}
                try {reopened.acceptDefaultDescriptor(descriptor(1));fail("default descriptor rollback accepted")}catch(_:IllegalArgumentException){}
                assertEquals(2L,reopened.accept(second).floor.revision)
                val next=pair();val nextAnchor=TrustAnchor("test-root-next",Base64.getEncoder().encodeToString(next.public.encoded),2)
                val transition=RootTransition(1,"syn443-root-transition",anchor.id,nextAnchor.id,nextAnchor.spki,2,now,now,now+3600)
                val payload=Canonical.json.encodeToJsonElement(transition)
                val rotation=RootRotation(signed(root,anchor.id,payload,"syn443-root-transition+jws"),signed(next,nextAnchor.id,payload,"syn443-root-transition+jws"))
                reopened.rotate(Canonical.json.encodeToString(rotation))
                val third=link(3,next,nextAnchor)
                assertEquals(3L,BootstrapTrustStore(context,namespace,anchor).accept(third).floor.revision)
                val unrelated=TrustAnchor("unrelated",Base64.getEncoder().encodeToString(pair().public.encoded),1)
                try {BootstrapTrustStore(context,namespace,unrelated).acceptDefaultDescriptor(descriptor(3,next,nextAnchor));fail("old rotation crossed installations")}catch(_:IllegalArgumentException){}
                try {reopened.preview(link(4));fail("retired installation root accepted")}catch(_:IllegalArgumentException){}
                val file=File(context.noBackupFilesDir,"$namespace.bin")
                val raw=file.readBytes();assertFalse(raw.toString(Charsets.ISO_8859_1).contains("api.example.invalid"))
                file.writeBytes(raw.copyOf().apply {this[lastIndex]=(this[lastIndex].toInt() xor 1).toByte()})
                try {BootstrapTrustStore(context,namespace,anchor).preview(third);fail("corruption reset trust")}catch(_:Exception){}
            }.get(20,TimeUnit.SECONDS)
        }finally{executor.shutdownNow();File(context.noBackupFilesDir,"$namespace.bin").delete()}
    }
}
