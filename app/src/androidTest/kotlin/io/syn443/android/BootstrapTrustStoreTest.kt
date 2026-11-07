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
