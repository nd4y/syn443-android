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
    @Test fun floorsPersistAcrossRecreationAndCorruptionNeverResetsToInstallationRoot(){
        assumeTrue(android.os.Build.HARDWARE in setOf("ranchu","goldfish"))
        val context=InstrumentationRegistry.getInstrumentation().targetContext
        val namespace="test-trust-"+UUID.randomUUID().toString().replace("-","").take(20)
        val root=pair();val online=pair();val anchor=TrustAnchor("test-root",Base64.getEncoder().encodeToString(root.public.encoded),1)
        val now=System.currentTimeMillis()/1000
        fun link(revision:Long):String {
            val value=ServiceDescriptor(1,"syn443-client-bootstrap",1,revision,"service-a","https://id.example.invalid/realms/test","syn443-android","https://api.example.invalid",
                mapOf("online" to Base64.getEncoder().encodeToString(online.public.encoded)),now,now,now+3600)
            val manifest=signed(root,anchor.id,Canonical.json.encodeToJsonElement(value),"syn443-bootstrap+jws")
            fun url(s:String)=URLEncoder.encode(s,"UTF-8")
            return "syn443://enroll/v1?service=service-a&origin="+url(value.apiOrigin)+"&code="+Identity.random()+"&bootstrap="+url(manifest)
        }
        val executor=Executors.newSingleThreadExecutor()
        try {
            val first=link(1);val second=link(2)
            executor.submit {
                val store=BootstrapTrustStore(context,namespace,anchor)
                assertEquals(1L,store.preview(first).floor.revision)
                assertEquals(2L,store.accept(second).floor.revision)
                val reopened=BootstrapTrustStore(context,namespace,anchor)
                try {reopened.preview(first);fail("bootstrap rollback accepted")}catch(_:IllegalArgumentException){}
                assertEquals(2L,reopened.accept(second).floor.revision)
                val file=File(context.noBackupFilesDir,"$namespace.bin")
                val raw=file.readBytes();assertFalse(raw.toString(Charsets.ISO_8859_1).contains("api.example.invalid"))
                file.writeBytes(raw.copyOf().apply {this[lastIndex]=(this[lastIndex].toInt() xor 1).toByte()})
                try {BootstrapTrustStore(context,namespace,anchor).preview(second);fail("corruption reset trust")}catch(_:Exception){}
            }.get(20,TimeUnit.SECONDS)
        }finally{executor.shutdownNow();File(context.noBackupFilesDir,"$namespace.bin").delete()}
    }
}
