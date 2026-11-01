package io.syn443.identity

import io.syn443.policy.Canonical
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import org.junit.Assert.*
import org.junit.Test
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64

class BootstrapTrustTest {
    companion object {
        private const val now=1_800_000_000L
        private fun key()=KeyPairGenerator.getInstance("EC").apply {initialize(ECGenParameterSpec("secp256r1"))}.generateKeyPair()
        private val old=key();private val next=key();private val publication=key()
        private fun spki(key:KeyPair)=Base64.getEncoder().encodeToString(key.public.encoded)
        private val anchor=TrustAnchor("offline-root-a",spki(old),1)
        private val nextAnchor=TrustAnchor("offline-root-b",spki(next),2)
        private fun descriptor()=ServiceDescriptor(1,"syn443-client-bootstrap",1,1,"service-a",
            "https://identity.example.invalid/realms/test","syn443-android","https://api.example.invalid",
            mapOf("publication-a" to spki(publication)),now,now,now+3600)
        private fun fail(block:()->Unit){try{block();throw AssertionError("untrusted bootstrap accepted")}catch(e:Exception){}}
        private fun signed(value:JsonElement,type:String,key:KeyPair=old,id:String=anchor.id):String {
            val header=buildJsonObject {put("alg","ES256");put("kid",id);put("typ",type)}
            return signRaw(Canonical.encode(header),Canonical.encode(value),key)
        }
        private fun signRaw(header:String,payload:String,key:KeyPair):String {
            val input=Identity.encode(header.toByteArray(Charsets.US_ASCII))+"."+Identity.encode(payload.toByteArray(Charsets.US_ASCII))
            val signature=Signature.getInstance("SHA256withECDSA").run {initSign(key.private);update(input.toByteArray(Charsets.US_ASCII));sign()}
            return input+"."+Identity.encode(Identity.derToRaw(signature))
        }
        private fun manifest(value:ServiceDescriptor=descriptor())=signed(Canonical.parse(Canonical.json.encodeToString(value)),"syn443-bootstrap+jws")
        private fun link(raw:String=manifest(),origin:String=descriptor().apiOrigin,code:String=Identity.hash("synthetic-invite".toByteArray()))=
            "syn443://enroll/v1?"+Identity.form(linkedMapOf("service" to "service-a","origin" to origin,"code" to code,"bootstrap" to raw))
    }
    @Test fun authenticatesServiceBeforeDiscoveryAndRetainsRevisionFloor() {
        val raw=manifest();val (value,floor)=BootstrapTrust.descriptor(raw,anchor,ServiceFloor(),now)
        assertEquals(descriptor(),value);assertEquals(1L,floor.revision)
        assertEquals(floor,BootstrapTrust.descriptor(raw,anchor,floor,now).second)
        val newer=manifest(value.copy(revision=2));val advanced=BootstrapTrust.descriptor(newer,anchor,floor,now).second
        fail {BootstrapTrust.descriptor(raw,anchor,advanced,now)}
        fail {BootstrapTrust.descriptor(manifest(value.copy(revision=2,issuer="https://other.example.invalid")),anchor,advanced,now)}
        val authenticated=BootstrapTrust.authenticate(link(),anchor,ServiceFloor(),now)
        assertEquals(value.serviceId,authenticated.bootstrap().serviceId)
        assertEquals(value.apiOrigin,authenticated.bootstrap().apiOrigin)
        assertFalse(authenticated.toString().contains(authenticated.code));assertFalse(value.toString().contains(value.issuer))
        assertFalse(anchor.toString().contains(anchor.spki));assertFalse(BootstrapTrust.parse(link()).toString().contains(authenticated.code))
        fail {BootstrapTrust.authenticate(link(origin="https://other.example.invalid"),anchor,ServiceFloor(),now)}
    }
    @Test fun rootTransitionRequiresBothKeysExactPayloadAndNextEpoch() {
        val transition=RootTransition(1,"syn443-root-transition",anchor.id,nextAnchor.id,nextAnchor.spki,2,now,now,now+3600)
        val body=Canonical.parse(Canonical.json.encodeToString(transition))
        val rotation=RootRotation(signed(body,"syn443-root-transition+jws"),signed(body,"syn443-root-transition+jws",next,nextAnchor.id))
        val active=BootstrapTrust.advance(rotation,anchor,now)
        assertEquals(nextAnchor.id,active.id);assertEquals(2L,active.epoch)
        assertEquals(active,BootstrapTrust.advance(rotation,active,now+7200))
        fail {BootstrapTrust.descriptor(manifest(),active,ServiceFloor(),now)}
        val newManifest=descriptor().copy(rootEpoch=2,revision=2)
        val encoded=signed(Canonical.parse(Canonical.json.encodeToString(newManifest)),"syn443-bootstrap+jws",next,active.id)
        assertEquals(newManifest,BootstrapTrust.descriptor(encoded,active,ServiceFloor(),now).first)
        fail {BootstrapTrust.advance(rotation.copy(next=rotation.previous),anchor,now)}
        fail {BootstrapTrust.advance(rotation.copy(previous=rotation.next),anchor,now)}
        fail {BootstrapTrust.advance(rotation,anchor,now+7200)}
        val other=Canonical.parse(Canonical.json.encodeToString(transition.copy(expires=now+3500)))
        fail {BootstrapTrust.advance(rotation.copy(next=signed(other,"syn443-root-transition+jws",next,nextAnchor.id)),anchor,now)}
        val skipped=Canonical.parse(Canonical.json.encodeToString(transition.copy(epoch=3)))
        fail {BootstrapTrust.advance(RootRotation(signed(skipped,"syn443-root-transition+jws"),signed(skipped,"syn443-root-transition+jws",next,nextAnchor.id)),anchor,now)}
    }
    @Test fun deniesMalformedExpiredSubstitutedAndNoncanonicalInputs() {
        val original=descriptor()
        for(value in listOf(original.copy(schemaVersion=2),original.copy(audience="other"),original.copy(rootEpoch=2),
            original.copy(revision=0),original.copy(serviceId="../bad"),original.copy(clientId=""),original.copy(expires=now),
            original.copy(expires=now+31*86400),original.copy(notBefore=now+1),original.copy(roots=emptyMap()),
            original.copy(roots=mapOf(anchor.id to anchor.spki)),original.copy(roots=mapOf("publication-a" to "invalid")),
            original.copy(apiOrigin="https://API.example.invalid"),original.copy(apiOrigin="https://api.example.invalid:443"),
            original.copy(apiOrigin="https://api.example.invalid/path"),original.copy(issuer=original.issuer+"/"))) {
            fail {BootstrapTrust.descriptor(manifest(value),anchor,ServiceFloor(),now)}
        }
        for(floor in listOf(ServiceFloor(revision=-1),ServiceFloor(hash="invalid"),ServiceFloor("other",1,Identity.random()),ServiceFloor("service-a",1,"invalid"))) {
            fail {BootstrapTrust.descriptor(manifest(),anchor,floor,now)}
        }
        val raw=manifest()
        for(bad in listOf("",raw+".",raw+"=","x".repeat(BootstrapTrust.MAX_MANIFEST+1),raw.substringBeforeLast('.')+".AA")) {
            fail {BootstrapTrust.descriptor(bad,anchor,ServiceFloor(),now)}
        }
        for(bad in listOf(anchor.copy(id="../bad"),anchor.copy(epoch=0),anchor.copy(spki="invalid"),anchor.copy(lastTransition="invalid"))) {
            fail {BootstrapTrust.validateAnchor(bad)}
        }
        fail {BootstrapTrust.publicKey(Base64.getEncoder().encodeToString(ByteArray(257)))}
        fail {BootstrapTrust.descriptor(signed(Canonical.parse(Canonical.json.encodeToString(original)),"syn443-policy+jws"),anchor,ServiceFloor(),now)}
        val payload=Canonical.encode(Canonical.parse(Canonical.json.encodeToString(original)))
        for(header in listOf("""{"alg":"ES256","kid":"offline-root-a","typ":"syn443-bootstrap+jws","jwk":{}}""",
            """{"alg":"ES256","alg":"ES256","kid":"offline-root-a","typ":"syn443-bootstrap+jws"}""")) {
            fail {BootstrapTrust.descriptor(signRaw(header,payload,old),anchor,ServiceFloor(),now)}
        }
    }
    @Test fun invitationParserRejectsSubstitutionDuplicatesAndInvalidUtf8() {
        val raw=link()
        for(bad in listOf(raw+"&code=other",raw+"&%63ode=other",raw+"&extra=x",raw+"#fragment",raw.replace("/v1?","/v2?"),
            raw.replace("syn443://enroll","syn443://other"),raw.replace("syn443:","SYN443:"),raw.replace("service-a","service-b"),
            link(code="invalid"),"x".repeat(BootstrapTrust.MAX_LINK+1),raw.replace("service=service-a","service=%FF"),raw+"&unknown=%G0")) {
            fail {BootstrapTrust.authenticate(bad,anchor,ServiceFloor(),now)}
        }
    }
}
