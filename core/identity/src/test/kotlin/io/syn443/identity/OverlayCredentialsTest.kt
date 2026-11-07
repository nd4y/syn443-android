package io.syn443.identity

import io.syn443.policy.Canonical
import kotlinx.serialization.json.*
import org.junit.Assert.*
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class OverlayCredentialsTest {
    private val now=1_800_000_000_000L
    private val key=KeyPairGenerator.getInstance("EC").apply {initialize(ECGenParameterSpec("secp256r1"))}.generateKeyPair()
    private val roots=mapOf("fixture-online" to Base64.getEncoder().encodeToString(key.public.encoded))
    private val address=OverlayAddress("service-a",Identity.hash("synthetic-owner-a".toByteArray()),"device-a","personal-overlay","netbird","cloud-resource","provider-network",1,"https://api.example.invalid")
    private val binding=OverlayCredentialBinding(address,Identity.hash("synthetic-device-key".toByteArray()),Identity.hash("synthetic-reference".toByteArray()),1,0,now+120_000)
    private val value=UUID.randomUUID().toString()
    private fun text(v:String)=JsonPrimitive(v)
    private fun addressJSON()=buildJsonObject {
        put("serviceId",text(address.serviceId));put("ownerTag",text(address.ownerTag));put("deviceId",text(address.deviceId));put("overlayId",text(address.overlayId));put("provider",text(address.provider));put("resourceId",text(address.resourceId));put("networkId",text(address.networkId));put("identityEpoch",JsonPrimitive(address.identityEpoch));put("managementURL",text(address.managementURL))
    }
    private fun body()=buildJsonObject {
        put("schemaVersion",JsonPrimitive(1));put("audience",text("syn443-overlay-credential"));put("address",addressJSON());put("keyThumbprint",text(binding.keyThumbprint));put("reference",text(binding.reference));put("version",JsonPrimitive(1));put("securityEpoch",JsonPrimitive(0));put("kind",text("netbird.setup-key"));put("issuedAtMs",JsonPrimitive(now));put("notBeforeMs",JsonPrimitive(now));put("expiresMs",JsonPrimitive(now+60_000));put("value",text(value))
    }
    private fun signed(payload:JsonObject=body(),header:JsonObject=buildJsonObject {put("alg",text("ES256"));put("kid",text("fixture-online"));put("typ",text("syn443-overlay-credential+jws"))},rawBody:String=Canonical.encode(payload),rawHeader:String=Canonical.encode(header)):String {
        val input=Identity.encode(rawHeader.toByteArray())+"."+Identity.encode(rawBody.toByteArray())
        val sig=Signature.getInstance("SHA256withECDSAinP1363Format").run {initSign(key.private);update(input.toByteArray());sign()}
        return input+"."+Identity.encode(sig)
    }
    private fun reject(raw:String,b:OverlayCredentialBinding=binding,lower:Long=now,upper:Long=now,keys:Map<String,String> = roots) {
        val e=assertThrows(IllegalArgumentException::class.java) {OverlayCredentials.verify(raw,keys,b,lower,upper)}
        assertEquals("overlay_credential_invalid",e.message)
    }
    @Test fun signedAddressedCredentialHasIndependentContextAndZeroesEveryBorrowedCopy() {
        val secret=OverlayCredentials.verify(signed(),roots,binding,now,now)
        assertEquals(ManagedOverlay.namespace(address),secret.namespace);assertEquals(binding.reference,secret.reference)
        assertEquals(1L,secret.version);assertEquals(0L,secret.securityEpoch);assertEquals(now+60_000,secret.expiresMs)
        var borrowed=byteArrayOf()
        secret.useValue {borrowed=it;assertEquals(value,it.toString(Charsets.US_ASCII))};assertTrue(borrowed.all {it==0.toByte()})
        assertThrows(IllegalStateException::class.java) {secret.useValue {borrowed=it;throw IllegalStateException("synthetic SDK failure")}}
        assertTrue(borrowed.all {it==0.toByte()});assertFalse(secret.toString().contains(value));assertFalse(binding.toString().contains(binding.reference))
        secret.close();secret.close();assertThrows(IllegalStateException::class.java) {secret.useValue {error("closed secret was readable")}}
        OverlayCredentials.verify(signed(),roots,binding.copy(address=address.copy(managementURL="https://API.EXAMPLE.INVALID:443/")),now,now).close()
    }
    @Test fun closingOwnedSecretDoesNotWaitForAnUninterruptibleBorrower() {
        val owned=value.toByteArray();val secret=OverlaySetupSecret("managed-netbird/test",binding.reference,1,0,now+60_000,owned)
        val entered=CountDownLatch(1);val release=CountDownLatch(1);val done=CountDownLatch(1);val closed=CountDownLatch(1)
        val thread=Thread {try {secret.useValue {entered.countDown();check(release.await(5,TimeUnit.SECONDS))}}finally {done.countDown()}}
        val closer=Thread {secret.close();closed.countDown()}
        thread.start();assertTrue(entered.await(2,TimeUnit.SECONDS));closer.start()
        try {assertTrue("secret close waited for borrower",closed.await(1,TimeUnit.SECONDS));assertTrue(owned.all {it==0.toByte()})}
        finally {release.countDown();assertTrue(done.await(2,TimeUnit.SECONDS));thread.join(1000);closer.join(1000)}
    }
    @Test fun everyRecipientAndEpochReferenceOrConservativeLeaseBoundaryIsEnforced() {
        val raw=signed()
        for(bad in listOf(binding.copy(address=address.copy(serviceId="service-b")),binding.copy(address=address.copy(ownerTag=Identity.hash("other-owner".toByteArray()))),binding.copy(address=address.copy(deviceId="device-b")),binding.copy(address=address.copy(overlayId="overlay-b")),binding.copy(address=address.copy(resourceId="resource-b")),binding.copy(address=address.copy(networkId="network-b")),binding.copy(address=address.copy(identityEpoch=2)),binding.copy(address=address.copy(managementURL="https://other.example.invalid")),binding.copy(keyThumbprint=Identity.hash("other-key".toByteArray())),binding.copy(reference=Identity.hash("other-ref".toByteArray())),binding.copy(version=2),binding.copy(securityEpoch=1),binding.copy(offlineUntilMs=now+59_999)))reject(raw,bad)
        reject(raw,lower=now-1,upper=now+1);reject(raw,lower=now+60_000,upper=now+60_000)
        reject(raw,lower=-1);reject(raw,lower=now+1,upper=now);reject(raw,lower=0,upper=9_007_199_254_740_991L)
    }
    @Test fun signedInvalidClaimsUnknownMembersTypesAndLimitsCannotBecomeSecrets() {
        val changes=mapOf("schemaVersion" to JsonPrimitive(2),"audience" to text("syn443-device"),"kind" to text("provider-management-token"),"value" to text("invalid"),"reference" to text("bad"),"keyThumbprint" to text("_".repeat(43)),"version" to JsonPrimitive(0),"securityEpoch" to JsonPrimitive(-1),"issuedAtMs" to JsonPrimitive(0),"notBeforeMs" to JsonPrimitive(now-1),"expiresMs" to JsonPrimitive(now),"unknown" to JsonPrimitive(true))
        for((field,replacement) in changes)reject(signed(JsonObject(body()+(field to replacement))))
        reject(signed(JsonObject(body()-("value"))))
        reject(signed(JsonObject(body()+("version" to text("1")))))
        reject(signed(JsonObject(body()+("audience" to JsonPrimitive(1)))))
        val maximumVersion=JsonObject(body()+("version" to JsonPrimitive(9_007_199_254_740_991L)))
        reject(signed(maximumVersion),b=binding.copy(version=9_007_199_254_740_991L-1))
        reject(signed(JsonObject(body()+("expiresMs" to JsonPrimitive(now+1_800_001)))),b=binding.copy(offlineUntilMs=now+1_800_001))
        reject(signed(JsonObject(body()+("issuedAtMs" to JsonPrimitive(now+30_001)))))
        reject(signed(JsonObject(body()+("notBeforeMs" to JsonPrimitive(now+1)))))
        reject(signed(JsonObject(body()+("address" to JsonObject(addressJSON()+("provider" to text("tailscale")))))))
        reject(signed(JsonObject(body()+("address" to JsonObject(addressJSON()+("extra" to JsonPrimitive(true)))))))
        reject(signed(rawBody=" "+Canonical.encode(body())));reject(signed(rawBody="x".repeat(8193)))
    }
    @Test fun malformedSignatureKeysAndCanonicalHeaderAreRejectedWithFixedErrorOnly() {
        val raw=signed();val parts=raw.split('.')
        for(bad in listOf("","x".repeat(16_385),"a.b",raw+"\n","A".repeat(1025)+".AA.AA","!.AA.AA",parts[0]+"=."+parts[1]+"."+parts[2],parts[0]+"."+parts[1]+".AA",parts[0]+"."+parts[1]+"."+Identity.encode(ByteArray(64)),parts[0]+"."+Identity.encode("{}".toByteArray())+"."+parts[2]))reject(bad)
        val original=Canonical.parse(policyUtf8(parts[0])).jsonObject
        for((field,replacement) in mapOf("alg" to text("none"),"typ" to text("syn443-policy+jws"),"kid" to text("missing"),"extra" to JsonPrimitive(true)))reject(signed(header=JsonObject(original+(field to replacement))))
        reject(signed(rawHeader=" "+Canonical.encode(original)));reject(raw,keys=emptyMap());reject(raw,keys=mapOf("fixture-online" to "bad"))
        val other=KeyPairGenerator.getInstance("EC").apply {initialize(ECGenParameterSpec("secp256r1"))}.generateKeyPair();reject(raw,keys=mapOf("fixture-online" to Base64.getEncoder().encodeToString(other.public.encoded)))
        val p384=KeyPairGenerator.getInstance("EC").apply {initialize(ECGenParameterSpec("secp384r1"))}.generateKeyPair();reject(raw,keys=mapOf("fixture-online" to Base64.getEncoder().encodeToString(p384.public.encoded)))
    }
    private fun policyUtf8(raw:String)=io.syn443.policy.Policy.utf8(io.syn443.policy.Policy.decode64(raw))
}
