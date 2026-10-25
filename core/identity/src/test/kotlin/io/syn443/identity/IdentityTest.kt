package io.syn443.identity

import io.syn443.policy.Canonical
import io.syn443.policy.Policy
import kotlinx.serialization.json.*
import org.junit.Assert.*
import org.junit.Test
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.Base64

class IdentityTest {
    companion object {
        private val ec=KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        private val rsa=KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        private val publicEC=ec.public as ECPublicKey
        private val publicRSA=rsa.public as RSAPublicKey
        private val roots=mapOf("fixture-root" to Base64.getEncoder().encodeToString(ec.public.encoded))
        private val bootstrap=Bootstrap("fixture","https://id.example.invalid/realms/test","syn443-android","https://api.example.invalid",roots)
        private const val now=1_800_000_000L
        private fun fail(block:()->Unit) { try {block();throw AssertionError("accepted invalid identity input")} catch(e:Exception) {} }
        private fun jwks():String = Canonical.encode(buildJsonObject { putJsonArray("keys") { add(buildJsonObject {
            put("kty","RSA");put("use","sig");put("alg","RS256");put("kid","fixture");put("n",Identity.encode(unsigned(publicRSA.modulus)));put("e","AQAB")
        }) } })
        private fun unsigned(value:BigInteger):ByteArray = value.toByteArray().let { if(it[0]==0.toByte())it.copyOfRange(1,it.size) else it }
        private fun pending()=Identity.newPending(7,Identity.thumbprint(publicEC),2,1000)
        private fun token(claims:JsonObject,header:String="""{"alg":"RS256","kid":"fixture","typ":"JWT"}"""):String {
            val input=Identity.encode(header.toByteArray())+"."+Identity.encode(Canonical.encode(claims).toByteArray())
            val sig=Signature.getInstance("SHA256withRSA").run {initSign(rsa.private);update(input.toByteArray());sign()}
            return input+"."+Identity.encode(sig)
        }
        private fun claims(p:Pending,id:Boolean)=buildJsonObject {
            put("iss",bootstrap.issuer);put("sub","fixture-user");put("aud",if(id)bootstrap.clientId else "syn443-api");put("azp",bootstrap.clientId);put("iat",now);put("exp",now+300)
            if(id)put("nonce",p.nonce) else putJsonObject("cnf") {put("jkt",p.thumbprint)}
            put("name","Иван")
        }
        private fun validate(p:Pending,id:JsonObject=claims(p,true),access:JsonObject=claims(p,false))=Identity.identity(token(id),token(access),Identity.rsaKeys(jwks()),bootstrap,p,now)
        private fun change(c:JsonObject,name:String,value:JsonElement)=JsonObject(c.toMutableMap().also {it[name]=value})
        private fun callback(p:Pending,extra:Map<String,String> = emptyMap())=Identity.callback(Identity.callback+"?"+Identity.form(mapOf("code" to "synthetic-code","state" to p.state,"iss" to bootstrap.issuer)+extra),bootstrap,p,7,2,2000)
    }
    @Test fun pkceBrowserRequestBindsExactIssuerCallbackStateNonceAndKey() {
        val p=pending();val auth=Identity.authorization(bootstrap,p)
        assertTrue(auth.startsWith(bootstrap.issuer+"/protocol/openid-connect/auth?"))
        assertTrue(auth.contains("code_challenge_method=S256"));assertTrue(auth.contains("dpop_jkt="+p.thumbprint))
        assertTrue(auth.contains("code_challenge="+Identity.hash(p.verifier.toByteArray())))
        assertFalse(auth.contains(p.verifier));assertTrue(auth.contains("redirect_uri=syn443%3A%2F%2Foauth%2Fcallback"))
        assertNotEquals(p.state,p.nonce);assertEquals(43,p.verifier.length)
    }
    @Test fun callbackRequiresCurrentIntentBootAndMonotonicDeadline() {
        val p=pending();assertEquals("synthetic-code",callback(p).code)
        assertTrue(p.current(7,2,1000));assertTrue(p.current(7,2,300999))
        assertFalse(p.current(7,2,301000));assertFalse(p.current(8,2,2000));assertFalse(p.current(7,3,2000));assertFalse(p.current(7,2,999))
        val uri=Identity.callback+"?"+Identity.form(mapOf("code" to "code","state" to p.state,"iss" to bootstrap.issuer))
        fail {Identity.callback(uri,bootstrap,p,8,2,2000)};fail {Identity.callback(uri,bootstrap,p,7,2,301000)}
    }
    @Test fun callbackRejectsWrongStateIssuerAndMixedCodeError() {
        val p=pending();for(extra in listOf(mapOf("state" to "wrong"),mapOf("iss" to "https://other.example.invalid"),mapOf("error" to "access_denied"),mapOf("unexpected" to "x"))) fail {callback(p,extra)}
        val uri=Identity.callback+"?"+Identity.form(mapOf("error" to "access_denied","state" to p.state,"iss" to bootstrap.issuer))
        assertEquals("access_denied",Identity.callback(uri,bootstrap,p,7,2,2000).error)
    }
    @Test fun callbackRejectsDuplicateEncodedMembersAndWrongSurface() {
        val p=pending();val query=Identity.form(mapOf("code" to "code","state" to p.state,"iss" to bootstrap.issuer))
        for(uri in listOf(Identity.callback+"?"+query+"&%73tate="+p.state,"syn443://user@oauth/callback?"+query,"syn443://oauth:443/callback?"+query,"syn443://oauth/%63allback?"+query,"syn443://other/callback?"+query,Identity.callback+"?"+query+"#fragment",Identity.callback+"?"+query+"&error_description=%ff")) fail {Identity.callback(uri,bootstrap,p,7,2,2000)}
    }
    @Test fun bootstrapRequiresPinnedRootsAndUnambiguousHttpsOrigins() {
        bootstrap.validate()
        for(url in listOf("http://id.example.invalid","https://user@id.example.invalid","https://id.example.invalid?x=1","https://id.example.invalid#x","https://id.example.invalid/a/../b","https://id.example.invalid/%61","https://id.example.invalid:65536")) fail {Identity.https(url)}
        fail {bootstrap.copy(roots=emptyMap()).validate()};fail {bootstrap.copy(apiOrigin=bootstrap.apiOrigin+"/api").validate()}
        fail {bootstrap.copy(tlsCaDer="fixture").validate()};bootstrap.copy(apiOrigin="https://127.0.0.1:17847",tlsCaDer="fixture").validate()
    }
    @Test fun proofUsesPublicJwkAndRawEs256WithAllRequestBindings() {
        val token=Identity.random();val body="{}".toByteArray();val uri=bootstrap.apiOrigin+"/v1/devices/enroll"
        val proof=Identity.proof(publicEC,{input->Signature.getInstance("SHA256withECDSA").run {initSign(ec.private);update(input);sign()}},"POST",uri,now,token,"server-nonce",body)
        val parts=proof.split('.');val h=Identity.objectJSON(Policy.utf8(Policy.decode64(parts[0])));val c=Identity.objectJSON(Policy.utf8(Policy.decode64(parts[1])))
        assertEquals(setOf("alg","jwk","typ"),h.keys);assertEquals(setOf("crv","kty","x","y"),h.getValue("jwk").jsonObject.keys)
        assertEquals("POST",c.getValue("htm").jsonPrimitive.content);assertEquals(uri,c.getValue("htu").jsonPrimitive.content)
        assertEquals(Identity.hash(token.toByteArray()),c.getValue("ath").jsonPrimitive.content);assertEquals(Identity.hash(body),c.getValue("req_hash").jsonPrimitive.content)
        assertEquals("server-nonce",c.getValue("nonce").jsonPrimitive.content);assertEquals(now,c.getValue("iat").jsonPrimitive.long)
        val raw=Policy.decode64(parts[2]);assertEquals(64,raw.size)
        fun integer(raw:ByteArray):ByteArray {val b=BigInteger(1,raw).toByteArray();return byteArrayOf(2,b.size.toByte())+b}
        val integers=integer(raw.copyOfRange(0,32))+integer(raw.copyOfRange(32,64));val der=byteArrayOf(0x30,integers.size.toByte())+integers
        assertTrue(Signature.getInstance("SHA256withECDSA").run {initVerify(ec.public);update((parts[0]+"."+parts[1]).toByteArray());verify(der)})
        assertEquals(Identity.hash(Canonical.encode(h.getValue("jwk")).toByteArray()),Identity.thumbprint(publicEC))
    }
    @Test fun tokenEndpointProofDoesNotInventAccessHashOrRequestBody() {
        val proof=Identity.proof(publicEC,{b->Signature.getInstance("SHA256withECDSA").run {initSign(ec.private);update(b);sign()}},"POST",bootstrap.issuer+"/protocol/openid-connect/token",now)
        val c=Identity.objectJSON(Policy.utf8(Policy.decode64(proof.split('.')[1])))
        assertFalse("ath" in c);assertFalse("req_hash" in c);assertFalse("nonce" in c)
    }
    @Test fun proofRejectsUnsafeAddressMethodAndMalformedSignature() {
        fail {Identity.proof(publicEC,{byteArrayOf()},"DELETE",bootstrap.apiOrigin,now)}
        fail {Identity.proof(publicEC,{byteArrayOf()},"POST","http://api.example.invalid",now)}
        for(raw in listOf(byteArrayOf(),byteArrayOf(0x30,6,2,1,0,2,1,0),byteArrayOf(0x30,6,2,1,-1,2,1,1),byteArrayOf(0x30,7,2,2,0,1,2,1,1))) fail {Identity.derToRaw(raw)}
    }
    @Test fun strictJsonRejectsDuplicateAndInvalidUnicodeBeforeVerification() {
        assertEquals("Иван",Identity.objectJSON("""{"name":"Иван"}""").getValue("name").jsonPrimitive.content)
        for(raw in listOf("""{"a":1,"a":2}""","""{"a":{"x":1,"x":2}}""","""{"a":"\ud800"}""","{} {}","""{"a":1.5}""","{"+"\"x\":0,".repeat(100)+"\"y\":1}")) fail {Identity.objectJSON(raw)}
    }
    @Test fun oidcRequiresSignedIdentityAndSenderConstrainedAccess() {
        val p=pending();assertEquals("fixture-user",validate(p).subject)
        fail {validate(p,access=change(claims(p,false),"cnf",buildJsonObject {put("jkt",Identity.random())}))}
        fail {validate(p,access=change(claims(p,false),"sub",JsonPrimitive("other")))}
        fail {validate(p,id=change(claims(p,true),"nonce",JsonPrimitive("wrong")))}
    }
    @Test fun oidcRejectsIssuerAudienceAuthorizedPartyAndTimeErrors() {
        val p=pending();val original=claims(p,true)
        for((name,value) in listOf("iss" to JsonPrimitive("https://other.example.invalid"),"aud" to JsonPrimitive("other"),"azp" to JsonPrimitive("other"),"exp" to JsonPrimitive(now),"exp" to JsonPrimitive(now+601),"iat" to JsonPrimitive(now+31),"iat" to JsonPrimitive(now-601),"nbf" to JsonPrimitive(now+31),"sub" to JsonPrimitive("user\u0000id"),"sub" to JsonPrimitive(123),"exp" to JsonPrimitive((now+300).toString()))) fail {validate(p,id=change(original,name,value))}
        for(name in listOf("iss","sub","aud","exp","iat","nonce")) fail {validate(p,id=JsonObject(original.toMutableMap().also {it.remove(name)}))}
    }
    @Test fun jwtRejectsUntrustedHeadersSignaturesAndDuplicateClaims() {
        val p=pending();val keys=Identity.rsaKeys(jwks());val id=token(claims(p,true));val access=token(claims(p,false))
        val parts=id.split('.');val sig=Policy.decode64(parts[2]);sig[0]=(sig[0].toInt() xor 1).toByte();val bad=parts.take(2).joinToString(".")+"."+Identity.encode(sig)
        fail {Identity.identity(bad,access,keys,bootstrap,p,now)}
        fail {Identity.identity(token(claims(p,true),"""{"alg":"RS256","kid":"fixture","typ":"JWT","jku":"https://other.example.invalid"}"""),access,keys,bootstrap,p,now)}
        fail {Identity.identity(id,access,emptyMap(),bootstrap,p,now)}
    }
    @Test fun jwksRejectsWrongExponentMissingOrDuplicateKeys() {
        assertEquals(publicRSA.modulus,Identity.rsaKeys(jwks()).getValue("fixture").modulus)
        fail {Identity.rsaKeys(jwks().replace("AQAB","Aw"))};fail {Identity.rsaKeys("""{"keys":[]}""")}
        val value=Identity.objectJSON(jwks()).getValue("keys").jsonArray[0]
        fail {Identity.rsaKeys(Canonical.encode(buildJsonObject {put("keys",JsonArray(listOf(value,value)))}))}
    }
}
