package io.syn443.policy

import kotlinx.serialization.encodeToString
import org.junit.Assert.*
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64

class RouteCheckPlanPolicyTest {
    private val now=1_800_000_000_000L
    private val key=KeyPairGenerator.getInstance("EC").apply {initialize(ECGenParameterSpec("secp256r1"))}.generateKeyPair()
    private fun enc(raw:ByteArray)=Base64.getUrlEncoder().withoutPadding().encodeToString(raw)
    private val thumb=enc(ByteArray(32){9})
    private val profile="""{"schemaVersion":2,"id":"connectivity","revision":1,"deadlineMs":12000,"leaves":[{"id":"tcp","check":{"method":"tcp","target":"a.example.invalid:443"}}],"gates":[],"stages":[{"leaf":"tcp"}]}"""
    private fun engine(row:String="\"profile\":$profile")="""{"outbounds":[{"type":"http","tag":"entry","server":"192.0.2.1","server_port":443}],"route":{"final":"entry"},"route_checks":[{"outbound":"entry","required":true,$row}]}"""
    private fun payload(config:String=engine())=Payload(2,1,0,0,"composition-device","syn443-device",now-1000,now-1000,now+300000,now+600000,
        listOf("engine-config.v1","tun.lease.v1","policy.keybound.v2","route.health.v1",Policy.ROUTE_CHECK_PLAN),Policy.BASELINE_ALGORITHM,
        enc(config.toByteArray()),Policy.hash(config),Gate(30,false,listOf(Check("internet","https_204","https://health.example.invalid/generate_204"))),keyThumbprint=thumb)
    private fun sign(p:Payload):String {
        val header="""{"alg":"ES256","kid":"composition","typ":"syn443-policy+jws"}"""
        val body=Canonical.encode(Canonical.parse(Policy.json.encodeToString(p)))
        val input=enc(header.toByteArray())+"."+enc(body.toByteArray())
        val signature=Signature.getInstance("SHA256withECDSAinP1363Format").run {initSign(key.private);update(input.toByteArray());sign()}
        return input+"."+enc(signature)
    }
    private fun verify(p:Payload)=Policy.verifyBound(sign(p),mapOf("composition" to Base64.getEncoder().encodeToString(key.public.encoded)),"composition-device",thumb,now)
    private fun rejected(label:String="case",block:()->Unit) {try {block();fail("composition_admission_case_$label")}catch(_:IllegalArgumentException){}catch(_:IllegalStateException){}}
    @Test fun signedCompositionRequiresExactCapabilityHealthConfigureAndKeyBinding() {
        val base=payload()
        assertEquals(engine(),verify(base).engineConfig)
        for(cap in listOf(Policy.ROUTE_CHECK_PLAN,"route.health.v1","policy.keybound.v2")) rejected {
            verify(base.copy(requiredCapabilities=base.requiredCapabilities-cap))
        }
        rejected {verify(base.copy(operation="release"))}
        rejected {verify(base.copy(schemaVersion=1,keyThumbprint="",requiredCapabilities=base.requiredCapabilities-"policy.keybound.v2"))}
        rejected {verify(base.copy(contentHash="0".repeat(64)))}
    }
    @Test fun countryAndIpLeavesKeepIndependentCapabilitiesAndCannotHideInAlternatives() {
        val country=profile.replace("\"id\":\"tcp\",\"check\":{\"method\":\"tcp\",\"target\":\"a.example.invalid:443\"}",
            "\"id\":\"tcp\",\"check\":{\"method\":\"https_exit_country\",\"target\":\"https://country.example.invalid/\",\"expected_exit_class\":\"RU\"}")
            .replace("\"gates\":[],\"stages\":[{\"leaf\":\"tcp\"}]","\"gates\":[\"tcp\"],\"stages\":[]")
        val raw=engine("\"profile\":$country")
        val base=payload(raw)
        rejected {verify(base)}
        assertEquals(raw,verify(base.copy(requiredCapabilities=base.requiredCapabilities+Policy.ROUTE_EXIT_COUNTRY)).engineConfig)
        rejected {verify(base.copy(requiredCapabilities=base.requiredCapabilities+Policy.ROUTE_EXIT_IP))}
        val ip=country.replace("https_exit_country","https_exit_ip").replace("https://country.example.invalid/","https://address.example.invalid/ip")
            .replace("\"expected_exit_class\":\"RU\"","\"expected_ip\":\"192.0.2.9\"")
        val ipPayload=payload(engine("\"profile\":$ip"))
        assertNotNull(verify(ipPayload.copy(requiredCapabilities=ipPayload.requiredCapabilities+Policy.ROUTE_EXIT_IP)))
        val alternative=country.replace("\"gates\":[\"tcp\"],\"stages\":[]","\"gates\":[],\"stages\":[{\"leaf\":\"tcp\"}]")
        rejected {verify(payload(engine("\"profile\":$alternative")).copy(requiredCapabilities=base.requiredCapabilities+Policy.ROUTE_EXIT_COUNTRY))}
    }
    @Test fun legacySignedBytesRemainOpaqueAndNullDuplicateCaseOrMixedProfileCannotDowngrade() {
        val old=engine("\"checks\":[{\"method\":\"tcp\",\"target\":\"a.example.invalid:443\"}]")
        val legacy=payload(old).copy(requiredCapabilities=payload().requiredCapabilities-Policy.ROUTE_CHECK_PLAN)
        assertEquals(old,verify(legacy).engineConfig)
        val omitted=old.replace("\"required\":true,", "")
        assertEquals(omitted,verify(payload(omitted).copy(requiredCapabilities=legacy.requiredCapabilities)).engineConfig)
        rejected {verify(legacy.copy(requiredCapabilities=legacy.requiredCapabilities+Policy.ROUTE_CHECK_PLAN))}
        for((index,raw) in listOf(engine("\"profile\":null"),engine("\"profile\":[]"),engine("\"Profile\":$profile"),
            engine("\"checks\":[],\"profile\":$profile"),engine().replace("\"revision\":1","\"revision\":1.0"),
            engine().replace("\"revision\":1","\"revision\":1,\"\\u0072evision\":1"),engine().dropLast(1)+",\"unrelated\":tru}",
            engine().replace("\"required\":true,", ""),engine().replace("\"required\":true", "\"required\":\"true\""),
            engine().replace("\"outbound\":\"entry\"", "\"outbound\":1"),engine().replace("\"required\":true", "\"required\":true,\"\\u0072equired\":true")).withIndex()) {
            rejected("profile-shape-$index") {verify(payload(raw))}
            rejected("profile-shape-no-cap-$index") {verify(payload(raw).copy(requiredCapabilities=legacy.requiredCapabilities))}
        }
        // These are actual signed-policy calls, not direct extractor assertions.
        // Extra fields remain opaque to Policy; EngineConfig validates its own
        // supported fields and finite/typed values before any engine activation.
        val invalidAtoms=listOf("tru","fals","undefined","TRUE","False","nul","NaN","Infinity","+1","01","1.","1e","-")
        for((index,atom) in invalidAtoms.withIndex()) {
            val top=engine().dropLast(1)+",\"outside\":$atom}"
            val nested=engine().dropLast(1)+",\"outside\":{\"level\":[1,{\"value\":$atom}]}}"
            rejected("atom-top-$index") {verify(payload(top))}
            rejected("atom-nested-$index") {verify(payload(nested))}
        }
        val validAtoms=listOf("0","-12","1.5","-0.25","1e2","-2.500E+3","null","true","false","\"tru\"","\"undefined\"",
            "[0,1.5,1e2,null,true,false,\"tru\",{\"value\":2.5E-1}]",(0 until 256).joinToString(",","[","]"))
        for((index,atom) in validAtoms.withIndex()) {
            val raw=engine().dropLast(1)+",\"outside\":{\"value\":$atom}}"
            val verified=try {verify(payload(raw))}catch(failure:Exception) {
                throw AssertionError("valid_atom_case_${index}_${failure.javaClass.simpleName}")
            }
            assertTrue("opaque_atom_case_$index",raw==verified.engineConfig)
        }
    }
}
