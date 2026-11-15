package io.syn443.identity

import io.syn443.policy.Canonical
import io.syn443.policy.Policy
import kotlinx.serialization.json.*
import java.math.BigInteger
import java.security.KeyFactory
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/** Caller derives this binding from its verified assignment and login state. */
data class OverlayCredentialBinding(val address:OverlayAddress,val keyThumbprint:String,
    val reference:String,val version:Long,val securityEpoch:Long,val offlineUntilMs:Long) {
    override fun toString()="OverlayCredentialBinding([redacted])"
}

/** The secret has one owner. Every borrowed copy is zeroed even if SDK preparation
 * fails. Strings inside platform crypto/JSON parsers remain subject to JVM GC. */
class OverlaySetupSecret internal constructor(val namespace:String,val reference:String,val version:Long,
    val securityEpoch:Long,val expiresMs:Long,private val value:ByteArray):AutoCloseable {
    private var closed=false
    fun <T> useValue(block:(ByteArray)->T):T {
        val copy=synchronized(this) {check(!closed);value.copyOf()}
        try {return block(copy)}finally {copy.fill(0)}
    }
    @Synchronized override fun close() {value.fill(0);closed=true}
    override fun toString()="AddressedOverlaySetupSecret([redacted])"
}

object OverlayCredentials {
    private val setupKey=Regex("[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}")
    private fun text(value:JsonObject,key:String):String=value.getValue(key).jsonPrimitive.let {require(it.isString);it.content}
    private fun number(value:JsonObject,key:String):Long=value.getValue(key).jsonPrimitive.let {require(!it.isString);it.long}
    private fun digest(raw:String) {require(Policy.decode64(raw).size==32 && raw.length==43)}
    /** Both clock bounds must come from the existing conservative trusted-time
     * window. Wall clock or an unsigned response cannot extend this permit. */
    fun verify(raw:String,roots:Map<String,String>,binding:OverlayCredentialBinding,
        lowerMs:Long,upperMs:Long):OverlaySetupSecret = try {
        require(lowerMs in 0..upperMs && upperMs<=9_007_199_254_710_991L)
        require(raw.length in 1..16_384 && raw.all {it.code in 33..126})
        val parts=raw.split('.');require(parts.size==3 && parts[0].length<=1024)
        val headerRaw=Policy.utf8(Policy.decode64(parts[0]));val header=Canonical.parse(headerRaw).jsonObject
        require(headerRaw==Canonical.encode(header) && header.keys==setOf("alg","kid","typ"))
        require(text(header,"alg")=="ES256" && text(header,"typ")=="syn443-overlay-credential+jws")
        val kid=text(header,"kid");require(kid.matches(Regex("[A-Za-z0-9_-]{1,64}")))
        val key=KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(Base64.getDecoder().decode(roots.getValue(kid)))) as ECPublicKey
        require(key.params.order==Identity.ecParameters.order && key.params.cofactor==1 && key.params.curve.field.fieldSize==256)
        val signature=Policy.decode64(parts[2]);require(signature.size==64)
        fun integer(bytes:ByteArray):ByteArray {
            val n=BigInteger(1,bytes);require(n.signum()>0 && n<key.params.order)
            val value=n.toByteArray();return byteArrayOf(2,value.size.toByte())+value
        }
        val integers=integer(signature.copyOfRange(0,32))+integer(signature.copyOfRange(32,64))
        val der=byteArrayOf(0x30,integers.size.toByte())+integers
        require(Signature.getInstance("SHA256withECDSA").run {initVerify(key);update((parts[0]+"."+parts[1]).toByteArray(Charsets.US_ASCII));verify(der)})
        val bytes=Policy.decode64(parts[1]);require(bytes.size<=8192)
        val payloadRaw=try {Policy.utf8(bytes)}finally {bytes.fill(0)}
        val payload=Canonical.parse(payloadRaw).jsonObject
        require(payloadRaw==Canonical.encode(payload) && payload.keys==setOf("schemaVersion","audience","address","keyThumbprint","reference","version","securityEpoch","kind","issuedAtMs","notBeforeMs","expiresMs","value"))
        require(number(payload,"schemaVersion")==1L && text(payload,"audience")=="syn443-overlay-credential" && text(payload,"kind")=="netbird.setup-key")
        val address=payload.getValue("address").jsonObject
        require(address.keys==setOf("serviceId","ownerTag","deviceId","overlayId","provider","resourceId","networkId","identityEpoch","managementURL"))
        val actual=OverlayAddress(text(address,"serviceId"),text(address,"ownerTag"),text(address,"deviceId"),text(address,"overlayId"),text(address,"provider"),text(address,"resourceId"),text(address,"networkId"),number(address,"identityEpoch"),text(address,"managementURL"))
        val namespace=ManagedOverlay.namespace(actual);require(namespace==ManagedOverlay.namespace(binding.address))
        val thumb=text(payload,"keyThumbprint");val reference=text(payload,"reference");digest(thumb);digest(reference)
        val version=number(payload,"version");val epoch=number(payload,"securityEpoch")
        require(version in 1..9_007_199_254_740_991L && epoch in 0..9_007_199_254_740_991L)
        require(thumb==binding.keyThumbprint && reference==binding.reference && version==binding.version && epoch==binding.securityEpoch)
        val issued=number(payload,"issuedAtMs");val notBefore=number(payload,"notBeforeMs");val expires=number(payload,"expiresMs")
        require(issued>0 && issued<=upperMs+30_000 && notBefore>=issued && notBefore<=lowerMs && expires>upperMs && expires>notBefore && expires-issued<=1_800_000 && expires<=binding.offlineUntilMs)
        val value=text(payload,"value");require(setupKey.matches(value))
        OverlaySetupSecret(namespace,reference,version,epoch,expires,value.toByteArray(Charsets.US_ASCII))
    }catch(_:Exception){throw IllegalArgumentException("overlay_credential_invalid")}
}
