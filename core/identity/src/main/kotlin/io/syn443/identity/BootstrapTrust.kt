package io.syn443.identity

import io.syn443.policy.Canonical
import io.syn443.policy.Policy
import kotlinx.serialization.Serializable
import kotlinx.serialization.EncodeDefault
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.net.URI
import java.security.KeyFactory
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

@Serializable data class TrustAnchor(val id:String,val spki:String,val epoch:Long,val lastTransition:String="") {
    override fun toString()="TrustAnchor([redacted])"
}
@Serializable data class ServiceFloor(val serviceId:String="",val revision:Long=0,val hash:String="")
@OptIn(ExperimentalSerializationApi::class)
@Serializable data class ServiceDescriptor(val schemaVersion:Int,val audience:String,val rootEpoch:Long,val revision:Long,
    val serviceId:String,val issuer:String,val clientId:String,val apiOrigin:String,val roots:Map<String,String>,
    val issuedAt:Long,val notBefore:Long,val expires:Long,
    @EncodeDefault(EncodeDefault.Mode.NEVER) val controlPanelOrigin:String="") {
    override fun toString()="ServiceDescriptor([redacted])"
}
@Serializable data class RootTransition(val schemaVersion:Int,val audience:String,val from:String,val to:String,
    val spki:String,val epoch:Long,val issuedAt:Long,val notBefore:Long,val expires:Long)
@Serializable data class RootRotation(val previous:String,val next:String)
data class InviteLink(val serviceId:String,val origin:String,val code:String,val manifest:String) {
    override fun toString()="InviteLink([redacted])"
}
class AuthenticatedInvite internal constructor(val descriptor:ServiceDescriptor,val floor:ServiceFloor,val code:String) {
    override fun toString()="AuthenticatedInvite([redacted])"
    fun bootstrap()=Bootstrap(descriptor.serviceId,descriptor.issuer,descriptor.clientId,descriptor.apiOrigin,
        descriptor.roots.toMap(),controlPanelOrigin=descriptor.controlPanelOrigin).also {it.validate()}
}

/** Local authentication only. The QR supplies no new root and causes no network
 * request until its service/endpoint metadata passes the installation authority. */
object BootstrapTrust {
    const val MAX_MANIFEST=6144
    const val MAX_LINK=8192
    private const val SAFE=9_007_199_254_740_991L
    private val identifier=Regex("[A-Za-z0-9_-]{1,64}")
    private val digest=Regex("[A-Za-z0-9_-]{43}")
    fun publicKey(raw:String):ECPublicKey {
        require(raw.length<=344)
        val der=Base64.getDecoder().decode(raw)
        require(der.size<=256 && Base64.getEncoder().encodeToString(der)==raw)
        val key=KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(der)) as ECPublicKey
        val expected=Identity.ecParameters
        require(key.params.order==expected.order && key.params.cofactor==expected.cofactor &&
            key.params.curve==expected.curve && key.params.generator==expected.generator)
        return key
    }
    fun validateAnchor(anchor:TrustAnchor) {
        require(identifier.matches(anchor.id) && anchor.epoch in 1..SAFE &&
            (anchor.lastTransition.isEmpty() || digest.matches(anchor.lastTransition)))
        publicKey(anchor.spki)
    }
    private fun secureURL(raw:String,path:Boolean) {
        val u=Identity.https(raw)
        require(raw.startsWith("https://") && u.rawAuthority==u.rawAuthority.lowercase() &&
            !u.host.endsWith('.') && !u.rawAuthority.endsWith(':') && u.port!=443)
        require(if(path) !u.path.endsWith('/') else u.path.isEmpty())
    }
    private fun validate(descriptor:ServiceDescriptor,anchor:TrustAnchor,now:Long) {
        require(descriptor.schemaVersion==1 && descriptor.audience=="syn443-client-bootstrap" &&
            descriptor.rootEpoch==anchor.epoch && descriptor.revision in 1..SAFE &&
            identifier.matches(descriptor.serviceId) && identifier.matches(descriptor.clientId))
        secureURL(descriptor.apiOrigin,false); secureURL(descriptor.issuer,true)
        if(descriptor.controlPanelOrigin.isNotEmpty())Identity.controlOrigin(descriptor.controlPanelOrigin)
        require(descriptor.issuedAt>0 && descriptor.issuedAt<=now+30 && descriptor.notBefore>=descriptor.issuedAt &&
            descriptor.notBefore<=now && descriptor.expires>now && descriptor.expires-descriptor.issuedAt<=30*86400)
        require(descriptor.roots.size in 1..4)
        descriptor.roots.forEach {(id,spki)->require(identifier.matches(id) && spki!=anchor.spki);publicKey(spki)}
    }
    private fun signed(raw:String,type:String,anchor:TrustAnchor):String {
        require(raw.length in 1..MAX_MANIFEST && raw.all {it.code<128})
        validateAnchor(anchor)
        val parts=raw.split('.');require(parts.size==3 && parts[0].length<=512)
        val text=Policy.utf8(Policy.decode64(parts[0]));val header=Canonical.parse(text).jsonObject
        require(header.keys==setOf("alg","kid","typ") && text==Canonical.encode(header) &&
            header.values.all {it is JsonPrimitive && it.isString})
        require(header.getValue("alg").jsonPrimitive.content=="ES256" &&
            header.getValue("kid").jsonPrimitive.content==anchor.id && header.getValue("typ").jsonPrimitive.content==type)
        val signature=Policy.decode64(parts[2]);require(signature.size==64)
        val key=publicKey(anchor.spki)
        fun integer(raw:ByteArray):ByteArray {val n=BigInteger(1,raw);require(n.signum()>0 && n<key.params.order)
            val bytes=n.toByteArray();return byteArrayOf(2,bytes.size.toByte())+bytes}
        val integers=integer(signature.copyOfRange(0,32))+integer(signature.copyOfRange(32,64))
        require(Signature.getInstance("SHA256withECDSA").run {initVerify(key);update((parts[0]+"."+parts[1]).toByteArray(Charsets.US_ASCII));
            verify(byteArrayOf(0x30,integers.size.toByte())+integers)})
        val payload=Policy.decode64(parts[1]);require(payload.size<=4096)
        return Policy.utf8(payload).also {require(Canonical.encode(Canonical.parse(it))==it)}
    }
    fun descriptor(raw:String,anchor:TrustAnchor,floor:ServiceFloor,now:Long):Pair<ServiceDescriptor,ServiceFloor> {
        val text=signed(raw,"syn443-bootstrap+jws",anchor)
        val value=Canonical.json.decodeFromString<ServiceDescriptor>(text);validate(value,anchor,now)
        val hash=Identity.hash(text.toByteArray(Charsets.UTF_8))
        require(floor.revision in 0..SAFE && (if(floor.revision==0L) floor.hash.isEmpty()&&floor.serviceId.isEmpty()
            else digest.matches(floor.hash)&&floor.serviceId==value.serviceId))
        require(value.revision>=floor.revision && (value.revision!=floor.revision || hash==floor.hash))
        return value to ServiceFloor(value.serviceId,value.revision,hash)
    }
    private fun validate(transition:RootTransition,current:TrustAnchor,now:Long) {
        require(transition.schemaVersion==1 && transition.audience=="syn443-root-transition" &&
            transition.from==current.id && identifier.matches(transition.to) && transition.to!=current.id &&
            transition.spki!=current.spki && transition.epoch==current.epoch+1 && transition.epoch<=SAFE)
        require(transition.issuedAt>0 && transition.issuedAt<=now+30 && transition.notBefore>=transition.issuedAt &&
            transition.notBefore<=now && transition.expires>now && transition.expires-transition.issuedAt<=7*86400)
        publicKey(transition.spki)
    }
    /** Caller commits the new anchor/floors in one protected journal before use.
     * Retired roots are not retained as fresh enrollment authorities. */
    fun advance(rotation:RootRotation,current:TrustAnchor,now:Long):TrustAnchor {
        validateAnchor(current);require(rotation.previous.length<=MAX_MANIFEST && rotation.next.length<=MAX_MANIFEST)
        val hash=Identity.hash(Canonical.encode(Canonical.parse(Canonical.json.encodeToString(rotation))).toByteArray(Charsets.UTF_8))
        if(hash==current.lastTransition)return current
        val previous=signed(rotation.previous,"syn443-root-transition+jws",current)
        val transition=Canonical.json.decodeFromString<RootTransition>(previous);validate(transition,current,now)
        val candidate=TrustAnchor(transition.to,transition.spki,transition.epoch,hash)
        val next=signed(rotation.next,"syn443-root-transition+jws",candidate)
        require(previous==next)
        Canonical.json.decodeFromString<RootTransition>(next)
        return candidate
    }
    private fun decode(raw:String):String {
        val bytes=ByteArrayOutputStream();var at=0
        while(at<raw.length) {val c=raw[at++];when(c) {
            '%'->{require(at+2<=raw.length);bytes.write(raw.substring(at,at+2).toInt(16));at+=2}
            '+'->bytes.write(32)
            else->{require(c.code in 33..126);bytes.write(c.code)}
        }}
        return Policy.utf8(bytes.toByteArray()).also {require(it.none(Char::isISOControl))}
    }
    fun parse(raw:String):InviteLink {
        require(raw.length in 1..MAX_LINK && raw.startsWith("syn443://") && raw.all {it.code in 33..126})
        val u=URI(raw);require(u.scheme=="syn443" && u.host=="enroll" && u.port==-1 &&
            u.rawPath=="/v1" && u.rawUserInfo==null && u.rawFragment==null)
        val values=linkedMapOf<String,String>()
        requireNotNull(u.rawQuery).split('&').forEach {entry->
            if(entry.isNotEmpty()) {val pair=entry.split('=',limit=2);require(pair.size==2 && values.size<4)
                val name=decode(pair[0]);require(name !in values);values[name]=decode(pair[1])}
        }
        require(values.keys==setOf("service","origin","code","bootstrap"))
        val result=InviteLink(values.getValue("service"),values.getValue("origin"),values.getValue("code"),values.getValue("bootstrap"))
        require(identifier.matches(result.serviceId) && digest.matches(result.code) && Policy.decode64(result.code).size==32 &&
            result.manifest.length in 1..MAX_MANIFEST);secureURL(result.origin,false)
        return result
    }
    fun authenticate(raw:String,anchor:TrustAnchor,floor:ServiceFloor,now:Long):AuthenticatedInvite {
        val invitation=parse(raw);val (value,next)=descriptor(invitation.manifest,anchor,floor,now)
        require(invitation.serviceId==value.serviceId && invitation.origin==value.apiOrigin)
        return AuthenticatedInvite(value,next,invitation.code)
    }
}
