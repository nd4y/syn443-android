package io.syn443.identity

import io.syn443.policy.Canonical
import io.syn443.policy.Policy
import kotlinx.serialization.json.*

data class CapabilitySnapshot(val version:Long,val hash:String,val capabilities:List<String>,val authorityHash:String) {
    override fun toString()="CapabilitySnapshot([redacted])"
}
data class CapabilityOperation(val requestId:String,val body:String,val proposedHash:String,val expectedVersion:Long) {
    override fun toString()="CapabilityOperation([redacted])"
}
enum class CapabilityRequestState { QUEUED, APPROVED, REJECTED }

/** Availability declarations only. No policy, account permission, native owner
 * or private key changes here. A repeated authenticated snapshot derives the
 * same operation bytes; a committed head makes another mutation unnecessary. */
object CapabilityNegotiation {
    private val name=Regex("[A-Za-z0-9._-]{1,64}")
    private fun opaque(raw:String) {require(raw.matches(Regex("[A-Za-z0-9_-]{43}")) && Policy.decode64(raw).size==32)}
    private fun text(value:JsonElement):String=value.jsonPrimitive.let {require(it.isString);it.content}
    private fun integer(value:JsonElement):Long=value.jsonPrimitive.let {require(!it.isString);requireNotNull(it.longOrNull)}
    fun canonical(input:List<String>):List<String> {
        require(input.size in 3..16 && input.distinct().size==input.size && input.all {name.matches(it)} && input.containsAll(IdentityOperation.requiredCapabilities))
        return input.sorted()
    }
    fun hash(input:List<String>):String=Identity.hash(Canonical.encode(JsonArray(canonical(input).map(::JsonPrimitive))).toByteArray(Charsets.UTF_8))
    fun snapshot(raw:String):CapabilitySnapshot {
        require(raw.toByteArray(Charsets.UTF_8).size<=8192)
        val o=Identity.objectJSON(raw);require(o.keys==setOf("version","hash","capabilities","authorityHash"))
        val version=integer(o.getValue("version"));require(version in 0L..13L)
        val caps=canonical(o.getValue("capabilities").jsonArray.map(::text));require(caps.size>=3+version)
        val digest=text(o.getValue("hash"));val authority=text(o.getValue("authorityHash"));opaque(digest);opaque(authority)
        require(hash(caps)==digest)
        return CapabilitySnapshot(version,digest,caps,authority)
    }
    fun operation(scope:String,before:CapabilitySnapshot,implemented:List<String>):CapabilityOperation? {
        require(scope.matches(Regex("[A-Za-z0-9_./-]{1,512}")))
        opaque(before.hash);opaque(before.authorityHash);require(before.version in 0L..13L && hash(before.capabilities)==before.hash)
        val wanted=canonical(implemented);val previous=canonical(before.capabilities)
        require(wanted.containsAll(previous))
        if(wanted==previous)return null
        require(wanted.size>previous.size && before.version<13)
        val proposed=hash(wanted)
        val id=Identity.hash(Canonical.encode(buildJsonObject {
            put("kind","capability-operation-v1");put("scope",scope);put("authority",before.authorityHash);put("previous",before.hash);put("proposed",proposed)
        }).toByteArray(Charsets.UTF_8))
        val body=Canonical.encode(buildJsonObject {put("requestId",id);put("previousHash",before.hash);put("capabilities",JsonArray(wanted.map(::JsonPrimitive)))})
        require(body.toByteArray(Charsets.UTF_8).size<=8192)
        return CapabilityOperation(id,body,proposed,before.version+1)
    }
    fun response(raw:String,operation:CapabilityOperation):CapabilityRequestState {
        val o=Identity.objectJSON(raw);require(o.keys.containsAll(setOf("requestId","state","version","hash")) && o.keys.all {it in setOf("requestId","state","version","hash","error")})
        require(text(o.getValue("requestId"))==operation.requestId)
        val version=integer(o.getValue("version"));val hash=text(o.getValue("hash"));val error=o["error"]?.let(::text)
        return when(text(o.getValue("state"))) {
            "queued"->{require(version==0L && hash.isEmpty() && error==null);CapabilityRequestState.QUEUED}
            "approved"->{require(version==operation.expectedVersion && hash==operation.proposedHash && error==null);CapabilityRequestState.APPROVED}
            "rejected"->{require(version==0L && hash.isEmpty() && error in setOf("capability_denied","capability_conflict","capability_expired"));CapabilityRequestState.REJECTED}
            else->kotlin.error("capability_reply")
        }
    }
}
