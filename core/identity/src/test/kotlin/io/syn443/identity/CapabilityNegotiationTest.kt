package io.syn443.identity

import io.syn443.policy.Canonical
import kotlinx.serialization.json.*
import org.junit.Assert.*
import org.junit.Test

class CapabilityNegotiationTest {
    private val base=IdentityOperation.requiredCapabilities
    private val extra=base+"overlay.credentials.v1"
    private fun fail(block:()->Unit){try{block();throw AssertionError("untrusted capability data accepted")}catch(_:IllegalArgumentException){}catch(_:IllegalStateException){}}
    private fun raw(caps:List<String> =base,version:Long=0,hash:String=CapabilityNegotiation.hash(caps))=Canonical.encode(buildJsonObject {put("version",version);put("hash",hash);put("capabilities",JsonArray(caps.map(::JsonPrimitive)));put("authorityHash",Identity.hash("current-scope".toByteArray()))})
    @Test fun canonicalAvailabilityAndOperationAreStableWithoutMutatingAnOldRequest() {
        val before=CapabilityNegotiation.snapshot(raw(base.reversed()))
        assertEquals(base.sorted(),before.capabilities)
        val operation=checkNotNull(CapabilityNegotiation.operation("device/scope/device-a/0",before,extra))
        assertEquals(operation,CapabilityNegotiation.operation("device/scope/device-a/0",before,extra.reversed()))
        assertNotEquals(operation.requestId,CapabilityNegotiation.operation("device/scope/device-a/1",before,extra)!!.requestId)
        assertEquals(before.hash,Identity.objectJSON(operation.body).getValue("previousHash").jsonPrimitive.content)
        assertEquals(extra.sorted(),Identity.objectJSON(operation.body).getValue("capabilities").jsonArray.map {it.jsonPrimitive.content})
        assertNull(CapabilityNegotiation.operation("device/scope/device-a/0",CapabilityNegotiation.snapshot(raw(extra,1)),extra))
        assertEquals(base,IdentityOperation.requiredCapabilities)
        assertFalse(operation.toString().contains(operation.body));assertFalse(before.toString().contains(before.authorityHash))
    }
    @Test fun malformedUnknownAndInconsistentHistoryCannotBecomeAvailability() {
        for(text in listOf("{}",raw(hash=Identity.hash("wrong".toByteArray())),raw(version=14),raw(version=1),raw().dropLast(1)+",\"approved\":true}",raw().replace("\"version\":0","\"version\":\"0\""),raw().dropLast(1)+",\"version\":0}"))fail {CapabilityNegotiation.snapshot(text)}
        for(caps in listOf(emptyList(),base.dropLast(1),base+base[0],base+"bad feature",base+"x".repeat(65),base+(0..13).map {"feature$it"}))fail {CapabilityNegotiation.canonical(caps)}
        fail {CapabilityNegotiation.operation("device/scope",CapabilityNegotiation.snapshot(raw(extra,1)),base)}
        fail {CapabilityNegotiation.operation("invalid scope",CapabilityNegotiation.snapshot(raw()),extra)}
    }
    @Test fun pendingAndApprovedRepliesAreBoundToExactOperationAndExpectedHead() {
        val op=checkNotNull(CapabilityNegotiation.operation("device/scope",CapabilityNegotiation.snapshot(raw()),extra))
        fun reply(state:String,version:Long=0,hash:String="",id:String=op.requestId,error:String?=null)=Canonical.encode(buildJsonObject {put("requestId",id);put("state",state);put("version",version);put("hash",hash);if(error!=null)put("error",error)})
        assertEquals(CapabilityRequestState.QUEUED,CapabilityNegotiation.response(reply("queued"),op))
        assertEquals(CapabilityRequestState.APPROVED,CapabilityNegotiation.response(reply("approved",1,op.proposedHash),op))
        assertEquals(CapabilityRequestState.REJECTED,CapabilityNegotiation.response(reply("rejected",error="capability_conflict"),op))
        for(text in listOf(reply("applied"),reply("queued",hash=op.proposedHash),reply("approved",2,op.proposedHash),reply("approved",1,Identity.hash("different".toByteArray())),reply("approved",1,op.proposedHash,id=Identity.random()),reply("rejected",error="arbitrary-detail")))fail {CapabilityNegotiation.response(text,op)}
    }
}
