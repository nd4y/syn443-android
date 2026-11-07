package io.syn443.identity

import io.syn443.policy.*
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import org.junit.Assert.*
import org.junit.Test
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECGenParameterSpec
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.Base64
import java.util.Locale

class AuthProtocolTest {
    @Test fun technicalTelemetryIsProofBoundAndDisabledEndpointDoesNotAcknowledge() {
        val f=Fixture();val current=f.current()
        val batch=TechnicalTelemetry.Batch(1,Identity.random(),52,0,1,listOf(
            TechnicalTelemetry.Event(Identity.random(),now,1,0,"vpn","online","unknown")))
        var status=200
        var receipt="""{"schemaVersion":1,"eventIds":["${batch.events.single().id}"]}"""
        f.handler={method,url,headers,raw,_,maxReply->
            assertEquals("POST",method);assertEquals(b.apiOrigin+TechnicalTelemetry.PATH,url)
            assertEquals("application/json",headers["Content-Type"]);assertEquals(2048,maxReply)
            val bytes=checkNotNull(raw)
            assertArrayEquals(batch.body(),bytes)
            val proof=Identity.objectJSON(Policy.utf8(Policy.decode64(headers.getValue("DPoP").split('.')[1])))
            assertEquals(Identity.hash(bytes),proof.getValue("req_hash").jsonPrimitive.content)
            json(status,text=receipt)
        }
        assertTrue(f.client.uploadTechnicalTelemetry(batch,current,IdentityScope()))
        receipt="""{"schemaVersion":1,"eventIds":["${Identity.random()}"]}"""
        assertFalse(f.client.uploadTechnicalTelemetry(batch,current,IdentityScope()))
        receipt=""
        status=204
        assertFalse(f.client.uploadTechnicalTelemetry(batch,current,IdentityScope()))
        status=404
        assertFalse(f.client.uploadTechnicalTelemetry(batch,current,IdentityScope()))
    }
    @Test fun administrationHintIsBoundedAndOlderServersDenyNavigation() {
        val f=Fixture(b.copy(controlPanelOrigin="https://control.example.invalid"));val current=f.current()
        var response=json(text="""{"schemaVersion":1,"untilMs":${now+60_000}}""")
        f.handler={method,url,headers,body,_,maximum->
            assertEquals("GET",method);assertEquals(b.apiOrigin+"/v1/device/control-panel",url)
            assertEquals("DPoP "+current.session.accessToken,headers["Authorization"])
            assertNull(body);assertEquals(1024,maximum);response
        }
        val expiry=f.client.controlPanelUntilElapsed(current,IdentityScope())
        assertTrue(expiry in (f.elapsed+58_000)..(f.elapsed+60_000))
        response=json(text="""{"schemaVersion":1,"untilMs":0}""")
        assertEquals(0L,f.client.controlPanelUntilElapsed(current,IdentityScope()))
        response=json(404)
        assertEquals(0L,f.client.controlPanelUntilElapsed(current,IdentityScope()))
        response=json(text="""{"schemaVersion":1,"untilMs":${now+600_000}}""")
        error(AuthFailure.INVALID_REPLY){f.client.controlPanelUntilElapsed(current,IdentityScope())}
    }
    @Test fun sourceFetchUploadBindsTheCompleteBinaryFrameToTheDeviceProof() {
        val f=Fixture();val session=f.current();val scope=IdentityScope()
        val lease=DeviceSubscription.Lease(Identity.random(),Identity.random(),now/1000+60,listOf("wifi"),
            SubscriptionCredential("https://source.example.invalid/list?key=synthetic"))
        val payload=ByteArray(10_000){(it%7).toByte()}
        var leaseReply=json(text=Canonical.json.encodeToString(lease))
        f.handler={method,url,headers,body,_,maximum->
            val proof=Identity.objectJSON(Policy.utf8(Policy.decode64(headers.getValue("DPoP").split('.')[1])))
            assertEquals(Identity.hash(session.session.accessToken.toByteArray()),proof.getValue("ath").jsonPrimitive.content)
            if(method=="GET") {
                assertEquals(b.apiOrigin+DeviceSubscription.CLAIM_PATH,url)
                assertNull(body);assertEquals(65_536,maximum);leaseReply
            } else {
                assertEquals(b.apiOrigin+DeviceSubscription.RESULT_PATH,url)
                assertEquals("application/octet-stream",headers["Content-Type"])
                val raw=checkNotNull(body)
                assertArrayEquals((lease.jobId+"\n"+lease.lease+"\n").toByteArray()+payload,raw)
                assertEquals(Identity.hash(raw),proof.getValue("req_hash").jsonPrimitive.content)
                json(204,text="")
            }
        }
        val claim=f.client.claimSubscription(session,scope)
        assertEquals(lease,claim.lease)
        f.client.submitSubscription(claim,payload,session,scope)
        error(AuthFailure.INVALID_REPLY){f.client.submitSubscription(claim,byteArrayOf(),session,scope)}
        leaseReply=json(204,text="");assertTrue(f.client.claimSubscription(session,scope).available)
        leaseReply=json(404);assertFalse(f.client.claimSubscription(session,scope).available)
        leaseReply=json(text=Canonical.json.encodeToString(lease.copy(until=now/1000)))
        error(AuthFailure.INVALID_REPLY){f.client.claimSubscription(session,scope)}
    }
    @Test fun conditionalSourceLeaseSignsMetadataAndFallsBackOnOldServers() {
        val f=Fixture();val session=f.current();val scope=IdentityScope()
        val lease=DeviceSubscription.Lease(Identity.random(),Identity.random(),now/1000+60,listOf("wifi"),
            SubscriptionCredential("https://source.example.invalid/list"),DeviceSubscription.Validators("\"previous\""))
        val seen=mutableListOf<String>()
        var newEndpoint=true
        f.handler={method,url,headers,body,_,_->
            val path=url.removePrefix(b.apiOrigin);seen.add(path)
            when(path) {
                DeviceSubscription.CONDITIONAL_CLAIM_PATH -> {
                    assertEquals("GET",method)
                    if(newEndpoint)json(text=Canonical.json.encodeToString(lease)) else json(404)
                }
                DeviceSubscription.CLAIM_PATH -> json(text=Canonical.json.encodeToString(lease.copy(validators=null)))
                DeviceSubscription.CONDITIONAL_RESULT_PATH -> {
                    assertEquals("POST",method)
                    val raw=checkNotNull(body)
                    val proof=Identity.objectJSON(Policy.utf8(Policy.decode64(headers.getValue("DPoP").split('.')[1])))
                    assertEquals(Identity.hash(raw),proof.getValue("req_hash").jsonPrimitive.content)
                    assertArrayEquals(byteArrayOf(0,83,52,52,51,2),raw.copyOfRange(88,94))
                    val size=((raw[94].toInt() and 255) shl 8) or (raw[95].toInt() and 255)
                    assertEquals(96+size,raw.size)
                    val metadata=Identity.objectJSON(raw.copyOfRange(96,raw.size).decodeToString())
                    assertEquals(304,metadata.getValue("status").jsonPrimitive.int)
                    assertEquals("upload=1; download=2; total=10; expire=0",metadata.getValue("quota").jsonPrimitive.content)
                    json(204,text="")
                }
                else -> kotlin.error("unexpected operation")
            }
        }
        val claim=f.client.claimSubscription(session,scope,conditional=true)
        assertTrue(claim.conditional);assertEquals(lease,claim.lease)
        val response=Reply(304,mapOf("subscription-userinfo" to listOf("upload=1; download=2; total=10; expire=0")),byteArrayOf())
        f.client.submitSubscriptionResult(claim,response,session,scope)
        error(AuthFailure.INVALID_REPLY) {f.client.submitSubscriptionResult(claim,response.copy(body=byteArrayOf(1)),session,scope)}
        val gone=lease.conditionalFrame(Reply(410,mapOf("etag" to listOf("\"ignored\"")),"provider error".toByteArray()))
        assertEquals("""{"status":410}""",gone.copyOfRange(96,gone.size).decodeToString())
        newEndpoint=false
        val fallback=f.client.claimSubscription(session,scope,conditional=true)
        assertFalse(fallback.conditional);assertNull(fallback.lease?.validators)
        assertEquals(listOf(DeviceSubscription.CONDITIONAL_CLAIM_PATH,DeviceSubscription.CONDITIONAL_RESULT_PATH,
            DeviceSubscription.CONDITIONAL_CLAIM_PATH,DeviceSubscription.CLAIM_PATH),seen)
    }
    @Test fun activationReportBindsBodyToCurrentDeviceProofAndSupportsOlderServers() {
        val f=Fixture();val current=f.current()
        val report=DeviceActivationReport(1,2,Identity.random(),3,"rolled_back",1)
        var response=204
        f.handler={method,url,headers,body,_,maximum->
            assertEquals("POST",method);assertEquals(b.apiOrigin+"/v1/device/policy/status",url)
            assertEquals(8192,maximum);assertEquals("application/json",headers["Content-Type"])
            assertEquals("DPoP "+current.session.accessToken,headers["Authorization"])
            val raw=checkNotNull(body)
            val proof=Identity.objectJSON(Policy.utf8(Policy.decode64(headers.getValue("DPoP").split('.')[1])))
            assertEquals(Identity.hash(raw),proof.getValue("req_hash").jsonPrimitive.content)
            assertEquals(current.session.nonce,proof.getValue("nonce").jsonPrimitive.content)
            assertEquals(report,Canonical.json.decodeFromString<DeviceActivationReport>(raw.toString(Charsets.UTF_8)))
            json(response,text="")
        }
        assertTrue(f.client.reportActivation(report,current,IdentityScope()))
        response=404;assertFalse(f.client.reportActivation(report,current,IdentityScope()))
        error(AuthFailure.INVALID_REPLY) {f.client.reportActivation(report,current.copy(session=current.session.copy(accessUntilMs=now)),IdentityScope())}
        assertEquals(2,f.requests.size)
    }
    private fun capabilitySnapshot(caps:List<String>,version:Long)=Canonical.encode(buildJsonObject {
        put("version",version);put("hash",CapabilityNegotiation.hash(caps));put("capabilities",JsonArray(caps.map(::JsonPrimitive)))
        put("authorityHash",Identity.hash("capability-fixture-authority".toByteArray()))
    })
    private fun capabilityReply(body:ByteArray,state:String,version:Long=0,error:String?=null)=Canonical.encode(buildJsonObject {
        val input=Identity.objectJSON(body.toString(Charsets.UTF_8))
        put("requestId",input.getValue("requestId"));put("state",state);put("version",version)
        put("hash",if(state=="approved")CapabilityNegotiation.hash(input.getValue("capabilities").jsonArray.map {it.jsonPrimitive.content}) else "")
        if(error!=null)put("error",error)
    })
    @Test fun deviceCapabilitiesReusePendingBytesAndRecoverAnUnknownApprovalAck() {
        val f=Fixture();val scope=IdentityScope();val base=IdentityOperation.requiredCapabilities;val wanted=IdentityOperation.supportedCapabilities
        var caps=base;var version=0L;var posts=0;val bodies=mutableListOf<String>()
        f.handler={method,url,headers,body,_,maximum->
            assertEquals(b.apiOrigin+"/v1/device/capabilities",url);assertEquals(8192,maximum)
            val proof=Identity.objectJSON(Policy.utf8(Policy.decode64(headers.getValue("DPoP").split('.')[1])))
            assertEquals(session().nonce,proof.getValue("nonce").jsonPrimitive.content)
            assertEquals("DPoP "+session().accessToken,headers.getValue("Authorization"))
            if(method=="GET")json(text=capabilitySnapshot(caps,version)) else {
                val raw=checkNotNull(body);assertEquals(Identity.hash(raw),proof.getValue("req_hash").jsonPrimitive.content)
                bodies+=raw.toString(Charsets.UTF_8);posts++
                if(posts==1)json(text=capabilityReply(raw,"queued")) else {
                    caps=wanted;version=1
                    throw DeliveryException(DeliveryFailure.TRANSPORT)
                }
            }
        }
        error(AuthFailure.PENDING){f.client.negotiateCapabilities(f.current(),wanted,scope)}
        error(AuthFailure.TRANSPORT){f.client.negotiateCapabilities(f.current(),wanted,scope)}
        assertEquals(2,posts);assertEquals(bodies[0],bodies[1])
        assertEquals(wanted.sorted(),f.client.negotiateCapabilities(f.current(),wanted,scope));assertEquals(2,posts)
    }
    @Test fun independentlyApprovedCapabilitiesAreConfirmedBeforeBecomingProtectedMetadata() {
        val f=Fixture();var approved=false;var posts=0
        f.handler={method,_,_,body,_,_->
            if(method=="GET")json(text=capabilitySnapshot(if(approved)IdentityOperation.supportedCapabilities else IdentityOperation.requiredCapabilities,if(approved)1 else 0))
            else {approved=true;posts++;json(text=capabilityReply(checkNotNull(body),"approved",1))}
        }
        assertEquals(IdentityOperation.supportedCapabilities.sorted(),f.client.negotiateCapabilities(f.current(),IdentityOperation.supportedCapabilities,IdentityScope()))
        assertEquals(1,posts)
        approved=false
        f.handler={method,_,_,body,_,_->if(method=="GET")json(text=capabilitySnapshot(IdentityOperation.requiredCapabilities,0))
            else json(text=capabilityReply(checkNotNull(body),"approved",1))}
        error(AuthFailure.INVALID_REPLY){f.client.negotiateCapabilities(f.current(),IdentityOperation.supportedCapabilities,IdentityScope())}
    }
    @Test fun oidcCapabilityApprovalRetainsTheOriginalDurableEnrollmentOperation() {
        val f=Fixture();val op=IdentityOperation.enroll(pub);val enrolls=mutableListOf<String>();val upgrades=mutableListOf<String>()
        var approved=false;var queued=true
        f.handler={method,url,_,body,_,_->when {
            url.endsWith("/devices/enroll")->{enrolls+=checkNotNull(body).toString(Charsets.UTF_8)
                if(!approved)json(409,"""{"code":"capabilities_update_required"}""") else json(text=sessionWire())}
            method=="GET"->json(text=capabilitySnapshot(IdentityOperation.requiredCapabilities,0))
            else->{val raw=checkNotNull(body);upgrades+=raw.toString(Charsets.UTF_8)
                if(queued) {queued=false;json(text=capabilityReply(raw,"queued"))}
                else {approved=true;json(text=capabilityReply(raw,"approved",1))}}
        }}
        error(AuthFailure.PENDING){f.client.enroll(op,f.user(),IdentityScope())}
        assertEquals(session().deviceId,f.client.enroll(op,f.user(),IdentityScope()).session.deviceId)
        assertEquals(3,enrolls.size);assertTrue(enrolls.all {it==op.body});assertEquals(upgrades[0],upgrades[1])
        var enrollment=0
        f.handler={_,url,_,_,_,_->if(url.endsWith("/devices/enroll")) {
            enrollment++;if(enrollment==1)json(409,"""{"code":"capabilities_update_required"}""") else json(text=sessionWire())
        } else json(text=capabilitySnapshot(IdentityOperation.supportedCapabilities,1))}
        assertEquals(session().deviceId,f.client.enroll(op,f.user(),IdentityScope()).session.deviceId)
        assertEquals(2,enrollment)
    }
    @Test fun capabilityErrorsUnknownModulesCancellationAndMalformedApprovalDoNotGrantAccess() {
        val f=Fixture();val wanted=IdentityOperation.supportedCapabilities
        for((status,reason) in listOf(403 to AuthFailure.ACCESS_DENIED,503 to AuthFailure.UNAVAILABLE,404 to AuthFailure.INVALID_REPLY)) {
            f.handler={_,_,_,_,_,_->json(status)}
            error(reason){f.client.negotiateCapabilities(f.current(),wanted,IdentityScope())}
        }
        f.handler={method,_,_,body,_,_->if(method=="GET")json(text=capabilitySnapshot(IdentityOperation.requiredCapabilities,0))
            else json(text=capabilityReply(checkNotNull(body),"rejected",error="capability_conflict"))}
        error(AuthFailure.CONFLICT){f.client.negotiateCapabilities(f.current(),wanted,IdentityScope())}
        val op=IdentityOperation.enroll(pub)
        val baseHandler=f.handler
        f.handler={method,url,headers,body,scope,maximum->if(url.endsWith("/devices/enroll"))json(409,"""{"code":"capabilities_update_required"}""")
            else baseHandler(method,url,headers,body,scope,maximum)}
        error(AuthFailure.CONFLICT){f.client.enroll(op,f.user(),IdentityScope())}
        f.handler={_,_,_,_,_,_->json(text=capabilitySnapshot(wanted+"future.unsupported.v1",1))}
        error(AuthFailure.INVALID_REPLY){f.client.negotiateCapabilities(f.current(),wanted,IdentityScope())}
        f.handler={method,_,_,body,_,_->if(method=="GET")json(text=capabilitySnapshot(IdentityOperation.requiredCapabilities,0))
            else json(text=capabilityReply(checkNotNull(body),"approved",2))}
        error(AuthFailure.INVALID_REPLY){f.client.negotiateCapabilities(f.current(),wanted,IdentityScope())}
        val cancelled=IdentityScope().also {it.cancel()}
        error(AuthFailure.CANCELLED){f.client.negotiateCapabilities(f.current(),wanted,cancelled)}
        error(AuthFailure.REAUTHENTICATE){f.client.negotiateCapabilities(f.current(session().copy(accessUntilMs=now)),wanted,IdentityScope())}
    }
    private fun overlayBinding()=OverlayCredentialBinding(OverlayAddress(b.serviceId,Identity.hash("owner".toByteArray()),session().deviceId,"home","netbird","resource","tenant",1,"https://overlay.example.invalid"),Identity.thumbprint(pub),Identity.hash("reference".toByteArray()),1,0,now+120_000)
    private fun overlayEnvelope(binding:OverlayCredentialBinding):String {
        val a=binding.address
        val body=buildJsonObject {
            put("schemaVersion",1);put("audience","syn443-overlay-credential")
            putJsonObject("address") {
                put("serviceId",a.serviceId);put("ownerTag",a.ownerTag);put("deviceId",a.deviceId);put("overlayId",a.overlayId);put("provider",a.provider);put("resourceId",a.resourceId);put("networkId",a.networkId);put("identityEpoch",a.identityEpoch);put("managementURL",a.managementURL)
            }
            put("keyThumbprint",binding.keyThumbprint);put("reference",binding.reference);put("version",binding.version);put("securityEpoch",binding.securityEpoch);put("kind","netbird.setup-key");put("issuedAtMs",now);put("notBeforeMs",now);put("expiresMs",now+60_000);put("value",java.util.UUID.randomUUID().toString())
        }
        val header=buildJsonObject {put("alg","ES256");put("kid","test-root");put("typ","syn443-overlay-credential+jws")}
        val input=Identity.encode(Canonical.encode(header).toByteArray())+"."+Identity.encode(Canonical.encode(body).toByteArray())
        return input+"."+Identity.encode(Signature.getInstance("SHA256withECDSAinP1363Format").run {initSign(root.private);update(input.toByteArray());sign()})
    }
    @Test fun addressedOverlayDeliveryBindsProofBodySessionAndIndependentEnvelope() {
        val f=Fixture();val binding=overlayBinding()
        val operation=OverlayOperation(Identity.random(),ManagedOverlay.namespace(binding.address),binding.reference,binding.version)
        val envelope=overlayEnvelope(binding)
        f.handler={method,url,headers,bytes,_,maximum->
            assertEquals("POST",method);assertEquals(b.apiOrigin+"/v1/device/overlay/fetch",url);assertEquals(24576,maximum)
            assertEquals(operation.body(),bytes!!.toString(Charsets.UTF_8))
            val proof=Identity.objectJSON(Policy.utf8(Policy.decode64(headers.getValue("DPoP").split('.')[1])))
            assertEquals(Identity.hash(bytes),proof.getValue("req_hash").jsonPrimitive.content)
            assertEquals(Identity.hash(f.current().session.accessToken.toByteArray()),proof.getValue("ath").jsonPrimitive.content)
            json(text=Canonical.encode(buildJsonObject {put("envelope",envelope);put("consumed",false)}))
        }
        val reply=f.client.overlay(operation,false,binding,f.current(),IdentityScope())
        assertEquals(envelope,reply.envelope);assertFalse(reply.consumed);assertFalse(reply.toString().contains(envelope))
        f.handler={_,url,_,bytes,_,_->
            assertEquals(b.apiOrigin+"/v1/device/overlay/consume",url);assertEquals(operation.body(),bytes!!.toString(Charsets.UTF_8));json(text="{\"consumed\":true}")
        }
        val ack=f.client.overlay(operation,true,binding,f.current(),IdentityScope())
        assertTrue(ack.consumed);assertNull(ack.envelope)
        val canceled=IdentityScope().also {it.cancel()}
        error(AuthFailure.CANCELLED){f.client.overlay(operation,true,binding,f.current(),canceled)}
    }
    @Test fun overlayCannotAcceptUnsignedSecretCrossScopeOrFalseConsumption() {
        val f=Fixture();val binding=overlayBinding()
        fun op(b:OverlayCredentialBinding)=OverlayOperation(Identity.random(),ManagedOverlay.namespace(b.address),b.reference,b.version)
        for(body in listOf("{}","{\"consumed\":true}","{\"consumed\":false,\"envelope\":\"unsigned\"}","{\"consumed\":false,\"envelope\":\"\",\"extra\":true}")) {
            f.handler={_,_,_,_,_,_->json(text=body)};error(AuthFailure.INVALID_REPLY){f.client.overlay(op(binding),false,binding,f.current(),IdentityScope())}
        }
        for(body in listOf("{\"consumed\":false}","{\"consumed\":true,\"envelope\":\"must-not-appear\"}","{\"consumed\":\"true\"}")) {
            f.handler={_,_,_,_,_,_->json(text=body)};error(AuthFailure.INVALID_REPLY){f.client.overlay(op(binding),true,binding,f.current(),IdentityScope())}
        }
        f.handler={_,_,_,_,_,_->json(text="{\"consumed\":true}").copy(headers=mapOf("content-type" to listOf("text/html"),"date" to listOf(date())))}
        error(AuthFailure.INVALID_REPLY){f.client.overlay(op(binding),true,binding,f.current(),IdentityScope())}
        for(changed in listOf(binding.copy(address=binding.address.copy(serviceId="other")),binding.copy(address=binding.address.copy(deviceId="another-device")),binding.copy(keyThumbprint=Identity.hash("other".toByteArray())))) {
            error(AuthFailure.INVALID_REPLY){f.client.overlay(op(changed),false,changed,f.current(),IdentityScope())}
        }
        error(AuthFailure.INVALID_REPLY){f.client.overlay(op(binding),false,binding.copy(version=2),f.current(),IdentityScope())}
        error(AuthFailure.INVALID_REPLY){f.client.overlay(op(binding),false,binding,f.current(session().copy(accessUntilMs=now)),IdentityScope())}
        for((status,reason) in listOf(403 to AuthFailure.ACCESS_DENIED,409 to AuthFailure.CONFLICT,503 to AuthFailure.UNAVAILABLE)) {
            f.handler={_,_,_,_,_,_->json(status)};error(reason){f.client.overlay(op(binding),false,binding,f.current(),IdentityScope())}
        }
    }
    @Test fun overlayConsumptionKeepsItsOperationAfterCurrentReferenceAndEpochRefresh() {
        val f=Fixture();val initial=overlayBinding()
        val operation=OverlayOperation(Identity.random(),ManagedOverlay.namespace(initial.address),initial.reference,initial.version)
        val refreshed=initial.copy(reference=Identity.hash("renewed reference".toByteArray()),version=2,securityEpoch=1)
        var calls=0
        f.handler={_,url,headers,bytes,_,_->
            calls++;assertEquals(b.apiOrigin+"/v1/device/overlay/consume",url)
            assertEquals(operation.body(),bytes!!.toString(Charsets.UTF_8))
            val proof=Identity.objectJSON(Policy.utf8(Policy.decode64(headers.getValue("DPoP").split('.')[1])))
            assertEquals(Identity.hash(bytes),proof.getValue("req_hash").jsonPrimitive.content)
            json(text="{\"consumed\":true}")
        }
        val ack=f.client.overlay(operation,true,refreshed,f.current(),IdentityScope())
        assertTrue(ack.consumed);assertNull(ack.envelope);assertEquals(1,calls)
        error(AuthFailure.INVALID_REPLY){f.client.overlay(operation,false,refreshed,f.current(),IdentityScope())}
        error(AuthFailure.INVALID_REPLY){f.client.overlay(operation,true,refreshed.copy(address=refreshed.address.copy(identityEpoch=2)),f.current(),IdentityScope())}
        assertEquals(1,calls)
    }
    @Test fun publicationReauthenticationIsDistinctFromAnIdempotencyConflict() {
        val f=Fixture()
        for((code,expected) in listOf("reauthentication_required" to AuthFailure.REAUTHENTICATE,"idempotency_conflict" to AuthFailure.CONFLICT)) {
            f.handler={_,_,_,_,_,_->json(409,text="""{"code":"$code"}""")}
            error(expected) {f.client.policy(f.current(),IdentityScope())}
        }
        f.handler={_,_,_,_,_,_->json(409,text="not-json")}
        error(AuthFailure.INVALID_REPLY) {f.client.policy(f.current(),IdentityScope())}
    }
    @Test fun chatBindsExactBodyAccountAndScopeWithBoundedLargeReply() {
        val f=Fixture();val body="{\"data\":\""+"a".repeat(349528)+"\"}"
        f.handler={m,u,h,bytes,_,max->
            assertEquals("POST",m);assertEquals(b.apiOrigin+"/v1/chat/uploads/part",u);assertEquals(524288,max)
            assertEquals(body,bytes!!.toString(Charsets.UTF_8))
            val claims=Identity.objectJSON(Policy.utf8(Policy.decode64(h.getValue("DPoP").split('.')[1])))
            assertEquals(Identity.hash(bytes),claims.getValue("req_hash").jsonPrimitive.content)
            assertEquals(Identity.hash(f.current().session.accessToken.toByteArray()),claims.getValue("ath").jsonPrimitive.content)
            json(text="{\"data\":\""+"b".repeat(349528)+"\"}")
        }
        assertTrue(f.client.chat("uploads/part",body,f.current(),IdentityScope()).length>349528)
        error(AuthFailure.INVALID_REPLY) {f.client.chat("uploads/part",body,f.current().copy(keyThumbprint="wrong"),IdentityScope())}
        val scope=IdentityScope();scope.cancel();error(AuthFailure.CANCELLED) {f.client.chat("self","{}",f.current(),scope)}
    }
    @Test fun chatRejectsUnknownPathOversizeExpiredSessionAndUnsafeJson() {
        val f=Fixture()
        for((action,body) in listOf("../identity" to "{}","self" to "a".repeat(32769),"uploads/part" to "a".repeat(360449),"self" to "[]","self" to "{\"x\":1,\"x\":2}")) {
            error(AuthFailure.INVALID_REPLY) {f.client.chat(action,body,f.current(),IdentityScope())}
        }
        error(AuthFailure.INVALID_REPLY) {f.client.chat("self","{}",f.current(session().copy(accessUntilMs=now)),IdentityScope())}
        for(reply in listOf(json(text="{\"x\":1,\"x\":2}"),json(text="{} "+"x"),json().copy(headers=mapOf("content-type" to listOf("text/html"),"date" to listOf(date()))))) {
            f.handler={_,_,_,_,_,_->reply};error(AuthFailure.INVALID_REPLY) {f.client.chat("self","{}",f.current(),IdentityScope())}
        }
        for((status,reason) in listOf(403 to AuthFailure.ACCESS_DENIED,429 to AuthFailure.THROTTLED,503 to AuthFailure.UNAVAILABLE)) {
            f.handler={_,_,_,_,_,_->json(status)};error(reason) {f.client.chat("self","{}",f.current(),IdentityScope())}
        }
    }
    companion object {
        private const val now=1_800_000_000_000L
        private val ec=KeyPairGenerator.getInstance("EC").apply {initialize(ECGenParameterSpec("secp256r1"))}.generateKeyPair()
        private val rsa=KeyPairGenerator.getInstance("RSA").apply {initialize(2048)}.generateKeyPair()
        private val root=KeyPairGenerator.getInstance("EC").apply {initialize(ECGenParameterSpec("secp256r1"))}.generateKeyPair()
        private val pub=ec.public as ECPublicKey
        private val key=object:ProofKey {
            override val publicKey=pub
            override fun sign(input:ByteArray)=Signature.getInstance("SHA256withECDSA").run {initSign(ec.private);update(input);sign()}
        }
        private val b=Bootstrap("fixture","https://id.example.invalid/realms/test","syn443-android","https://api.example.invalid",
            mapOf("test-root" to Base64.getEncoder().encodeToString(root.public.encoded)))
        private val dateFormat=DateTimeFormatter.ofPattern("EEE, dd MMM uuuu HH:mm:ss 'GMT'",Locale.US).withZone(ZoneOffset.UTC)
        private fun date(ms:Long=now)=dateFormat.format(Instant.ofEpochMilli(ms))
        private fun raw(n:BigInteger)=n.toByteArray().let {if(it.first()==0.toByte())it.drop(1).toByteArray() else it}
        private fun jwks()=Canonical.encode(buildJsonObject {putJsonArray("keys") {add(buildJsonObject {
            val r=rsa.public as RSAPublicKey;put("kid","fixture");put("kty","RSA");put("alg","RS256");put("use","sig")
            put("n",Identity.encode(raw(r.modulus)));put("e","AQAB")
        })}})
        private fun jwt(p:Pending,id:Boolean):String {
            val claims=buildJsonObject {
                put("iss",b.issuer);put("sub","fixture-subject");put("aud",if(id)b.clientId else "syn443-api");put("azp",b.clientId)
                put("iat",now/1000);put("exp",now/1000+300)
                if(id)put("nonce",p.nonce) else putJsonObject("cnf") {put("jkt",p.thumbprint)}
            }
            val input=Identity.encode("""{"alg":"RS256","kid":"fixture","typ":"JWT"}""".toByteArray())+"."+Identity.encode(Canonical.encode(claims).toByteArray())
            return input+"."+Identity.encode(Signature.getInstance("SHA256withRSA").run {initSign(rsa.private);update(input.toByteArray());sign()})
        }
        private fun json(status:Int=200,text:String="{}",extra:Map<String,String> = emptyMap(),time:Long=now)=Reply(status,
            (mapOf("content-type" to "application/json; charset=utf-8","date" to date(time))+extra).mapValues {listOf(it.value)},text.toByteArray())
        private fun session(generation:Long=0,device:String=Identity.hash("fixture-device".toByteArray()),refreshUntil:Long=now+86_000_000)=DeviceSession(
            device,Identity.hash("access-$generation".toByteArray()),Identity.hash("refresh-$generation".toByteArray()),now+590_000,refreshUntil,generation,Identity.hash("nonce-$generation".toByteArray()))
        private fun sessionWire(s:DeviceSession=session())=Policy.json.encodeToString(s)
        private fun error(reason:AuthFailure,block:()->Unit) {try {block();fail("invalid protocol accepted")}catch(e:AuthException) {assertEquals(reason,e.reason);assertNull(e.cause)}}
        private fun invalid(block:()->Unit) {try {block();fail("invalid state accepted")}catch(_:IllegalArgumentException) {}}
    }
    private class Fixture(bootstrap:Bootstrap=b) {
        var elapsed=1000L;var boot=2
        val pending=Identity.newPending(7,Identity.thumbprint(pub),boot,elapsed)
        val requests=mutableListOf<String>()
        var handler:(String,String,Map<String,String>,ByteArray?,BoundedHttp.Scope,Int)->Reply={method,url,_,_,_,_->
            when {
                url.endsWith("openid-configuration")->json(text=Canonical.encode(buildJsonObject {
                    put("issuer",b.issuer);put("authorization_endpoint",b.issuer+"/protocol/openid-connect/auth")
                    put("token_endpoint",b.issuer+"/protocol/openid-connect/token");put("jwks_uri",b.issuer+"/protocol/openid-connect/certs")
                    put("id_token_signing_alg_values_supported",JsonArray(listOf(JsonPrimitive("RS256"))))
                    put("dpop_signing_alg_values_supported",JsonArray(listOf(JsonPrimitive("ES256"))))
                    put("code_challenge_methods_supported",JsonArray(listOf(JsonPrimitive("S256"))))
                }))
                url.endsWith("/certs")->json(text=jwks())
                url.endsWith("/token")->json(text=Canonical.encode(buildJsonObject {
                    put("token_type","DPoP");put("access_token",jwt(pending,false));put("id_token",jwt(pending,true));put("expires_in",300)
                }))
                method=="POST" && url.endsWith("/revoke")->json(204,text="")
                else->json(text=sessionWire())
            }
        }
        val client=AuthProtocol(bootstrap,key,IdentityExchange {m,u,h,body,scope,max->requests.add(u);handler(m,u,h,body,scope,max)}, {boot},{elapsed})
        fun time()=TrustedTime(boot,elapsed,now,now+1000)
        fun current(s:DeviceSession=session())=SessionReply(s,time(),client.authority,pending.thumbprint)
        fun user()=UserCredential(jwt(pending,false),"fixture-subject",pending.thumbprint,time(),client.authority)
        fun login(scope:IdentityScope=IdentityScope())=client.exchangeCode("fixture-code",pending,client.discover(scope),scope)
    }
    @Test fun trustedClockBoundsPrecisionRttDriftAndNeverUsesWallClock() {
        val a=TrustedTime.observe(date(),2,1000,2000)
        assertEquals(a,Policy.json.decodeFromString<TrustedTime>(Policy.json.encodeToString(a)))
        assertEquals(TimeWindow(now,now+2000),a.window(2,2000))
        val w=a.window(2,7000);assertEquals(now+4999,w.lowerMs);assertEquals(now+7001,w.upperMs)
        assertEquals(now/1000+6,a.proofSecond(2,7000))
        val next=TrustedTime.observe(date(now+5000),2,7000,8000,a)
        assertTrue(next.lowerMs>=a.window(2,8000).lowerMs)
    }
    @Test fun clockRejectsRebootRollbackStaleAnchorsAndMalformedDates() {
        val a=TrustedTime.observe(date(),2,1000,1000)
        invalid {a.window(3,2000)};invalid {a.window(2,999)};invalid {a.window(2,86_401_001)}
        invalid {TrustedTime.observe(date(),2,0,20_001)};invalid {TrustedTime.observe(date(),2,3,2)}
        invalid {TrustedTime.observe(date(now-60_000),2,1000,1000,a)}
        invalid {TrustedTime.observe(date(now+60_000),2,1000,1000,a)}
        invalid {TrustedTime.observe("Fri, 15 Jan 2027 08:00:00 +0100",2,0,1)}
        invalid {TrustedTime(2,0,0,1)};invalid {TrustedTime(2,0,now,now+51_001)}
        invalid {TrustedTime(2,0,now,now+51_000).proofSecond(2,0)}
    }
    @Test fun pinnedDiscoveryAndCodeExchangeVerifyActualRsaTokens() {
        val f=Fixture();val credential=f.login()
        assertEquals("fixture-subject",credential.subject);assertEquals(f.pending.thumbprint,credential.keyThumbprint)
        assertEquals(3,f.requests.size);assertFalse(credential.toString().contains(credential.accessToken))
        val original=f.handler
        f.handler={m,u,h,body,s,max->
            if(u.endsWith("/token")) {
                assertEquals("application/x-www-form-urlencoded",h["Content-Type"])
                assertTrue(body!!.toString(Charsets.UTF_8).contains("code_verifier="+f.pending.verifier))
                val proof=Identity.objectJSON(Policy.utf8(Policy.decode64(h.getValue("DPoP").split('.')[1])))
                assertFalse(proof.containsKey("ath"));assertFalse(proof.containsKey("req_hash"))
            };original(m,u,h,body,s,max)
        };f.login()
    }
    @Test fun discoveryRejectsEndpointSubstitutionMissingAlgorithmsAndMalformedReplies() {
        val f=Fixture();val original=f.handler
        for(change in listOf<(String)->String>({it.replace("/certs","/elsewhere")},{it.replace("ES256","ES384")},{it.replace("S256","plain")},{it.replace("RS256","HS256")})) {
            f.handler={m,u,h,body,s,max->val r=original(m,u,h,body,s,max);r.copy(body=change(r.body.toString(Charsets.UTF_8)).toByteArray())}
            error(AuthFailure.INVALID_REPLY) {f.client.discover(IdentityScope())}
        }
        f.handler={_,_,_,_,_,_->json(text="{\"issuer\":\"a\",\"issuer\":\"b\"}")};error(AuthFailure.INVALID_REPLY) {f.client.discover(IdentityScope())}
        f.handler={_,_,_,_,_,_->json().copy(headers=emptyMap())};error(AuthFailure.INVALID_REPLY) {f.client.discover(IdentityScope())}
    }
    @Test fun oidcNonceChallengeIsOneRetryWithFreshProofAndSameCodeBody() {
        val f=Fixture();val issuer=f.client.discover(IdentityScope());val original=f.handler;var calls=0;var prior="";var bodyHash=""
        f.handler={m,u,h,body,s,max->
            if(u.endsWith("/token")) {
                calls++;val proof=h.getValue("DPoP");assertNotEquals(prior,proof);prior=proof
                val hash=Identity.hash(body!!);if(calls==1)bodyHash=hash else assertEquals(bodyHash,hash)
                if(calls==1)json(400,"""{"error":"use_dpop_nonce"}""",mapOf("dpop-nonce" to "fixture-issuer-nonce"))
                else {assertTrue(Policy.utf8(Policy.decode64(proof.split('.')[1])).contains("fixture-issuer-nonce"));original(m,u,h,body,s,max)}
            } else original(m,u,h,body,s,max)
        }
        f.client.exchangeCode("fixture-code",f.pending,issuer,IdentityScope());assertEquals(2,calls)
        f.handler={_,_,_,_,_,_->json(401,"""{"error":"use_dpop_nonce"}""",mapOf("dpop-nonce" to "again"))}
        error(AuthFailure.REAUTHENTICATE) {f.client.exchangeCode("fixture-code",f.pending,issuer,IdentityScope())}
        f.handler={_,_,_,_,_,_->json(400,"""{"error":"use_dpop_nonce"}""")}
        error(AuthFailure.INVALID_REPLY) {f.client.exchangeCode("fixture-code",f.pending,issuer,IdentityScope())}
    }
    @Test fun tokenRepliesRequireDpopTypedExpiryIdentityAndFreshIssuerTime() {
        val f=Fixture();val issuer=f.client.discover(IdentityScope());val original=f.handler
        error(AuthFailure.INVALID_REPLY) {f.client.exchangeCode("fixture-code",f.pending,IssuerState(issuer.keys,issuer.time,"another-service"),IdentityScope())}
        for(transform in listOf<(String)->String>({it.replace("DPoP","Bearer")},{it.replace("\"expires_in\":300","\"expires_in\":\"300\"")},{it.replace("\"expires_in\":300","\"expires_in\":601")},{it.replace(jwt(f.pending,true),jwt(f.pending,false))})) {
            f.handler={m,u,h,body,s,max->original(m,u,h,body,s,max).let {it.copy(body=transform(it.body.toString(Charsets.UTF_8)).toByteArray())}}
            error(AuthFailure.INVALID_REPLY) {f.client.exchangeCode("fixture-code",f.pending,issuer,IdentityScope())}
        }
        f.handler={m,u,h,body,s,max->original(m,u,h,body,s,max).copy(headers=mapOf("content-type" to listOf("application/json"),"date" to listOf(date(now-60_000))))}
        error(AuthFailure.INVALID_REPLY) {f.client.exchangeCode("fixture-code",f.pending,issuer,IdentityScope())}
        error(AuthFailure.INVALID_REPLY) {f.client.exchangeCode("",f.pending,issuer,IdentityScope())}
        f.elapsed+=300_000;error(AuthFailure.INVALID_REPLY) {f.client.exchangeCode("fixture-code",f.pending,issuer,IdentityScope())}
    }
    @Test fun enrollmentChallengesFreshProofsBindTheSamePersistedRawBody() {
        val f=Fixture();val op=IdentityOperation.enroll(pub);var prior="";var calls=0
        f.handler={m,u,h,body,_,_->
            assertEquals("POST",m);assertEquals(b.apiOrigin+op.path,u);assertEquals(op.body,body!!.toString(Charsets.UTF_8))
            assertEquals("application/json",h["Content-Type"]);val proof=h.getValue("DPoP");assertNotEquals(prior,proof);prior=proof
            val claims=Identity.objectJSON(Policy.utf8(Policy.decode64(proof.split('.')[1])))
            assertEquals(Identity.hash(body),claims.getValue("req_hash").jsonPrimitive.content)
            assertEquals(Identity.hash(f.user().accessToken.toByteArray()),claims.getValue("ath").jsonPrimitive.content)
            if(++calls==1)json(401,"""{"code":"use_dpop_nonce"}""",mapOf("dpop-nonce" to Identity.random())) else json(text=sessionWire())
        }
        val result=f.client.enroll(op,f.user(),IdentityScope());assertEquals(session(),result.session);assertEquals(2,calls)
        assertEquals("IdentityOperation([redacted])",op.toString());assertFalse(result.toString().contains(result.session.accessToken))
    }
    @Test fun serverNonceChallengeCannotLoopAndErrorCategoriesAreRedacted() {
        val f=Fixture();val op=IdentityOperation.enroll(pub)
        f.handler={_,_,_,_,_,_->json(401,"""{"code":"use_dpop_nonce"}""",mapOf("dpop-nonce" to "nonce"))}
        error(AuthFailure.REAUTHENTICATE) {f.client.enroll(op,f.user(),IdentityScope())};assertEquals(2,f.requests.size)
        for((code,reason) in listOf(202 to AuthFailure.PENDING,401 to AuthFailure.REAUTHENTICATE,403 to AuthFailure.ACCESS_DENIED,
            409 to AuthFailure.CONFLICT,429 to AuthFailure.THROTTLED,503 to AuthFailure.UNAVAILABLE,302 to AuthFailure.INVALID_REPLY)) {
            f.handler={_,_,_,_,_,_->json(code,"""{"code":"untrusted-text"}""")};error(reason) {f.client.enroll(op,f.user(),IdentityScope())}
        }
        f.handler={_,_,_,_,_,_->throw DeliveryException(DeliveryFailure.DNS)};error(AuthFailure.TRANSPORT) {f.client.enroll(op,f.user(),IdentityScope())}
    }
    @Test fun invalidSessionShapesTokensScalarTypesAndLifetimesCannotBeCached() {
        val f=Fixture();val op=IdentityOperation.enroll(pub);val s=session()
        for(wire in listOf(sessionWire(s.copy(accessToken="invalid")),sessionWire(s.copy(refreshToken=s.accessToken)),sessionWire(s.copy(generation=-1)),
            sessionWire(s.copy(accessUntilMs=now+1000)),sessionWire(s.copy(accessUntilMs=now+600_001)),sessionWire(s.copy(refreshUntilMs=now+86_400_001)),
            sessionWire(s.copy(refreshUntilMs=now+1000)),sessionWire().replace("\"generation\":0","\"generation\":\"0\""),sessionWire().dropLast(1)+",\"extra\":true}")) {
            f.handler={_,_,_,_,_,_->json(text=wire)};error(AuthFailure.INVALID_REPLY) {f.client.enroll(op,f.user(),IdentityScope())}
        }
        error(AuthFailure.INVALID_REPLY) {f.client.enroll(op,UserCredential("short","subject",f.pending.thumbprint,f.time(),f.client.authority),IdentityScope())}
        error(AuthFailure.INVALID_REPLY) {f.client.enroll(op,UserCredential(jwt(f.pending,false),"subject",Identity.random(),f.time(),f.client.authority),IdentityScope())}
    }
    @Test fun refreshRotatesOneGenerationWithoutExtendingAbsoluteGrantAndRevokeUsesAccess() {
        val f=Fixture();val previous=f.current();val refresh=IdentityOperation.refresh();val next=session(1)
        f.handler={_,u,h,body,_,_->
            if(u.endsWith("/refresh")) {assertEquals("DPoP "+previous.session.refreshToken,h["Authorization"]);assertEquals(refresh.body,body!!.toString(Charsets.UTF_8));json(text=sessionWire(next))}
            else {assertEquals("DPoP "+next.accessToken,h["Authorization"]);json(204,text="")}
        }
        error(AuthFailure.INVALID_REPLY) {f.client.refresh(refresh,previous.copy(authority="wrong"),IdentityScope())}
        error(AuthFailure.INVALID_REPLY) {f.client.policy(previous.copy(keyThumbprint=Identity.random()),IdentityScope())}
        assertEquals(previous,Policy.json.decodeFromString<SessionReply>(Policy.json.encodeToString(previous)))
        val result=f.client.refresh(refresh,previous,IdentityScope());assertEquals(next,result.session)
        f.client.revoke(IdentityOperation.revoke(),result,IdentityScope())
        for(bad in listOf(next.copy(generation=3),next.copy(deviceId=Identity.random()),next.copy(refreshUntilMs=next.refreshUntilMs-1),
            next.copy(accessToken=previous.session.accessToken),next.copy(refreshToken=previous.session.refreshToken),next.copy(nonce=previous.session.nonce))) {
            f.handler={_,_,_,_,_,_->json(text=sessionWire(bad))};error(AuthFailure.INVALID_REPLY) {f.client.refresh(refresh,previous,IdentityScope())}
        }
        f.elapsed+=86_000_001;error(AuthFailure.INVALID_REPLY) {f.client.refresh(refresh,previous,IdentityScope())}
    }
    @Test fun expiredAccessLogoutRefreshesInRamAndRevokesOnlyTheSameDeviceWithCurrentProof() {
        val f=Fixture();val previous=f.current();f.elapsed=601_000
        val next=session(1).copy(accessUntilMs=now+1_190_000);val revoke=IdentityOperation.revoke()
        f.handler={_,url,headers,body,_,_->
            if(url.endsWith("/refresh")) {
                assertEquals("DPoP "+previous.session.refreshToken,headers["Authorization"])
                json(text=sessionWire(next),time=now+600_000)
            } else {
                assertTrue(url.endsWith("/revoke"));assertEquals(revoke.body,body!!.toString(Charsets.UTF_8))
                assertEquals("DPoP "+next.accessToken,headers["Authorization"])
                val proof=Identity.objectJSON(Policy.utf8(Policy.decode64(headers.getValue("DPoP").split('.')[1])))
                assertEquals(next.nonce,proof.getValue("nonce").jsonPrimitive.content)
                assertEquals(Identity.hash(next.accessToken.toByteArray()),proof.getValue("ath").jsonPrimitive.content)
                json(204,"",time=now+600_000)
            }
        }
        f.client.revoke(revoke,previous,IdentityScope())
        assertEquals(listOf(b.apiOrigin+"/v1/device/session/refresh",b.apiOrigin+"/v1/device/revoke"),f.requests)
        assertEquals(0L,previous.session.generation) // The caller's protected snapshot was not replaced.
    }
    @Test fun freshAccessLogoutDoesNotRotateAndExpiredRefreshOrBootCannotDispatch() {
        val f=Fixture();f.client.revoke(IdentityOperation.revoke(),f.current(),IdentityScope())
        assertEquals(listOf(b.apiOrigin+"/v1/device/revoke"),f.requests)
        for(reboot in listOf(false,true)) {
            val bad=Fixture();val previous=bad.current()
            if(reboot)bad.boot++ else bad.elapsed=86_001_000
            error(AuthFailure.INVALID_REPLY) {bad.client.revoke(IdentityOperation.revoke(),previous,IdentityScope())}
            assertTrue(bad.requests.isEmpty())
        }
    }
    @Test fun uncertainExpiredLogoutRefreshNeverReenrollsOrSendsAnOldRevocationCredential() {
        val f=Fixture();val previous=f.current();f.elapsed=601_000
        f.handler={_,url,_,_,_,_->assertTrue(url.endsWith("/refresh"));throw DeliveryException(DeliveryFailure.TRANSPORT)}
        error(AuthFailure.TRANSPORT) {f.client.revoke(IdentityOperation.revoke(),previous,IdentityScope())}
        assertEquals(listOf(b.apiOrigin+"/v1/device/session/refresh"),f.requests)
    }
    @Test fun substitutedOrCancelledLogoutRefreshCannotReachRevocation() {
        for(cancel in listOf(false,true)) {
            val f=Fixture();val previous=f.current();f.elapsed=601_000;val scope=IdentityScope()
            f.handler={_,url,_,_,_,_->
                assertTrue(url.endsWith("/refresh"))
                if(cancel)scope.cancel()
                json(text=sessionWire(session(1,device=if(cancel)previous.session.deviceId else Identity.random()).copy(accessUntilMs=now+1_190_000)),time=now+600_000)
            }
            error(if(cancel)AuthFailure.CANCELLED else AuthFailure.INVALID_REPLY) {f.client.revoke(IdentityOperation.revoke(),previous,scope)}
            assertEquals(listOf(b.apiOrigin+"/v1/device/session/refresh"),f.requests)
        }
    }
    @Test fun ownerCleanupNeedsFreshMatchingIdentityAndNeverReturnsASession() {
        val f=Fixture();val op=IdentityOperation.cleanup(listOf(Identity.random()))
        f.handler={m,u,h,body,_,_->assertEquals("POST",m);assertTrue(u.endsWith("/identity/devices/revoke"));assertEquals(op.body,body!!.toString(Charsets.UTF_8));assertTrue(h["Authorization"]!!.startsWith("DPoP "));json(204,text="")}
        assertEquals(now,f.client.cleanup(op,f.user(),IdentityScope()).lowerMs)
        error(AuthFailure.INVALID_REPLY) {f.client.cleanup(op,UserCredential(jwt(f.pending,false),"subject",f.pending.thumbprint,f.time(),"wrong"),IdentityScope())}
        error(AuthFailure.INVALID_REPLY) {f.client.cleanup(IdentityOperation.revoke(),f.user(),IdentityScope())}
        error(AuthFailure.INVALID_REPLY) {f.client.revoke(op,f.current(),IdentityScope())}
        error(AuthFailure.INVALID_REPLY) {f.client.refresh(op,f.current(),IdentityScope())}
        error(AuthFailure.INVALID_REPLY) {f.client.enroll(op,f.user(),IdentityScope())}
    }
    @Test fun operationsPreserveExactBodiesAndRejectUnboundedOrAmbiguousPersistence() {
        val a=IdentityOperation.enroll(pub);assertEquals(a,Policy.json.decodeFromString<IdentityOperation>(Policy.json.encodeToString(a)))
        assertNotEquals(a.body,IdentityOperation.enroll(pub).body)
        invalid {IdentityOperation("/elsewhere",a.body)};invalid {IdentityOperation(a.path," ".repeat(8193))}
        invalid {IdentityOperation(a.path,a.body.replace("P-256","P-384"))};invalid {IdentityOperation(a.path,a.body.replace("policy.keybound.v2","policy.unsupported"))}
        invalid {IdentityOperation(a.path,a.body.dropLast(1)+",\"requestId\":\"duplicate\"}")}
        invalid {IdentityOperation.cleanup(emptyList())};val t=Identity.random();invalid {IdentityOperation.cleanup(listOf(t,t))}
        invalid {IdentityOperation.cleanup(List(17){Identity.random()})};invalid {IdentityOperation.cleanup(listOf("invalid"))}
        invalid {IdentityOperation(IdentityOperation.revoke().path,"{\"requestId\":24}")}
        invalid {IdentityOperation(IdentityOperation.revoke().path,"{\"requestId\":\"short\"}")}
        invalid {IdentityOperation(IdentityOperation.revoke().path,IdentityOperation.revoke().body.dropLast(1)+",\"extra\":true}")}
        val f=Fixture();assertFalse(f.pending.toString().contains(f.pending.verifier));assertFalse(b.toString().contains(b.issuer))
        assertEquals("Callback([redacted])",Callback("sensitive-code",null).toString())
        assertEquals("UserIdentity([redacted])",UserIdentity("private-subject").toString())
        assertEquals("Reply(status=200, [redacted])",json(text="sensitive-body").toString())
    }
    @Test fun uncertainRefreshRetriesTheSameOperationAndCancelledEnrollmentCannotReturnACredential() {
        val f=Fixture();val previous=f.current();val op=IdentityOperation.refresh();var calls=0;var firstProof=""
        f.handler={_,_,headers,body,_,_->
            assertEquals(op.body,body!!.toString(Charsets.UTF_8))
            if(++calls==1) {firstProof=headers.getValue("DPoP");throw DeliveryException(DeliveryFailure.EOF)}
            assertNotEquals(firstProof,headers.getValue("DPoP"));json(text=sessionWire(session(1)))
        }
        error(AuthFailure.TRANSPORT) {f.client.refresh(op,previous,IdentityScope())}
        assertEquals(0L,previous.session.generation)
        assertEquals(1L,f.client.refresh(op,previous,IdentityScope()).session.generation);assertEquals(2,calls)
        val scope=IdentityScope();f.handler={_,_,_,_,_,_->scope.cancel();json(text=sessionWire())}
        error(AuthFailure.CANCELLED) {f.client.enroll(IdentityOperation.enroll(pub),f.user(),scope)}
    }
    @Test fun oneOperationSupportsSequentialChildrenButCancelRejectsLateAndFutureResults() {
        val f=Fixture();val scope=IdentityScope();f.login(scope);scope.cancel()
        error(AuthFailure.CANCELLED) {f.client.discover(scope)}
        val late=IdentityScope();f.handler={_,_,_,_,_,_->late.cancel();json()}
        error(AuthFailure.CANCELLED) {f.client.discover(late)}
        val active=IdentityScope();f.handler={_,_,_,_,child,_->active.cancel();child.active();json()}
        error(AuthFailure.CANCELLED) {f.client.discover(active)}
    }
    @Test fun policyRequiresJoseAndActualSignatureDeviceAndLocalKeyAtConservativeTime() {
        val f=Fixture();val s=session();val config="""{"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}"""
        fun signed(device:String=s.deviceId,thumb:String=f.pending.thumbprint):String {
            val p=Payload(2,1,0,0,device,"syn443-device",now-1000,now-1000,now+300_000,now+600_000,
                IdentityOperation.requiredCapabilities,"m1-local-v1",Identity.encode(config.toByteArray()),Policy.hash(config),Gate(30,false,listOf(Check("internet","https_204","https://health.example.org/generate_204"))),keyThumbprint=thumb)
            val input=Identity.encode("""{"alg":"ES256","kid":"test-root","typ":"syn443-policy+jws"}""".toByteArray())+"."+Identity.encode(Canonical.encode(Canonical.parse(Policy.json.encodeToString(p))).toByteArray())
            return input+"."+Identity.encode(Signature.getInstance("SHA256withECDSAinP1363Format").run {initSign(root.private);update(input.toByteArray());sign()})
        }
        val valid=signed()
        f.handler={m,u,h,body,_,max->assertEquals("GET",m);assertEquals(b.apiOrigin+"/v1/device/policy",u);assertNull(body);assertEquals(524_288,max);assertTrue(h.containsKey("DPoP"));json(text=valid).copy(headers=mapOf("content-type" to listOf("application/jose"),"date" to listOf(date())))}
        val result=f.client.policy(f.current(),IdentityScope());assertEquals(valid,result.envelope);assertFalse(result.toString().contains(valid))
        val mutableRoots=b.roots.toMutableMap()
        val isolated=AuthProtocol(b.copy(roots=mutableRoots),key,IdentityExchange {m,u,h,body,scope,max->f.handler(m,u,h,body,scope,max)},{f.boot},{f.elapsed})
        mutableRoots.clear();assertEquals(valid,isolated.policy(f.current(),IdentityScope()).envelope)
        val original=f.handler
        for(wire in listOf(signed(thumb=Identity.random()),signed(device=Identity.random()),valid.dropLast(2)+"xx")) {
            f.handler={m,u,h,body,scope,max->original(m,u,h,body,scope,max).copy(body=wire.toByteArray())};error(AuthFailure.INVALID_REPLY) {f.client.policy(f.current(),IdentityScope())}
        }
        f.handler={_,_,_,_,_,_->json(text=valid)};error(AuthFailure.INVALID_REPLY) {f.client.policy(f.current(),IdentityScope())}
        val current=f.current();f.elapsed+=600_000;error(AuthFailure.INVALID_REPLY) {f.client.policy(current,IdentityScope())}
    }
}
