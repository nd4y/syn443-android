package io.syn443.identity

import io.syn443.policy.Canonical
import io.syn443.policy.Policy
import kotlinx.serialization.json.*
import org.junit.Assert.*
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/** Generated signatures and Go-shaped wire values. Live ACL/MFA/compiler and actual Go-byte conformance remain separate gates. */
class AdminLayerControlTest {
    private class Fixture {
        val now=1_800_000_000_000L
        val time=TimeWindow(now,now+1000)
        val device="synthetic-device"
        val owner=Identity.hash("synthetic-owner".toByteArray())
        val actor=Identity.hash("synthetic-actor".toByteArray())
        val origin="https://control.example.invalid"
        val baseHash="a".repeat(64)
        val graph="""{"profiles":{"p":{"profileId":"profile-a","sourceId":"source-a"}},"chains":{},"balancers":{},"final":"p"}"""
        val network="""{"schemaVersion":1.00,"requiredNetworks":["tcp","udp"],"dnsFinal":"system","dnsStrategy":"prefer_ipv4"}"""
        val activation="""{"checks":[{"required":true,"target":"https:\u002f\u002fhealth.example.invalid\u002fgenerate_204","expected":"","port":0,"type":"https_204","id":"internet"}],"allowDegraded":false,"timeoutSeconds":3.0E+1}"""
        val template="""{"id":"template","kind":"template","priority":0,"revision":7,"changes":[{"path":"/schemaVersion","operation":"set","value":1},{"path":"/graph","operation":"set","value":$graph},{"path":"/network","operation":"set","value":$network},{"path":"/activation","operation":"set","value":$activation}],"permissions":[{"path":"/activation/timeoutSeconds","mode":"range","minimum":1,"maximum":180},{"path":"/network/dnsFinal","mode":"choice","choices":["\u0073ystem","local"]}]}"""
        val own="""{"id":"$device","kind":"device","priority":0,"revision":4,"changes":[{"path":"/activation/timeoutSeconds","operation":"set","value":30},{"path":"/network/schemaVersion","operation":"set","value":1},{"path":"/network/dnsFinal","operation":"set","value":"\u0073ystem"}],"permissions":[{"path":"/activation/timeoutSeconds","mode":"range","minimum":2,"maximum":120}]}"""
        fun inventory(historical:Boolean=false,extraLayers:String="",fields:String?=null):String {
            val effective="""{"document":{"schemaVersion":1,"graph":$graph,"network":${network.replace("1.00","1")},"activation":${activation.replace("3.0E+1","30")}},"fields":${fields?:"""{"/schemaVersion":{"layerId":"template","kind":"template","revision":7}}"""},"restrictions":[]}"""
            return """{"device":"$device","owner":"$owner","state":"assigned","revision":2,"hash":"$baseHash","policyRevision":9,"mode":"wifi","approvalUntilMs":${now+3_600_000},"layers":[$template,$own$extraLayers],"effective":$effective,"currentRevision":${if(historical)3 else 2}${if(historical)",\"historical\":true" else ""}}"""
        }
        fun readInventory(raw:String=inventory())=AdminLayerControl.parseReply(AdminLayerControl.inventory(device,Identity.random()),raw,time) as AdminLayerInventory
        fun proposal()=AdminLayerControl.editDevice(readInventory(),"private-draft","device",device,"/activation/timeoutSeconds",AdminLayerEdit.SET,"45",now+3_600_000)
        fun draft(p:AdminLayerProposal=proposal(),revision:Long=p.draftRevision)=
            """{"id":"${p.draftId}","revision":$revision,"proposal":${p.wireJson()},"savedAtMs":$now}"""
        fun originValues()= """{"owner":"$owner","device":"$device","thumbprint":"${Identity.hash("key".toByteArray())}","grantHash":"${Identity.hash("grant".toByteArray())}","baseRevision":2,"baseHash":"$baseHash","capabilitiesHash":"${"b".repeat(64)}"}"""
        fun previewResult(request:AdminLayerRequest,expires:Long=now+120_000):String {
            val p=checkNotNull(request.expected.proposal)
            val v="""{"schemaVersion":1,"origin":"$origin","actor":"$actor","requestId":"${request.expected.initialRequestId}","draftId":"${p.draftId}","draftRevision":${p.draftRevision},"draftHash":"${"c".repeat(64)}","targetKind":"${p.targetKind}","targetId":"${p.targetId}","mode":"${p.mode}","dependencyHash":"${"d".repeat(64)}","effectiveHash":"${"e".repeat(64)}","recipients":[${originValues()}],"issuedAtMs":$now,"expiresAtMs":$expires}"""
            val pair=KeyPairGenerator.getInstance("EC").apply {initialize(ECGenParameterSpec("secp256r1"))}.generateKeyPair()
            // Match actual Go struct ordering; tickets are not sorted-key JCS.
            val input=Identity.encode("""{"alg":"ES256","typ":"syn443-configuration-preview+jws","kid":"synthetic-preview"}""".toByteArray())+"."+Identity.encode(v.toByteArray())
            val signature=Signature.getInstance("SHA256withECDSA").run {initSign(pair.private);update(input.toByteArray(Charsets.US_ASCII));sign()}
            val ticket=input+"."+Identity.encode(Identity.derToRaw(signature))
            return """{"previewId":"${request.expected.jobId}","ticket":"$ticket","preview":$v}"""
        }
        fun job(request:AdminLayerRequest,state:String="queued",result:String?=null,error:String?=null)=
            """{"id":"${request.expected.jobId}","state":"$state"${result?.let {",\"result\":$it"}?:""}${error?.let {",\"error\":\"$it\""}?:""}}"""
        fun ready():AdminLayerJob {
            val request=AdminLayerControl.preview(proposal(),actor,origin,Identity.random())
            return AdminLayerControl.parseReply(request,job(request,"ready",previewResult(request)),time) as AdminLayerJob
        }
    }
    private fun invalid(block:()->Unit) {
        val error=assertThrows(AdminException::class.java,block)
        assertEquals(AdminFailure.INVALID_REPLY,error.reason);assertEquals(error.reason.name,error.message);assertNull(error.cause)
    }
    private fun changed(raw:String,field:String,value:JsonElement)=JsonObject(AdminLayerJson.parse(raw,true).jsonObject+mapOf(field to value)).toString()
    private fun layers(p:AdminLayerProposal)=p.document.root.jsonObject.getValue("bundles").jsonArray.single().jsonObject.getValue("layers").jsonArray

    @Test fun existingActionsBuildOwnedStableBytesWithoutCredentialsAndKeepLostAckIdentity() {
        val f=Fixture();val p=f.proposal();val id=Identity.random()
        val saved=AdminLayerControl.parseReply(AdminLayerControl.saveDraft(0,p,id),f.draft(p),f.time) as AdminLayerDraft
        val ready=f.ready();val preview=checkNotNull(ready.preview)
        val requests=listOf(AdminLayerControl.inventory(f.device,id),AdminLayerControl.history(f.device,2,f.baseHash,id),
            AdminLayerControl.listDrafts("device",f.device,id),AdminLayerControl.getDraft(p.draftId,"device",f.device,id),
            AdminLayerControl.saveDraft(0,p,id),AdminLayerControl.discardDraft(saved,id),
            AdminLayerControl.preview(p,f.actor,f.origin,id),AdminLayerControl.poll(ready,id),AdminLayerControl.publish(preview,f.actor,f.origin,id,f.time))
        assertEquals(AdminLayerAction.entries.toSet(),requests.map {it.action}.toSet())
        for(request in requests) {
            val before=request.bodyBytes();val copy=request.bodyBytes();copy.fill(0)
            assertArrayEquals(before,request.bodyBytes());assertEquals(request.wireJson(),before.toString(Charsets.UTF_8))
            val envelope=AdminLayerJson.parse(request.wireJson()).jsonObject
            assertEquals(setOf("version","action","requestId","payload"),envelope.keys)
            assertEquals(1,envelope.getValue("version").jsonPrimitive.int);assertEquals(id,envelope.getValue("requestId").jsonPrimitive.content)
            assertEquals(request.action.wire,envelope.getValue("action").jsonPrimitive.content)
            assertFalse(request.toString().contains(f.device));assertFalse(request.toString().contains(f.origin))
            assertEquals(524_288,request.maxReplyBytes)
        }
        assertEquals(AdminLayerControl.saveDraft(0,p,id).wireJson(),AdminLayerControl.saveDraft(0,p,id).wireJson())
        assertNotEquals(AdminLayerControl.saveDraft(0,p,id).wireJson(),AdminLayerControl.saveDraft(0,p,Identity.random()).wireJson())
        invalid {AdminLayerControl.inventory("foreign/path",id)};invalid {AdminLayerControl.inventory(f.device,"short")}
        invalid {AdminLayerControl.history(f.device,0,"",id)};invalid {AdminLayerControl.listDrafts("local",f.device,id)}
        invalid {AdminLayerControl.preview(p,Identity.random()+"A",f.origin,id)}
        invalid {AdminLayerControl.preview(p,f.actor,"https://foreign.example.invalid/path",id)}
        invalid {AdminLayerControl.saveDraft(1,p,id)}
        assertFalse(AdminLayerAction.INVENTORY.requiresFreshMfa);assertFalse(AdminLayerAction.DRAFT_LIST.requiresFreshMfa)
        assertTrue(AdminLayerAction.entries.filter {it !in setOf(AdminLayerAction.INVENTORY,AdminLayerAction.DRAFT_LIST)}.all {it.requiresFreshMfa})
    }
    @Test fun inventoryHistoryAndDraftsRetainGoShapedProvenanceAndExactRawParents() {
        val f=Fixture();val inventory=f.readInventory();assertEquals(f.inventory(),inventory.wireJson())
        assertEquals(2L,inventory.revision);assertEquals(2L,inventory.currentRevision);assertFalse(inventory.historical)
        val history=AdminLayerControl.parseReply(AdminLayerControl.history(f.device,2,f.baseHash,Identity.random()),f.inventory(true),f.time) as AdminLayerInventory
        assertTrue(history.historical);assertEquals(3L,history.currentRevision)
        val proposal=f.proposal();assertEquals(f.template,proposal.document.raw(layers(proposal).first()))
        assertEquals("wifi",proposal.mode);assertEquals("device",proposal.targetKind);assertEquals(f.device,proposal.targetId)
        val saved=AdminLayerControl.parseReply(AdminLayerControl.getDraft(proposal.draftId,"device",f.device,Identity.random()),f.draft(proposal),f.time) as AdminLayerDraft
        assertEquals(proposal.wireJson(),saved.proposal.wireJson());assertEquals(f.draft(proposal),saved.wireJson())
        for(value in listOf(inventory,history,proposal,saved))assertFalse(value.toString().contains(f.device))
        invalid {AdminLayerControl.parseReply(AdminLayerControl.history(f.device,1,f.baseHash,Identity.random()),f.inventory(true),f.time)}
        invalid {AdminLayerControl.parseReply(AdminLayerControl.inventory("other-device",Identity.random()),f.inventory(),f.time)}
        invalid {AdminLayerControl.parseReply(AdminLayerControl.getDraft(proposal.draftId,"user",f.owner,Identity.random()),f.draft(proposal),f.time)}
    }
    @Test fun oneDeviceOverrideKeepsRawEscapesFractionExponentsParentsAndPermissionsUntouched() {
        val f=Fixture();val p=f.proposal();val all=layers(p)
        assertEquals(2,all.size);assertEquals(f.template,p.document.raw(all.first()))
        val target=all.last().jsonObject;assertEquals(5L,target.getValue("revision").jsonPrimitive.long)
        val before=AdminLayerJson.document(f.own);val original=before.root.jsonObject
        assertEquals(before.raw(original.getValue("permissions")),p.document.raw(target.getValue("permissions")))
        val unchanged=target.getValue("changes").jsonArray.first {it.jsonObject.getValue("path").jsonPrimitive.content=="/network/dnsFinal"}
        assertTrue(p.document.raw(unchanged).contains("\\u0073ystem"))
        assertTrue(p.document.raw(all.first()).contains("1.00"));assertTrue(p.document.raw(all.first()).contains("3.0E+1"))
        assertTrue(p.document.raw(all.first()).contains("\\u002f"))
        val decodedTemplate=all.first().jsonObject.getValue("changes").jsonArray
        assertEquals("3.0E+1",decodedTemplate.last().jsonObject.getValue("value").jsonObject.getValue("timeoutSeconds").jsonPrimitive.content)
        val changed=target.getValue("changes").jsonArray.single {it.jsonObject.getValue("path").jsonPrimitive.content=="/activation/timeoutSeconds"}
        assertEquals("45",changed.jsonObject.getValue("value").jsonPrimitive.content)
        assertEquals("/activation/timeoutSeconds",changed.jsonObject.getValue("path").jsonPrimitive.content)
        // The inherited fractional timeout/network version are overridden by
        // integer device values before the authoritative Go settings compiler.
        assertEquals("1",target.getValue("changes").jsonArray.first {it.jsonObject.getValue("path").jsonPrimitive.content=="/network/schemaVersion"}.jsonObject.getValue("value").jsonPrimitive.content)
    }
    @Test fun deviceHelpersDistinguishDeletionInheritanceAndExplicitBoundNewLocalLayer() {
        val f=Fixture();val current=f.readInventory()
        val deleted=AdminLayerControl.editDevice(current,"delete-copy","device",f.device,"/network/dnsFinal",AdminLayerEdit.DELETE,null,f.now+60_000)
        val change=layers(deleted).last().jsonObject.getValue("changes").jsonArray.last().jsonObject
        assertEquals("delete",change.getValue("operation").jsonPrimitive.content);assertFalse("value" in change)
        val inherited=AdminLayerControl.editDevice(current,"inherit-copy","device",f.device,"/network/dnsFinal",AdminLayerEdit.INHERIT,null,f.now+60_000)
        assertFalse(layers(inherited).last().jsonObject.getValue("changes").jsonArray.any {it.jsonObject.getValue("path").jsonPrimitive.content=="/network/dnsFinal"})
        val local=AdminLayerControl.editDevice(current,"local-copy","local",f.device,"/network/dnsStrategy",AdminLayerEdit.SET,"\"prefer_ipv6\"",f.now+60_000)
        assertEquals(3,layers(local).size);assertEquals(f.template,local.document.raw(layers(local)[0]));assertEquals(f.own,local.document.raw(layers(local)[1]))
        assertEquals("local",layers(local).last().jsonObject.getValue("kind").jsonPrimitive.content)
        invalid {AdminLayerControl.editDevice(current,"bad","device","foreign-device","/network/dnsFinal",AdminLayerEdit.SET,"\"system\"",f.now+60_000)}
        invalid {AdminLayerControl.editDevice(current,"bad","template",f.device,"/network/dnsFinal",AdminLayerEdit.DELETE,null,f.now+60_000)}
        invalid {AdminLayerControl.editDevice(current,"bad","device",f.device,"/network",AdminLayerEdit.DELETE,null,f.now+60_000)}
        invalid {AdminLayerControl.editDevice(current,"bad","device",f.device,"/absent",AdminLayerEdit.INHERIT,null,f.now+60_000)}
        invalid {AdminLayerControl.editDevice(current,"bad","device",f.device,"/network/dnsFinal",AdminLayerEdit.DELETE,"0",f.now+60_000)}
        invalid {AdminLayerControl.editDevice(current,"bad","device",f.device,"/network/dnsFinal",AdminLayerEdit.SET,"null",f.now+60_000)}
    }
    @Test fun previewPublicationAndPollingBindActorRecipientBaseAndDesiredRevisionExactly() {
        val f=Fixture();val request=AdminLayerControl.preview(f.proposal(),f.actor,f.origin,Identity.random())
        val expected=Identity.hash((f.actor+"\u0000"+request.requestId).toByteArray())
        val queued=AdminLayerControl.parseReply(request,f.job(request),f.time) as AdminLayerJob
        assertEquals(expected,queued.id);assertNull(queued.preview);assertTrue(queued.heads.isEmpty())
        val poll=AdminLayerControl.poll(queued,Identity.random())
        assertEquals(queued.id,AdminLayerJson.parse(poll.wireJson()).jsonObject.getValue("payload").jsonObject.getValue("id").jsonPrimitive.content)
        val ready=AdminLayerControl.parseReply(poll,f.job(request,"ready",f.previewResult(request)),f.time) as AdminLayerJob
        val preview=checkNotNull(ready.preview);assertEquals(queued.id,preview.previewId)
        assertFalse(preview.toString().contains(preview.ticket));assertTrue(preview.wireJson().contains("\"recipients\""))
        val publication=AdminLayerControl.publish(preview,f.actor,f.origin,Identity.random(),f.time)
        val result="""{"heads":[{"device":"${f.device}","revision":3,"hash":"${preview.draftHash}"}]}"""
        val done=AdminLayerControl.parseReply(publication,f.job(publication,"published",result),f.time) as AdminLayerJob
        assertEquals("published",done.state);assertEquals(3L,done.heads.single().revision);assertEquals(preview.draftHash,done.heads.single().hash)
        assertFalse(done.heads.single().toString().contains(f.device))
        assertThrows(UnsupportedOperationException::class.java) {(done.heads as MutableList<*>).clear()}
        invalid {AdminLayerControl.publish(preview,Identity.random(),f.origin,Identity.random(),f.time)}
        invalid {AdminLayerControl.publish(preview,f.actor,"https://other.example.invalid",Identity.random(),f.time)}
        invalid {AdminLayerControl.parseReply(publication,f.job(publication,"published",result.replace("\"revision\":3","\"revision\":4")),f.time)}
        invalid {AdminLayerControl.parseReply(publication,f.job(publication,"ready",f.previewResult(request)),f.time)}
    }
    @Test fun expiredRejectedUnknownAndLegacyJobsNeverMintPublicationOrActivation() {
        val f=Fixture();val request=AdminLayerControl.preview(f.proposal(),f.actor,f.origin,Identity.random())
        for(state in listOf("queued","running","rejected","expired","cancelled")) {
            val raw=f.job(request,state,error=if(state=="rejected")"configuration_conflict" else null)
            val value=AdminLayerControl.parseReply(request,raw,f.time) as AdminLayerJob
            assertEquals(state,value.state);assertNull(value.preview);assertTrue(value.heads.isEmpty())
        }
        val old=AdminLayerControl.parseReply(request,f.job(request,"ready",f.previewResult(request,f.now+100)),f.time) as AdminLayerJob
        assertNotNull(old.preview)
        invalid {AdminLayerControl.publish(checkNotNull(old.preview),f.actor,f.origin,Identity.random(),f.time)}
        for(raw in listOf(f.job(request,"applied"),f.job(request,"queued","{}"),f.job(request,"rejected",error="raw private exception"),f.job(request,"published","{\"heads\":[]}"))) {
            invalid {AdminLayerControl.parseReply(request,raw,f.time)}
        }
        invalid {AdminLayerControl.parseReply(request,f.job(request).replace(request.expected.jobId,Identity.random()),f.time)}
    }
    @Test fun substitutedPreviewScopeRecipientTimeAndPurposeCannotEnablePublication() {
        val f=Fixture();val request=AdminLayerControl.preview(f.proposal(),f.actor,f.origin,Identity.random())
        val result=f.previewResult(request)
        for(raw in listOf(result.replace(f.origin,"https://foreign.example.invalid"),result.replace(f.actor,Identity.random()),
            result.replace("\"draftRevision\":1","\"draftRevision\":2"),result.replace("\"mode\":\"wifi\"","\"mode\":\"cellular\""),
            result.replace("\"baseRevision\":2","\"baseRevision\":3"),result.replace("\"expiresAtMs\":${f.now+120_000}","\"expiresAtMs\":${f.now+180_001}"),
            result.replace("\"recipients\":[","\"recipients\":[${f.originValues()},"),result.replace("\"schemaVersion\":1","\"schemaVersion\":2"))) {
            invalid {AdminLayerControl.parseReply(request,f.job(request,"ready",raw),f.time)}
        }
        val resultObject=AdminLayerJson.parse(result).jsonObject
        val malformed=JsonObject(resultObject+mapOf("ticket" to JsonPrimitive("not-a-compact-ticket-at-all"))).toString()
        invalid {AdminLayerControl.parseReply(request,f.job(request,"ready",malformed),f.time)}
    }
    @Test fun savedCopiesOrderingDiscardReceiptsAndRevisionCasRemainOwned() {
        val f=Fixture();val list=AdminLayerControl.listDrafts("device",f.device,Identity.random())
        val raw="""{"targetKind":"device","targetId":"${f.device}","drafts":[{"id":"a","revision":2,"savedAtMs":${f.now}},{"id":"b","revision":1,"savedAtMs":${f.now}}]}"""
        val copies=AdminLayerControl.parseReply(list,raw,f.time) as AdminLayerDraftList
        assertEquals(listOf("a","b"),copies.drafts.map {it.id});assertFalse(copies.drafts.single {it.id=="a"}.toString().contains("revision"))
        assertThrows(UnsupportedOperationException::class.java) {(copies.drafts as MutableList<*>).clear()}
        for(bad in listOf(raw.replace("\"id\":\"b\"","\"id\":\"a\""),raw.replace("\"id\":\"a\"","\"id\":\"z\""),raw.replace(f.device,"foreign-device")))invalid {AdminLayerControl.parseReply(list,bad,f.time)}
        val p=f.proposal();val save=AdminLayerControl.saveDraft(0,p,Identity.random())
        val saved=AdminLayerControl.parseReply(save,f.draft(p),f.time) as AdminLayerDraft
        val discard=AdminLayerControl.discardDraft(saved,Identity.random())
        val receipt="""{"id":"${saved.id}","revision":1,"discarded":true}"""
        assertEquals(1L,(AdminLayerControl.parseReply(discard,receipt,f.time) as AdminLayerDiscarded).revision)
        invalid {AdminLayerControl.parseReply(discard,receipt.replace("true","false"),f.time)}
        invalid {AdminLayerControl.parseReply(save,f.draft(p,2),f.time)}
        invalid {AdminLayerControl.parseReply(save,f.draft(p).replace("\"savedAtMs\":${f.now}","\"savedAtMs\":${f.now+30_002}"),f.time)}
    }
    @Test fun portableShapesEnforceActualLayerPermissionChangesAndScopeBounds() {
        val f=Fixture();val good=f.proposal().wireJson()
        for(bad in listOf(good.replace("\"targetKind\":\"device\"","\"targetKind\":\"local\""),
            good.replace("\"targetId\":\"${f.device}\"","\"targetId\":\"foreign\""),good.replace("\"mode\":\"wifi\"","\"mode\":\"lte\""),
            good.replace("\"priority\":0","\"priority\":1"),good.replace("\"revision\":7","\"revision\":0"),
            good.replace("\"kind\":\"template\"","\"kind\":\"user\""),good.replace("\"path\":\"/schemaVersion\"","\"path\":\"/../escape\""),
            good.replace("\"minimum\":1","\"minimum\":181"),good.replace("\"mode\":\"range\"","\"mode\":\"unknown\""),
            good.replace("\"value\":1}","\"value\":null}"),good.replace("\"operation\":\"set\"","\"operation\":\"delete\"")))invalid {AdminLayerControl.proposal(bad)}
        val doc=AdminLayerJson.document(good);val root=doc.root.jsonObject;val bundle=root.getValue("bundles").jsonArray.single().jsonObject
        val invalidBundles=JsonArray(List(65){JsonObject(bundle+mapOf("device" to JsonPrimitive("d$it")))})
        invalid {AdminLayerControl.proposal(JsonObject(root+mapOf("targetKind" to JsonPrimitive("template"),"bundles" to invalidBundles)).toString())}
        val first=layers(f.proposal()).first().jsonObject
        val changes=JsonArray(List(257){buildJsonObject {put("path","/k$it");put("operation","set");put("value",it)}})
        val tooMany=JsonObject(first+mapOf("changes" to changes))
        val changedBundle=JsonObject(bundle+mapOf("layers" to JsonArray(listOf(tooMany,layers(f.proposal()).last()))))
        invalid {AdminLayerControl.proposal(JsonObject(root+mapOf("bundles" to JsonArray(listOf(changedBundle)))).toString())}
    }
    @Test fun validFractionalInheritedValuesRetainLexemesAndIntegerMetadataStaysStrict() {
        val f=Fixture();val p=f.proposal();assertTrue(p.wireJson().contains("1.00"));assertTrue(p.wireJson().contains("3.0E+1"))
        for(raw in listOf("0","-0","1.00","3.0E+1","1e-308","0e+308","9007199254740991","-9007199254740991")) {
            val doc=AdminLayerJson.document(raw);assertEquals(raw,doc.raw(doc.root));assertEquals(raw,doc.root.toString())
        }
        for(raw in listOf("NaN","Infinity","1e309","1e-309","9007199254740992","-9007199254740992","0."+"0".repeat(63),"01","1.","1e","1e+","+1")) {
            assertThrows(Exception::class.java){AdminLayerJson.parse(raw)}
        }
        assertThrows(Exception::class.java){Canonical.parse("1.00")}
        invalid {AdminLayerControl.proposal(p.wireJson().replace("\"draftRevision\":1","\"draftRevision\":1.0"))}
        invalid {AdminLayerControl.parseReply(AdminLayerControl.inventory(f.device,Identity.random()),f.inventory().replace("\"revision\":2","\"revision\":2e0"),f.time)}
    }
    @Test fun repliesRejectUnknownNullDuplicateCrossScopeAndInvalidOriginBindings() {
        val f=Fixture();val request=AdminLayerControl.inventory(f.device,Identity.random())
        for(raw in listOf("null","[]",f.inventory().dropLast(1)+",\"unexpected\":true}",
            f.inventory().replace("\"device\":","\"Device\":"),f.inventory().replace("\"device\":","\"device\":null,\"device\":"),
            f.inventory().replace("\"layerId\":\"template\"","\"layerId\":\"foreign\""),f.inventory().replace("\"effective\":{","\"effective\":null,\"shadow\":{")))invalid {AdminLayerControl.parseReply(request,raw,f.time)}
        val historical=f.readInventory(f.inventory())
        invalid {AdminLayerControl.editDevice(historical,"bad/id","device",f.device,"/network/dnsFinal",AdminLayerEdit.SET,"\"system\"",f.now+60_000)}
        val actualHistory=AdminLayerControl.parseReply(AdminLayerControl.history(f.device,2,f.baseHash,Identity.random()),f.inventory(true),f.time) as AdminLayerInventory
        invalid {AdminLayerControl.editDevice(actualHistory,"no-history-write","device",f.device,"/network/dnsFinal",AdminLayerEdit.DELETE,null,f.now+60_000)}
    }
    @Test fun bodyAndReplyUtf8BoundsDoNotTruncateOrResetStableOperationIdentity() {
        val f=Fixture();val p=f.proposal();val request=AdminLayerControl.saveDraft(0,p,Identity.random())
        val before=request.bodyBytes();val hash=Identity.hash(before)
        invalid {AdminLayerControl.proposal(p.wireJson().padEnd(262_145,' '))}
        invalid {AdminLayerControl.parseReply(AdminLayerControl.inventory(f.device,Identity.random()),"{}".padEnd(524_289,' '),f.time)}
        invalid {AdminLayerControl.parseReply(request,f.draft(p).padEnd(262_145,' '),f.time)}
        assertEquals(hash,Identity.hash(request.bodyBytes()));assertArrayEquals(before,request.bodyBytes())
        assertTrue(AdminLayerControl.proposal(p.wireJson().padEnd(262_144,' ')).wireJson().contains("1.00"))
        val oversized=AdminLayerControl.proposal(p.wireJson().padEnd(262_144,' '))
        // Retained proposal excludes surrounding whitespace but never drops its
        // opaque parent spans in order to fit a request.
        assertTrue(AdminLayerControl.saveDraft(0,oversized,Identity.random()).bodyBytes().size<=262_144)
    }
    @Test fun everyFixedOperationRestoresExactAuthenticatedBodyAndOwnedContextWithoutNewAuthority() {
        val f=Fixture();val p=f.proposal();val saved=AdminLayerControl.parseReply(AdminLayerControl.saveDraft(0,p,Identity.random()),f.draft(p),f.time) as AdminLayerDraft
        val ready=f.ready();val publication=AdminLayerControl.publish(checkNotNull(ready.preview),f.actor,f.origin,Identity.random(),f.time)
        val pending=AdminLayerControl.parseReply(publication,f.job(publication),f.time) as AdminLayerJob
        val requests=listOf(AdminLayerControl.inventory(f.device,Identity.random()),AdminLayerControl.history(f.device,2,f.baseHash,Identity.random()),
            AdminLayerControl.listDrafts("device",f.device,Identity.random()),AdminLayerControl.getDraft(p.draftId,"device",f.device,Identity.random()),
            AdminLayerControl.saveDraft(0,p,Identity.random()),AdminLayerControl.discardDraft(saved,Identity.random()),
            AdminLayerControl.preview(p,f.actor,f.origin,Identity.random()),AdminLayerControl.poll(ready,Identity.random()),publication,AdminLayerControl.poll(pending,Identity.random()))
        for(request in requests) {
            val proposal=request.expected.proposal?.wireJson();val bytes=request.bodyBytes()
            val context=AdminLayerControl.replayContext(request,f.actor,f.origin);assertTrue(context.size<=8192)
            val restored=AdminLayerControl.restoreRequest(bytes,context,proposal,f.actor,f.origin)
            assertArrayEquals(bytes,restored.bodyBytes());assertEquals(request.requestId,restored.requestId);assertEquals(request.action,restored.action)
            assertArrayEquals(context,AdminLayerControl.replayContext(restored,f.actor,f.origin))
            bytes.fill(0);context.fill(0);assertEquals(request.wireJson(),restored.wireJson())
            assertFalse(restored.toString().contains(f.actor))
        }
        // An unsaved/invalid local editor buffer must not prevent discarding the saved CAS revision.
        val discard=AdminLayerControl.discardDraft(saved,Identity.random())
        val restored=AdminLayerControl.restoreRequest(discard.bodyBytes(),AdminLayerControl.replayContext(discard,f.actor,f.origin),"not valid draft JSON",f.actor,f.origin)
        assertEquals(discard.wireJson(),restored.wireJson())
    }
    @Test fun replayedPreviewAndPublishCanOnlyReconcileOriginalOperationEvenAfterTicketExpiry() {
        val f=Fixture();val previewRequest=AdminLayerControl.preview(f.proposal(),f.actor,f.origin,Identity.random())
        val result=f.previewResult(previewRequest)
        val restored=AdminLayerControl.restoreRequest(previewRequest.bodyBytes(),AdminLayerControl.replayContext(previewRequest,f.actor,f.origin),
            previewRequest.expected.proposal!!.wireJson(),f.actor,f.origin)
        val ready=AdminLayerControl.parseReply(restored,f.job(restored,"ready",result),f.time) as AdminLayerJob
        assertTrue(checkNotNull(ready.preview).replayOnly)
        invalid {AdminLayerControl.publish(checkNotNull(ready.preview),f.actor,f.origin,Identity.random(),f.time)}
        val liveReady=AdminLayerControl.parseReply(previewRequest,f.job(previewRequest,"ready",result),f.time) as AdminLayerJob
        val publish=AdminLayerControl.publish(checkNotNull(liveReady.preview),f.actor,f.origin,Identity.random(),f.time)
        val context=AdminLayerControl.replayContext(publish,f.actor,f.origin)
        val same=AdminLayerControl.restoreRequest(publish.bodyBytes(),context,publish.expected.proposal!!.wireJson(),f.actor,f.origin)
        assertArrayEquals(publish.bodyBytes(),same.bodyBytes());assertTrue(checkNotNull(same.expected.preview).replayOnly)
        val afterExpiry=TimeWindow(f.now+3_600_000,f.now+3_600_001)
        invalid {AdminLayerControl.publish(checkNotNull(same.expected.preview),f.actor,f.origin,Identity.random(),afterExpiry)}
        val pending=AdminLayerControl.parseReply(same,f.job(same),afterExpiry) as AdminLayerJob
        val poll=AdminLayerControl.poll(pending,Identity.random())
        val pollCopy=AdminLayerControl.restoreRequest(poll.bodyBytes(),AdminLayerControl.replayContext(poll,f.actor,f.origin),publish.expected.proposal!!.wireJson(),f.actor,f.origin)
        val heads="""{"heads":[{"device":"${f.device}","revision":3,"hash":"${checkNotNull(same.expected.preview).draftHash}"}]}"""
        val done=AdminLayerControl.parseReply(pollCopy,f.job(pollCopy,"published",heads),afterExpiry) as AdminLayerJob
        assertEquals("published",done.state);assertEquals(3L,done.heads.single().revision);assertTrue(done.context.replayOnly)
        assertFalse(pollCopy.wireJson().contains("ticket"));assertTrue(AdminLayerControl.replayContext(pollCopy,f.actor,f.origin).size<8192)
    }
    @Test fun replayRejectsBodyContextProposalActorOriginTicketAndUtf8Substitution() {
        val f=Fixture();val p=f.proposal();val ready=f.ready()
        val publish=AdminLayerControl.publish(checkNotNull(ready.preview),f.actor,f.origin,Identity.random(),f.time)
        val body=publish.bodyBytes();val context=AdminLayerControl.replayContext(publish,f.actor,f.origin)
        fun restore(b:ByteArray=body,c:ByteArray=context,proposal:String?=p.wireJson(),actor:String=f.actor,origin:String=f.origin) {
            AdminLayerControl.restoreRequest(b,c,proposal,actor,origin)
        }
        fun changedContext(key:String,value:JsonElement)=changed(context.toString(Charsets.UTF_8),key,value).toByteArray()
        invalid {restore(actor=Identity.random())};invalid {restore(origin="https://other.example.invalid")}
        invalid {restore(proposal=null)};invalid {restore(proposal=p.wireJson().replace("1.00","1.0"))}
        invalid {restore(b=AdminLayerControl.preview(p,f.actor,f.origin,Identity.random()).bodyBytes())}
        for((key,value) in listOf("bodyHash" to JsonPrimitive(Identity.random()),"proposalHash" to JsonPrimitive(Identity.random()),
            "jobId" to JsonPrimitive(Identity.random()),"initialRequestId" to JsonPrimitive(Identity.random()),
            "previewId" to JsonPrimitive(Identity.random()),"previewDraftHash" to JsonPrimitive("f".repeat(64)),
            "previewIssuedAtMs" to JsonPrimitive(f.now+1),"previewExpiresAtMs" to JsonPrimitive(f.now+180_001),
            "ticketHash" to JsonPrimitive(Identity.random()),"revision" to JsonPrimitive(1),"jobKind" to JsonPrimitive("configuration.inventory.get"))) {
            invalid {restore(c=changedContext(key,value))}
        }
        val stolen=JsonObject(AdminLayerJson.parse(publish.wireJson()).jsonObject.let {root->
            val payload=root.getValue("payload").jsonObject
            root+mapOf("payload" to JsonObject(payload+mapOf("ticket" to JsonPrimitive(checkNotNull(ready.preview).ticket+"A"))))
        }).toString().toByteArray()
        invalid {restore(b=stolen)}
        invalid {restore(c=context+ByteArray(8193-context.size){32})}
        invalid {restore(c=context+byteArrayOf(0xc3.toByte()))}
        invalid {restore(b=body+byteArrayOf(0xc3.toByte()))}
        invalid {restore(c=changed(context.toString(Charsets.UTF_8),"unknown",JsonPrimitive(true)).toByteArray())}
        invalid {restore(c=context.toString(Charsets.UTF_8).replace("\"schemaVersion\":1","\"schemaVersion\":null").toByteArray())}
        invalid {restore(c=context.toString(Charsets.UTF_8).replace("\"schemaVersion\":1","\"schemaVersion\":1,\"schemaVersion\":1").toByteArray())}
        invalid {restore(c=changedContext("schemaVersion",JsonPrimitive(2)))}
    }
    @Test fun actualGoTicketHeaderOrderWorksButMalformedPurposeShapeOrPayloadNeverMintsPreview() {
        val f=Fixture();val request=AdminLayerControl.preview(f.proposal(),f.actor,f.origin,Identity.random())
        val result=f.previewResult(request);val root=AdminLayerJson.parse(result).jsonObject
        val ticket=root.getValue("ticket").jsonPrimitive.content;val parts=ticket.split('.')
        fun withTicket(value:String)=JsonObject(root+mapOf("ticket" to JsonPrimitive(value))).toString()
        fun rejected(header:String,body:String=Policy.decode64(parts[1]).toString(Charsets.UTF_8),signature:ByteArray=Policy.decode64(parts[2])) {
            invalid {AdminLayerControl.parseReply(request,f.job(request,"ready",withTicket(Identity.encode(header.toByteArray())+"."+Identity.encode(body.toByteArray())+"."+Identity.encode(signature))),f.time)}
        }
        val goodHeader=Policy.decode64(parts[0]).toString(Charsets.UTF_8)
        assertTrue(goodHeader.indexOf("typ")<goodHeader.indexOf("kid"))
        assertNotNull((AdminLayerControl.parseReply(request,f.job(request,"ready",result),f.time) as AdminLayerJob).preview)
        rejected(goodHeader.replace("ES256","none"));rejected(goodHeader.replace("syn443-configuration-preview+jws","JWT"))
        rejected(goodHeader.replace("synthetic-preview","bad/id"));rejected(goodHeader.dropLast(1)+",\"jku\":\"https://foreign.example.invalid\"}")
        rejected(goodHeader.dropLast(1)+",\"alg\":\"ES256\"}");rejected(goodHeader,signature=ByteArray(63))
        rejected(" ".repeat(513));rejected(goodHeader,body="{}".padEnd(65_537,' '))
        rejected(goodHeader,body=Policy.decode64(parts[1]).toString(Charsets.UTF_8).replace("\"draftRevision\":1","\"draftRevision\":2"))
    }

    @Test fun wireBoundsAcceptSixtyFourRecipientsTwentyLayersAndExactAggregateChangePermissionLimits() {
        val f=Fixture()
        fun layer(kind:String,id:String,changes:String="[]",permissions:String="[]",priority:Int=0)=
            """{"id":"$id","kind":"$kind","priority":$priority,"revision":1,"changes":$changes,"permissions":$permissions}"""
        fun allLayers(device:String)=(listOf(layer("template","template"))+List(16){layer("group","g$it",priority=if(it==0)-10_000 else 10_000)}+
            listOf(layer("user",f.owner),layer("device",device),layer("local",device))).joinToString(",","[","]")
        fun proposal(bundles:String)="""{"draftId":"bounded","draftRevision":1,"targetKind":"template","targetId":"template","mode":"wifi","approvalUntilMs":${f.now+60_000},"bundles":$bundles}"""
        val bundles=(0 until 64).joinToString(",","[","]"){"""{"device":"d$it","baseRevision":0,"baseHash":"","layers":${allLayers("d$it")}}"""}
        val p=AdminLayerControl.proposal(proposal(bundles));assertEquals(64,p.document.root.jsonObject.getValue("bundles").jsonArray.size)
        assertTrue(AdminLayerControl.preview(p,f.actor,f.origin,"r".repeat(128)).bodyBytes().size<=262_144)
        assertNotNull(AdminLayerControl.inventory("i".repeat(64),"r".repeat(24)))
        invalid {AdminLayerControl.inventory("i".repeat(65),Identity.random())};invalid {AdminLayerControl.inventory("i","r".repeat(129))}
        invalid {AdminLayerControl.inventory("i","r".repeat(23))}
        val sixtyFive=bundles.dropLast(1)+","+"""{"device":"extra","baseRevision":0,"baseHash":"","layers":${allLayers("extra")}}]"""
        invalid {AdminLayerControl.proposal(proposal(sixtyFive))}
        val tooManyLayers=allLayers("d").dropLast(1)+","+layer("group","extra")+"]"
        invalid {AdminLayerControl.proposal(proposal("""[{"device":"d","baseRevision":0,"baseHash":"","layers":$tooManyLayers}]"""))}
        fun changes(prefix:String,count:Int)=(0 until count).joinToString(",","[","]"){"""{"path":"/${prefix}k$it","operation":"set","value":$it}"""}
        val permissions=(0 until 256).joinToString(",","[","]"){"""{"path":"/k$it","mode":"free"}"""}
        fun oneBundle(rows:String)=proposal("""[{"device":"d","baseRevision":0,"baseHash":"","layers":$rows}]""")
        val exact="["+layer("template","template",changes("",256),permissions)+","+layer("group","g",changes("v",256))+"]"
        assertNotNull(AdminLayerControl.proposal(oneBundle(exact)))
        invalid {AdminLayerControl.proposal(oneBundle("["+layer("template","template",changes("",257))+"]"))}
        invalid {AdminLayerControl.proposal(oneBundle(exact.dropLast(1)+","+layer("group","g2",changes("z",1))+"]"))}
        val extraPermission="""[{"path":"/k0","mode":"locked"}]"""
        invalid {AdminLayerControl.proposal(oneBundle("["+layer("template","template",permissions=permissions)+","+layer("local","d",permissions=extraPermission)+"]"))}
        val choice=(0 until 32).joinToString(",","[","]"){"\"v$it\""}
        val permissionCases=listOf("""{"path":"/a","mode":"locked"}""","""{"path":"/a","mode":"free","choices":[]}""",
            """{"path":"/a","mode":"choice","choices":$choice}""","""{"path":"/a","mode":"range","maximum":9007199254740991}""",
            """{"path":"/a","mode":"range","minimum":-9007199254740991}""")
        for(permission in permissionCases)assertNotNull(AdminLayerControl.proposal(oneBundle("["+layer("template","template",permissions="[$permission]")+"]")))
        for(permission in listOf("""{"path":"/a","mode":"choice","choices":["a","a"]}""","""{"path":"/a","mode":"free","minimum":1}""",
            """{"path":"/a","mode":"range"}""","""{"path":"/a","mode":"range","minimum":1,"maximum":0}""",
            """{"path":"/a","mode":"choice","choices":${choice.dropLast(1)+",\"extra\"]"}}""")) {
            invalid {AdminLayerControl.proposal(oneBundle("["+layer("template","template",permissions="[$permission]")+"]"))}
        }
    }

    @Test fun newAssignedDraftCopiesRawAuthoritativeLayersWithoutChangingAnyLayerRevision() {
        val f=Fixture();val base=f.readInventory()
        val p=AdminLayerControl.newDeviceDraft(base,"fresh-private-draft",f.now+60_000)
        assertEquals(1L,p.draftRevision);assertEquals("device",p.targetKind);assertEquals(f.device,p.targetId);assertEquals(base.mode,p.mode)
        val b=p.document.root.jsonObject.getValue("bundles").jsonArray.single().jsonObject
        assertEquals(base.revision,b.getValue("baseRevision").jsonPrimitive.long);assertEquals(base.hash,b.getValue("baseHash").jsonPrimitive.content)
        assertEquals(base.document.raw(base.document.root.jsonObject.getValue("layers")),p.document.raw(b.getValue("layers")))
        assertEquals(f.template,p.document.raw(layers(p)[0]));assertEquals(f.own,p.document.raw(layers(p)[1]))
        assertEquals(7L,layers(p)[0].jsonObject.getValue("revision").jsonPrimitive.long);assertEquals(4L,layers(p)[1].jsonObject.getValue("revision").jsonPrimitive.long)
        invalid {AdminLayerControl.newDeviceDraft(base,"bad/id",f.now+60_000)}
        invalid {AdminLayerControl.newDeviceDraft(base,"draft",base.approvalUntilMs+1)}
        invalid {AdminLayerControl.newDeviceDraft(base,"draft",0)}
        val expired=f.readInventory(f.inventory().replace("\"state\":\"assigned\"","\"state\":\"expired\""))
        invalid {AdminLayerControl.newDeviceDraft(expired,"draft",f.now+60_000)}
        val old=AdminLayerControl.parseReply(AdminLayerControl.history(f.device,2,f.baseHash,Identity.random()),f.inventory(true),f.time) as AdminLayerInventory
        invalid {AdminLayerControl.newDeviceDraft(old,"draft",f.now+60_000)}
        val root=AdminLayerJson.parse(f.inventory(),true).jsonObject
        val unassigned=JsonObject(root.filterKeys {it!="effective"}+mapOf("state" to JsonPrimitive("unassigned"),"revision" to JsonPrimitive(0),"currentRevision" to JsonPrimitive(0),
            "hash" to JsonPrimitive(""),"mode" to JsonPrimitive(""),"approvalUntilMs" to JsonPrimitive(0),"layers" to JsonArray(emptyList())))
        val missing=f.readInventory(unassigned.toString())
        invalid {AdminLayerControl.newDeviceDraft(missing,"draft",f.now+60_000)}
        invalid {AdminLayerControl.prepareDeviceDraft(missing,p,p.draftId,0)}
    }
    @Test fun preparePrivateDraftBatchesOwnEditsIntoOneLayerRevisionAndSeparateSavedDraftCas() {
        val f=Fixture();val base=f.readInventory();val fresh=AdminLayerControl.newDeviceDraft(base,"batch",f.now+60_000)
        val root=fresh.document.root.jsonObject;val b=root.getValue("bundles").jsonArray.single().jsonObject
        val before=layers(fresh).last().jsonObject
        val changes=before.getValue("changes").jsonArray.map {row->
            val c=row.jsonObject;val path=c.getValue("path").jsonPrimitive.content
            when(path) {
                "/activation/timeoutSeconds"->JsonObject(c+mapOf("value" to JsonPrimitive(45)))
                "/network/dnsFinal"->JsonObject(c+mapOf("value" to JsonPrimitive("local")))
                else->row
            }
        }
        val edited=JsonObject(before+mapOf("changes" to JsonArray(changes),"revision" to JsonPrimitive(999)))
        val cb=JsonObject(b+mapOf("layers" to JsonArray(listOf(layers(fresh).first(),edited))))
        val candidate=AdminLayerControl.proposal(JsonObject(root+mapOf("draftRevision" to JsonPrimitive(400),"bundles" to JsonArray(listOf(cb)))).toString())
        val prepared=AdminLayerControl.prepareDeviceDraft(base,candidate,"batch",5)
        assertEquals(6L,prepared.draftRevision);assertEquals(5L,layers(prepared).last().jsonObject.getValue("revision").jsonPrimitive.long)
        assertEquals(f.template,prepared.document.raw(layers(prepared).first()))
        val baseDoc=AdminLayerJson.document(f.own)
        assertEquals(baseDoc.raw(baseDoc.root.jsonObject.getValue("permissions")),prepared.document.raw(layers(prepared).last().jsonObject.getValue("permissions")))
        assertEquals(6L,AdminLayerControl.saveDraft(5,prepared,Identity.random()).expected.revision)
        val preparedAgain=AdminLayerControl.prepareDeviceDraft(base,prepared,"batch",6)
        assertEquals(7L,preparedAgain.draftRevision);assertEquals(5L,layers(preparedAgain).last().jsonObject.getValue("revision").jsonPrimitive.long)
        val old=AdminLayerControl.parseReply(AdminLayerControl.history(f.device,2,f.baseHash,Identity.random()),f.inventory(true),f.time) as AdminLayerInventory
        assertEquals(prepared.wireJson(),AdminLayerControl.prepareDeviceDraft(old,candidate,"batch",5).wireJson())
        // A changed captured base remains a conflict; private preparation never silently rebases it.
        val newer=f.readInventory(f.inventory().replace("\"revision\":2","\"revision\":3").replace("\"currentRevision\":2","\"currentRevision\":3"))
        invalid {AdminLayerControl.prepareDeviceDraft(newer,candidate,"batch",5)}
        invalid {AdminLayerControl.prepareDeviceDraft(base,candidate,"other",5)}
        invalid {AdminLayerControl.prepareDeviceDraft(base,candidate,"batch",-1)}
        invalid {AdminLayerControl.prepareDeviceDraft(base,candidate,"batch",9_007_199_254_740_991L)}
    }
    @Test fun protectedParentPrettyPrintingUsesExactDecimalSemanticsAndRestoresServerRawBytes() {
        val f=Fixture();val base=f.readInventory();val p=AdminLayerControl.newDeviceDraft(base,"semantic",f.now+60_000)
        val normalized=AdminLayerJson.parse(p.wireJson()).toString().replace("1.00","1").replace("3.0E+1","30")
        val candidate=AdminLayerControl.proposal(normalized)
        assertFalse(candidate.wireJson().contains("\\u002f"));assertFalse(candidate.wireJson().contains("\\u0073ystem"))
        val prepared=AdminLayerControl.prepareDeviceDraft(base,candidate,"semantic",0)
        assertEquals(f.template,prepared.document.raw(layers(prepared).first()));assertEquals(f.own,prepared.document.raw(layers(prepared).last()))
        val integerRevisionChanged=AdminLayerControl.proposal(candidate.wireJson().replace("\"revision\":4","\"revision\":999"))
        val unchanged=AdminLayerControl.prepareDeviceDraft(base,integerRevisionChanged,"semantic",1)
        assertEquals(f.own,unchanged.document.raw(layers(unchanged).last()));assertEquals(2L,unchanged.draftRevision)
        val a="1.00000000000000000000000000000001";val b="1.00000000000000000000000000000002"
        assertEquals(a.toDouble(),b.toDouble(),0.0)
        val preciseBase=f.readInventory(f.inventory().replace("1.00",a))
        val precise=AdminLayerControl.newDeviceDraft(preciseBase,"precision",f.now+60_000)
        val different=AdminLayerControl.proposal(precise.wireJson().replace(a,b))
        invalid {AdminLayerControl.prepareDeviceDraft(preciseBase,different,"precision",0)}
        val trueChange=AdminLayerControl.proposal(p.wireJson().replace("3.0E+1","31.0"))
        invalid {AdminLayerControl.prepareDeviceDraft(base,trueChange,"semantic",0)}
    }
    @Test fun preparationRejectsProtectedParentsPermissionsRecipientsAndBaseButAddsEmptyPermissionOwnLayer() {
        val f=Fixture();val base=f.readInventory();val p=AdminLayerControl.newDeviceDraft(base,"scope",f.now+60_000)
        val root=p.document.root.jsonObject;val bundle=root.getValue("bundles").jsonArray.single().jsonObject
        fun rows(values:List<JsonElement>)=AdminLayerControl.proposal(JsonObject(root+mapOf("bundles" to JsonArray(listOf(JsonObject(bundle+mapOf("layers" to JsonArray(values))))))).toString())
        val initial=layers(p)
        invalid {AdminLayerControl.prepareDeviceDraft(base,rows(listOf(initial.first())),"scope",0)}
        val parent=initial.first().jsonObject
        invalid {AdminLayerControl.prepareDeviceDraft(base,rows(listOf(JsonObject(parent+mapOf("revision" to JsonPrimitive(8))),initial.last())),"scope",0)}
        val own=initial.last().jsonObject
        invalid {AdminLayerControl.prepareDeviceDraft(base,rows(listOf(initial.first(),JsonObject(own+mapOf("permissions" to JsonArray(emptyList()))))),"scope",0)}
        val group=AdminLayerJson.parse("""{"id":"new-group","kind":"group","priority":0,"revision":1,"changes":[],"permissions":[]}""")
        invalid {AdminLayerControl.prepareDeviceDraft(base,rows(initial+group),"scope",0)}
        val local=AdminLayerJson.parse("""{"id":"${f.device}","kind":"local","priority":0,"revision":77,"changes":[{"path":"/network/dnsStrategy","operation":"set","value":"prefer_ipv4"}],"permissions":[]}""")
        val newLocal=AdminLayerControl.prepareDeviceDraft(base,rows(initial+local),"scope",0)
        assertEquals(3,layers(newLocal).size);assertEquals(1L,layers(newLocal).last().jsonObject.getValue("revision").jsonPrimitive.long)
        assertEquals(f.template,newLocal.document.raw(layers(newLocal).first()));assertEquals(f.own,newLocal.document.raw(layers(newLocal)[1]))
        val permission=AdminLayerJson.parse("""{"path":"/network/dnsStrategy","mode":"locked"}""")
        val withPermission=JsonObject(local.jsonObject+mapOf("permissions" to JsonArray(listOf(permission))))
        invalid {AdminLayerControl.prepareDeviceDraft(base,rows(initial+withPermission),"scope",0)}
        fun replaced(key:String,value:JsonElement)=AdminLayerControl.proposal(JsonObject(root+mapOf(key to value)).toString())
        for(mode in listOf("home_wifi","wifi","cellular_restricted","cellular")) {
            val changedMode=AdminLayerControl.prepareDeviceDraft(base,replaced("mode",JsonPrimitive(mode)),"scope",0)
            assertEquals(mode,changedMode.mode)
            assertEquals(f.template,changedMode.document.raw(layers(changedMode).first()))
            assertEquals(f.own,changedMode.document.raw(layers(changedMode).last()))
        }
        invalid {AdminLayerControl.prepareDeviceDraft(base,replaced("mode",JsonPrimitive("invalid_mode")),"scope",0)}
        for(candidate in listOf(replaced("approvalUntilMs",JsonPrimitive(base.approvalUntilMs+1)),
            replaced("targetKind",JsonPrimitive("template"))))invalid {AdminLayerControl.prepareDeviceDraft(base,candidate,"scope",0)}
        for((key,value) in listOf("baseRevision" to JsonPrimitive(3),"baseHash" to JsonPrimitive("f".repeat(64)))) {
            val candidate=replaced("bundles",JsonArray(listOf(JsonObject(bundle+mapOf(key to value)))))
            invalid {AdminLayerControl.prepareDeviceDraft(base,candidate,"scope",0)}
        }
        val secondBundle=JsonObject(bundle+mapOf("device" to JsonPrimitive("device-b"),"layers" to JsonArray(listOf(initial.first()))))
        val manyRoot=JsonObject(root+mapOf("targetKind" to JsonPrimitive("template"),"bundles" to JsonArray(listOf(bundle,secondBundle))))
        invalid {AdminLayerControl.prepareDeviceDraft(base,AdminLayerControl.proposal(manyRoot.toString()),"scope",0)}
    }

    @Test fun acceptedGoLayerWireHashesScenariosAndPortableEditorRequestsConformWithoutParentReencoding() {
        fun resource(name:String)=checkNotNull(javaClass.getResourceAsStream("/$name")).use {it.readBytes()}
        fun sha(bytes:ByteArray)=java.security.MessageDigest.getInstance("SHA-256").digest(bytes).joinToString(""){"%02x".format(it)}
        val bytes=resource("admin-layer-wire.json");assertTrue(bytes.size<=262_144)
        val source=AdminLayerJson.parse(resource("admin-layer-wire-source.json").toString(Charsets.UTF_8)).jsonObject
        assertEquals("nd4y/syn443-control-plane",source.getValue("producerRepository").jsonPrimitive.content)
        assertEquals("4407bd8747bf4f7f66d889ec9b444b52b8853fe8",source.getValue("sourceCommit").jsonPrimitive.content)
        assertEquals(43_928_005_749L,source.getValue("run").jsonPrimitive.long)
        assertEquals("a70a87e162484e2dbe77e81659080af25f6eef641330bbab582f1a193522b713",sha(bytes))
        assertEquals(sha(bytes),source.getValue("fixtureSha256").jsonPrimitive.content)
        val fixture=AdminLayerJson.parse(bytes.toString(Charsets.UTF_8)).jsonObject
        assertEquals(setOf("schemaVersion","hashAlgorithm","layers","scenarios"),fixture.keys)
        assertEquals(1,fixture.getValue("schemaVersion").jsonPrimitive.int)
        assertEquals("sha256-lowercase-hex",fixture.getValue("hashAlgorithm").jsonPrimitive.content)
        assertEquals(5,fixture.getValue("layers").jsonArray.size);assertEquals(4,fixture.getValue("scenarios").jsonArray.size)
        val vectors=fixture.getValue("layers").jsonArray.associate {row->val v=row.jsonObject;v.getValue("name").jsonPrimitive.content to v}
        val scenarios=fixture.getValue("scenarios").jsonArray.associate {row->val v=row.jsonObject;v.getValue("name").jsonPrimitive.content to v}
        assertEquals(setOf("template-parent","device-before","device-after","local-before","local-after"),vectors.keys)
        assertEquals(setOf("before-device-edit","after-device-edit","before-local-edit","after-local-edit"),scenarios.keys)
        fun layerWire(name:String)=vectors.getValue(name).getValue("layerWire").jsonPrimitive.content
        fun layerHash(name:String)=vectors.getValue(name).getValue("globalLayerHash").jsonPrimitive.content
        fun names(s:JsonObject,key:String)=s.getValue(key).jsonArray.map {it.jsonPrimitive.content}
        for((_,v) in vectors) {
            assertEquals(setOf("name","layerWire","globalLayerHash","knownFieldPaths"),v.keys)
            val wire=v.getValue("layerWire").jsonPrimitive.content
            assertEquals(v.getValue("globalLayerHash").jsonPrimitive.content,sha(wire.toByteArray(Charsets.UTF_8)))
            assertEquals(wire,AdminLayerJson.document(wire).let {it.raw(it.root)})
            val name=v.getValue("name").jsonPrimitive.content
            val expectedPaths=when {
                name=="template-parent"->setOf("/activation/timeoutSeconds","/graph/final","/network/dnsFinal","/network/dnsStrategy")
                name.startsWith("device-")->setOf("/activation/timeoutSeconds","/network/dnsStrategy")
                else->setOf("/activation/timeoutSeconds")
            }
            assertEquals(expectedPaths,v.getValue("knownFieldPaths").jsonArray.map {it.jsonPrimitive.content}.toSet())
        }
        val parentWire=layerWire("template-parent")
        assertTrue(parentWire.contains("1.00"));assertTrue(parentWire.contains("1e0"));assertTrue(parentWire.contains("30.125"))
        assertTrue(parentWire.contains("\\u0065"));assertTrue(parentWire.contains("\\u003c\\u0026\\u003e"));assertTrue(parentWire.contains("\\u2028\\u2029"))
        val genericallyEncoded=Canonical.encode(AdminLayerJson.parse(parentWire))
        assertNotEquals(layerHash("template-parent"),sha(genericallyEncoded.toByteArray(Charsets.UTF_8)))
        val f=Fixture();val device="fixture-device"
        fun inventory(s:JsonObject):AdminLayerInventory {
            assertEquals(setOf("name","layerNames","unchangedParents","editedLayers","effectiveWire","knownFieldPaths"),s.keys)
            val layerNames=names(s,"layerNames");val rawLayers=layerNames.joinToString(",","[","]"){layerWire(it)}
            val parsed=layerNames.map {AdminLayerJson.parse(layerWire(it)).jsonObject}
            val origins=s.getValue("knownFieldPaths").jsonArray.associate {field->
                val path=field.jsonPrimitive.content
                val writer=parsed.last {l->l.getValue("changes").jsonArray.any {change->
                    val changed=change.jsonObject.getValue("path").jsonPrimitive.content;path==changed || path.startsWith(changed+"/")
                }}
                path to buildJsonObject {put("layerId",writer.getValue("id"));put("kind",writer.getValue("kind"));put("revision",writer.getValue("revision"))}
            }
            val effective=s.getValue("effectiveWire").jsonPrimitive.content
            val raw="""{"device":"$device","owner":"${f.owner}","state":"assigned","revision":2,"hash":"${f.baseHash}","policyRevision":9,"mode":"wifi","approvalUntilMs":${f.now+3_600_000},"layers":$rawLayers,"effective":{"document":$effective,"fields":${JsonObject(origins)},"restrictions":[]},"currentRevision":2}"""
            val base=AdminLayerControl.parseReply(AdminLayerControl.inventory(device,Identity.random()),raw,f.time) as AdminLayerInventory
            assertEquals(effective,base.document.raw(base.document.root.jsonObject.getValue("effective").jsonObject.getValue("document")))
            assertEquals(4,origins.size)
            return base
        }
        fun rawByIdentity(p:AdminLayerProposal)=layers(p).associate {row->
            val l=row.jsonObject;l.getValue("kind").jsonPrimitive.content+"/"+l.getValue("id").jsonPrimitive.content to p.document.raw(row)
        }
        for((_,s) in scenarios) {
            val base=inventory(s);val p=AdminLayerControl.newDeviceDraft(base,"go-conformance",f.now+60_000)
            val sourceLayers=names(s,"layerNames")
            val pretty=AdminLayerControl.proposal(AdminLayerJson.parse(p.wireJson()).toString().replace("1.00","1").replace("1e0","1"))
            val prepared=AdminLayerControl.prepareDeviceDraft(base,pretty,p.draftId,0)
            assertEquals(1L,prepared.draftRevision);assertEquals(sourceLayers.size,layers(prepared).size)
            for((index,name) in sourceLayers.withIndex()) {
                val wire=prepared.document.raw(layers(prepared)[index]);assertEquals(layerWire(name),wire)
                assertEquals(layerHash(name),sha(wire.toByteArray(Charsets.UTF_8)))
            }
            for(request in listOf(AdminLayerControl.saveDraft(0,prepared,Identity.random()),AdminLayerControl.preview(prepared,f.actor,f.origin,Identity.random()))) {
                assertTrue(request.wireJson().contains(parentWire))
                val restored=AdminLayerControl.restoreRequest(request.bodyBytes(),AdminLayerControl.replayContext(request,f.actor,f.origin),prepared.wireJson(),f.actor,f.origin)
                assertArrayEquals(request.bodyBytes(),restored.bodyBytes());assertTrue(restored.wireJson().contains(parentWire))
            }
        }
        for((beforeName,afterName) in listOf("before-device-edit" to "after-device-edit","before-local-edit" to "after-local-edit")) {
            val before=scenarios.getValue(beforeName);val after=scenarios.getValue(afterName);val base=inventory(before)
            val targetName=names(after,"editedLayers").single();val targetDoc=AdminLayerJson.document(layerWire(targetName));val target=targetDoc.root.jsonObject
            val kind=target.getValue("kind").jsonPrimitive.content
            val path=if(kind=="device")"/network/dnsStrategy" else "/activation/timeoutSeconds"
            val desiredValue=target.getValue("changes").jsonArray.single {it.jsonObject.getValue("path").jsonPrimitive.content==path}.jsonObject.getValue("value")
            val edited=AdminLayerControl.editDevice(base,"go-edited",kind,device,path,AdminLayerEdit.SET,targetDoc.raw(desiredValue),f.now+60_000)
            val editedRow=layers(edited).single {it.jsonObject.getValue("kind").jsonPrimitive.content==kind}.jsonObject
            assertEquals(target.getValue("revision"),editedRow.getValue("revision"))
            fun changes(layer:JsonObject)=layer.getValue("changes").jsonArray.associate {it.jsonObject.getValue("path").jsonPrimitive.content to it}
            assertEquals(changes(target),changes(editedRow));assertEquals(target.getValue("permissions"),editedRow.getValue("permissions"))
            val unchanged=rawByIdentity(edited)
            for(name in names(before,"unchangedParents")) {
                val l=AdminLayerJson.parse(layerWire(name)).jsonObject;val identity=l.getValue("kind").jsonPrimitive.content+"/"+l.getValue("id").jsonPrimitive.content
                assertEquals(layerWire(name),unchanged.getValue(identity));assertEquals(layerHash(name),sha(unchanged.getValue(identity).toByteArray(Charsets.UTF_8)))
            }
            val candidate=AdminLayerControl.proposal(edited.wireJson().replace(edited.document.raw(editedRow),layerWire(targetName)))
            val prepared=AdminLayerControl.prepareDeviceDraft(base,candidate,"go-edited",0)
            val own=layers(prepared).single {it.jsonObject.getValue("kind").jsonPrimitive.content==kind}.jsonObject
            assertEquals(target,own)
            val effective=AdminLayerJson.parse(after.getValue("effectiveWire").jsonPrimitive.content).jsonObject
            if(kind=="device")assertEquals(desiredValue,effective.getValue("network").jsonObject.getValue("dnsStrategy"))
            else assertEquals(desiredValue,effective.getValue("activation").jsonObject.getValue("timeoutSeconds"))
        }
    }

    @Test fun ownedFreshAndRestoredJobOperationsPollWithoutResendingOrReplacingPendingIdentity() {
        val f=Fixture();val proposal=f.proposal();val preview=AdminLayerControl.preview(proposal,f.actor,f.origin,Identity.random())
        val ready=AdminLayerControl.parseReply(preview,f.job(preview,"ready",f.previewResult(preview)),f.time) as AdminLayerJob
        val publish=AdminLayerControl.publish(checkNotNull(ready.preview),f.actor,f.origin,Identity.random(),f.time)
        for(operation in listOf(preview,publish)) {
            val before=operation.bodyBytes();val originalId=operation.requestId
            val context=AdminLayerControl.replayContext(operation,f.actor,f.origin)
            val restored=AdminLayerControl.restoreRequest(before,context,proposal.wireJson(),f.actor,f.origin)
            for(owned in listOf(operation,restored)) {
                val poll=AdminLayerControl.poll(owned,Identity.random())
                assertEquals(AdminLayerAction.REQUEST_GET,poll.action);assertNotEquals(originalId,poll.requestId)
                val payload=AdminLayerJson.parse(poll.wireJson()).jsonObject.getValue("payload").jsonObject
                assertEquals(setOf("id"),payload.keys);assertEquals(operation.expected.jobId,payload.getValue("id").jsonPrimitive.content)
                assertSame(owned.expected,poll.expected);assertEquals(owned.expected.replayOnly,poll.expected.replayOnly)
                val response=AdminLayerControl.parseReply(poll,f.job(operation),f.time) as AdminLayerJob
                assertEquals(operation.expected.jobId,response.id);assertNull(response.preview);assertTrue(response.heads.isEmpty())
                val secondPoll=AdminLayerControl.poll(poll,Identity.random())
                assertSame(poll.expected,secondPoll.expected);assertEquals(payload,AdminLayerJson.parse(secondPoll.wireJson()).jsonObject.getValue("payload"))
            }
            assertArrayEquals(before,operation.bodyBytes());assertEquals(originalId,operation.requestId)
            assertArrayEquals(context,AdminLayerControl.replayContext(operation,f.actor,f.origin))
            invalid {AdminLayerControl.restoreRequest(before,context,proposal.wireJson(),Identity.random(),f.origin)}
        }
        for(unsupported in listOf(AdminLayerControl.inventory(f.device,Identity.random()),AdminLayerControl.saveDraft(0,proposal,Identity.random())))
            invalid {AdminLayerControl.poll(unsupported,Identity.random())}
        invalid {AdminLayerControl.poll(preview,"short")}
        val e=preview.expected
        val foreign=AdminLayerExpected(proposal=e.proposal,actor=Identity.random(),origin=e.origin,jobId=e.jobId,jobKind=e.jobKind,initialRequestId=e.initialRequestId)
        invalid {AdminLayerControl.poll(AdminLayerRequest(preview.action,preview.requestId,preview.bodyBytes(),foreign),Identity.random())}
        val wrongKind=AdminLayerExpected(proposal=e.proposal,actor=e.actor,origin=e.origin,jobId=e.jobId,jobKind=AdminLayerAction.PUBLISH,initialRequestId=e.initialRequestId)
        invalid {AdminLayerControl.poll(AdminLayerRequest(preview.action,preview.requestId,preview.bodyBytes(),wrongKind),Identity.random())}
    }

}
