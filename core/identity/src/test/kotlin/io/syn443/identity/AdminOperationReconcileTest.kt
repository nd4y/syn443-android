package io.syn443.identity

import io.syn443.policy.Policy
import kotlinx.serialization.json.*
import org.junit.Assert.*
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/** Pure generated wire/signature fixtures. Live ACL/MFA, SQL commit history,
 * actual Go-byte conformance and pending Android CAS remain separate gates. */
class AdminOperationReconcileTest {
    private class Fixture {
        val now=1_800_000_000_000L
        val time=TimeWindow(now,now+1000)
        val actor=Identity.hash("synthetic-admin".toByteArray())
        val owner=Identity.hash("synthetic-owner".toByteArray())
        val origin="https://reconcile.example.invalid"
        val device="synthetic-device"
        // Portable proposals retain the required template even for a device-only wire case.
        fun proposal(blob:Int=0)=AdminLayerControl.proposal("""{"draftId":"draft-a","draftRevision":1,"targetKind":"device","targetId":"$device","mode":"wifi","approvalUntilMs":${now+3_600_000},"bundles":[{"device":"$device","baseRevision":2,"baseHash":"${"a".repeat(64)}","layers":[{"id":"synthetic-template","kind":"template","priority":0,"revision":1,"changes":[],"permissions":[]},{"id":"$device","kind":"device","priority":0,"revision":1,"changes":[{"path":"/blob","operation":"set","value":"${"x".repeat(blob)}"}],"permissions":[]}]}]}""")
        fun saved():AdminLayerDraft {
            val p=proposal()
            val raw="""{"id":"${p.draftId}","revision":1,"proposal":${p.wireJson()},"savedAtMs":$now}"""
            return AdminLayerControl.parseReply(AdminLayerControl.getDraft(p.draftId,p.targetKind,p.targetId,Identity.random()),raw,time) as AdminLayerDraft
        }
        fun preview(version:Int=1,id:String=Identity.random())=AdminLayerControl.preview(proposal(),actor,origin,id,version)
        fun previewResult(request:AdminLayerRequest):String {
            val p=checkNotNull(request.expected.proposal)
            val v="""{"schemaVersion":1,"origin":"$origin","actor":"$actor","requestId":"${request.expected.initialRequestId}","draftId":"${p.draftId}","draftRevision":1,"draftHash":"${"c".repeat(64)}","targetKind":"device","targetId":"$device","mode":"wifi","dependencyHash":"${"d".repeat(64)}","effectiveHash":"${"e".repeat(64)}","recipients":[{"owner":"$owner","device":"$device","thumbprint":"${Identity.hash("key".toByteArray())}","grantHash":"${Identity.hash("grant".toByteArray())}","baseRevision":2,"baseHash":"${"a".repeat(64)}","capabilitiesHash":"${"b".repeat(64)}"}],"issuedAtMs":$now,"expiresAtMs":${now+120_000}}"""
            val pair=KeyPairGenerator.getInstance("EC").apply {initialize(ECGenParameterSpec("secp256r1"))}.generateKeyPair()
            val input=Identity.encode("""{"alg":"ES256","kid":"synthetic-preview","typ":"syn443-configuration-preview+jws"}""".toByteArray())+"."+Identity.encode(v.toByteArray())
            val signature=Signature.getInstance("SHA256withECDSA").run {initSign(pair.private);update(input.toByteArray(Charsets.US_ASCII));sign()}
            val ticket=input+"."+Identity.encode(Identity.derToRaw(signature))
            return """{"previewId":"${request.expected.jobId}","ticket":"$ticket","preview":$v}"""
        }
        fun ready():AdminLayerPreview {
            val request=preview()
            val wire="""{"id":"${request.expected.jobId}","state":"ready","result":${previewResult(request)}}"""
            return checkNotNull((AdminLayerControl.parseReply(request,wire,time) as AdminLayerJob).preview)
        }
        fun original(action:AdminLayerAction=AdminLayerAction.DRAFT_PUT,version:Int=1,id:String=Identity.random()):AdminLayerRequest=when(action) {
            AdminLayerAction.DRAFT_PUT->AdminLayerControl.saveDraft(0,proposal(),id,version)
            AdminLayerAction.DRAFT_DISCARD->AdminLayerControl.discardDraft(saved(),id,version)
            AdminLayerAction.PREVIEW->preview(version,id)
            AdminLayerAction.PUBLISH->AdminLayerControl.publish(ready(),actor,origin,id,time,version)
            else->error("synthetic_mutation_only")
        }
        fun request(original:AdminLayerRequest=original(),intent:AdminOperationIntent=AdminOperationIntent.LOOKUP)=
            AdminOperationReconcile.request(original,actor,origin,Identity.random(),intent)
        fun job(r:AdminOperationRequest,state:String="queued",error:String?=null,result:String?=null)=
            """{"id":"${r.effectId}","state":"$state"${error?.let {",\"error\":${JsonPrimitive(it)}"}?:""}${result?.let {",\"result\":$it"}?:""}}"""
        fun reply(r:AdminOperationRequest,outcome:AdminOperationOutcome=AdminOperationOutcome.RECORDED,
            queue:String?=if(r.effectKind=="job" && outcome==AdminOperationOutcome.RECORDED)job(r) else null,
            recorded:Long=if(outcome==AdminOperationOutcome.UNKNOWN)0 else now):String {
            val absent=outcome in setOf(AdminOperationOutcome.UNKNOWN,AdminOperationOutcome.NO_EFFECT)
            return """{"version":1,"actor":"$actor","action":"${r.original.action.wire}","requestId":"${r.original.requestId}","bodyHash":"${r.originalBodyHash}","targetKind":"${r.targetKind}","targetId":"${r.targetId}","outcome":"${outcome.name}","recordedAtMs":$recorded,"effectKind":"${if(absent)"" else r.effectKind}","effectId":"${if(absent)"" else r.effectId}","effectRevision":${if(absent)0 else r.effectRevision}${queue?.let {",\"job\":$it"}?:""}}"""
        }
        fun parse(r:AdminOperationRequest,raw:String=reply(r))=AdminOperationReconcile.parseReply(r,raw,time)
    }
    private val mutations=listOf(AdminLayerAction.DRAFT_PUT,AdminLayerAction.DRAFT_DISCARD,AdminLayerAction.PREVIEW,AdminLayerAction.PUBLISH)
    private fun invalid(block:()->Unit) {
        val error=assertThrows(AdminException::class.java,block)
        assertEquals(AdminFailure.INVALID_REPLY,error.reason);assertNull(error.cause);assertEquals("INVALID_REPLY",error.message)
    }
    private fun changed(raw:String,key:String,value:JsonElement)=JsonObject(AdminLayerJson.reconciliationDocument(raw).root.jsonObject+mapOf(key to value)).toString()

    @Test fun explicitMutationVersionTwoKeepsEveryDefaultVersionOneByteAndReadBuilderUnchanged() {
        val f=Fixture();val id=Identity.random();val proposal=f.proposal();val draft=f.saved();val preview=f.ready()
        val defaults=listOf(AdminLayerControl.saveDraft(0,proposal,id),AdminLayerControl.discardDraft(draft,id),AdminLayerControl.preview(proposal,f.actor,f.origin,id),AdminLayerControl.publish(preview,f.actor,f.origin,id,f.time))
        val explicit=listOf(AdminLayerControl.saveDraft(0,proposal,id,1),AdminLayerControl.discardDraft(draft,id,1),AdminLayerControl.preview(proposal,f.actor,f.origin,id,1),AdminLayerControl.publish(preview,f.actor,f.origin,id,f.time,1))
        val v2=listOf(AdminLayerControl.saveDraft(0,proposal,id,2),AdminLayerControl.discardDraft(draft,id,2),AdminLayerControl.preview(proposal,f.actor,f.origin,id,2),AdminLayerControl.publish(preview,f.actor,f.origin,id,f.time,2))
        for(i in defaults.indices) {
            assertArrayEquals(defaults[i].bodyBytes(),explicit[i].bodyBytes())
            assertEquals(defaults[i].wireJson().replace("\"version\":1","\"version\":2"),v2[i].wireJson())
            assertNotEquals(f.request(defaults[i]).originalBodyHash,f.request(v2[i]).originalBodyHash)
        }
        val reads=listOf(AdminLayerControl.inventory(f.device,id),AdminLayerControl.history(f.device,2,"a".repeat(64),id),AdminLayerControl.listDrafts("device",f.device,id),AdminLayerControl.getDraft("draft-a","device",f.device,id))
        assertTrue(reads.all {AdminLayerJson.parse(it.wireJson()).jsonObject.getValue("version")==JsonPrimitive(1)})
        for(version in listOf(0,3,-1))for(action in mutations)invalid {f.original(action,version)}
    }
    @Test fun versionTwoRestoreAndWrapperPreserveExactBodyContextIdAndReplayOnlyOwnership() {
        val f=Fixture()
        for(version in listOf(1,2))for(action in mutations) {
            val original=f.original(action,version);val exact=original.bodyBytes();val context=AdminLayerControl.replayContext(original,f.actor,f.origin)
            val restored=AdminLayerControl.restoreRequest(exact,context,original.expected.proposal?.wireJson(),f.actor,f.origin)
            val request=f.request(restored,AdminOperationIntent.SEAL_IF_ABSENT)
            assertArrayEquals(exact,request.original.bodyBytes());assertTrue(request.original.expected.replayOnly)
            assertArrayEquals(context,AdminLayerControl.replayContext(request.original,f.actor,f.origin))
            assertEquals(original.requestId,request.original.requestId);assertEquals(version,request.protocolVersion)
            val body=AdminLayerJson.parse(request.wireJson()).jsonObject
            assertEquals(setOf("version","requestId","intent","originalBody64"),body.keys)
            assertEquals("seal_if_absent",body.getValue("intent").jsonPrimitive.content)
            assertArrayEquals(exact,Policy.decode64(body.getValue("originalBody64").jsonPrimitive.content))
            assertArrayEquals(exact,original.bodyBytes())
        }
    }
    @Test fun reconciliationOnlyAcceptsClosedGoStyleOrderingWithoutRelaxingDurableRestoreOrRawHashes() {
        val f=Fixture()
        // Synthetic Go-shaped ordering from invitation.Envelope/ConfigurationDraft;
        // this is not the later accepted Go producer artifact/conformance proof.
        for(version in listOf(1,2))for(action in mutations) {
            val canonical=f.original(action,version);val doc=AdminLayerJson.document(canonical.wireJson());val root=doc.root.jsonObject
            var payload=doc.raw(root.getValue("payload"))
            if(action==AdminLayerAction.DRAFT_PUT) {
                val draft=root.getValue("payload").jsonObject.getValue("draft").jsonObject
                payload="{\"draft\":"+listOf("id","revision","proposal","savedAtMs").joinToString(",","{","}"){JsonPrimitive(it).toString()+":"+doc.raw(draft.getValue(it))}+"}"
            }
            val goStyle=" {\"version\":$version,\"action\":\"${action.wire}\",\"requestId\":\"${canonical.requestId}\",\"payload\":$payload} "
            val body=goStyle.toByteArray(Charsets.UTF_8);val original=AdminLayerRequest(action,canonical.requestId,body,canonical.expected)
            invalid {AdminLayerControl.restoreRequest(body,AdminLayerControl.replayContext(original,f.actor,f.origin),original.expected.proposal?.wireJson(),f.actor,f.origin)}
            val request=f.request(original)
            assertArrayEquals(body,request.original.bodyBytes());assertTrue(request.original.expected.replayOnly)
            assertNotEquals(f.request(canonical).originalBodyHash,request.originalBodyHash)
            assertEquals(request.originalBodyHash,f.parse(request).bodyHash)
            assertArrayEquals(body,Policy.decode64(AdminLayerJson.parse(request.wireJson()).jsonObject.getValue("originalBody64").jsonPrimitive.content))
            assertArrayEquals(body,original.bodyBytes())
            invalid {f.request(AdminLayerRequest(action,canonical.requestId,body,AdminLayerExpected(id="foreign",revision=1,kind="device",target=f.device)))}
            val extra=goStyle.trim().dropLast(1)+",\"ignored\":true}"
            invalid {f.request(AdminLayerRequest(action,canonical.requestId,extra.toByteArray(),canonical.expected))}
        }
        val put=f.original();val wrong=AdminLayerExpected(id="draft-a",revision=1,kind="device",target=f.device,proposal=f.proposal(1))
        invalid {f.request(AdminLayerRequest(put.action,put.requestId,put.bodyBytes(),wrong))}
    }
    @Test fun versionTwoNeverPromotesReadActionsPollsOrChangedPersistedVersionOneBodies() {
        val f=Fixture();val reads=listOf(AdminLayerControl.inventory(f.device,Identity.random()),AdminLayerControl.getDraft("draft-a","device",f.device,Identity.random()),AdminLayerControl.poll(f.preview(),Identity.random()))
        for(read in reads) {
            invalid {f.request(read)}
            val body=read.wireJson().replace("\"version\":1","\"version\":2").toByteArray()
            val forged=AdminLayerRequest(read.action,read.requestId,body,read.expected)
            invalid {AdminLayerControl.restoreRequest(body,AdminLayerControl.replayContext(forged,f.actor,f.origin),read.expected.proposal?.wireJson(),f.actor,f.origin)}
        }
        val original=f.original();val context=AdminLayerControl.replayContext(original,f.actor,f.origin)
        invalid {AdminLayerControl.restoreRequest(original.wireJson().replace("\"version\":1","\"version\":2").toByteArray(),context,original.expected.proposal?.wireJson(),f.actor,f.origin)}
    }
    @Test fun requestCopiesBothBodiesKeepsOnlyFixedRouteAndRejectsForeignExistingScopeOrNoncanonicalActor() {
        val f=Fixture();val original=f.preview();val request=f.request(original);val originalBytes=original.bodyBytes();val bytes=request.bodyBytes()
        assertFalse(original.expected.replayOnly);assertTrue(request.original.expected.replayOnly)
        request.bodyBytes().fill(0);request.original.bodyBytes().fill(0)
        assertArrayEquals(bytes,request.bodyBytes());assertArrayEquals(originalBytes,request.original.bodyBytes())
        assertFalse(original.expected.replayOnly)
        assertEquals(f.origin+"/v1/control/configuration/reconcile",request.uri);assertEquals(1_048_576,request.maxReplyBytes)
        assertEquals("AdminOperationRequest([redacted])",request.toString())
        for(origin in listOf(f.origin+"/path",f.origin+"?x=1",f.origin+"#x","http://reconcile.example.invalid","https://user@reconcile.example.invalid","https://reconcile.example.invalid:443","https://foreign.example.invalid"))
            invalid {AdminOperationReconcile.request(original,f.actor,origin,Identity.random(),AdminOperationIntent.LOOKUP)}
        invalid {AdminOperationReconcile.request(original,Identity.random(),f.origin,Identity.random(),AdminOperationIntent.LOOKUP)}
        invalid {AdminOperationReconcile.request(original,f.actor,f.origin,"short",AdminOperationIntent.LOOKUP)}
        val alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";val index=alphabet.indexOf(f.actor.last())
        val noncanonical=f.actor.dropLast(1)+alphabet[index+1]
        assertArrayEquals(java.util.Base64.getUrlDecoder().decode(f.actor),java.util.Base64.getUrlDecoder().decode(noncanonical))
        invalid {AdminOperationReconcile.request(f.original(),noncanonical,f.origin,Identity.random(),AdminOperationIntent.LOOKUP)}
        val forged=AdminLayerRequest(original.action,original.requestId,originalBytes,AdminLayerExpected(proposal=original.expected.proposal,actor=f.actor,origin=f.origin,jobId=Identity.random(),jobKind=AdminLayerAction.PREVIEW,initialRequestId=original.requestId))
        invalid {f.request(forged)}
    }
    @Test fun draftSaveAndDiscardRecordedReceiptsBindExactEffectReferencesWithoutReturningProposal() {
        val f=Fixture()
        for(action in listOf(AdminLayerAction.DRAFT_PUT,AdminLayerAction.DRAFT_DISCARD)) {
            val request=f.request(f.original(action));val receipt=f.parse(request)
            assertEquals(AdminOperationOutcome.RECORDED,receipt.outcome);assertEquals("draft",receipt.effectKind)
            assertEquals("draft-a",receipt.effectId);assertEquals(1L,receipt.effectRevision);assertNull(receipt.job)
            assertEquals(request.original.requestId,receipt.requestId);assertEquals(request.originalBodyHash,receipt.bodyHash)
            assertFalse(receipt.wireJson().contains("bundles"));assertEquals("AdminOperationReceipt([redacted])",receipt.toString())
        }
    }
    @Test fun jobReceiptsPreserveOpaqueCurrentAndLegacyStatesAndActualFiniteWorkerErrors() {
        val f=Fixture()
        for(action in listOf(AdminLayerAction.PREVIEW,AdminLayerAction.PUBLISH)) {
            val request=f.request(f.original(action));assertEquals(Identity.hash((f.actor+"\u0000"+request.original.requestId).toByteArray()),request.effectId)
            for(state in AdminOperationJobState.entries) {
                val error=if(state==AdminOperationJobState.EXPIRED)"deadline_or_retry_limit" else if(state==AdminOperationJobState.REJECTED)"configuration_denied" else ""
                val receipt=f.parse(request,f.reply(request,queue=f.job(request,state.wire,error,result="{\"historical\":1.00}")))
                assertEquals(state,receipt.job?.state);assertEquals(error,receipt.job?.error)
                assertEquals("{\"historical\":1.00}",receipt.job?.rawResultJson());assertEquals("AdminOperationJob([redacted])",receipt.job.toString())
                assertEquals(0L,receipt.effectRevision)
            }
            invalid {f.parse(request,f.reply(request,queue=f.job(request,"connected")))}
            invalid {f.parse(request,f.reply(request,queue=f.job(request,"expired","raw-private-error")))}
            invalid {f.parse(request,f.reply(request,queue=f.job(request,"queued","configuration_conflict")))}
        }
    }
    @Test fun versionOneAbsenceRemainsUnknownAndOnlyVersionTwoMayReportAtomicNoEffect() {
        val f=Fixture()
        for(intent in AdminOperationIntent.entries)for(version in listOf(1,2)) {
            val request=f.request(f.original(version=version),intent)
            val unknown=f.parse(request,f.reply(request,AdminOperationOutcome.UNKNOWN))
            assertEquals(0L,unknown.recordedAtMs);assertEquals("",unknown.effectId);assertNull(unknown.job)
            if(version==1)invalid {f.parse(request,f.reply(request,AdminOperationOutcome.NO_EFFECT))}
            else assertEquals(AdminOperationOutcome.NO_EFFECT,f.parse(request,f.reply(request,AdminOperationOutcome.NO_EFFECT)).outcome)
        }
    }
    @Test fun prunedResultsKeepRecordedReferencesAndCannotSupplyAJobOrNoEffectShortcut() {
        val f=Fixture()
        for(action in mutations) {
            val request=f.request(f.original(action));val raw=f.reply(request,AdminOperationOutcome.RECORDED_RESULT_UNAVAILABLE,recorded=1)
            val receipt=f.parse(request,raw);assertEquals(AdminOperationOutcome.RECORDED_RESULT_UNAVAILABLE,receipt.outcome)
            assertEquals(request.effectId,receipt.effectId);assertEquals(request.effectRevision,receipt.effectRevision);assertEquals(1L,receipt.recordedAtMs);assertNull(receipt.job)
            invalid {f.parse(request,changed(raw,"job",buildJsonObject {put("id",request.effectId);put("state","queued")}))}
        }
    }
    @Test fun closedReplyRejectsForeignActorActionRequestBodyHashTargetAndEffectSubstitution() {
        val f=Fixture();val request=f.request();val raw=f.reply(request)
        val replacements=mapOf("actor" to JsonPrimitive(Identity.random()),"action" to JsonPrimitive(AdminLayerAction.DRAFT_DISCARD.wire),
            "requestId" to JsonPrimitive(Identity.random()),"bodyHash" to JsonPrimitive("f".repeat(64)),"targetKind" to JsonPrimitive("group"),
            "targetId" to JsonPrimitive("foreign-device"),"effectKind" to JsonPrimitive("job"),"effectId" to JsonPrimitive("foreign-draft"),
            "effectRevision" to JsonPrimitive(2),"version" to JsonPrimitive(2),"unknown" to JsonPrimitive(1))
        for((field,value) in replacements)invalid {f.parse(request,changed(raw,field,value))}
        invalid {f.parse(request,changed(raw,"bodyHash",JsonPrimitive(request.originalBodyHash.uppercase())))}
        invalid {f.parse(f.request(f.original()),raw)}
        invalid {f.parse(request,JsonObject(AdminLayerJson.parse(raw).jsonObject.filterKeys {it!="effectRevision"}).toString())}
    }
    @Test fun outcomeAndJobShapesCannotInventReferencesOrHideMissingRecordedJobs() {
        val f=Fixture();val draft=f.request();val job=f.request(f.preview())
        for(outcome in listOf(AdminOperationOutcome.UNKNOWN,AdminOperationOutcome.NO_EFFECT)) {
            val request=f.request(f.original(version=2));val raw=f.reply(request,outcome)
            for((key,value) in mapOf("effectKind" to JsonPrimitive("draft"),"effectId" to JsonPrimitive("draft-a"),"effectRevision" to JsonPrimitive(1),"job" to JsonNull))invalid {f.parse(request,changed(raw,key,value))}
        }
        invalid {f.parse(draft,changed(f.reply(draft),"job",AdminLayerJson.parse(f.job(job))))}
        invalid {f.parse(job,f.reply(job,queue=null))}
        invalid {f.parse(job,f.reply(job,queue=f.job(job).replace(job.effectId,Identity.random())))}
        invalid {f.parse(job,f.reply(job,queue=f.job(job).dropLast(1)+",\"scope\":\"admin\"}"))}
    }
    @Test fun receiptIntegersAndObservationBoundsAreExactWithoutRenewingHistoricalSessionTime() {
        val f=Fixture();val request=f.request();val raw=f.reply(request)
        assertEquals(1L,f.parse(request,f.reply(request,recorded=1)).recordedAtMs)
        assertEquals(f.time.upperMs+30_000,f.parse(request,f.reply(request,recorded=f.time.upperMs+30_000)).recordedAtMs)
        val safe=9_007_199_254_740_991L
        assertEquals(safe,AdminOperationReconcile.parseReply(request,f.reply(request,recorded=safe),TimeWindow(safe,safe)).recordedAtMs)
        invalid {f.parse(request,f.reply(request,recorded=f.time.upperMs+30_001))}
        invalid {f.parse(request,f.reply(request,recorded=0))}
        for(value in listOf("1.0","1e0","-1","9007199254740992","\"1\"","true","null"))
            invalid {f.parse(request,raw.replace("\"effectRevision\":1","\"effectRevision\":"+value))}
        invalid {AdminOperationReconcile.parseReply(request,raw,TimeWindow(f.now+1,f.now))}
        invalid {AdminOperationReconcile.parseReply(request,raw,TimeWindow(-1,f.now))}
        invalid {AdminOperationReconcile.parseReply(request,raw,TimeWindow(f.now,safe+1))}
    }
    @Test fun duplicateCaseUnknownNullMalformedUnicodeAndUnsafeResultNumbersFailClosed() {
        val f=Fixture();val request=f.request(f.preview());val raw=f.reply(request)
        for(bad in listOf(raw.dropLast(1)+",\"version\":1}",raw.replace("\"version\":1","\"Version\":1"),raw.replace("\"actor\":\"${f.actor}\"","\"actor\":null"),raw+"{}",raw.replace("\"targetId\":\"${f.device}\"","\"targetId\":\"\\ud800\"")))invalid {f.parse(request,bad)}
        for(result in listOf("{\"x\":1,\"x\":2}","NaN","1e309","9007199254740992","01","[1,]","\"\\udc00\""))invalid {f.parse(request,f.reply(request,queue=f.job(request,result=result)))}
        val legitimate=f.parse(request,f.reply(request,queue=f.job(request,result="{\"line\":\"\\u2028\\ud83d\\ude00\",\"n\":-4.50e+1}")))
        assertTrue(checkNotNull(legitimate.job?.rawResultJson()).contains("-4.50e+1"))
        assertEquals("null",f.parse(request,f.reply(request,queue=f.job(request,result="null"))).job?.rawResultJson())
    }
    @Test fun htmlEscapedResultExpansionHasScopedFrameRawAndMinimalRepresentationBounds() {
        val f=Fixture();val request=f.request(f.preview())
        val exact="\""+"\\u003c".repeat(99_998)+"\""
        val raw=f.reply(request,queue=f.job(request,"ready",result=exact))
        assertTrue(raw.toByteArray().size>524_288)
        val receipt=f.parse(request,raw);assertEquals(exact,receipt.job?.rawResultJson())
        assertThrows(IllegalArgumentException::class.java){AdminLayerJson.document(raw)}
        invalid {f.parse(request,f.reply(request,queue=f.job(request,result="\""+"\\u003c".repeat(99_999)+"\"")))}
        invalid {f.parse(request,f.reply(request,queue=f.job(request,result="\""+"\\u003c".repeat(100_000)+"\"")))}
        val escapedLiteral=JsonPrimitive("\\u003c".repeat(20_000)).toString()
        invalid {f.parse(request,f.reply(request,queue=f.job(request,result=escapedLiteral)))}
        val unicode="\""+"\\u2028".repeat(33_332)+"\""
        assertEquals(unicode,f.parse(request,f.reply(request,queue=f.job(request,result=unicode))).job?.rawResultJson())
    }
    @Test fun reconciliationFrameOneMiBAndExistingLayerHalfMiBCapsRemainIndependent() {
        val f=Fixture();val request=f.request();val raw=f.reply(request)
        val exact=raw+" ".repeat(1_048_576-raw.toByteArray().size)
        assertEquals(1_048_576,exact.toByteArray().size);assertEquals(exact,f.parse(request,exact).wireJson())
        invalid {f.parse(request,exact+" ")}
        val ordinary="{}"+" ".repeat(524_286)
        assertNotNull(AdminLayerJson.document(ordinary));assertThrows(IllegalArgumentException::class.java){AdminLayerJson.document(ordinary+" ")}
        assertNotNull(AdminLayerJson.reconciliationDocument(ordinary+" "))
    }
    @Test fun exactOriginal262KiBBoundProducesBoundedCanonicalOuterBodyWithoutChangingVersion() {
        val f=Fixture();val id=Identity.random()
        fun original(padding:Int)=AdminLayerControl.saveDraft(0,f.proposal(padding),id,2)
        val amount=262_144-original(0).bodyBytes().size
        val exact=original(amount);assertEquals(262_144,exact.bodyBytes().size)
        val request=f.request(exact);assertTrue(request.bodyBytes().size<350_000);assertTrue(request.bodyBytes().size<=524_288)
        val outer=AdminLayerJson.parse(request.wireJson()).jsonObject
        assertEquals(349526,outer.getValue("originalBody64").jsonPrimitive.content.length)
        assertArrayEquals(exact.bodyBytes(),Policy.decode64(outer.getValue("originalBody64").jsonPrimitive.content))
        invalid {original(amount+1)}
        val over=AdminLayerRequest(exact.action,exact.requestId,ByteArray(262_145){32},exact.expected)
        invalid {f.request(over)}
    }
    @Test fun resultTreesKeepObjectArrayAndDepthBoundsBeforeReturningOpaqueRawValues() {
        val f=Fixture();val request=f.request(f.preview())
        val object512=(0 until 512).joinToString(",","{","}"){"\"k$it\":0"}
        assertEquals(object512,f.parse(request,f.reply(request,queue=f.job(request,result=object512))).job?.rawResultJson())
        invalid {f.parse(request,f.reply(request,queue=f.job(request,result=object512.dropLast(1)+",\"extra\":1}")))}
        val array512=List(512){"0"}.joinToString(",","[","]")
        assertEquals(array512,f.parse(request,f.reply(request,queue=f.job(request,result=array512))).job?.rawResultJson())
        invalid {f.parse(request,f.reply(request,queue=f.job(request,result=List(513){"0"}.joinToString(",","[","]"))))}
        val depth24="[".repeat(22)+"0"+"]".repeat(22)
        assertEquals(depth24,f.parse(request,f.reply(request,queue=f.job(request,result=depth24))).job?.rawResultJson())
        invalid {f.parse(request,f.reply(request,queue=f.job(request,result="["+depth24+"]")))}
    }
    @Test fun retainedSignedPreviewResultNeverMintsAFreshPreviewOrPublicationAfterReconciliation() {
        val f=Fixture();val original=f.preview();val request=f.request(original)
        val result=f.previewResult(original);val receipt=f.parse(request,f.reply(request,queue=f.job(request,"ready",result=result)))
        assertEquals(result,receipt.job?.rawResultJson());assertTrue(request.original.expected.replayOnly)
        val ordinaryJob="""{"id":"${request.effectId}","state":"ready","result":$result}"""
        val preview=checkNotNull((AdminLayerControl.parseReply(request.original,ordinaryJob,f.time) as AdminLayerJob).preview)
        assertTrue(preview.replayOnly)
        invalid {AdminLayerControl.publish(preview,f.actor,f.origin,Identity.random(),f.time,2)}
        val again=f.request(request.original)
        assertArrayEquals(original.bodyBytes(),again.original.bodyBytes());assertEquals(request.originalBodyHash,again.originalBodyHash)
    }
}
