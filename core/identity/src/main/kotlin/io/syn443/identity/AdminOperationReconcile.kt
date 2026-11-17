package io.syn443.identity

import io.syn443.policy.Policy
import kotlinx.serialization.json.*
import java.security.MessageDigest

enum class AdminOperationIntent(val wire:String) { LOOKUP("lookup"), SEAL_IF_ABSENT("seal_if_absent") }
enum class AdminOperationOutcome { UNKNOWN, NO_EFFECT, RECORDED, RECORDED_RESULT_UNAVAILABLE }
enum class AdminOperationJobState(val wire:String) {
    QUEUED("queued"), RUNNING("running"), READY("ready"), PUBLISHED("published"),
    LEGACY_APPLIED("applied"), REJECTED("rejected"), EXPIRED("expired"), CANCELLED("cancelled")
}

/** Value-only lookup of an owned operation. The original is conservatively
 * restored replay-only; its exact bytes/version/ID are never rewritten. */
class AdminOperationRequest internal constructor(val original:AdminLayerRequest,val actor:String,val origin:String,
    val requestId:String,val intent:AdminOperationIntent,body:ByteArray,internal val protocolVersion:Int,
    internal val targetKind:String,internal val targetId:String,internal val effectKind:String,
    internal val effectId:String,internal val effectRevision:Long,val originalBodyHash:String) {
    private val body=body.copyOf()
    val uri:String get()=origin+AdminOperationReconcile.PATH
    val maxReplyBytes:Int get()=1_048_576
    val originalVersion:Int get()=protocolVersion
    fun bodyBytes()=body.copyOf()
    fun wireJson()=body.toString(Charsets.UTF_8)
    override fun toString()="AdminOperationRequest([redacted])"
}

/** Historical queue metadata only. Even LEGACY_APPLIED/READY/PUBLISHED and a
 * retained ticket/result are not device activation, preview or a new grant. */
class AdminOperationJob internal constructor(val id:String,val state:AdminOperationJobState,val error:String,
    private val result:String?,private val wire:String) {
    fun rawResultJson():String?=result
    fun wireJson():String=wire
    override fun toString()="AdminOperationJob([redacted])"
}

/** Body-bound receipt, never an ACL, MFA, session lease or publication grant.
 * The caller still needs a current authorized operation and exact pending CAS. */
class AdminOperationReceipt internal constructor(val actor:String,val action:AdminLayerAction,val requestId:String,
    val bodyHash:String,val targetKind:String,val targetId:String,val outcome:AdminOperationOutcome,
    val recordedAtMs:Long,val effectKind:String,val effectId:String,val effectRevision:Long,
    val job:AdminOperationJob?,private val wire:String) {
    fun wireJson()=wire
    override fun toString()="AdminOperationReceipt([redacted])"
}

object AdminOperationReconcile {
    const val PATH="/v1/control/configuration/reconcile"
    const val MAX_REQUEST_BYTES=524_288
    const val MAX_REPLY_BYTES=1_048_576
    private const val MAX=9_007_199_254_740_991L
    private val requestId=Regex("[A-Za-z0-9_-]{24,128}")
    private val objectId=Regex("[A-Za-z0-9_-]{1,64}")
    private val hash=Regex("[a-f0-9]{64}")
    private val htmlEscapes=setOf(0x003c,0x003e,0x0026,0x2028,0x2029)
    private val mutations=setOf(AdminLayerAction.DRAFT_PUT,AdminLayerAction.DRAFT_DISCARD,AdminLayerAction.PREVIEW,AdminLayerAction.PUBLISH)
    private val fields=setOf("version","actor","action","requestId","bodyHash","targetKind","targetId","outcome",
        "recordedAtMs","effectKind","effectId","effectRevision")
    private inline fun <T> checked(block:()->T):T=try {block()}catch(error:AdminException){throw error}
        catch(_:Exception){throw AdminException(AdminFailure.INVALID_REPLY)}
    private fun text(value:JsonElement)=value.jsonPrimitive.let {require(it.isString);it.content}
    private fun number(value:JsonElement,min:Long=0,max:Long=MAX)=value.jsonPrimitive.let {
        require(!it.isString && Regex("(0|[1-9][0-9]*)").matches(it.content))
        it.long.also {value->require(value in min..max)}
    }
    private fun shape(value:JsonObject,required:Set<String>,optional:Set<String> = emptySet(),nullable:Set<String> = emptySet()) {
        require(value.keys.containsAll(required) && value.keys.all {it in required || it in optional})
        require(value.all {(key,v)->v!=JsonNull || key in nullable})
    }
    private fun digest(value:String):String {
        require(value.length==43 && value.matches(Regex("[A-Za-z0-9_-]{43}")))
        val decoded=Policy.decode64(value)
        try {require(decoded.size==32 && Identity.encode(decoded)==value)}finally {decoded.fill(0)}
        return value
    }
    private fun sha(raw:ByteArray)=MessageDigest.getInstance("SHA-256").digest(raw).joinToString(""){"%02x".format(it)}
    private fun encoded(vararg values:Pair<String,String>)=values.sortedBy {it.first}.joinToString(",","{","}") {
        JsonPrimitive(it.first).toString()+":"+it.second
    }
    private fun lexicalSame(a:JsonElement,b:JsonElement):Boolean=when {
        a is JsonObject && b is JsonObject->a.keys==b.keys && a.all {(key,value)->lexicalSame(value,b.getValue(key))}
        a is JsonArray && b is JsonArray->a.size==b.size && a.indices.all {lexicalSame(a[it],b[it])}
        a is JsonPrimitive && b is JsonPrimitive->a.isString==b.isString && a.content==b.content
        else->false
    }
    /** A non-dispatched canonical witness reuses the closed durable validator.
     * Envelope/container order and equivalent string escaping may differ.
     * Proposal raw spans and ticket values stay exact; numeric comparison is
     * lexical, never Double.
     * The returned operation owns the ORIGINAL bytes and replay-only context. */
    private fun ownOriginal(original:AdminLayerRequest,exact:ByteArray,actor:String,origin:String):Pair<AdminLayerRequest,Int> {
        val doc=AdminLayerJson.document(Policy.utf8(exact));val envelope=doc.root.jsonObject
        shape(envelope,setOf("version","requestId","action","payload"))
        val version=number(envelope.getValue("version"),1,2).toInt()
        require(text(envelope.getValue("action"))==original.action.wire && text(envelope.getValue("requestId"))==original.requestId && requestId.matches(original.requestId))
        val payload=envelope.getValue("payload").jsonObject
        val canonicalPayload=when(original.action) {
            AdminLayerAction.DRAFT_PUT->{
                shape(payload,setOf("draft"));val draft=payload.getValue("draft").jsonObject
                shape(draft,setOf("id","revision","proposal","savedAtMs"))
                require(objectId.matches(text(draft.getValue("id"))) && number(draft.getValue("revision"))<MAX && number(draft.getValue("savedAtMs"))==0L)
                encoded("draft" to encoded("id" to JsonPrimitive(text(draft.getValue("id"))).toString(),
                    "revision" to number(draft.getValue("revision")).toString(),"proposal" to doc.raw(draft.getValue("proposal")),"savedAtMs" to "0"))
            }
            AdminLayerAction.DRAFT_DISCARD->{
                shape(payload,setOf("id","revision","targetKind","targetId"))
                require(objectId.matches(text(payload.getValue("id"))) && number(payload.getValue("revision"),1)>0)
                encoded("id" to JsonPrimitive(text(payload.getValue("id"))).toString(),"revision" to number(payload.getValue("revision"),1).toString(),
                    "targetKind" to JsonPrimitive(text(payload.getValue("targetKind"))).toString(),"targetId" to JsonPrimitive(text(payload.getValue("targetId"))).toString())
            }
            AdminLayerAction.PREVIEW->{shape(payload,setOf("proposal"));encoded("proposal" to doc.raw(payload.getValue("proposal")))}
            AdminLayerAction.PUBLISH->{shape(payload,setOf("previewId","ticket"));encoded("previewId" to JsonPrimitive(text(payload.getValue("previewId"))).toString(),"ticket" to JsonPrimitive(text(payload.getValue("ticket"))).toString())}
            else->error("reconciliation_mutation_only")
        }
        val witnessBody=encoded("version" to version.toString(),"requestId" to JsonPrimitive(original.requestId).toString(),
            "action" to JsonPrimitive(original.action.wire).toString(),"payload" to canonicalPayload).toByteArray(Charsets.UTF_8)
        try {
            require(witnessBody.size<=262_144 && lexicalSame(envelope,AdminLayerJson.parse(Policy.utf8(witnessBody))))
            val witness=AdminLayerRequest(original.action,original.requestId,witnessBody,original.expected)
            val context=AdminLayerControl.replayContext(witness,actor,origin)
            val validated=try {AdminLayerControl.restoreRequest(witnessBody,context,original.expected.proposal?.wireJson(),actor,origin)}
                finally {context.fill(0)}
            return AdminLayerRequest(original.action,original.requestId,exact,validated.expected) to version
        }finally {witnessBody.fill(0)}
    }

    fun request(original:AdminLayerRequest,actor:String,origin:String,outerRequestId:String,intent:AdminOperationIntent):AdminOperationRequest=checked {
        digest(actor);Identity.controlOrigin(origin);require(requestId.matches(outerRequestId) && original.action in mutations)
        val expected=original.expected
        require(expected.actor.isEmpty()==expected.origin.isEmpty())
        require(expected.actor.isEmpty() || expected.actor==actor && expected.origin==origin)
        val exact=original.bodyBytes()
        try {
            require(exact.size in 1..262_144)
            val (owned,version)=ownOriginal(original,exact,actor,origin)
            val e=owned.expected
            val kind=e.proposal?.targetKind?:e.kind;val target=e.proposal?.targetId?:e.target
            require(kind in setOf("template","group","user","device") && objectId.matches(target))
            val family=if(original.action in setOf(AdminLayerAction.DRAFT_PUT,AdminLayerAction.DRAFT_DISCARD))"draft" else "job"
            val effectId=if(family=="draft")e.id else digest(e.jobId)
            val revision=if(family=="draft")e.revision else 0L
            require(if(family=="draft")objectId.matches(effectId) && revision in 1..MAX else
                effectId==Identity.hash((actor+"\u0000"+original.requestId).toByteArray(Charsets.UTF_8)))
            val body=encoded("version" to "1","requestId" to JsonPrimitive(outerRequestId).toString(),
                "intent" to JsonPrimitive(intent.wire).toString(),"originalBody64" to JsonPrimitive(Identity.encode(exact)).toString()).toByteArray(Charsets.UTF_8)
            try {
                require(body.size in 1..MAX_REQUEST_BYTES)
                AdminOperationRequest(owned,actor,origin,outerRequestId,intent,body,version,kind,target,family,effectId,revision,sha(exact))
            }finally {body.fill(0)}
        }finally {exact.fill(0)}
    }

    fun parseReply(request:AdminOperationRequest,raw:String,time:TimeWindow):AdminOperationReceipt=checked {
        require(time.lowerMs in 0..MAX && time.upperMs in time.lowerMs..MAX)
        val doc=AdminLayerJson.reconciliationDocument(raw);val root=doc.root.jsonObject
        shape(root,fields,setOf("job"))
        require(number(root.getValue("version"),1,1)==1L)
        require(text(root.getValue("actor"))==request.actor && text(root.getValue("action"))==request.original.action.wire &&
            text(root.getValue("requestId"))==request.original.requestId)
        val bodyHash=text(root.getValue("bodyHash"));require(hash.matches(bodyHash) && bodyHash==request.originalBodyHash)
        require(text(root.getValue("targetKind"))==request.targetKind && text(root.getValue("targetId"))==request.targetId)
        val outcome=AdminOperationOutcome.valueOf(text(root.getValue("outcome")))
        val recorded=number(root.getValue("recordedAtMs"));val family=text(root.getValue("effectKind"))
        val effectId=text(root.getValue("effectId"));val revision=number(root.getValue("effectRevision"))
        val job=root["job"]
        when(outcome) {
            AdminOperationOutcome.UNKNOWN->require(recorded==0L && family.isEmpty() && effectId.isEmpty() && revision==0L && job==null)
            AdminOperationOutcome.NO_EFFECT->require(request.protocolVersion==2 && recorded>0 && family.isEmpty() && effectId.isEmpty() && revision==0L && job==null)
            AdminOperationOutcome.RECORDED,AdminOperationOutcome.RECORDED_RESULT_UNAVAILABLE->{
                require(recorded>0 && family==request.effectKind && effectId==request.effectId && revision==request.effectRevision)
                require(if(family=="draft")job==null else outcome==AdminOperationOutcome.RECORDED && job!=null || outcome==AdminOperationOutcome.RECORDED_RESULT_UNAVAILABLE && job==null)
            }
        }
        if(recorded>0)require(recorded<=Math.addExact(time.upperMs,30_000))
        val queue=job?.let {decodeJob(it.jsonObject,doc,request)}
        AdminOperationReceipt(request.actor,request.original.action,request.original.requestId,bodyHash,request.targetKind,request.targetId,
            outcome,recorded,family,effectId,revision,queue,raw)
    }

    /** A separately checked historical job is useful for a local pending CAS,
     * never for recreating a fresh confirmation or an activation receipt. */
    fun historicalJob(request:AdminOperationRequest,receipt:AdminOperationReceipt,time:TimeWindow):AdminLayerJob?=checked {
        val owned=parseReply(request,receipt.wireJson(),time)
        require(owned.outcome==AdminOperationOutcome.RECORDED)
        val job=owned.job ?:return@checked null
        if(job.state==AdminOperationJobState.LEGACY_APPLIED)return@checked null
        AdminLayerControl.historicalJob(request.original,job.wireJson(),time)
    }

    private fun decodeJob(root:JsonObject,doc:AdminLayerJson.Document,request:AdminOperationRequest):AdminOperationJob {
        shape(root,setOf("id","state"),setOf("error","result"),setOf("result"))
        val id=text(root.getValue("id"));require(id==request.effectId && digest(id)==Identity.hash((request.actor+"\u0000"+request.original.requestId).toByteArray(Charsets.UTF_8)))
        val state=AdminOperationJobState.entries.single {it.wire==text(root.getValue("state"))}
        val error=root["error"]?.let(::text)?:""
        require(error in setOf("","configuration_denied","configuration_conflict","deadline_or_retry_limit"))
        require(state !in setOf(AdminOperationJobState.QUEUED,AdminOperationJobState.RUNNING,AdminOperationJobState.READY,AdminOperationJobState.PUBLISHED,AdminOperationJobState.LEGACY_APPLIED) || error.isEmpty())
        val rawResult=root["result"]?.let {doc.raw(it).also {value->
            require(value.toByteArray(Charsets.UTF_8).size<=600_000 && compactResultBytes(value)<=100_000)
        }}
        return AdminOperationJob(id,state,error,rawResult,doc.raw(root))
    }

    /** Resource bound only, not an attestation of the original DB lexical bytes.
     * The input was strictly parsed once. Remove formatting outside strings and
     * undo only the encoder's HTML/U+2028/U+2029 escaping; preserve every other
     * string/number spelling. No original operation byte/hash is touched. */
    private fun compactResultBytes(raw:String):Int {
        val compact=StringBuilder(raw.length);var i=0;var quoted=false
        while(i<raw.length) {
            val c=raw[i]
            if(quoted && c=='\\') {
                if(i+5<raw.length && raw[i+1]=='u') {
                    val value=raw.substring(i+2,i+6).toIntOrNull(16)
                    if(value!=null && value in htmlEscapes) {compact.append(value.toChar());i+=6;continue}
                }
                compact.append(c).append(raw[i+1]);i+=2;continue
            }
            if(c=='"')quoted=!quoted
            if(quoted || c !in " \r\n\t")compact.append(c)
            i++
        }
        return compact.toString().toByteArray(Charsets.UTF_8).size
    }
}
