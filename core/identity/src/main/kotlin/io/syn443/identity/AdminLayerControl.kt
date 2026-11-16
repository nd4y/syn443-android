package io.syn443.identity

import io.syn443.policy.Canonical
import io.syn443.policy.Policy
import kotlinx.serialization.json.*
import java.math.BigDecimal
import java.util.Collections

enum class AdminLayerAction(val wire:String,val requiresFreshMfa:Boolean) {
    INVENTORY("configuration.inventory.get",false), HISTORY("configuration.history.get",true),
    DRAFT_LIST("configuration.layers.drafts.list",false), DRAFT_GET("configuration.layers.draft.get",true),
    DRAFT_PUT("configuration.layers.draft.put",true), DRAFT_DISCARD("configuration.layers.draft.discard",true),
    PREVIEW("configuration.preview.request",true), REQUEST_GET("configuration.request.get",true),
    PUBLISH("configuration.publish",true)
}
enum class AdminLayerEdit { SET, DELETE, INHERIT }

/** Pure value codecs. A request/context is never an ACL, MFA or publication grant. */
class AdminLayerRequest internal constructor(val action:AdminLayerAction,val requestId:String,body:ByteArray,
    internal val expected:AdminLayerExpected) {
    private val body=body.copyOf()
    val maxReplyBytes:Int get()=524_288
    fun bodyBytes()=body.copyOf()
    fun wireJson()=body.toString(Charsets.UTF_8)
    override fun toString()="AdminLayerRequest([redacted])"
}
internal class AdminLayerExpected(val id:String="",val revision:Long=0,val hash:String="",val kind:String="",val target:String="",
    val proposal:AdminLayerProposal?=null,val actor:String="",val origin:String="",val jobId:String="",
    val jobKind:AdminLayerAction?=null,val initialRequestId:String="",val preview:AdminLayerPreview?=null,
    val replayOnly:Boolean=false)

class AdminLayerProposal internal constructor(internal val document:AdminLayerJson.Document) {
    private val root get()=document.root.jsonObject
    val draftId get()=root.getValue("draftId").jsonPrimitive.content
    val draftRevision get()=root.getValue("draftRevision").jsonPrimitive.long
    val targetKind get()=root.getValue("targetKind").jsonPrimitive.content
    val targetId get()=root.getValue("targetId").jsonPrimitive.content
    val mode get()=root.getValue("mode").jsonPrimitive.content
    val approvalUntilMs get()=root.getValue("approvalUntilMs").jsonPrimitive.long
    fun wireJson()=document.raw(document.root)
    override fun toString()="AdminLayerProposal([redacted])"
}
sealed class AdminLayerReply protected constructor(private val wire:String) {
    fun wireJson()=wire
    override fun toString()="AdminLayerReply([redacted])"
}
class AdminLayerInventory internal constructor(wire:String,internal val document:AdminLayerJson.Document,
    val device:String,val revision:Long,val hash:String,val mode:String,val approvalUntilMs:Long,
    val currentRevision:Long,val historical:Boolean):AdminLayerReply(wire)
class AdminLayerDraft internal constructor(wire:String,val id:String,val revision:Long,val proposal:AdminLayerProposal,
    val savedAtMs:Long):AdminLayerReply(wire)
class AdminLayerDraftSummary internal constructor(val id:String,val revision:Long,val savedAtMs:Long) {
    override fun toString()="AdminLayerDraftSummary([redacted])"
}
class AdminLayerDraftList internal constructor(wire:String,val targetKind:String,val targetId:String,rows:List<AdminLayerDraftSummary>):AdminLayerReply(wire) {
    val drafts:List<AdminLayerDraftSummary> = Collections.unmodifiableList(ArrayList(rows))
}
class AdminLayerDiscarded internal constructor(wire:String,val id:String,val revision:Long):AdminLayerReply(wire)
class AdminLayerPublishedHead internal constructor(val device:String,val revision:Long,val hash:String) {
    override fun toString()="AdminLayerPublishedHead([redacted])"
}
/** Opaque server ticket with checked response bindings, not client-side signature/authority verification. */
class AdminLayerPreview internal constructor(val previewId:String,val ticket:String,val issuedAtMs:Long,val expiresAtMs:Long,
    val draftHash:String,internal val context:AdminLayerExpected,private val wire:String,val replayOnly:Boolean=false,
    internal val ticketHash:String=Identity.hash(ticket.toByteArray(Charsets.UTF_8))) {
    fun wireJson()=wire
    override fun toString()="AdminLayerPreview([redacted])"
}
class AdminLayerJob internal constructor(wire:String,val id:String,val state:String,val error:String,
    val preview:AdminLayerPreview?,heads:List<AdminLayerPublishedHead>,internal val context:AdminLayerExpected):AdminLayerReply(wire) {
    val heads:List<AdminLayerPublishedHead> = Collections.unmodifiableList(ArrayList(heads))
}

object AdminLayerControl {
    private const val MAX=9_007_199_254_740_991L
    private const val REQUEST_LIMIT=262_144
    private val id=Regex("[A-Za-z0-9_-]{1,64}")
    private val requestPattern=Regex("[A-Za-z0-9_-]{24,128}")
    private val hash=Regex("[0-9a-f]{64}")
    private val path=Regex("/[A-Za-z][A-Za-z0-9_-]{0,63}(/[A-Za-z][A-Za-z0-9_-]{0,63}){0,15}")
    private val kinds=setOf("template","group","user","device","local")
    private val modes=setOf("home_wifi","wifi","cellular_restricted","cellular")
    private fun <T> checked(block:()->T):T=try {block()}catch(error:AdminException){throw error}
        catch(_:Exception){throw AdminException(AdminFailure.INVALID_REPLY)}
    private fun quote(value:String)=JsonPrimitive(value).toString()
    private fun objectBytes(vararg fields:Pair<String,String>)=fields.sortedBy {it.first}.joinToString(",","{","}"){quote(it.first)+":"+it.second}
    private fun shape(root:JsonObject,required:Set<String>,optional:Set<String> = emptySet(),nullable:Set<String> = emptySet()) {
        require(root.keys.containsAll(required) && root.keys.all {it in required || it in optional})
        require(root.all {(requestId,value)->value!=JsonNull || requestId in nullable})
    }
    private fun text(value:JsonElement)=value.jsonPrimitive.let {require(it.isString);it.content}
    private fun integer(value:JsonElement,min:Long=0,max:Long=MAX)=value.jsonPrimitive.let {
        require(!it.isString && it.content.matches(Regex("-?(0|[1-9][0-9]*)")))
        it.long.also {number->require(number in min..max)}
    }
    private fun number(root:JsonObject,requestId:String,min:Long=0,max:Long=MAX)=integer(root.getValue(requestId),min,max)
    private fun identifier(value:String)=value.also {require(id.matches(it))}
    private fun digest(value:String):String {require(value.length==43 && Policy.decode64(value).size==32);return value}
    private fun base(revision:Long,hashValue:String) {require(revision in 0..MAX && if(revision==0L)hashValue.isEmpty() else hash.matches(hashValue))}
    private fun target(kind:String,value:String) {require(kind in setOf("template","group","user","device"));identifier(value)}
    private fun validPath(value:String)=value.also {require(it.length in 2..512 && path.matches(it))}
    private fun observed(value:Long,time:TimeWindow) {require(value in 1..MAX && value<=Math.addExact(time.upperMs,30_000))}
    private fun request(action:AdminLayerAction,requestId:String,payload:String,expect:AdminLayerExpected):AdminLayerRequest {
        require(requestPattern.matches(requestId))
        val raw=objectBytes("version" to "1","action" to quote(action.wire),"requestId" to quote(requestId),"payload" to payload)
        val bytes=raw.toByteArray(Charsets.UTF_8);require(bytes.size<=REQUEST_LIMIT)
        return AdminLayerRequest(action,requestId,bytes,expect)
    }
    fun inventory(device:String,requestId:String)=checked {request(AdminLayerAction.INVENTORY,requestId,objectBytes("id" to quote(identifier(device))),AdminLayerExpected(id=device))}
    fun history(device:String,revision:Long,hashValue:String,requestId:String)=checked {
        identifier(device);base(revision,hashValue);require(revision>0)
        request(AdminLayerAction.HISTORY,requestId,objectBytes("id" to quote(device),"revision" to revision.toString(),"hash" to quote(hashValue)),AdminLayerExpected(id=device,revision=revision,hash=hashValue))
    }
    fun listDrafts(kind:String,targetId:String,requestId:String)=checked {
        target(kind,targetId);request(AdminLayerAction.DRAFT_LIST,requestId,objectBytes("targetKind" to quote(kind),"targetId" to quote(targetId)),AdminLayerExpected(kind=kind,target=targetId))
    }
    fun getDraft(draftId:String,kind:String,targetId:String,requestId:String)=checked {
        identifier(draftId);target(kind,targetId)
        request(AdminLayerAction.DRAFT_GET,requestId,objectBytes("id" to quote(draftId)),AdminLayerExpected(id=draftId,kind=kind,target=targetId))
    }
    fun saveDraft(expectedRevision:Long,proposal:AdminLayerProposal,requestId:String)=checked {
        require(expectedRevision in 0 until MAX && proposal.draftRevision==expectedRevision+1)
        val draft=objectBytes("id" to quote(proposal.draftId),"revision" to expectedRevision.toString(),"proposal" to proposal.wireJson(),"savedAtMs" to "0")
        request(AdminLayerAction.DRAFT_PUT,requestId,objectBytes("draft" to draft),AdminLayerExpected(id=proposal.draftId,revision=expectedRevision+1,kind=proposal.targetKind,target=proposal.targetId,proposal=proposal))
    }
    fun discardDraft(draft:AdminLayerDraft,requestId:String)=checked {
        request(AdminLayerAction.DRAFT_DISCARD,requestId,objectBytes("id" to quote(draft.id),"revision" to draft.revision.toString(),
            "targetKind" to quote(draft.proposal.targetKind),"targetId" to quote(draft.proposal.targetId)),
            AdminLayerExpected(id=draft.id,revision=draft.revision,kind=draft.proposal.targetKind,target=draft.proposal.targetId))
    }
    fun preview(proposal:AdminLayerProposal,actor:String,origin:String,requestId:String)=checked {
        digest(actor);Identity.controlOrigin(origin);require(requestPattern.matches(requestId))
        val job=Identity.hash((actor+"\u0000"+requestId).toByteArray(Charsets.UTF_8))
        request(AdminLayerAction.PREVIEW,requestId,objectBytes("proposal" to proposal.wireJson()),
            AdminLayerExpected(proposal=proposal,actor=actor,origin=origin,jobId=job,jobKind=AdminLayerAction.PREVIEW,initialRequestId=requestId))
    }
    fun poll(job:AdminLayerJob,requestId:String)=checked {
        request(AdminLayerAction.REQUEST_GET,requestId,objectBytes("id" to quote(job.id)),job.context)
    }
    /** Read only the job described by an owned fresh/restored operation. This
     * never retries its mutation or changes its durable body/hash/request ID. */
    fun poll(operation:AdminLayerRequest,newRequestId:String):AdminLayerRequest=checked {
        val e=operation.expected
        require(e.jobKind in setOf(AdminLayerAction.PREVIEW,AdminLayerAction.PUBLISH) && e.proposal!=null)
        when(operation.action) {
            AdminLayerAction.PREVIEW,AdminLayerAction.PUBLISH->require(e.jobKind==operation.action && e.initialRequestId==operation.requestId)
            AdminLayerAction.REQUEST_GET->Unit
            else->error("admin_layer_poll")
        }
        digest(e.actor);Identity.controlOrigin(e.origin);digest(e.jobId);require(requestPattern.matches(e.initialRequestId))
        require(e.jobId==Identity.hash((e.actor+"\u0000"+e.initialRequestId).toByteArray(Charsets.UTF_8)))
        request(AdminLayerAction.REQUEST_GET,newRequestId,objectBytes("id" to quote(e.jobId)),e)
    }
    fun publish(preview:AdminLayerPreview,actor:String,origin:String,requestId:String,time:TimeWindow)=checked {
        require(!preview.replayOnly && digest(actor)==preview.context.actor && origin==preview.context.origin && preview.expiresAtMs>time.upperMs)
        Identity.controlOrigin(origin);require(requestPattern.matches(requestId))
        request(AdminLayerAction.PUBLISH,requestId,objectBytes("previewId" to quote(preview.previewId),"ticket" to quote(preview.ticket)),
            AdminLayerExpected(proposal=preview.context.proposal,actor=actor,origin=origin,
                jobId=Identity.hash((actor+"\u0000"+requestId).toByteArray(Charsets.UTF_8)),jobKind=AdminLayerAction.PUBLISH,initialRequestId=requestId,preview=preview))
    }
    private val replayFields=setOf("schemaVersion","action","requestId","bodyHash","actor","origin","id","revision","hash","kind","target",
        "proposalHash","jobId","jobKind","initialRequestId","previewId","previewDraftHash","previewIssuedAtMs","previewExpiresAtMs","ticketHash")
    private fun utf8(bytes:ByteArray,limit:Int):String {
        require(bytes.size in 1..limit)
        return bytes.toString(Charsets.UTF_8).also {require(it.toByteArray(Charsets.UTF_8).contentEquals(bytes))}
    }
    /** Value-only reconciliation metadata. The caller must encrypt/authenticate it
     * with the exact body before dispatch. It never restores a session or grant. */
    fun replayContext(request:AdminLayerRequest,actualActor:String,actualOrigin:String):ByteArray=checked {
        digest(actualActor);Identity.controlOrigin(actualOrigin)
        val e=request.expected;val p=e.preview
        require(e.actor.isEmpty() || (e.actor==actualActor && e.origin==actualOrigin))
        val fields=objectBytes("schemaVersion" to "1","action" to quote(request.action.wire),"requestId" to quote(request.requestId),
            "bodyHash" to quote(Identity.hash(request.bodyBytes())),"actor" to quote(actualActor),"origin" to quote(actualOrigin),
            "id" to quote(e.id),"revision" to e.revision.toString(),"hash" to quote(e.hash),"kind" to quote(e.kind),"target" to quote(e.target),
            "proposalHash" to quote(e.proposal?.let {Identity.hash(it.wireJson().toByteArray(Charsets.UTF_8))}?:""),
            "jobId" to quote(e.jobId),"jobKind" to quote(e.jobKind?.wire?:""),"initialRequestId" to quote(e.initialRequestId),
            "previewId" to quote(p?.previewId?:""),"previewDraftHash" to quote(p?.draftHash?:""),
            "previewIssuedAtMs" to (p?.issuedAtMs?:0).toString(),"previewExpiresAtMs" to (p?.expiresAtMs?:0).toString(),
            "ticketHash" to quote(p?.ticketHash?:""))
        fields.toByteArray(Charsets.UTF_8).also {require(it.size<=8192)}
    }
    /** Explicit poll/exact-idempotent retry only. Restored previews cannot mint a
     * new publish operation, including after the original ticket has expired. */
    fun restoreRequest(exactBody:ByteArray,context:ByteArray,ownedProposalRaw:String?,actualActor:String,actualOrigin:String):AdminLayerRequest=checked {
        digest(actualActor);Identity.controlOrigin(actualOrigin)
        val c=AdminLayerJson.parse(utf8(context,8192)).jsonObject;shape(c,replayFields)
        require(number(c,"schemaVersion")==1L && text(c.getValue("actor"))==actualActor && text(c.getValue("origin"))==actualOrigin)
        val raw=utf8(exactBody,REQUEST_LIMIT);val body=AdminLayerJson.document(raw);val root=body.root.jsonObject
        shape(root,setOf("version","requestId","action","payload"));require(number(root,"version")==1L)
        val requestId=text(root.getValue("requestId"));require(requestPattern.matches(requestId) && requestId==text(c.getValue("requestId")))
        val action=AdminLayerAction.entries.single {it.wire==text(root.getValue("action"))};require(action.wire==text(c.getValue("action")))
        require(digest(text(c.getValue("bodyHash")))==Identity.hash(exactBody))
        val payload=root.getValue("payload").jsonObject
        val proposalHash=text(c.getValue("proposalHash"))
        val proposal=if(proposalHash.isEmpty())null else {
            digest(proposalHash);proposal(checkNotNull(ownedProposalRaw)).also {require(Identity.hash(it.wireJson().toByteArray(Charsets.UTF_8))==proposalHash)}
        }
        val idValue=text(c.getValue("id"));val revision=number(c,"revision");val hashValue=text(c.getValue("hash"))
        val kind=text(c.getValue("kind"));val targetValue=text(c.getValue("target"))
        val jobId=text(c.getValue("jobId"));val initial=text(c.getValue("initialRequestId"));val jobKind=text(c.getValue("jobKind"))
        val previewId=text(c.getValue("previewId"));val draftHash=text(c.getValue("previewDraftHash"))
        val issued=number(c,"previewIssuedAtMs");val expires=number(c,"previewExpiresAtMs");val ticketHash=text(c.getValue("ticketHash"))
        val jobAction=when(jobKind) {""->null;AdminLayerAction.PREVIEW.wire->AdminLayerAction.PREVIEW;AdminLayerAction.PUBLISH.wire->AdminLayerAction.PUBLISH;else->error("admin_layer_replay")}
        val isJob=action in setOf(AdminLayerAction.PREVIEW,AdminLayerAction.PUBLISH,AdminLayerAction.REQUEST_GET)
        if(isJob) {
            require(idValue.isEmpty() && revision==0L && hashValue.isEmpty() && kind.isEmpty() && targetValue.isEmpty() && proposal!=null)
            require(requestPattern.matches(initial) && digest(jobId)==Identity.hash((actualActor+"\u0000"+initial).toByteArray(Charsets.UTF_8)))
            require(jobAction!=null && (action==AdminLayerAction.REQUEST_GET || (action==jobAction && requestId==initial)))
        } else require(jobAction==null && jobId.isEmpty() && initial.isEmpty())
        var savedPreview:AdminLayerPreview?=null
        if(jobAction==AdminLayerAction.PUBLISH) {
            digest(previewId);require(hash.matches(draftHash) && issued in 1..MAX && expires>issued && expires-issued<=180_000 && expires<=checkNotNull(proposal).approvalUntilMs)
            digest(ticketHash)
            val previewContext=AdminLayerExpected(proposal=proposal,actor=actualActor,origin=actualOrigin,jobId=previewId,jobKind=AdminLayerAction.PREVIEW,replayOnly=true)
            // A poll body has no ticket. Its authenticated snapshot retains only
            // enough metadata to validate the desired-head result, never publish.
            savedPreview=AdminLayerPreview(previewId,"",issued,expires,draftHash,previewContext,"{}",true,ticketHash)
            if(action==AdminLayerAction.PUBLISH) {
                shape(payload,setOf("previewId","ticket"));require(text(payload.getValue("previewId"))==previewId)
                val ticket=text(payload.getValue("ticket"));require(Identity.hash(ticket.toByteArray(Charsets.UTF_8))==ticketHash)
                val v=ticketPayload(ticket);val previewRequestId=text(v.getValue("requestId"))
                require(requestPattern.matches(previewRequestId) && previewId==Identity.hash((actualActor+"\u0000"+previewRequestId).toByteArray(Charsets.UTF_8)))
                val expected=AdminLayerExpected(proposal=proposal,actor=actualActor,origin=actualOrigin,jobId=previewId,
                    jobKind=AdminLayerAction.PREVIEW,initialRequestId=previewRequestId,replayOnly=true)
                val result=JsonObject(mapOf("previewId" to JsonPrimitive(previewId),"ticket" to JsonPrimitive(ticket),"preview" to v))
                savedPreview=previewResult(result,Canonical.encode(result),expected,null,true)
                require(savedPreview.draftHash==draftHash && savedPreview.issuedAtMs==issued && savedPreview.expiresAtMs==expires)
            }
        } else require(previewId.isEmpty() && draftHash.isEmpty() && issued==0L && expires==0L && ticketHash.isEmpty())
        val expected=AdminLayerExpected(idValue,revision,hashValue,kind,targetValue,proposal,
            if(isJob)actualActor else "",if(isJob)actualOrigin else "",jobId,jobAction,initial,savedPreview,true)
        val reconstructed=when(action) {
            AdminLayerAction.INVENTORY->inventory(idValue,requestId)
            AdminLayerAction.HISTORY->history(idValue,revision,hashValue,requestId)
            AdminLayerAction.DRAFT_LIST->listDrafts(kind,targetValue,requestId)
            AdminLayerAction.DRAFT_GET->getDraft(idValue,kind,targetValue,requestId)
            AdminLayerAction.DRAFT_PUT->saveDraft(revision-1,checkNotNull(proposal),requestId)
            AdminLayerAction.DRAFT_DISCARD->{identifier(idValue);target(kind,targetValue);require(revision in 1..MAX && proposal==null)
                request(action,requestId,objectBytes("id" to quote(idValue),"revision" to revision.toString(),"targetKind" to quote(kind),"targetId" to quote(targetValue)),
                    AdminLayerExpected(id=idValue,revision=revision,kind=kind,target=targetValue))}
            AdminLayerAction.PREVIEW->preview(checkNotNull(proposal),actualActor,actualOrigin,requestId)
            AdminLayerAction.REQUEST_GET->request(action,requestId,objectBytes("id" to quote(jobId)),expected)
            AdminLayerAction.PUBLISH->request(action,requestId,objectBytes("previewId" to quote(previewId),"ticket" to quote(text(payload.getValue("ticket")))),expected)
        }
        require(reconstructed.bodyBytes().contentEquals(exactBody))
        // Reject extraneous or changed context too; replayOnly is intentionally
        // not serialized, and never changes the exact operation bytes.
        val restored=AdminLayerRequest(action,requestId,exactBody,expected)
        require(replayContext(if(action in setOf(AdminLayerAction.PUBLISH,AdminLayerAction.REQUEST_GET))restored else reconstructed,actualActor,actualOrigin).contentEquals(context))
        restored
    }
    private fun portable(value:JsonElement,depth:Int=1) {
        require(depth<=16 && value!=JsonNull)
        when(value) {
            is JsonObject->{require(value.size<=128);value.values.forEach {portable(it,depth+1)}}
            is JsonArray->{require(value.size<=256);value.forEach {portable(it,depth+1)}}
            else->Unit // Numeric syntax/range and Unicode were bounded before the tree was built.
        }
    }
    private fun permission(value:JsonElement) {
        val p=value.jsonObject;shape(p,setOf("path","mode"),setOf("choices","minimum","maximum"))
        validPath(text(p.getValue("path")));val mode=text(p.getValue("mode"))
        val choices=p["choices"]?.jsonArray;require(choices==null || choices.size<=32)
        val minimum=p["minimum"]?.let {integer(it,-MAX)};val maximum=p["maximum"]?.let {integer(it,-MAX)}
        when(mode) {
            "locked","free"->require(choices.isNullOrEmpty() && minimum==null && maximum==null)
            "choice"->{require(!choices.isNullOrEmpty() && minimum==null && maximum==null);choices.forEach {portable(it)}
                require(choices.map {Canonical.encode(it)}.toSet().size==choices.size)}
            "range"->require(choices.isNullOrEmpty() && (minimum!=null || maximum!=null) && (minimum==null || maximum==null || minimum<=maximum))
            else->error("admin_layer_permission")
        }
    }
    private fun layers(values:JsonArray,device:String):Map<String,Long> {
        require(values.size in 1..20)
        val seen=linkedMapOf<String,Long>();val counts=mutableMapOf<String,Int>();var changesCount=0;var permissionsCount=0
        for(value in values) {
            val layer=value.jsonObject
            shape(layer,setOf("id","kind","priority","revision","changes","permissions"),nullable=setOf("changes","permissions"))
            val layerId=identifier(text(layer.getValue("id")));val kind=text(layer.getValue("kind"));require(kind in kinds)
            if(kind in setOf("device","local"))require(layerId==device)
            val priority=number(layer,"priority",-10_000,10_000);require(kind=="group" || priority==0L)
            val revision=number(layer,"revision",1);require(seen.put(kind+"/"+layerId,revision)==null)
            counts[kind]=(counts[kind]?:0)+1;require(counts.getValue(kind)<=if(kind=="group")16 else 1)
            val changes=layer.getValue("changes").takeIf {it!=JsonNull}?.jsonArray.orEmpty();require(changes.size<=256);changesCount+=changes.size
            val paths=HashSet<String>()
            for(change in changes) {
                val c=change.jsonObject;shape(c,setOf("path","operation"),setOf("value"))
                val changed=validPath(text(c.getValue("path")))
                require(paths.none {it==changed || it.startsWith(changed+"/") || changed.startsWith(it+"/")});paths.add(changed)
                when(text(c.getValue("operation"))) {
                    "set"->portable(c.getValue("value"))
                    "delete"->require("value" !in c)
                    else->error("admin_layer_change")
                }
            }
            val permissions=layer.getValue("permissions").takeIf {it!=JsonNull}?.jsonArray.orEmpty();require(permissions.size<=256)
            permissionsCount+=permissions.size;permissions.forEach(::permission)
        }
        require(counts["template"]==1 && changesCount<=512 && permissionsCount<=256)
        return seen
    }
    fun proposal(raw:String):AdminLayerProposal=checked {
        require(raw.toByteArray(Charsets.UTF_8).size<=REQUEST_LIMIT)
        val doc=AdminLayerJson.document(raw);val p=doc.root.jsonObject
        shape(p,setOf("draftId","draftRevision","targetKind","targetId","mode","approvalUntilMs","bundles"))
        identifier(text(p.getValue("draftId")));number(p,"draftRevision",1);target(text(p.getValue("targetKind")),text(p.getValue("targetId")))
        require(text(p.getValue("mode")) in modes);number(p,"approvalUntilMs",1)
        val bundles=p.getValue("bundles").jsonArray;require(bundles.size in 1..64);val devices=HashSet<String>()
        for(value in bundles) {
            val b=value.jsonObject;shape(b,setOf("device","baseRevision","baseHash","layers"))
            val device=identifier(text(b.getValue("device")));require(devices.add(device));base(number(b,"baseRevision"),text(b.getValue("baseHash")))
            layers(b.getValue("layers").jsonArray,device)
        }
        if(text(p.getValue("targetKind"))=="device")require(devices==setOf(text(p.getValue("targetId"))))
        AdminLayerProposal(doc)
    }
    private fun origin(value:JsonElement,layers:Map<String,Long>) {
        val o=value.jsonObject;shape(o,setOf("layerId","kind","revision"))
        val requestId=text(o.getValue("kind"))+"/"+text(o.getValue("layerId"))
        require(layers[requestId]==number(o,"revision",1))
    }
    private fun inventory(request:AdminLayerRequest,doc:AdminLayerJson.Document,time:TimeWindow,wire:String):AdminLayerInventory {
        val value=doc.root.jsonObject;val expected=request.expected;val historical=request.action==AdminLayerAction.HISTORY
        val revision=number(value,"revision");val current=number(value,"currentRevision");val hashValue=text(value.getValue("hash"))
        if(historical)require(value["historical"]==JsonPrimitive(true) && revision==expected.revision && hashValue==expected.hash && current>=revision)
        val normalized=if(historical)JsonObject(value.filterKeys {it!="historical"}+mapOf("currentRevision" to JsonPrimitive(revision))) else value
        val ordinary=AdminControl.configuration(normalized,expected.id,time,wire)
        val values=value.getValue("layers").jsonArray
        if(revision>0) {
            val origins=layers(values,expected.id)
            val effective=value.getValue("effective").jsonObject;shape(effective,setOf("document","fields","restrictions"))
            require(effective.getValue("document") is JsonObject && doc.raw(effective.getValue("document")).toByteArray(Charsets.UTF_8).size<=REQUEST_LIMIT)
            val fields=effective.getValue("fields").jsonObject;require(fields.size<=4096)
            fields.forEach {(path,value)->validPath(path);origin(value,origins)}
            val restrictions=effective.getValue("restrictions").jsonArray;require(restrictions.size<=256)
            restrictions.forEach {val r=it.jsonObject;shape(r,setOf("permission","origin"));permission(r.getValue("permission"));origin(r.getValue("origin"),origins)}
        }
        return AdminLayerInventory(wire,doc,ordinary.device,revision,hashValue,ordinary.mode,number(value,"approvalUntilMs"),current,historical)
    }
    fun parseReply(request:AdminLayerRequest,raw:String,time:TimeWindow):AdminLayerReply=checked {
        require(raw.toByteArray(Charsets.UTF_8).size in 1..524_288)
        val doc=AdminLayerJson.document(raw,request.action in setOf(AdminLayerAction.INVENTORY,AdminLayerAction.HISTORY))
        val root=doc.root.jsonObject;val expected=request.expected
        when(request.action) {
            AdminLayerAction.INVENTORY,AdminLayerAction.HISTORY->inventory(request,doc,time,raw)
            AdminLayerAction.DRAFT_LIST->{
                shape(root,setOf("targetKind","targetId","drafts"));require(text(root.getValue("targetKind"))==expected.kind && text(root.getValue("targetId"))==expected.target)
                val rows=root.getValue("drafts").jsonArray;require(rows.size<=64);val seen=HashSet<String>();var previous:AdminLayerDraftSummary?=null
                val parsed=rows.map {
                    val row=it.jsonObject;shape(row,setOf("id","revision","savedAtMs"));val id=identifier(text(row.getValue("id")));require(seen.add(id))
                    val next=AdminLayerDraftSummary(id,number(row,"revision",1),number(row,"savedAtMs",1));observed(next.savedAtMs,time)
                    previous?.let {require(next.savedAtMs<it.savedAtMs || next.savedAtMs==it.savedAtMs && next.id>it.id)};previous=next;next
                }
                AdminLayerDraftList(raw,expected.kind,expected.target,parsed)
            }
            AdminLayerAction.DRAFT_GET,AdminLayerAction.DRAFT_PUT->{
                require(raw.toByteArray(Charsets.UTF_8).size<=REQUEST_LIMIT)
                shape(root,setOf("id","revision","proposal","savedAtMs"));require(text(root.getValue("id"))==expected.id)
                val revision=number(root,"revision",1);val saved=number(root,"savedAtMs",1);observed(saved,time)
                val p=proposal(doc.raw(root.getValue("proposal")))
                require(p.draftId==expected.id && p.draftRevision==revision && p.targetKind==expected.kind && p.targetId==expected.target)
                if(request.action==AdminLayerAction.DRAFT_PUT)require(revision==expected.revision && p.document.root==expected.proposal?.document?.root)
                AdminLayerDraft(raw,expected.id,revision,p,saved)
            }
            AdminLayerAction.DRAFT_DISCARD->{
                shape(root,setOf("id","revision","discarded"));require(text(root.getValue("id"))==expected.id && number(root,"revision",1)==expected.revision && root["discarded"]==JsonPrimitive(true))
                AdminLayerDiscarded(raw,expected.id,expected.revision)
            }
            else->job(root,doc,raw,expected,time)
        }
    }
    private fun job(root:JsonObject,doc:AdminLayerJson.Document,wire:String,context:AdminLayerExpected,time:TimeWindow):AdminLayerJob {
        shape(root,setOf("id","state"),setOf("error","result"));require(text(root.getValue("id"))==context.jobId)
        val state=text(root.getValue("state"));require(state in setOf("queued","running","ready","published","rejected","expired","cancelled"))
        val error=root["error"]?.let(::text)?:"";require(error in setOf("","configuration_denied","configuration_conflict"))
        val result=root["result"]
        var preview:AdminLayerPreview?=null;val heads=ArrayList<AdminLayerPublishedHead>()
        if(state in setOf("ready","published")) {
            require(error.isEmpty() && result is JsonObject && doc.raw(result).toByteArray(Charsets.UTF_8).size<=100_000)
            val proposal=checkNotNull(context.proposal);val p=proposal.document.root.jsonObject
            val bundles=p.getValue("bundles").jsonArray.associate {val b=it.jsonObject;text(b.getValue("device")) to b}
            if(state=="ready") {
                preview=previewResult(result,doc.raw(result),context,time,context.replayOnly)
            } else {
                require(context.jobKind==AdminLayerAction.PUBLISH);shape(result,setOf("heads"))
                val rows=result.getValue("heads").jsonArray;require(rows.size==bundles.size);val seen=HashSet<String>()
                for(row in rows) {
                    val h=row.jsonObject;shape(h,setOf("device","revision","hash"));val device=text(h.getValue("device"));val bundle=checkNotNull(bundles[device])
                    require(seen.add(device) && number(h,"revision",1)==Math.addExact(number(bundle,"baseRevision"),1) && text(h.getValue("hash"))==context.preview?.draftHash)
                    heads+=AdminLayerPublishedHead(device,number(h,"revision",1),text(h.getValue("hash")))
                }
            }
        } else require(result==null && (state !in setOf("queued","running") || error.isEmpty()))
        return AdminLayerJob(wire,context.jobId,state,error,preview,heads,context)
    }
    private fun ticketPayload(ticket:String):JsonObject {
        require(ticket.length in 24..90_000 && ticket.all {it.code in 33..126})
        val parts=ticket.split('.');require(parts.size==3)
        val headerBytes=Policy.decode64(parts[0]);val payloadBytes=Policy.decode64(parts[1])
        require(headerBytes.size in 1..512 && payloadBytes.size in 1..65_536 && Policy.decode64(parts[2]).size==64)
        val header=Canonical.parse(utf8(headerBytes,512)).jsonObject
        shape(header,setOf("alg","kid","typ"))
        require(text(header.getValue("alg"))=="ES256" && text(header.getValue("typ"))=="syn443-configuration-preview+jws")
        identifier(text(header.getValue("kid")))
        // This is a closed shape/binding check, not signature verification or a grant.
        val payload=AdminLayerJson.parse(utf8(payloadBytes,65_536)).jsonObject
        return payload
    }
    private fun previewResult(result:JsonObject,wire:String,context:AdminLayerExpected,time:TimeWindow?,replayOnly:Boolean):AdminLayerPreview {
        require(context.jobKind==AdminLayerAction.PREVIEW);shape(result,setOf("previewId","ticket","preview"))
        require(text(result.getValue("previewId"))==context.jobId)
        val ticket=text(result.getValue("ticket"));val v=result.getValue("preview").jsonObject
        require(ticketPayload(ticket)==v)
        shape(v,setOf("schemaVersion","origin","actor","requestId","draftId","draftRevision","draftHash","targetKind","targetId","mode","dependencyHash","effectiveHash","recipients","issuedAtMs","expiresAtMs"))
        val proposal=checkNotNull(context.proposal)
        val bundles=proposal.document.root.jsonObject.getValue("bundles").jsonArray.associate {val b=it.jsonObject;text(b.getValue("device")) to b}
        require(number(v,"schemaVersion")==1L && text(v.getValue("origin"))==context.origin && text(v.getValue("actor"))==context.actor && text(v.getValue("requestId"))==context.initialRequestId)
        require(text(v.getValue("draftId"))==proposal.draftId && number(v,"draftRevision",1)==proposal.draftRevision && text(v.getValue("targetKind"))==proposal.targetKind && text(v.getValue("targetId"))==proposal.targetId && text(v.getValue("mode"))==proposal.mode)
        for(field in listOf("draftHash","dependencyHash","effectiveHash"))require(hash.matches(text(v.getValue(field))))
        val issued=number(v,"issuedAtMs",1);val expires=number(v,"expiresAtMs",1);if(time!=null)observed(issued,time)
        require(expires>issued && expires-issued<=180_000 && expires<=proposal.approvalUntilMs)
        val recipients=v.getValue("recipients").jsonArray;require(recipients.size==bundles.size);val seen=HashSet<String>();var previous=""
        for(recipient in recipients) {
            val r=recipient.jsonObject;shape(r,setOf("owner","device","thumbprint","grantHash","baseRevision","baseHash","capabilitiesHash"))
            val device=text(r.getValue("device"));val bundle=checkNotNull(bundles[device]);require(seen.add(device))
            val owner=digest(text(r.getValue("owner")));digest(text(r.getValue("thumbprint")));digest(text(r.getValue("grantHash")))
            require(hash.matches(text(r.getValue("capabilitiesHash"))) && number(r,"baseRevision")==number(bundle,"baseRevision") && text(r.getValue("baseHash"))==text(bundle.getValue("baseHash")))
            val ordered=owner+"/"+device;require(ordered>previous);previous=ordered
            if(proposal.targetKind=="user")require(owner==proposal.targetId)
        }
        return AdminLayerPreview(context.jobId,ticket,issued,expires,text(v.getValue("draftHash")),context,wire,replayOnly)
    }
    /** An assigned current inventory becomes a private draft without advancing
     * any global layer revision or reconstructing authoritative parent bytes. */
    fun newDeviceDraft(inventory:AdminLayerInventory,draftId:String,approvalUntilMs:Long):AdminLayerProposal=checked {
        require(!inventory.historical && inventory.revision>0 && approvalUntilMs in 1..inventory.approvalUntilMs)
        identifier(draftId)
        val doc=inventory.document
        require(text(doc.root.jsonObject.getValue("state"))=="assigned")
        val rawLayers=doc.raw(doc.root.jsonObject.getValue("layers"))
        deviceProposal(inventory,draftId,1,approvalUntilMs,rawLayers)
    }
    private fun deviceProposal(base:AdminLayerInventory,draftId:String,draftRevision:Long,approvalUntilMs:Long,rawLayers:String,mode:String=base.mode):AdminLayerProposal {
        val bundle=objectBytes("device" to quote(base.device),"baseRevision" to base.revision.toString(),"baseHash" to quote(base.hash),"layers" to rawLayers)
        return proposal(objectBytes("draftId" to quote(draftId),"draftRevision" to draftRevision.toString(),"targetKind" to quote("device"),
            "targetId" to quote(base.device),"mode" to quote(mode),"approvalUntilMs" to approvalUntilMs.toString(),"bundles" to "[$bundle]"))
    }
    private fun layerIdentity(layer:JsonElement):String=layer.jsonObject.let {text(it.getValue("kind"))+"/"+text(it.getValue("id"))}
    /** Exact JSON semantics for protected portable values. In particular, do
     * not compare via Double: distinct high-precision decimals may round alike. */
    private fun sameLayerValue(a:JsonElement,b:JsonElement):Boolean=when {
        a is JsonObject && b is JsonObject->a.keys==b.keys && a.all {(key,value)->sameLayerValue(value,b.getValue(key))}
        a is JsonArray && b is JsonArray->a.size==b.size && a.indices.all {sameLayerValue(a[it],b[it])}
        a==JsonNull || b==JsonNull->a==b
        a is JsonPrimitive && b is JsonPrimitive->{
            if(a.isString || b.isString)a.isString==b.isString && a.content==b.content
            else if(a.content in setOf("true","false") || b.content in setOf("true","false"))a.content==b.content
            else BigDecimal(a.content).compareTo(BigDecimal(b.content))==0
        }
        else->false
    }
    /** Value-only normalization against the captured base. A historical base
     * is useful for private preparation, never a fresh publication authority or
     * automatic conflict resolution. The server still owns preview/CAS checks. */
    fun prepareDeviceDraft(baseInventory:AdminLayerInventory,candidate:AdminLayerProposal,expectedDraftId:String,
        expectedSavedDraftRevision:Long):AdminLayerProposal=checked {
        require(baseInventory.revision>0 && expectedSavedDraftRevision in 0 until MAX)
        identifier(expectedDraftId)
        require(candidate.draftId==expectedDraftId && candidate.targetKind=="device" && candidate.targetId==baseInventory.device &&
            candidate.mode in modes && candidate.approvalUntilMs in 1..baseInventory.approvalUntilMs)
        val candidateDoc=candidate.document
        val bundles=candidateDoc.root.jsonObject.getValue("bundles").jsonArray;require(bundles.size==1)
        val bundle=bundles.single().jsonObject
        require(text(bundle.getValue("device"))==baseInventory.device && number(bundle,"baseRevision")==baseInventory.revision && text(bundle.getValue("baseHash"))==baseInventory.hash)
        val baseDoc=baseInventory.document
        val baseRows=baseDoc.root.jsonObject.getValue("layers").jsonArray
        val rows=bundle.getValue("layers").jsonArray
        val originals=baseRows.associateBy(::layerIdentity);val candidates=rows.associateBy(::layerIdentity)
        require(originals.keys.all {it in candidates})
        fun own(layer:JsonElement)=text(layer.jsonObject.getValue("kind")) in setOf("device","local") && text(layer.jsonObject.getValue("id"))==baseInventory.device
        val normalized=baseRows.map {original->
            val proposed=checkNotNull(candidates[layerIdentity(original)])
            if(!own(original)) {
                require(sameLayerValue(original,proposed));baseDoc.raw(original)
            } else {
                val old=original.jsonObject;val next=proposed.jsonObject
                require(sameLayerValue(old.getValue("permissions"),next.getValue("permissions")))
                if(sameLayerValue(old.getValue("changes"),next.getValue("changes")))baseDoc.raw(original)
                else {
                    val revision=Math.addExact(number(old,"revision",1),1);require(revision<=MAX)
                    objectBytes("id" to quote(baseInventory.device),"kind" to quote(text(old.getValue("kind"))),"priority" to "0","revision" to revision.toString(),
                        "changes" to candidateDoc.raw(next.getValue("changes")),"permissions" to baseDoc.raw(old.getValue("permissions")))
                }
            }
        }.toMutableList()
        for(row in rows)if(layerIdentity(row) !in originals) {
            require(own(row))
            val next=row.jsonObject;val permissions=next.getValue("permissions")
            require(permissions==JsonNull || permissions is JsonArray && permissions.isEmpty())
            normalized+=objectBytes("id" to quote(baseInventory.device),"kind" to quote(text(next.getValue("kind"))),"priority" to "0","revision" to "1",
                "changes" to candidateDoc.raw(next.getValue("changes")),"permissions" to "[]")
        }
        deviceProposal(baseInventory,expectedDraftId,expectedSavedDraftRevision+1,candidate.approvalUntilMs,normalized.joinToString(",","[","]"),candidate.mode)
    }
    /** One per-device override only. Existing parent layers and untouched target
     * changes/permissions retain exact validated raw spans, including escapes. */
    fun editDevice(inventory:AdminLayerInventory,draftId:String,kind:String,layerId:String,changedPath:String,
        edit:AdminLayerEdit,valueRaw:String?,approvalUntilMs:Long):AdminLayerProposal=checked {
        require(!inventory.historical && inventory.revision>0 && approvalUntilMs in 1..MAX)
        identifier(draftId);require(kind in setOf("device","local") && layerId==inventory.device);validPath(changedPath)
        val doc=inventory.document;val original=doc.root.jsonObject.getValue("layers").jsonArray
        val own=original.singleOrNull {val l=it.jsonObject;text(l.getValue("kind"))==kind && text(l.getValue("id"))==layerId}
        require(own!=null || original.size<20)
        val current=own?.jsonObject;val revision=current?.let {Math.addExact(number(it,"revision",1),1)}?:1L;require(revision<=MAX)
        val changes=current?.getValue("changes")?.takeIf {it!=JsonNull}?.jsonArray.orEmpty()
        val other=changes.filter {text(it.jsonObject.getValue("path"))!=changedPath}
        require(other.none {val p=text(it.jsonObject.getValue("path"));p.startsWith(changedPath+"/") || changedPath.startsWith(p+"/")})
        val next=other.map {doc.raw(it)}.toMutableList()
        when(edit) {
            AdminLayerEdit.SET->{val value=checkNotNull(valueRaw);val parsed=AdminLayerJson.document(value);portable(parsed.root)
                next+=objectBytes("path" to quote(changedPath),"operation" to quote("set"),"value" to parsed.raw(parsed.root))}
            AdminLayerEdit.DELETE->{require(valueRaw==null);next+=objectBytes("path" to quote(changedPath),"operation" to quote("delete"))}
            AdminLayerEdit.INHERIT->require(valueRaw==null && changes.size!=other.size)
        }
        require(next.size<=256)
        val permissions=current?.getValue("permissions")?.let {doc.raw(it)}?:"[]"
        val changed=objectBytes("id" to quote(layerId),"kind" to quote(kind),"priority" to "0","revision" to revision.toString(),"changes" to next.joinToString(",","[","]"),"permissions" to permissions)
        val all=original.map {if(it===own)changed else doc.raw(it)}.toMutableList();if(own==null)all+=changed
        val bundle=objectBytes("device" to quote(inventory.device),"baseRevision" to inventory.revision.toString(),"baseHash" to quote(inventory.hash),"layers" to all.joinToString(",","[","]"))
        proposal(objectBytes("draftId" to quote(draftId),"draftRevision" to "1","targetKind" to quote("device"),"targetId" to quote(inventory.device),"mode" to quote(inventory.mode),"approvalUntilMs" to approvalUntilMs.toString(),"bundles" to "[$bundle]"))
    }
}
