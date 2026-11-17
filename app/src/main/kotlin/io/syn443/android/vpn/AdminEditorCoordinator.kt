package io.syn443.android.vpn

import android.os.Looper
import io.syn443.android.admin.*
import io.syn443.identity.*
import io.syn443.policy.Policy
import org.json.JSONObject
import java.util.Collections

/** Sole controller worker's private editor state. No executor, credentials,
 * network implementation or authority survives here. Durable pending bytes are
 * conservative: cancellation/unknown replies never make them safe to replace. */
internal class AdminEditorCoordinator(private val storeFactory:()->AdminEditorStore,
    private val boot:()->Int,private val elapsed:()->Long) {
    enum class Kind { OPEN, SAVE_LOCAL, SAVE_DRAFT, PREVIEW, PUBLISH, POLL, RETRY_EXACT, CHECK_OUTCOME, SEAL_PENDING, COMPARE, REBASE, CLOSE }
    class Command(val kind:Kind,val device:String="",val binding:String="",val localRevision:Long=0,
        pages:List<String> = emptyList(),val reviewBinding:String="",val reviewDeadline:Long=0,val comparisonBinding:String="",val operationBinding:String="") {
        val pages:List<String> = Collections.unmodifiableList(ArrayList(pages))
        override fun toString()="AdminEditorCommand([redacted])"
    }
    enum class ComparisonKind { LOAD, PAGE, DETAIL, RESOLVE }
    class ComparisonCommand(val kind:ComparisonKind,val device:String,val documentBinding:String,val localRevision:Long,
        val comparisonBinding:String="",val section:AdminComparisonSection=AdminComparisonSection.CONFLICTS,val offset:Int=0,
        val rowId:String="",val side:AdminComparisonSide=AdminComparisonSide.BASE,val page:Int=0,val choice:String="") {
        override fun toString()="AdminComparisonCommand([redacted])"
    }
    interface Access {
        fun ownership():AdminLayerOwnership
        fun action(request:AdminLayerRequest):AdminLayerReply
        fun configurationRequestVersion():Int=1
        fun reconcile(request:AdminOperationRequest):AdminOperationReceipt=throw AdminException(AdminFailure.TRANSPORT)
        fun reviewDeadline(preview:AdminLayerPreview):Long
        fun check()
    }
    private class Failure(val code:String):Exception(code)
    private val store by lazy(storeFactory)
    private var record:AdminEditorRecord?=null
    private var base:AdminLayerInventory?=null
    private var head:AdminLayerInventory?=null
    private var savedRevision:Long?=null
    private var dirty=true
    private var publishedRevision=0L
    private var phase=AdminEditorPhase.INVENTORY
    private var error=""
    private var ownedService=""
    private var ownedActor=""
    private var ownedOrigin=""
    private var ownedBoot=-1
    private var ownedSessionUntil=-1L
    private var lastElapsed=-1L
    private var activeOperation:AdminLayerRequest?=null
    private var preview:AdminLayerPreview?=null
    private var reviewBinding=""
    private var reviewDeadline=0L
    private var reviewBoot=-1
    private var reviewDocument=""
    private var recipients=emptyList<String>()
    private var diffs=emptyList<String>()
    private var operationOutcome=""
    private var sealBinding=""
    private class ComparisonCache(val comparison:AdminLayerComparison?,val diff:AdminLayerDiff?,val current:AdminLayerInventory,val currentFacts:String,val baseRevision:Long,
        val saved:Long,val localRevision:Long,val document:String,val proposalHash:String,val service:String,val actor:String,val origin:String,
        val boot:Int,val sessionUntil:Long,val binding:String,val readOnly:Boolean,val review:String="",val reviewDeadline:Long=0)
    private class PreparedDiff(val diff:AdminLayerDiff,val proposalHash:String,val current:AdminLayerInventory,val saved:Long)
    private var comparisonCache:ComparisonCache?=null
    private var preparedDiff:PreparedDiff?=null
    private fun worker() {
        if(Looper.myLooper()==Looper.getMainLooper() || Thread.currentThread().name.startsWith("Binder:"))
            throw AdminEditorStorageException(AdminEditorStorageFailure.WRONG_THREAD)
    }
    private fun fail(code:String):Nothing=throw Failure(code)
    private fun clearReview() {preview=null;reviewBinding="";reviewDeadline=0;reviewBoot=-1;reviewDocument="";recipients=emptyList();diffs=emptyList()}
    private fun clearComparison() {comparisonCache=null;preparedDiff=null}
    private fun clearOutcome() {operationOutcome="";sealBinding=""}
    private fun clearRam() {record=null;base=null;head=null;savedRevision=null;dirty=true;publishedRevision=0;activeOperation=null;clearReview();clearComparison();clearOutcome();ownedService="";ownedActor="";ownedOrigin="";ownedBoot=-1;ownedSessionUntil=-1;lastElapsed=-1}
    private fun admitted(access:Access):AdminLayerOwnership {
        access.check();val owned=access.ownership();access.check()
        val now=elapsed()
        if(owned.bootCount!=boot() || now<owned.observedElapsedMs || now>=owned.sessionUntilElapsedMs || now<0 || now<lastElapsed)
            fail("REAUTHENTICATE")
        if(ownedService.isNotEmpty() && (owned.serviceHash!=ownedService || owned.actor!=ownedActor || owned.apiOrigin!=ownedOrigin || owned.bootCount!=ownedBoot)) {
            clearRam();fail("REAUTHENTICATE")
        }
        if(ownedSessionUntil>=0 && ownedSessionUntil!=owned.sessionUntilElapsedMs){clearReview();clearComparison();clearOutcome();activeOperation=null}
        ownedSessionUntil=owned.sessionUntilElapsedMs
        ownedService=owned.serviceHash;ownedActor=owned.actor;ownedOrigin=owned.apiOrigin;ownedBoot=owned.bootCount;lastElapsed=now
        return owned
    }
    private fun remote(request:AdminLayerRequest,access:Access):AdminLayerReply {
        admitted(access);val reply=access.action(request);admitted(access);return reply
    }
    private fun mutationVersion(access:Access):Int {
        admitted(access);val version=access.configurationRequestVersion();admitted(access)
        if(version !in 1..2)fail("INVALID_REPLY")
        return version
    }
    private fun text():String {
        val bytes=record?.proposal ?:return ""
        return try {Policy.utf8(bytes)}finally {bytes.fill(0)}
    }
    private fun documentBinding():String {
        val r=record ?:return ""
        val bytes=r.proposal
        return try {Identity.hash(("syn443.admin-editor.document.v1\u0000"+r.owner.serviceHash+"\u0000"+r.owner.actor+"\u0000"+
            r.owner.deviceId+"\u0000"+r.owner.draftId+"\u0000"+r.revision+"\u0000"+Identity.hash(bytes)).toByteArray(Charsets.UTF_8))}
        finally {bytes.fill(0)}
    }
    private fun selected(command:Command):AdminEditorRecord {
        val r=record ?:fail("UNAVAILABLE")
        if(command.binding!=documentBinding() || command.localRevision!=r.revision || command.device!=r.owner.deviceId)fail("CONFLICT")
        return r
    }
    private fun proposal():AdminLayerProposal=try {AdminLayerControl.proposal(text())}catch(_:Exception){fail("INVALID_PROPOSAL")}
    private fun currentInventory(device:String,access:Access)=remote(AdminLayerControl.inventory(device,Identity.random()),access) as? AdminLayerInventory ?:fail("INVALID_REPLY")
    private fun scope(proposal:AdminLayerProposal,r:AdminEditorRecord):JSONObject {
        if(proposal.draftId!=r.owner.draftId || proposal.targetKind!="device" || proposal.targetId!=r.owner.deviceId)fail("INVALID_PROPOSAL")
        val bundles=JSONObject(proposal.wireJson()).getJSONArray("bundles")
        if(bundles.length()!=1)fail("INVALID_PROPOSAL")
        return bundles.getJSONObject(0).also {if(it.getString("device")!=r.owner.deviceId)fail("INVALID_PROPOSAL")}
    }
    private fun capturedBase(proposal:AdminLayerProposal,access:Access):AdminLayerInventory {
        val r=checkNotNull(record);val bundle=scope(proposal,r)
        val revision=bundle.getLong("baseRevision");val hash=bundle.getString("baseHash")
        base?.let {if(it.device==r.owner.deviceId && it.revision==revision && it.hash==hash)return it}
        val current=head?.takeIf {it.device==r.owner.deviceId} ?:currentInventory(r.owner.deviceId,access).also {head=it}
        val captured=if(current.revision==revision && current.hash==hash)current else
            remote(AdminLayerControl.history(r.owner.deviceId,revision,hash,Identity.random()),access) as? AdminLayerInventory ?:fail("INVALID_REPLY")
        base=captured
        return captured
    }
    private fun loadSavedRevision(access:Access) {
        val r=checkNotNull(record)
        // The server reads LIMIT65 and rejects >64. A successful complete list
        // establishes absence; ACCESS_DENIED from getDraft alone never does.
        val list=remote(AdminLayerControl.listDrafts("device",r.owner.deviceId,Identity.random()),access) as? AdminLayerDraftList ?:fail("INVALID_REPLY")
        val row=list.drafts.singleOrNull {it.id==r.owner.draftId}
        if(row==null){savedRevision=0;dirty=true;return}
        val saved=remote(AdminLayerControl.getDraft(row.id,"device",r.owner.deviceId,Identity.random()),access) as? AdminLayerDraft ?:fail("INVALID_REPLY")
        if(saved.revision!=row.revision)fail("CONFLICT")
        savedRevision=saved.revision;dirty=text()!=saved.proposal.wireJson()
    }
    private fun open(command:Command,access:Access) {
        require(command.device.matches(Regex("[A-Za-z0-9_-]{1,64}")))
        clearReview();clearComparison();activeOperation=null;publishedRevision=0
        val owned=admitted(access)
        record=null;base=null;head=null;savedRevision=null;dirty=true
        val recovered=try {store.recoverOwned(owned.serviceHash,owned.actor,owned.legacyServiceHash)}catch(e:AdminEditorStorageException) {
            // A foreign owner is opaque. Only explicit create below may ask the
            // Store to consume a closed tombstone; active records remain intact.
            if(e.reason!=AdminEditorStorageFailure.OWNER_MISMATCH)throw e
            null
        }
        admitted(access)
        if(recovered!=null) {
            record=recovered;base=null;head=null;savedRevision=null;dirty=true
            if(recovered.pending!=null){phase=AdminEditorPhase.UNCERTAIN;return}
            if(recovered.owner.deviceId!=command.device){phase=AdminEditorPhase.CONFLICT;error="OTHER_DRAFT_OPEN";return}
            head=currentInventory(command.device,access)
            loadSavedRevision(access)
            val candidate=try {proposal()}catch(_:Failure){phase=AdminEditorPhase.LOCAL_DIRTY;error="INVALID_PROPOSAL";return}
            val captured=capturedBase(candidate,access)
            phase=if(captured.revision!=head?.revision || captured.hash!=head?.hash)AdminEditorPhase.CONFLICT else if(dirty)AdminEditorPhase.LOCAL_DIRTY else AdminEditorPhase.EDITING
            return
        }
        record=null;base=null;head=currentInventory(command.device,access);savedRevision=null
        val current=checkNotNull(head)
        if(current.revision==0L){phase=AdminEditorPhase.INVENTORY;return}
        val draftId="mobile-"+Identity.random()
        val candidate=AdminLayerControl.newDeviceDraft(current,draftId,current.approvalUntilMs)
        val owner=AdminEditorOwner(owned.serviceHash,owned.actor,command.device,draftId)
        val bytes=candidate.wireJson().toByteArray(Charsets.UTF_8)
        try {
            record=try {store.create(owner,bytes)}catch(e:AdminEditorStorageException) {
                if(e.reason==AdminEditorStorageFailure.ALREADY_EXISTS)fail("ACCESS_DENIED")
                throw e
            }
            admitted(access)
        }finally {bytes.fill(0)}
        base=current;savedRevision=0;dirty=true;phase=AdminEditorPhase.EDITING
    }
    private fun persistPrepared(candidate:AdminLayerProposal,access:Access) {
        if(candidate.wireJson()==text())return
        val bytes=candidate.wireJson().toByteArray(Charsets.UTF_8)
        try {access.check();record=store.edit(checkNotNull(record),bytes);admitted(access)}finally {bytes.fill(0)}
    }
    private fun prepared(access:Access,forSave:Boolean):AdminLayerProposal {
        if(record?.pending!=null)fail("PENDING")
        val candidate=proposal();val captured=capturedBase(candidate,access)
        if(head?.let {it.revision!=captured.revision || it.hash!=captured.hash}==true)fail("CONFLICT")
        if(savedRevision==null)loadSavedRevision(access)
        val saved=checkNotNull(savedRevision)
        val expected=if(!forSave && !dirty && saved>0)saved-1 else saved
        val result=AdminLayerControl.prepareDeviceDraft(captured,candidate,checkNotNull(record).owner.draftId,expected)
        persistPrepared(result,access)
        return result
    }
    private fun pending(request:AdminLayerRequest,access:Access) {
        clearOutcome()
        comparisonCache=null
        if(request.action!=AdminLayerAction.PREVIEW)preparedDiff=null
        val r=checkNotNull(record);val body=request.bodyBytes();val replay=AdminLayerControl.replayContext(request,ownedActor,ownedOrigin)
        val action=when(request.action) {
            AdminLayerAction.DRAFT_PUT->"layers.draft.put";AdminLayerAction.DRAFT_DISCARD->"layers.draft.discard"
            AdminLayerAction.PREVIEW->"preview.request";AdminLayerAction.PUBLISH->"publish";else->fail("INVALID_REPLY")
        }
        try {admitted(access);record=store.preparePending(r,action,request.requestId,body,replay);admitted(access);activeOperation=request}
        finally {body.fill(0);replay.fill(0)}
    }
    private fun restore(access:Access):AdminLayerRequest {
        admitted(access);val r=checkNotNull(record);val p=r.pending ?:fail("UNAVAILABLE")
        val bytes=p.body;val replay=p.replayContext
        return try {
            val retained=activeOperation
            if(retained!=null && retained.requestId==p.requestId && retained.bodyBytes().contentEquals(bytes) &&
                AdminLayerControl.replayContext(retained,ownedActor,ownedOrigin).contentEquals(replay))return retained
            AdminLayerControl.restoreRequest(bytes,replay,text(),ownedActor,ownedOrigin).also {
            val short=when(it.action){AdminLayerAction.DRAFT_PUT->"layers.draft.put";AdminLayerAction.DRAFT_DISCARD->"layers.draft.discard";AdminLayerAction.PREVIEW->"preview.request";AdminLayerAction.PUBLISH->"publish";else->fail("INVALID_REPLY")}
            if(short!=p.action || it.requestId!=p.requestId)fail("INVALID_REPLY")
        }}finally {bytes.fill(0);replay.fill(0)}
    }
    private fun resolve(proposal:String,access:Access) {
        val r=checkNotNull(record);val p=r.pending ?:fail("UNAVAILABLE");val bytes=proposal.toByteArray(Charsets.UTF_8)
        try {admitted(access);record=store.resolve(r,p.requestId,p.bodySha256,bytes);admitted(access);activeOperation=null}finally {bytes.fill(0)}
    }
    private fun operationBinding():String {
        val r=record ?:return "";val p=r.pending ?:return ""
        return Identity.hash(("syn443.admin-editor.operation.v1\u0000"+documentBinding()+"\u0000"+p.action+"\u0000"+p.requestId+"\u0000"+
            p.bodySha256+"\u0000"+ownedService+"\u0000"+ownedActor+"\u0000"+ownedOrigin+"\u0000"+ownedBoot+"\u0000"+ownedSessionUntil).toByteArray(Charsets.UTF_8))
    }
    private fun readCurrentAfterAcknowledgement(access:Access) {
        clearReview();clearComparison();activeOperation=null;sealBinding="";dirty=true;savedRevision=null;base=null;head=null
        val r=checkNotNull(record)
        head=currentInventory(r.owner.deviceId,access);loadSavedRevision(access)
        val candidate=proposal();val original=capturedBase(candidate,access)
        phase=if(head?.let {it.revision!=original.revision || it.hash!=original.hash}==true)AdminEditorPhase.CONFLICT else AdminEditorPhase.LOCAL_DIRTY
        error=if(phase==AdminEditorPhase.CONFLICT)"CONFIGURATION_CONFLICT" else "REVIEW_REQUIRED"
    }
    private fun checkOutcome(command:Command,seal:Boolean,access:Access) {
        val captured=checkNotNull(record);val p=captured.pending ?:fail("UNAVAILABLE")
        admitted(access)
        val binding=operationBinding()
        if(command.operationBinding!=binding || binding.isEmpty())fail("CONFLICT")
        if(seal && (sealBinding!=binding || operationOutcome!="UNKNOWN"))fail("OUTCOME_CHECK_REQUIRED")
        sameStoredRecord(captured,access)
        val restored=restore(access)
        val request=AdminOperationReconcile.request(restored,ownedActor,ownedOrigin,Identity.random(),
            if(seal)AdminOperationIntent.SEAL_IF_ABSENT else AdminOperationIntent.LOOKUP)
        if(seal && request.originalVersion!=2)fail("OUTCOME_CHECK_REQUIRED")
        clearReview();clearComparison();sealBinding=""
        val reply=access.reconcile(request);val owned=admitted(access)
        sameStoredRecord(captured,access)
        if(record!=captured || operationBinding()!=binding || reply.requestId!=p.requestId || reply.bodyHash!=p.bodySha256)fail("CONFLICT")
        // Every historical poll from this point keeps the replay-only context,
        // even when this process still remembers the original fresh request.
        activeOperation=request.original
        operationOutcome=reply.outcome.name
        when(reply.outcome) {
            AdminOperationOutcome.UNKNOWN->{
                phase=AdminEditorPhase.UNCERTAIN;error="OUTCOME_UNKNOWN"
                if(request.originalVersion==2)sealBinding=binding
            }
            AdminOperationOutcome.NO_EFFECT->{resolve(text(),access);readCurrentAfterAcknowledgement(access)}
            AdminOperationOutcome.RECORDED_RESULT_UNAVAILABLE->{phase=AdminEditorPhase.UNCERTAIN;error="RESULT_UNAVAILABLE"}
            AdminOperationOutcome.RECORDED->{
                val job=reply.job
                when {
                    job==null->{resolve(text(),access);readCurrentAfterAcknowledgement(access)}
                    job.state==AdminOperationJobState.LEGACY_APPLIED->{phase=AdminEditorPhase.UNCERTAIN;error="RESULT_UNAVAILABLE"}
                    job.state in setOf(AdminOperationJobState.QUEUED,AdminOperationJobState.RUNNING)->{phase=AdminEditorPhase.UNCERTAIN;error="BUSY"}
                    else->{val historical=AdminOperationReconcile.historicalJob(request,reply,owned.time) ?:fail("INVALID_REPLY")
                        admitted(access);sameStoredRecord(captured,access);result(historical,access)
                        if(phase!=AdminEditorPhase.PUBLISHED){dirty=true;savedRevision=null}
                    }
                }
            }
        }
    }
    private fun result(reply:AdminLayerReply,access:Access) {
        when(reply) {
            is AdminLayerDraft->{resolve(reply.proposal.wireJson(),access);savedRevision=reply.revision;dirty=false;phase=AdminEditorPhase.EDITING}
            is AdminLayerDiscarded->{resolve(text(),access);record=store.close(checkNotNull(record));admitted(access);clearRam();phase=AdminEditorPhase.INVENTORY}
            is AdminLayerJob->when(reply.state) {
                "queued","running"->{phase=AdminEditorPhase.UNCERTAIN;error="BUSY"}
                "ready"->{
                    val checked=reply.preview ?:fail("INVALID_REPLY")
                    resolve(text(),access)
                    if(checked.replayOnly){clearReview();clearComparison();phase=AdminEditorPhase.LOCAL_DIRTY;error="REVIEW_REQUIRED"}
                    else {
                        val deadline=access.reviewDeadline(checked);val owned=admitted(access)
                        if(deadline<=elapsed() || deadline>owned.sessionUntilElapsedMs)fail("REVIEW_EXPIRED")
                        preview=checked;reviewDeadline=deadline;reviewBoot=boot();reviewDocument=documentBinding()
                        reviewBinding=Identity.hash(("syn443.admin-editor.review.v1\u0000"+checked.previewId+"\u0000"+Identity.hash(checked.ticket.toByteArray(Charsets.UTF_8))+"\u0000"+reviewDocument+"\u0000"+reviewBoot+"\u0000"+deadline).toByteArray(Charsets.UTF_8))
                        val recipientsJson=JSONObject(checked.wireJson()).getJSONObject("preview").getJSONArray("recipients")
                        recipients=(0 until recipientsJson.length()).map {recipientsJson.getJSONObject(it).getString("device")}
                        diffs=overrideSummary();phase=AdminEditorPhase.REVIEW
                        val prepared=preparedDiff
                        if(prepared!=null && prepared.proposalHash==proposalHash())
                            comparisonCache=cache(null,prepared.diff,prepared.current,prepared.saved,owned,true,reviewBinding,deadline)
                        else comparisonCache=null
                        preparedDiff=null
                    }
                }
                "published"->{
                    val revision=reply.heads.singleOrNull {it.device==record?.owner?.deviceId}?.revision ?:fail("INVALID_REPLY")
                    resolve(text(),access);publishedRevision=revision;clearReview();clearComparison();phase=AdminEditorPhase.PUBLISHED;error=""
                }
                "rejected","expired","cancelled"->{
                    resolve(text(),access);clearReview();clearComparison()
                    phase=if(reply.error=="configuration_conflict")AdminEditorPhase.CONFLICT else AdminEditorPhase.LOCAL_DIRTY
                    error=when(reply.error){"configuration_conflict"->"CONFIGURATION_CONFLICT";"configuration_denied"->"ACCESS_DENIED";"deadline_or_retry_limit"->"REVIEW_EXPIRED";""->"REVIEW_REQUIRED";else->"INVALID_REPLY"}
                }
                else->fail("INVALID_REPLY")
            }
            else->fail("INVALID_REPLY")
        }
    }
    private fun overrideSummary():List<String> {
        val rows=JSONObject(proposal().wireJson()).getJSONArray("bundles").getJSONObject(0).getJSONArray("layers")
        val all=ArrayList<String>()
        for(i in 0 until rows.length()) {
            val layer=rows.getJSONObject(i);if(layer.getString("kind") !in setOf("device","local"))continue
            val changes=layer.optJSONArray("changes") ?:continue
            for(j in 0 until changes.length()){val c=changes.getJSONObject(j);all+="${layer.getString("kind")}: ${c.getString("path")} (${c.getString("operation")})"}
        }
        return if(all.size<=64)all else all.take(63)+"Ещё ${all.size-63} переопределений; сверяйте полное предложение."
    }
    private fun proposalHash()=Identity.hash(text().toByteArray(Charsets.UTF_8))
    private fun cache(value:AdminLayerComparison?,diff:AdminLayerDiff?,current:AdminLayerInventory,saved:Long,owned:AdminLayerOwnership,
        readOnly:Boolean,review:String="",deadline:Long=0):ComparisonCache {
        val r=checkNotNull(record);require(r.pending==null)
        val document=documentBinding();val hash=proposalHash()
        val resolutions=value?.conflicts?.sortedBy {it.id}?.joinToString("\u0000"){it.id+"="+(it.resolution?.choice?:"")}?:""
        val bodyHash=value?.proposal?.let {Identity.hash(it.wireJson().toByteArray(Charsets.UTF_8))}?:hash
        val facts=if(readOnly)Identity.hash(current.wireJson().toByteArray(Charsets.UTF_8)) else AdminLayerComparison.configurationBinding(current)
        val source=value?.binding?:Identity.hash(("prepared-diff\u0000"+hash+"\u0000"+facts+"\u0000"+checkNotNull(diff).beforeJson()+"\u0000"+diff.afterJson()).toByteArray(Charsets.UTF_8))
        val binding=Identity.hash(("syn443.admin-editor.comparison.v1\u0000"+source+"\u0000"+resolutions+"\u0000"+bodyHash+"\u0000"+
            document+"\u0000"+r.revision+"\u0000"+owned.serviceHash+"\u0000"+owned.actor+"\u0000"+owned.apiOrigin+"\u0000"+owned.bootCount+"\u0000"+
            owned.sessionUntilElapsedMs+"\u0000"+readOnly+"\u0000"+review+"\u0000"+deadline).toByteArray(Charsets.UTF_8))
        return ComparisonCache(value,diff,current,facts,base?.revision?:current.revision,saved,r.revision,document,hash,owned.serviceHash,owned.actor,owned.apiOrigin,
            owned.bootCount,owned.sessionUntilElapsedMs,binding,readOnly,review,deadline)
    }
    private fun sameStoredRecord(expected:AdminEditorRecord,access:Access) {
        val actual=store.load(expected.owner);admitted(access)
        if(actual!=expected){clearComparison();fail("COMPARISON_STALE")}
    }
    private fun currentComparison(access:Access):ComparisonCache {
        val owned=admitted(access);val c=comparisonCache ?:fail("COMPARISON_STALE")
        val r=record ?:fail("COMPARISON_STALE")
        if(r.pending!=null || r.revision!=c.localRevision || documentBinding()!=c.document || proposalHash()!=c.proposalHash ||
            owned.serviceHash!=c.service || owned.actor!=c.actor || owned.apiOrigin!=c.origin || owned.bootCount!=c.boot || owned.sessionUntilElapsedMs!=c.sessionUntil) {
            clearComparison();fail("COMPARISON_STALE")
        }
        sameStoredRecord(r,access)
        if(comparisonCache!==c)fail("COMPARISON_STALE")
        return c
    }
    private fun comparisonSelected(command:ComparisonCommand):AdminEditorRecord=selected(Command(Kind.COMPARE,command.device,command.documentBinding,command.localRevision))
    private fun freshComparison(command:ComparisonCommand,access:Access):ComparisonCache {
        val r=comparisonSelected(command);if(r.pending!=null)fail("PENDING")
        sameStoredRecord(r,access);clearReview();clearComparison()
        val candidate=proposal();val bundle=scope(candidate,r)
        val current=currentInventory(r.owner.deviceId,access)
        val revision=bundle.getLong("baseRevision");val hash=bundle.getString("baseHash")
        val captured=if(current.revision==revision && current.hash==hash)current else
            remote(AdminLayerControl.history(r.owner.deviceId,revision,hash,Identity.random()),access) as? AdminLayerInventory ?:fail("INVALID_REPLY")
        loadSavedRevision(access);val saved=checkNotNull(savedRevision)
        val value=AdminLayerComparison.compareDeviceDraft(captured,current,candidate,r.owner.draftId,saved)
        sameStoredRecord(r,access)
        val owned=admitted(access);base=captured;head=current
        return cache(value,value.diff,current,saved,owned,false).also {comparisonCache=it}
    }
    private fun row(c:ComparisonCache,section:AdminComparisonSection,index:Int):AdminComparisonRow {
        val sides=ArrayList<AdminComparisonSide>()
        return if(section==AdminComparisonSection.CONFLICTS) {
            val item=checkNotNull(c.comparison).conflicts[index]
            if(item.baseJson()!=null)sides+=AdminComparisonSide.BASE
            if(item.localJson()!=null)sides+=AdminComparisonSide.LOCAL_VALUE
            if(item.currentJson()!=null)sides+=AdminComparisonSide.CURRENT
            AdminComparisonRow(item.id,item.kind,item.path,item.code,item.resolvable,item.resolution?.choice?:"",sides)
        } else {
            val item=checkNotNull(c.diff).entries[index]
            if(item.beforeJson()!=null)sides+=AdminComparisonSide.BEFORE
            if(item.afterJson()!=null)sides+=AdminComparisonSide.AFTER
            if(item.beforeOriginJson()!=null)sides+=AdminComparisonSide.BEFORE_ORIGIN
            if(item.afterOriginJson()!=null)sides+=AdminComparisonSide.AFTER_ORIGIN
            val id=Identity.hash((c.binding+"\u0000DIFF\u0000"+index+"\u0000"+item.path+"\u0000"+item.kind).toByteArray(Charsets.UTF_8))
            val code=when {item.beforeJson()==null->"ADDED";item.afterJson()==null->"REMOVED";item.beforeJson()!=item.afterJson()->"VALUE_CHANGED";else->"ORIGIN_CHANGED"}
            AdminComparisonRow(id,item.kind,item.path,code,availableSides=sides)
        }
    }
    private fun comparisonModel(c:ComparisonCache,section:AdminComparisonSection,offset:Int,detail:AdminComparisonDetail?=null):AdminComparisonModel {
        val total=if(section==AdminComparisonSection.CONFLICTS)c.comparison?.conflicts?.size?:0 else c.diff?.entries?.size?:0
        require(offset in 0..total)
        val rows=(offset until minOf(offset+20,total)).map {row(c,section,it)}
        return AdminComparisonModel(device=checkNotNull(record).owner.deviceId,binding=c.binding,localRevision=c.localRevision,section=section,
            total=total,offset=offset,rows=rows,ready=!c.readOnly && c.comparison?.ready==true,detail=detail,readOnly=c.readOnly,
            baseRevision=c.baseRevision,currentRevision=c.current.revision)
    }
    private fun detailText(c:ComparisonCache,section:AdminComparisonSection,index:Int,side:AdminComparisonSide):String? {
        return if(section==AdminComparisonSection.CONFLICTS) {
            val item=checkNotNull(c.comparison).conflicts[index]
            when(side){AdminComparisonSide.BASE->item.baseJson();AdminComparisonSide.LOCAL_VALUE->item.localJson();AdminComparisonSide.CURRENT->item.currentJson();else->null}
        } else {
            val item=checkNotNull(c.diff).entries[index]
            when(side){AdminComparisonSide.BEFORE->item.beforeJson();AdminComparisonSide.AFTER->item.afterJson();AdminComparisonSide.BEFORE_ORIGIN->item.beforeOriginJson();AdminComparisonSide.AFTER_ORIGIN->item.afterOriginJson();else->null}
        }
    }
    fun comparison(command:ComparisonCommand,access:Access):AdminComparisonModel {
        worker()
        try {
            admitted(access)
            require(command.offset>=0 && command.page in 0..255)
            val c=if(command.kind==ComparisonKind.LOAD)freshComparison(command,access) else {
                comparisonSelected(command)
                currentComparison(access).also {if(command.comparisonBinding!=it.binding)fail("COMPARISON_STALE")}
            }
            val result=when(command.kind) {
                ComparisonKind.LOAD,ComparisonKind.PAGE->comparisonModel(c,command.section,command.offset)
                ComparisonKind.DETAIL->{
                    require(command.page in 0..255)
                    val model=comparisonModel(c,command.section,command.offset)
                    val position=model.rows.indexOfFirst {it.id==command.rowId}
                    if(position<0 || command.side !in model.rows[position].availableSides)fail("COMPARISON_STALE")
                    val value=detailText(c,command.section,command.offset+position,command.side) ?:fail("COMPARISON_STALE")
                    val chunks=pages(value);require(command.page<chunks.size)
                    val detail=AdminComparisonDetail(command.rowId,command.side,command.page,chunks.size,chunks[command.page])
                    comparisonModel(c,command.section,command.offset,detail)
                }
                ComparisonKind.RESOLVE->{
                    if(c.readOnly)fail("COMPARISON_READ_ONLY")
                    val before=comparisonModel(c,command.section,command.offset)
                    if(before.rows.none {it.id==command.rowId})fail("COMPARISON_STALE")
                    val value=checkNotNull(c.comparison)
                    val choice=when(command.choice){"LOCAL"->AdminLayerResolution.KEEP_LOCAL;"CURRENT"->AdminLayerResolution.CURRENT;else->fail("INVALID_COMPARISON")}
                    val next=AdminLayerComparison.resolveDeviceDraft(value,mapOf(command.rowId to choice))
                    val owned=admitted(access);sameStoredRecord(checkNotNull(record),access)
                    if(comparisonCache!==c)fail("COMPARISON_STALE")
                    val updated=cache(next,next.diff,c.current,c.saved,owned,false).also {comparisonCache=it}
                    val total=if(command.section==AdminComparisonSection.CONFLICTS)next.conflicts.size else next.diff?.entries?.size?:0
                    comparisonModel(updated,command.section,minOf(command.offset,total))
                }
            }
            currentComparison(access)
            return result
        }catch(e:Exception) {
            val code=when(e){is Failure->e.code;is AdminException->e.reason.name;is AdminEditorStorageException->"STORAGE_"+e.reason.name;else->"INVALID_COMPARISON"}
            if(code in setOf("REAUTHENTICATE","SESSION_EXPIRED","CANCELLED"))clearComparison()
            return AdminComparisonModel(error=code)
        }
    }
    fun comparisonSnapshot(access:Access):AdminComparisonModel? {
        worker();admitted(access)
        if(comparisonCache==null)return null
        val c=currentComparison(access)
        return comparisonModel(c,if(c.readOnly)AdminComparisonSection.DIFF else AdminComparisonSection.CONFLICTS,0)
    }
    private fun rebase(command:Command,access:Access) {
        val c=currentComparison(access)
        if(command.comparisonBinding!=c.binding)fail("COMPARISON_STALE")
        if(c.readOnly)fail("COMPARISON_READ_ONLY")
        val candidate=c.comparison?.takeIf {it.ready}?.proposal ?:fail("COMPARISON_REQUIRED")
        val r=checkNotNull(record)
        val current=currentInventory(r.owner.deviceId,access)
        if(AdminLayerComparison.configurationBinding(current)!=c.currentFacts) {
            head=current;clearComparison();fail("COMPARISON_STALE")
        }
        loadSavedRevision(access)
        if(savedRevision!=c.saved){clearComparison();fail("COMPARISON_STALE")}
        currentComparison(access)
        if(comparisonCache!==c)fail("COMPARISON_STALE")
        // Only the exact explicitly confirmed candidate is written. No remote
        // mutation, new preview or automatic choice follows this local CAS.
        clearReview();clearComparison();persistPrepared(candidate,access)
        base=current;head=current;savedRevision=c.saved;dirty=true;phase=AdminEditorPhase.LOCAL_DIRTY
    }
    fun execute(command:Command,access:Access):AdminEditorModel {
        worker();error=""
        try {
            admitted(access)
            if(command.kind==Kind.OPEN)open(command,access) else {
                val r=selected(command)
                if(command.kind !in setOf(Kind.POLL,Kind.RETRY_EXACT,Kind.CHECK_OUTCOME,Kind.SEAL_PENDING) && r.pending!=null)fail("PENDING")
                if(command.kind !in setOf(Kind.CHECK_OUTCOME,Kind.SEAL_PENDING))clearOutcome()
                when(command.kind) {
                    Kind.OPEN->Unit
                    Kind.SAVE_LOCAL->{
                        require(command.pages.size<=64 && command.pages.all {it.length<=8192 && editorUnicode(it)})
                        val raw=command.pages.joinToString("");val bytes=raw.toByteArray(Charsets.UTF_8)
                        try {require(bytes.size<=AdminEditorStore.MAX_TEXT);clearReview();clearComparison();record=store.edit(r,bytes);admitted(access)}finally {bytes.fill(0)}
                        dirty=true;phase=AdminEditorPhase.LOCAL_DIRTY
                    }
                    Kind.SAVE_DRAFT->{clearReview();clearComparison();val candidate=prepared(access,true);val version=mutationVersion(access);val request=AdminLayerControl.saveDraft(checkNotNull(savedRevision),candidate,Identity.random(),version);pending(request,access);result(remote(request,access),access)}
                    Kind.PREVIEW->{
                        clearReview();clearComparison();val candidate=prepared(access,false)
                        val captured=capturedBase(candidate,access)
                        preparedDiff=PreparedDiff(AdminLayerComparison.diffPreparedDeviceDraft(captured,candidate),proposalHash(),captured,checkNotNull(savedRevision))
                        val version=mutationVersion(access)
                        val request=AdminLayerControl.preview(candidate,ownedActor,ownedOrigin,Identity.random(),version);pending(request,access);result(remote(request,access),access)
                    }
                    Kind.PUBLISH->{
                        val checked=preview ?:fail("REVIEW_EXPIRED");admitted(access)
                        if(phase!=AdminEditorPhase.REVIEW || command.reviewBinding!=reviewBinding || command.reviewDeadline!=reviewDeadline || reviewDocument!=documentBinding() ||
                            boot()!=reviewBoot || elapsed()>=reviewDeadline || elapsed()<lastElapsed)fail("REVIEW_EXPIRED")
                        val version=mutationVersion(access);val owned=admitted(access)
                        if(preview!==checked || phase!=AdminEditorPhase.REVIEW || command.reviewBinding!=reviewBinding || command.reviewDeadline!=reviewDeadline ||
                            reviewDocument!=documentBinding() || boot()!=reviewBoot || elapsed()>=reviewDeadline || elapsed()<lastElapsed)fail("REVIEW_EXPIRED")
                        val request=AdminLayerControl.publish(checked,owned.actor,owned.apiOrigin,Identity.random(),owned.time,version)
                        clearReview();pending(request,access);result(remote(request,access),access)
                    }
                    Kind.POLL->{val operation=restore(access);if(operation.action !in setOf(AdminLayerAction.PREVIEW,AdminLayerAction.PUBLISH))fail("NO_JOB");result(remote(AdminLayerControl.poll(operation,Identity.random()),access),access)}
                    Kind.RETRY_EXACT->{val operation=restore(access);clearReview();result(remote(operation,access),access)}
                    Kind.CHECK_OUTCOME->checkOutcome(command,false,access)
                    Kind.SEAL_PENDING->checkOutcome(command,true,access)
                    Kind.COMPARE->fail("COMPARISON_REQUIRED")
                    Kind.REBASE->rebase(command,access)
                    Kind.CLOSE->{clearReview();record=store.close(r);admitted(access);clearRam();phase=AdminEditorPhase.INVENTORY}
                }
            }
            admitted(access)
            return model()
        }catch(e:Exception) {
            clearReview()
            val code=when(e) {
                is Failure->e.code;is AdminException->e.reason.name
                is AdminEditorStorageException->when(e.reason){AdminEditorStorageFailure.STALE->"CONFLICT";AdminEditorStorageFailure.OWNER_MISMATCH->"ACCESS_DENIED";else->"STORAGE_"+e.reason.name}
                else->"INVALID_PROPOSAL"
            }
            error=code
            if(code in setOf("REAUTHENTICATE","SESSION_EXPIRED","CANCELLED")){activeOperation=null;clearComparison();clearOutcome()}
            if(e is AdminEditorStorageException && e.reason==AdminEditorStorageFailure.OWNER_MISMATCH)clearRam()
            phase=when {
                code in setOf("REAUTHENTICATE","SESSION_EXPIRED","CANCELLED")->AdminEditorPhase.NEEDS_REAUTH
                record?.pending!=null->AdminEditorPhase.UNCERTAIN
                code in setOf("CONFLICT","CONFIGURATION_CONFLICT","COMPARISON_STALE")->AdminEditorPhase.CONFLICT
                code in setOf("INVALID_PROPOSAL","INVALID_CONFIGURATION","REVIEW_EXPIRED","REVIEW_REQUIRED")->AdminEditorPhase.LOCAL_DIRTY
                code in setOf("LIMITED","NO_JOB","REBASE_REQUIRED","COMPARISON_REQUIRED","COMPARISON_READ_ONLY")->AdminEditorPhase.LIMITED
                else->AdminEditorPhase.UNAVAILABLE
            }
            return model(phase!=AdminEditorPhase.NEEDS_REAUTH)
        }
    }
    fun snapshot(access:Access):AdminEditorModel {
        worker();admitted(access);return model()
    }
    private fun pages(raw:String):List<String> {
        if(raw.isEmpty())return listOf("")
        val pages=ArrayList<String>();var start=0
        while(start<raw.length){var end=minOf(start+8192,raw.length);if(end<raw.length && raw[end-1].isHighSurrogate())end--;require(end>start);pages+=raw.substring(start,end);start=end}
        require(pages.size<=64);return pages
    }
    private fun model(showBody:Boolean=true):AdminEditorModel {
        val current=record
        val body=if(showBody && current!=null)text() else ""
        val privateRevision=if(body.isEmpty())0 else try {AdminLayerControl.proposal(body).draftRevision}catch(_:Exception){0}
        val parents=if(showBody)base?.let {inventory->
            val rows=JSONObject(inventory.wireJson()).getJSONArray("layers")
            (0 until rows.length()).map {i->val row=rows.getJSONObject(i);AdminEditorParent(row.getString("kind"),row.getString("id"),row.getLong("revision"))}
        }.orEmpty() else emptyList()
        return AdminEditorModel(device=current?.owner?.deviceId ?:head?.device ?:"",privateDraftRevision=privateRevision,
            desiredHeadRevision=maxOf(publishedRevision,head?.revision ?:base?.currentRevision ?:0),localRevision=current?.revision ?:0,phase=phase,
            readOnly=phase in setOf(AdminEditorPhase.PUBLISHED,AdminEditorPhase.LIMITED,AdminEditorPhase.UNAVAILABLE),
            unassigned=head?.revision==0L,documentBinding=documentBinding(),pages=if(current!=null && showBody)pages(body) else emptyList(),parents=parents,
            reviewBinding=reviewBinding,reviewDeadlineElapsed=reviewDeadline,recipients=recipients,diffSummaries=diffs,error=error,
            comparisonBinding=if(showBody)comparisonCache?.binding?:"" else "",
            operationBinding=if(showBody)operationBinding() else "",operationOutcome=if(showBody)operationOutcome else "",
            canSeal=showBody && sealBinding.isNotEmpty() && sealBinding==operationBinding() && operationOutcome=="UNKNOWN" && phase==AdminEditorPhase.UNCERTAIN)
    }
}
