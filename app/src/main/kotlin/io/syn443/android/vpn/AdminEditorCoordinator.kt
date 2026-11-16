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
    enum class Kind { OPEN, SAVE_LOCAL, SAVE_DRAFT, PREVIEW, PUBLISH, POLL, RETRY_EXACT, COMPARE, REBASE, CLOSE }
    class Command(val kind:Kind,val device:String="",val binding:String="",val localRevision:Long=0,
        pages:List<String> = emptyList(),val reviewBinding:String="",val reviewDeadline:Long=0) {
        val pages:List<String> = Collections.unmodifiableList(ArrayList(pages))
        override fun toString()="AdminEditorCommand([redacted])"
    }
    interface Access {
        fun ownership():AdminLayerOwnership
        fun action(request:AdminLayerRequest):AdminLayerReply
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
    private fun worker() {
        if(Looper.myLooper()==Looper.getMainLooper() || Thread.currentThread().name.startsWith("Binder:"))
            throw AdminEditorStorageException(AdminEditorStorageFailure.WRONG_THREAD)
    }
    private fun fail(code:String):Nothing=throw Failure(code)
    private fun clearReview() {preview=null;reviewBinding="";reviewDeadline=0;reviewBoot=-1;reviewDocument="";recipients=emptyList();diffs=emptyList()}
    private fun clearRam() {record=null;base=null;head=null;savedRevision=null;dirty=true;publishedRevision=0;activeOperation=null;clearReview();ownedService="";ownedActor="";ownedOrigin="";ownedBoot=-1;ownedSessionUntil=-1;lastElapsed=-1}
    private fun admitted(access:Access):AdminLayerOwnership {
        access.check();val owned=access.ownership();access.check()
        val now=elapsed()
        if(owned.bootCount!=boot() || now<owned.observedElapsedMs || now>=owned.sessionUntilElapsedMs || now<0 || now<lastElapsed)
            fail("REAUTHENTICATE")
        if(ownedService.isNotEmpty() && (owned.serviceHash!=ownedService || owned.actor!=ownedActor || owned.apiOrigin!=ownedOrigin || owned.bootCount!=ownedBoot)) {
            clearRam();fail("REAUTHENTICATE")
        }
        if(ownedSessionUntil>=0 && ownedSessionUntil!=owned.sessionUntilElapsedMs){clearReview();activeOperation=null}
        ownedSessionUntil=owned.sessionUntilElapsedMs
        ownedService=owned.serviceHash;ownedActor=owned.actor;ownedOrigin=owned.apiOrigin;ownedBoot=owned.bootCount;lastElapsed=now
        return owned
    }
    private fun remote(request:AdminLayerRequest,access:Access):AdminLayerReply {
        admitted(access);val reply=access.action(request);admitted(access);return reply
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
        clearReview();activeOperation=null;publishedRevision=0
        val owned=admitted(access)
        val recovered=store.recoverOwned(owned.serviceHash,owned.actor);admitted(access)
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
        try {record=store.create(owner,bytes);admitted(access)}finally {bytes.fill(0)}
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
    private fun result(reply:AdminLayerReply,access:Access) {
        when(reply) {
            is AdminLayerDraft->{resolve(reply.proposal.wireJson(),access);savedRevision=reply.revision;dirty=false;phase=AdminEditorPhase.EDITING}
            is AdminLayerDiscarded->{resolve(text(),access);record=store.close(checkNotNull(record));admitted(access);clearRam();phase=AdminEditorPhase.INVENTORY}
            is AdminLayerJob->when(reply.state) {
                "queued","running"->{phase=AdminEditorPhase.UNCERTAIN;error="BUSY"}
                "ready"->{
                    val checked=reply.preview ?:fail("INVALID_REPLY")
                    resolve(text(),access)
                    if(checked.replayOnly){clearReview();phase=AdminEditorPhase.LOCAL_DIRTY;error="REVIEW_REQUIRED"}
                    else {
                        val deadline=access.reviewDeadline(checked);val owned=admitted(access)
                        if(deadline<=elapsed() || deadline>owned.sessionUntilElapsedMs)fail("REVIEW_EXPIRED")
                        preview=checked;reviewDeadline=deadline;reviewBoot=boot();reviewDocument=documentBinding()
                        reviewBinding=Identity.hash(("syn443.admin-editor.review.v1\u0000"+checked.previewId+"\u0000"+Identity.hash(checked.ticket.toByteArray(Charsets.UTF_8))+"\u0000"+reviewDocument+"\u0000"+reviewBoot+"\u0000"+deadline).toByteArray(Charsets.UTF_8))
                        val recipientsJson=JSONObject(checked.wireJson()).getJSONObject("preview").getJSONArray("recipients")
                        recipients=(0 until recipientsJson.length()).map {recipientsJson.getJSONObject(it).getString("device")}
                        diffs=overrideSummary();phase=AdminEditorPhase.REVIEW
                    }
                }
                "published"->{
                    val revision=reply.heads.singleOrNull {it.device==record?.owner?.deviceId}?.revision ?:fail("INVALID_REPLY")
                    resolve(text(),access);publishedRevision=revision;clearReview();phase=AdminEditorPhase.PUBLISHED;error=""
                }
                "rejected","expired","cancelled"->{
                    resolve(text(),access);clearReview()
                    phase=if(reply.error=="configuration_conflict")AdminEditorPhase.CONFLICT else AdminEditorPhase.LOCAL_DIRTY
                    error=when(reply.error){"configuration_conflict"->"CONFIGURATION_CONFLICT";"configuration_denied"->"ACCESS_DENIED";""->"REVIEW_REQUIRED";else->"INVALID_REPLY"}
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
    fun execute(command:Command,access:Access):AdminEditorModel {
        worker();error=""
        try {
            admitted(access)
            if(command.kind==Kind.OPEN)open(command,access) else {
                val r=selected(command)
                if(command.kind !in setOf(Kind.POLL,Kind.RETRY_EXACT) && r.pending!=null)fail("PENDING")
                when(command.kind) {
                    Kind.OPEN->Unit
                    Kind.SAVE_LOCAL->{
                        require(command.pages.size<=64 && command.pages.all {it.length<=8192 && editorUnicode(it)})
                        val raw=command.pages.joinToString("");val bytes=raw.toByteArray(Charsets.UTF_8)
                        try {require(bytes.size<=AdminEditorStore.MAX_TEXT);clearReview();record=store.edit(r,bytes);admitted(access)}finally {bytes.fill(0)}
                        dirty=true;phase=AdminEditorPhase.LOCAL_DIRTY
                    }
                    Kind.SAVE_DRAFT->{clearReview();val candidate=prepared(access,true);val request=AdminLayerControl.saveDraft(checkNotNull(savedRevision),candidate,Identity.random());pending(request,access);result(remote(request,access),access)}
                    Kind.PREVIEW->{clearReview();val candidate=prepared(access,false);val request=AdminLayerControl.preview(candidate,ownedActor,ownedOrigin,Identity.random());pending(request,access);result(remote(request,access),access)}
                    Kind.PUBLISH->{
                        val checked=preview ?:fail("REVIEW_EXPIRED");val owned=admitted(access)
                        if(phase!=AdminEditorPhase.REVIEW || command.reviewBinding!=reviewBinding || command.reviewDeadline!=reviewDeadline || reviewDocument!=documentBinding() ||
                            boot()!=reviewBoot || elapsed()>=reviewDeadline || elapsed()<lastElapsed)fail("REVIEW_EXPIRED")
                        val request=AdminLayerControl.publish(checked,owned.actor,owned.apiOrigin,Identity.random(),owned.time)
                        clearReview();pending(request,access);result(remote(request,access),access)
                    }
                    Kind.POLL->{val operation=restore(access);if(operation.action !in setOf(AdminLayerAction.PREVIEW,AdminLayerAction.PUBLISH))fail("NO_JOB");result(remote(AdminLayerControl.poll(operation,Identity.random()),access),access)}
                    Kind.RETRY_EXACT->{val operation=restore(access);clearReview();result(remote(operation,access),access)}
                    Kind.COMPARE->{clearReview();val candidate=proposal();val captured=capturedBase(candidate,access);head=currentInventory(r.owner.deviceId,access);phase=if(head?.revision==captured.revision && head?.hash==captured.hash)AdminEditorPhase.EDITING else AdminEditorPhase.CONFLICT;error=if(phase==AdminEditorPhase.CONFLICT)"CONFIGURATION_CONFLICT" else ""}
                    Kind.REBASE->{clearReview();val candidate=proposal();val captured=capturedBase(candidate,access);head=currentInventory(r.owner.deviceId,access)
                        if(head?.revision!=captured.revision || head?.hash!=captured.hash){phase=AdminEditorPhase.LIMITED;error="REBASE_REQUIRED"}
                        else {if(savedRevision==null)loadSavedRevision(access);persistPrepared(AdminLayerControl.prepareDeviceDraft(captured,candidate,r.owner.draftId,checkNotNull(savedRevision)),access);dirty=true;phase=AdminEditorPhase.LOCAL_DIRTY}}
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
            if(code in setOf("REAUTHENTICATE","SESSION_EXPIRED","CANCELLED"))activeOperation=null
            if(e is AdminEditorStorageException && e.reason==AdminEditorStorageFailure.OWNER_MISMATCH)clearRam()
            phase=when {
                code in setOf("REAUTHENTICATE","SESSION_EXPIRED","CANCELLED")->AdminEditorPhase.NEEDS_REAUTH
                record?.pending!=null->AdminEditorPhase.UNCERTAIN
                code in setOf("CONFLICT","CONFIGURATION_CONFLICT")->AdminEditorPhase.CONFLICT
                code in setOf("INVALID_PROPOSAL","INVALID_CONFIGURATION","REVIEW_EXPIRED","REVIEW_REQUIRED")->AdminEditorPhase.LOCAL_DIRTY
                code in setOf("LIMITED","NO_JOB","REBASE_REQUIRED")->AdminEditorPhase.LIMITED
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
            reviewBinding=reviewBinding,reviewDeadlineElapsed=reviewDeadline,recipients=recipients,diffSummaries=diffs,error=error)
    }
}
