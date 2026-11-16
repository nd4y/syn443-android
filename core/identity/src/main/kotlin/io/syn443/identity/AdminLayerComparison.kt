package io.syn443.identity

import kotlinx.serialization.json.*
import java.util.Collections

enum class AdminLayerResolution(val choice:String) { KEEP_LOCAL("LOCAL"), CURRENT("CURRENT") }

class AdminLayerConflict internal constructor(val id:String,val kind:String,val path:String,val code:String,val resolvable:Boolean,
    val resolution:AdminLayerResolution?,private val base:String?,private val local:String?,private val current:String?) {
    fun baseJson()=base
    fun localJson()=local
    fun currentJson()=current
    override fun toString()="AdminLayerConflict([redacted])"
}
class AdminLayerDifference internal constructor(val path:String,val kind:String,private val before:String?,private val after:String?,
    private val beforeOrigin:String?,private val afterOrigin:String?) {
    fun beforeJson()=before
    fun afterJson()=after
    fun beforeOriginJson()=beforeOrigin
    fun afterOriginJson()=afterOrigin
    override fun toString()="AdminLayerDifference([redacted])"
}
class AdminLayerDiff internal constructor(entries:List<AdminLayerDifference>,private val before:String,private val after:String) {
    val localProjection:Boolean get()=true
    val entries:List<AdminLayerDifference> = Collections.unmodifiableList(ArrayList(entries))
    fun beforeJson()=before
    fun afterJson()=after
    override fun toString()="AdminLayerDiff([redacted])"
}

/** Owned comparison values, not a proof, role, fresh head or publication grant.
 * Conflicts have no public candidate proposal until every permitted choice is
 * explicit. A successful local projection still requires server preview. */
class AdminLayerComparison private constructor(private val inputs:Inputs,private val choices:Map<String,AdminLayerResolution>,
    val proposal:AdminLayerProposal?,val diff:AdminLayerDiff?,conflicts:List<AdminLayerConflict>) {
    val binding:String get()=inputs.binding
    val ready:Boolean get()=proposal!=null && conflicts.all {it.resolvable && it.resolution!=null}
    val conflicts:List<AdminLayerConflict> = Collections.unmodifiableList(ArrayList(conflicts))
    override fun toString()="AdminLayerComparison([redacted])"
    private class Inputs(val base:AdminLayerInventory,val current:AdminLayerInventory,val local:AdminLayerProposal,
        val draftId:String,val saved:Long,val binding:String,val before:AdminLayerProjection)
    private class Row(val doc:AdminLayerJson.Document,val value:JsonObject) {
        val raw get()=doc.raw(value)
    }
    companion object {
        private val v=AdminLayerValues
        private fun <T> checked(block:()->T):T=try {block()}catch(e:AdminException){throw e}catch(_:Exception){throw AdminException(AdminFailure.INVALID_REPLY)}
        private fun layerRows(inventory:AdminLayerInventory)=inventory.document.root.jsonObject.getValue("layers").jsonArray
        private fun effective(inventory:AdminLayerInventory)=inventory.document.root.jsonObject.getValue("effective").jsonObject
        private fun projection(inventory:AdminLayerInventory):AdminLayerProjection {
            val rows=layerRows(inventory);val result=AdminLayerProjector.project(inventory.document,rows,inventory.device)
            val actual=effective(inventory)
            val projected=JsonObject(mapOf("document" to result.document,"fields" to JsonObject(result.fields),"restrictions" to JsonArray(result.restrictions)))
            require(v.lexicalSame(projected,actual))
            return result
        }
        fun compareDeviceDraft(base:AdminLayerInventory,current:AdminLayerInventory,local:AdminLayerProposal,
            expectedDraftId:String,expectedSavedDraftRevision:Long):AdminLayerComparison=checked {
            require(base.revision>0 && current.revision>=base.revision && !current.historical && current.device==base.device)
            require(base.revision!=current.revision || base.hash==current.hash)
            require(v.text(base.document.root.jsonObject.getValue("owner"))==v.text(current.document.root.jsonObject.getValue("owner")))
            require(base.wireJson().toByteArray(Charsets.UTF_8).size<=524_288 && current.wireJson().toByteArray(Charsets.UTF_8).size<=524_288)
            val normalized=AdminLayerControl.prepareDeviceDraft(base,AdminLayerControl.proposal(local.wireJson()),expectedDraftId,expectedSavedDraftRevision)
            projection(base);val before=projection(current)
            val binding=Identity.hash(("syn443.admin-layer-comparison.v1\u0000"+base.wireJson()+"\u0000"+current.wireJson()+"\u0000"+
                local.wireJson()+"\u0000"+expectedDraftId+"\u0000"+expectedSavedDraftRevision).toByteArray(Charsets.UTF_8))
            build(Inputs(base,current,normalized,expectedDraftId,expectedSavedDraftRevision,binding,before),emptyMap())
        }
        fun resolveDeviceDraft(comparison:AdminLayerComparison,choices:Map<String,AdminLayerResolution>):AdminLayerComparison=checked {
            require(choices.size<=2050)
            val allowed=comparison.conflicts.filter {it.resolvable}.map {it.id}.toSet()
            val owned=linkedMapOf<String,AdminLayerResolution>();var count=0
            for((id,value) in choices) {
                require(++count<=2050 && id in allowed && id !in owned && value in AdminLayerResolution.entries)
                owned[id]=value
            }
            build(comparison.inputs,comparison.choices+owned)
        }
        /** Exact same-proposal review only. The logical prior revision validates
         * this value; it is not a readback or inference of the server draft CAS. */
        fun diffPreparedDeviceDraft(base:AdminLayerInventory,prepared:AdminLayerProposal):AdminLayerDiff=checked {
            val normalized=AdminLayerControl.prepareDeviceDraft(base,prepared,prepared.draftId,prepared.draftRevision-1)
            require(normalized.wireJson()==prepared.wireJson())
            val before=projection(base)
            val rows=prepared.document.root.jsonObject.getValue("bundles").jsonArray.single().jsonObject.getValue("layers").jsonArray
            val after=AdminLayerProjector.project(prepared.document,rows,base.device)
            difference(base,prepared,before,after)
        }
        /** Exact configuration facts for readback; periodic policy/report
         * metadata is excluded. This hash is a value binding, never authority. */
        fun configurationBinding(inventory:AdminLayerInventory):String=checked {
            require(!inventory.historical && inventory.revision>0)
            projection(inventory)
            val doc=inventory.document;val root=doc.root.jsonObject
            val values=listOf("device","owner","state","revision","hash","mode","approvalUntilMs","layers","effective")
            val raw=values.joinToString("\u0000","syn443.admin-configuration-facts.v1\u0000"){doc.raw(root.getValue(it))}
            Identity.hash(raw.toByteArray(Charsets.UTF_8))
        }
        private fun difference(current:AdminLayerInventory,candidate:AdminLayerProposal,before:AdminLayerProjection,after:AdminLayerProjection):AdminLayerDiff {
            val differences=ArrayList<AdminLayerDifference>()
            val old=AdminLayerProjector.leaves(before.document);val next=AdminLayerProjector.leaves(after.document)
            for(path in (old.keys+next.keys).sorted())if(!v.same(old[path],next[path]) || before.fields[path]!=after.fields[path])differences+=AdminLayerDifference(path,"setting",old[path]?.let(v::go),next[path]?.let(v::go),before.fields[path]?.let(v::go),after.fields[path]?.let(v::go))
            if(candidate.mode!=current.mode)differences+=AdminLayerDifference("mode","metadata",v.quote(current.mode),v.quote(candidate.mode),null,null)
            if(candidate.approvalUntilMs!=current.approvalUntilMs)differences+=AdminLayerDifference("approvalUntilMs","metadata",current.approvalUntilMs.toString(),candidate.approvalUntilMs.toString(),null,null)
            require(differences.size<=8194)
            return AdminLayerDiff(differences,before.documentJson(),after.documentJson())
        }
        private fun build(input:Inputs,choices:Map<String,AdminLayerResolution>):AdminLayerComparison {
            val conflicts=ArrayList<AdminLayerConflict>()
            val conflictIds=HashMap<String,AdminLayerConflict>()
            fun conflict(kind:String,path:String,code:String,b:String?,l:String?,r:String?,resolvable:Boolean=true):AdminLayerResolution? {
                val id=Identity.hash((input.binding+"\u0000"+kind+"\u0000"+path+"\u0000"+code).toByteArray(Charsets.UTF_8))
                conflictIds[id]?.let {return it.resolution}
                require(conflicts.size<2050)
                val choice=if(resolvable)choices[id] else null
                val value=AdminLayerConflict(id,kind,path,code,resolvable,choice,b,l,r)
                conflicts+=value;conflictIds[id]=value
                return choice
            }
            fun pick(kind:String,path:String,b:Row?,l:Row?,r:Row?):Row?=when {
                v.same(l?.value,b?.value)->r
                v.same(r?.value,b?.value)->l
                v.same(l?.value,r?.value)->r
                else->if(conflict(kind,path,"VALUE_CHANGED",b?.raw,l?.raw,r?.raw)==AdminLayerResolution.KEEP_LOCAL)l else r
            }
            fun indexed(doc:AdminLayerJson.Document,layer:JsonElement?):Map<String,Row> = layer?.jsonObject?.let {l->
                v.rows(l,"changes").associate {c->val row=c.jsonObject;v.text(row.getValue("path")) to Row(doc,row)}
            }.orEmpty()
            val baseLayers=layerRows(input.base).associateBy(v::identity)
            val currentRows=layerRows(input.current);val currentLayers=currentRows.associateBy(v::identity)
            val localBundle=input.local.document.root.jsonObject.getValue("bundles").jsonArray.single().jsonObject
            val localLayers=localBundle.getValue("layers").jsonArray.associateBy(v::identity)
            for(localKind in listOf("device","local"))for(remoteKind in listOf("device","local"))if(localKind!=remoteKind) {
                val localKey=localKind+"/"+input.current.device;val remoteKey=remoteKind+"/"+input.current.device
                val lb=indexed(input.base.document,baseLayers[localKey]);val ll=indexed(input.local.document,localLayers[localKey])
                val rb=indexed(input.base.document,baseLayers[remoteKey]);val rr=indexed(input.current.document,currentLayers[remoteKey])
                val left=(lb.keys+ll.keys).filter {!v.same(lb[it]?.value,ll[it]?.value)}
                val right=(rb.keys+rr.keys).filter {!v.same(rb[it]?.value,rr[it]?.value)}
                for(a in left)for(b in right)if(v.overlaps(a,b) && !(a==b && v.same(ll[a]?.value,rr[b]?.value))) {
                    val root=if(v.contains(a,b))a else b
                    conflict("$localKind->$remoteKind",root,"CROSS_LAYER_OVERLAP",null,ll[a]?.raw,rr[b]?.raw,false)
                }
            }
            val replacements=mutableMapOf<String,String>()
            for(kind in listOf("device","local")) {
                val identity=kind+"/"+input.current.device
                val b=baseLayers[identity];val l=localLayers[identity];val r=currentLayers[identity]
                if(b!=null && r==null){conflict(kind,"","LAYER_REMOVED",null,null,null,false);continue}
                if(l==null){if(r!=null)replacements[identity]=input.current.document.raw(r);continue}
                val bm=indexed(input.base.document,b);val lm=indexed(input.local.document,l);val rm=indexed(input.current.document,r)
                val changedL=(bm.keys+lm.keys).filter {!v.same(bm[it]?.value,lm[it]?.value)}
                val changedR=(bm.keys+rm.keys).filter {!v.same(bm[it]?.value,rm[it]?.value)}
                val roots=ArrayList<String>()
                for(a in changedL)for(c in changedR)if(a!=c && v.overlaps(a,c)) {
                    val root=if(v.contains(a,c))a else c
                    if(roots.none {v.contains(it,root)}){roots.removeAll {v.contains(root,it)};roots+=root}
                }
                val merged=linkedMapOf<String,Row>()
                val covered=HashSet<String>()
                for(root in roots.sorted()) {
                    val keys=(bm.keys+lm.keys+rm.keys).filter {v.contains(root,it)}.sorted();covered+=keys
                    fun sub(map:Map<String,Row>)=keys.mapNotNull {map[it]}
                    fun same(a:List<Row>,c:List<Row>)=a.size==c.size && a.indices.all {v.same(a[it].value,c[it].value)}
                    fun raw(rows:List<Row>)=rows.joinToString(",","[","]"){it.raw}
                    val bs=sub(bm);val ls=sub(lm);val rs=sub(rm)
                    val chosen=when {same(ls,bs)->rs;same(rs,bs)->ls;same(ls,rs)->rs
                        else->if(conflict(kind,root,"OVERLAPPING_PATHS",raw(bs),raw(ls),raw(rs))==AdminLayerResolution.KEEP_LOCAL)ls else rs}
                    for(row in chosen)merged[v.text(row.value.getValue("path"))]=row
                }
                for(path in (bm.keys+lm.keys+rm.keys).sorted())if(path !in covered)pick(kind,path,bm[path],lm[path],rm[path])?.let {merged[path]=it}
                val paths=merged.keys.toList()
                if(paths.indices.any {i->paths.indices.any {j->i!=j && v.overlaps(paths[i],paths[j])}}) {
                    conflict(kind,"","INVALID_OVERLAP",null,null,null,false);continue
                }
                if(merged.size>256){conflict(kind,"","LIMIT",null,null,null,false);continue}
                val unchanged=r!=null && rm.keys==merged.keys && rm.all {(path,row)->v.same(row.value,merged.getValue(path).value)}
                if(unchanged)replacements[identity]=input.current.document.raw(checkNotNull(r))
                else {
                    val revision=if(r==null)1 else v.n(r.jsonObject.getValue("revision"))+1
                    if(revision>v.MAX){conflict(kind,"","LIMIT",null,null,null,false);continue}
                    replacements[identity]=v.rawObject("id" to v.quote(input.current.device),"kind" to v.quote(kind),"priority" to "0","revision" to revision.toString(),
                        "changes" to merged.values.joinToString(",","[","]"){it.raw},"permissions" to (r?.let {input.current.document.raw(it.jsonObject.getValue("permissions"))}?:"[]"))
                }
            }
            fun scalar(path:String,b:JsonElement,l:JsonElement,r:JsonElement):JsonElement=when {
                v.same(l,b)->r;v.same(r,b)->l;v.same(l,r)->r
                else->if(conflict("metadata",path,"VALUE_CHANGED",v.go(b),v.go(l),v.go(r))==AdminLayerResolution.KEEP_LOCAL)l else r
            }
            val mode=v.text(scalar("mode",JsonPrimitive(input.base.mode),JsonPrimitive(input.local.mode),JsonPrimitive(input.current.mode)))
            val approval=v.n(scalar("approvalUntilMs",JsonPrimitive(input.base.approvalUntilMs),JsonPrimitive(input.local.approvalUntilMs),JsonPrimitive(input.current.approvalUntilMs)))
            if(approval>input.current.approvalUntilMs)conflict("metadata","approvalUntilMs","APPROVAL_EXCEEDS_CURRENT",null,null,null,false)
            if(input.current.revision==v.MAX)conflict("metadata","revision","LIMIT",null,null,null,false)
            val all=currentRows.map {row->replacements.remove(v.identity(row)) ?:input.current.document.raw(row)}.toMutableList()
            all+=replacements.toSortedMap().values
            if(all.size>20)conflict("layers","","LIMIT",null,null,null,false)
            if(conflicts.any {!it.resolvable || it.resolution==null})return AdminLayerComparison(input,choices.toMap(),null,null,conflicts)
            val raw=v.rawObject("draftId" to v.quote(input.draftId),"draftRevision" to (input.saved+1).toString(),"targetKind" to v.quote("device"),"targetId" to v.quote(input.current.device),
                "mode" to v.quote(mode),"approvalUntilMs" to approval.toString(),"bundles" to "["+v.rawObject("device" to v.quote(input.current.device),
                    "baseRevision" to input.current.revision.toString(),"baseHash" to v.quote(input.current.hash),"layers" to all.joinToString(",","[","]"))+"]")
            val candidate=try {AdminLayerControl.proposal(raw)}catch(_:Exception){conflict("layers","","LIMIT_OR_SHAPE",null,null,null,false);return AdminLayerComparison(input,choices.toMap(),null,null,conflicts)}
            val after=try {AdminLayerProjector.project(candidate.document,candidate.document.root.jsonObject.getValue("bundles").jsonArray.single().jsonObject.getValue("layers").jsonArray,input.current.device)}
            catch(e:AdminLayerProjectionException){conflict("projection","",e.code.name,null,null,null,false);return AdminLayerComparison(input,choices.toMap(),null,null,conflicts)}
            return AdminLayerComparison(input,choices.toMap(),candidate,difference(input.current,candidate,input.before,after),conflicts)
        }
    }
}
