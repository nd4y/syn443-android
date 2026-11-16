package io.syn443.identity

import io.syn443.policy.Policy
import kotlinx.serialization.json.*
import org.junit.Assert.*
import org.junit.Test

/** Pure bounded merge/projection fixtures. No live ACL, supported client-schema
 * compile, source lookup, server preview or publication authority is inferred. */
class AdminLayerComparisonTest {
    private val device="synthetic-device"
    private val now=1_800_000_000_000L
    private val owner=Identity.hash("synthetic-owner".toByteArray())
    private fun origin(id:String,kind:String,revision:Long)="""{"layerId":"$id","kind":"$kind","revision":$revision}"""
    private fun change(path:String,value:String?,operation:String="set")="""{"path":"$path","operation":"$operation"${value?.let {",\"value\":$it"}?:""}}"""
    private fun layer(kind:String,id:String,revision:Long,changes:List<String>,permissions:String="[]",priority:Int=0)=
        """{"id":"$id","kind":"$kind","priority":$priority,"revision":$revision,"changes":${changes.joinToString(",","[","]")},"permissions":$permissions}"""
    private fun project(rows:List<String>):AdminLayerProjection {
        val doc=AdminLayerJson.document(rows.joinToString(",","[","]"))
        return AdminLayerProjector.project(doc,doc.root.jsonArray,device)
    }
    private fun snapshot(parentRevision:Long=1,ownRevision:Long=1,a:Int=1,b:Int?=null,revision:Long=2,
        mode:String="wifi",approval:Long=now+3_600_000,historical:Boolean=false,locked:Boolean=false):AdminLayerInventory {
        val parent=layer("template","parent",parentRevision,listOf(change("/settings","""{"a":0,"b":0,"flag":true,"items":[1,2]}""")),"""[{"path":"/settings","mode":"${if(locked)"locked" else "free"}"}]""")
        val own=layer("device",device,ownRevision,listOfNotNull(change("/settings/a",a.toString()),b?.let {change("/settings/b",it.toString())}))
        val parentOrigin=origin("parent","template",parentRevision);val ownOrigin=origin(device,"device",ownRevision)
        val fields="""{"/settings/a":$ownOrigin,"/settings/b":${if(b==null)parentOrigin else ownOrigin},"/settings/flag":$parentOrigin,"/settings/items":$parentOrigin}"""
        val effective="""{"document":{"settings":{"a":$a,"b":${b?:0},"flag":true,"items":[1,2]}},"fields":$fields,"restrictions":[{"permission":{"path":"/settings","mode":"${if(locked)"locked" else "free"}"},"origin":$parentOrigin}]}"""
        val hash=if(revision==2L)"a".repeat(64) else "b".repeat(64)
        val raw="""{"device":"$device","owner":"$owner","state":"assigned","revision":$revision,"hash":"$hash","policyRevision":0,"mode":"$mode","approvalUntilMs":$approval,"layers":[$parent,$own],"effective":$effective,"currentRevision":$revision${if(historical)",\"historical\":true" else ""}}"""
        val request=if(historical)AdminLayerControl.history(device,revision,hash,Identity.random()) else AdminLayerControl.inventory(device,Identity.random())
        return AdminLayerControl.parseReply(request,raw,TimeWindow(now,now+1000)) as AdminLayerInventory
    }
    private fun local(base:AdminLayerInventory,a:Int=3,b:Int?=null,mode:String=base.mode,approval:Long=base.approvalUntilMs):AdminLayerProposal {
        val raw=AdminLayerControl.newDeviceDraft(base,"draft-a",base.approvalUntilMs)
        val p=raw.document.root.jsonObject;val bundle=p.getValue("bundles").jsonArray.single().jsonObject
        val parent=bundle.getValue("layers").jsonArray.first();val own=AdminLayerJson.parse(layer("device",device,999,listOfNotNull(change("/settings/a",a.toString()),b?.let {change("/settings/b",it.toString())})))
        return AdminLayerControl.proposal(JsonObject(p+mapOf("mode" to JsonPrimitive(mode),"approvalUntilMs" to JsonPrimitive(approval),
            "bundles" to JsonArray(listOf(JsonObject(bundle+mapOf("layers" to JsonArray(listOf(parent,own)))))))).toString())
    }
    private fun compare(base:AdminLayerInventory,current:AdminLayerInventory,local:AdminLayerProposal,saved:Long=5)=
        AdminLayerComparison.compareDeviceDraft(base,current,local,"draft-a",saved)
    private fun rows(p:AdminLayerProposal)=p.document.root.jsonObject.getValue("bundles").jsonArray.single().jsonObject.getValue("layers").jsonArray
    private fun withChanges(p:AdminLayerProposal,changes:List<String>):AdminLayerProposal {
        val root=p.document.root.jsonObject;val bundle=root.getValue("bundles").jsonArray.single().jsonObject
        val layers=bundle.getValue("layers").jsonArray
        val own=layers.last().jsonObject
        val next=JsonObject(own+mapOf("changes" to AdminLayerJson.parse(changes.joinToString(",","[","]"))))
        return AdminLayerControl.proposal(JsonObject(root+mapOf("bundles" to JsonArray(listOf(JsonObject(bundle+mapOf("layers" to JsonArray(layers.dropLast(1)+next))))))).toString())
    }
    private fun invalid(block:()->Unit){assertEquals(AdminFailure.INVALID_REPLY,assertThrows(AdminException::class.java,block).reason)}
    private fun projectionFailure(expected:AdminLayerProjectionCode,rows:List<String>){assertEquals(expected,assertThrows(AdminLayerProjectionException::class.java){project(rows)}.code)}

    @Test fun disjointThreeWayMergePreservesCurrentParentsPermissionsAndIndependentRevisionDomains() {
        val base=snapshot();val current=snapshot(parentRevision=2,ownRevision=2,b=2,revision=3)
        val local=local(base);val original=local.wireJson();val result=compare(base,current,local)
        assertTrue(result.ready);assertTrue(result.conflicts.isEmpty());val p=checkNotNull(result.proposal)
        assertEquals(6L,p.draftRevision);assertEquals(3L,p.document.root.jsonObject.getValue("bundles").jsonArray.single().jsonObject.getValue("baseRevision").jsonPrimitive.long)
        assertEquals(current.hash,p.document.root.jsonObject.getValue("bundles").jsonArray.single().jsonObject.getValue("baseHash").jsonPrimitive.content)
        assertEquals(current.document.raw(current.document.root.jsonObject.getValue("layers").jsonArray.first()),p.document.raw(rows(p).first()))
        val own=rows(p).last().jsonObject;assertEquals(3L,own.getValue("revision").jsonPrimitive.long)
        val changes=own.getValue("changes").jsonArray.associate {it.jsonObject.getValue("path").jsonPrimitive.content to it.jsonObject.getValue("value")}
        assertEquals(JsonPrimitive(3),changes["/settings/a"]);assertEquals(JsonPrimitive(2),changes["/settings/b"])
        val diff=checkNotNull(result.diff);assertTrue(diff.localProjection)
        assertEquals(current.document.root.jsonObject.getValue("effective").jsonObject.getValue("document"),
            Json.parseToJsonElement(diff.beforeJson()))
        assertEquals("3",diff.entries.single {it.path=="/settings/a"}.afterJson())
        assertEquals("1",diff.entries.single {it.path=="/settings/a"}.beforeJson())
        assertTrue(checkNotNull(diff.entries.single {it.path=="/settings/a"}.beforeOriginJson()).contains("\"revision\":2"))
        assertTrue(checkNotNull(diff.entries.single {it.path=="/settings/a"}.afterOriginJson()).contains("\"revision\":3"))
        assertEquals("AdminLayerDifference([redacted])",diff.entries.first().toString())
        assertTrue(diff.afterJson().contains("\"b\":2"));assertEquals(original,local.wireJson())
        assertFalse(result.toString().contains(device));assertFalse(diff.toString().contains("settings"))
    }
    @Test fun boundExplicitChoicesResolveSamePathConflictsWithoutExposingAnUnresolvedProposal() {
        val base=snapshot();val current=snapshot(parentRevision=2,ownRevision=2,a=2,revision=3)
        val conflict=compare(base,current,local(base,a=3));assertFalse(conflict.ready);assertNull(conflict.proposal);assertNull(conflict.diff)
        val c=conflict.conflicts.single();assertEquals("VALUE_CHANGED",c.code);assertEquals("device",c.kind);assertEquals("/settings/a",c.path)
        assertTrue(checkNotNull(c.baseJson()).contains("\"value\":1"));assertFalse(c.toString().contains(device))
        assertTrue(checkNotNull(c.localJson()).contains("\"value\":3"));assertTrue(checkNotNull(c.currentJson()).contains("\"value\":2"))
        val currentChoice=AdminLayerComparison.resolveDeviceDraft(conflict,mapOf(c.id to AdminLayerResolution.CURRENT))
        assertTrue(currentChoice.ready)
        val p=checkNotNull(currentChoice.proposal);val original=current.document.root.jsonObject.getValue("layers").jsonArray.last()
        assertEquals(current.document.raw(original),p.document.raw(rows(p).last()))
        val mutableChoice=mutableMapOf(c.id to AdminLayerResolution.CURRENT)
        val ownedChoice=AdminLayerComparison.resolveDeviceDraft(conflict,mutableChoice);mutableChoice[c.id]=AdminLayerResolution.KEEP_LOCAL
        assertEquals(p.wireJson(),ownedChoice.proposal?.wireJson())
        val localChoice=AdminLayerComparison.resolveDeviceDraft(conflict,mapOf(c.id to AdminLayerResolution.KEEP_LOCAL))
        assertTrue(localChoice.ready);assertEquals(3L,rows(checkNotNull(localChoice.proposal)).last().jsonObject.getValue("revision").jsonPrimitive.long)
        invalid {AdminLayerComparison.resolveDeviceDraft(conflict,mapOf(Identity.random() to AdminLayerResolution.KEEP_LOCAL))}
        val another=compare(base,current,local(base,a=4));assertNotEquals(conflict.binding,another.binding)
        invalid {AdminLayerComparison.resolveDeviceDraft(another,mapOf(c.id to AdminLayerResolution.KEEP_LOCAL))}
        assertThrows(UnsupportedOperationException::class.java){(conflict.conflicts as MutableList<*>).clear()}
    }
    @Test fun sameResultAndUnchangedLocalChooseCurrentRawWhileModeAndApprovalAreThreeWay() {
        val base=snapshot();val current=snapshot(parentRevision=2,ownRevision=2,a=3,revision=3,mode="home_wifi",approval=now+2_000_000)
        val same=compare(base,current,local(base,a=3));assertTrue(same.ready);val p=checkNotNull(same.proposal)
        assertEquals("home_wifi",p.mode);assertEquals(current.approvalUntilMs,p.approvalUntilMs)
        assertEquals(current.document.raw(current.document.root.jsonObject.getValue("layers").jsonArray.last()),p.document.raw(rows(p).last()))
        val conflict=compare(base,current,local(base,a=1,mode="cellular",approval=now+1_000_000))
        assertFalse(conflict.ready);assertEquals(setOf("mode","approvalUntilMs"),conflict.conflicts.map {it.path}.toSet())
        val resolved=AdminLayerComparison.resolveDeviceDraft(conflict,conflict.conflicts.associate {it.id to AdminLayerResolution.KEEP_LOCAL})
        assertTrue(resolved.ready);assertEquals("cellular",checkNotNull(resolved.proposal).mode);assertEquals(now+1_000_000,resolved.proposal?.approvalUntilMs)
        val ceiling=compare(base,current,local(base,a=1,approval=now+3_000_000))
        val pickLocal=AdminLayerComparison.resolveDeviceDraft(ceiling,ceiling.conflicts.filter {it.resolvable}.associate {it.id to AdminLayerResolution.KEEP_LOCAL})
        assertFalse(pickLocal.ready);assertTrue(pickLocal.conflicts.any {it.code=="APPROVAL_EXCEEDS_CURRENT"})
    }
    @Test fun projectionAppliesDeletionContainersArraysAndGoLexicalChoiceAndRangeRules() {
        val template=layer("template","parent",1,listOf(change("/settings","""{"a":1,"items":[1,2],"empty":{}}""")),"""[{"path":"/settings","mode":"free"}]""")
        val own=layer("device",device,1,listOf(change("/settings/a",null,"delete"),change("/settings/new/value","2"),change("/settings/items","[2,1]")))
        val projected=project(listOf(template,own))
        assertEquals("""{"settings":{"empty":{},"items":[2,1],"new":{"value":2}}}""",projected.documentJson())
        assertFalse("/settings/a" in projected.fields);assertEquals("device",projected.fields.getValue("/settings/new/value").getValue("kind").jsonPrimitive.content)
        assertEquals(setOf("document","fields","restrictions"),AdminLayerJson.parse(projected.wireJson()).jsonObject.keys)
        assertEquals("AdminLayerProjection([redacted])",projected.toString())
        assertThrows(UnsupportedOperationException::class.java){(projected.fields as MutableMap<*,*>).clear()}
        val choice=layer("template","parent",1,listOf(change("/n","1.00")),"""[{"path":"/n","mode":"choice","choices":[1.00]}]""")
        assertEquals("{\"n\":1.00}",project(listOf(choice)).documentJson())
        projectionFailure(AdminLayerProjectionCode.LOCKED,listOf(choice,layer("device",device,1,listOf(change("/n","1")))))
        val range=layer("template","parent",1,listOf(change("/n","1")),"""[{"path":"/n","mode":"range","minimum":0,"maximum":2}]""")
        assertEquals("{\"n\":2}",project(listOf(range,layer("device",device,1,listOf(change("/n","2"))))).documentJson())
        projectionFailure(AdminLayerProjectionCode.LOCKED,listOf(range,layer("device",device,1,listOf(change("/n","2.0")))))
        projectionFailure(AdminLayerProjectionCode.INVALID,listOf(template,layer("device",device,1,listOf(change("/settings/a/x","1")))))
    }
    @Test fun projectionEnforcesLockedInheritedLocalPermissionsAndEqualPriorityGroupClaims() {
        val parent=layer("template","parent",1,listOf(change("/n","0")),"""[{"path":"/n","mode":"free"}]""")
        val locked=layer("group","g",1,emptyList(),"""[{"path":"/n","mode":"locked"}]""")
        projectionFailure(AdminLayerProjectionCode.LOCKED,listOf(parent,locked,layer("device",device,1,listOf(change("/n","1")))))
        assertNotNull(project(listOf(parent,locked,layer("device",device,1,listOf(change("/n","0"))))))
        projectionFailure(AdminLayerProjectionCode.LOCKED,listOf(layer("template","parent",1,listOf(change("/n","0"))),layer("local",device,1,listOf(change("/n","1")))))
        projectionFailure(AdminLayerProjectionCode.LOCKED,listOf(layer("template","parent",1,listOf(change("/n","0"))),layer("device",device,1,emptyList(),"""[{"path":"/n","mode":"free"}]""")))
        fun group(id:String,value:String)=layer("group",id,1,listOf(change("/n",value)),priority=1)
        assertEquals("{\"n\":1}",project(listOf(parent,group("a","1"),group("b","1"))).documentJson())
        projectionFailure(AdminLayerProjectionCode.CONFLICT,listOf(parent,group("a","1"),group("b","2")))
        projectionFailure(AdminLayerProjectionCode.CONFLICT,listOf(parent,group("a","1.00"),group("b","1")))
        assertEquals("{}",project(listOf(parent,layer("group","a",1,listOf(change("/absent",null,"delete"),change("/n",null,"delete")),priority=1),
            layer("group","b",1,listOf(change("/absent/child",null,"delete")),priority=1))).documentJson())
    }
    @Test fun inconsistentActualEffectiveAndForeignScopeOrParentsAreRejectedBeforeComparison() {
        val base=snapshot();val current=snapshot(parentRevision=2,ownRevision=2,b=2,revision=3);val candidate=local(base)
        val badDocument=AdminLayerInventory(current.wireJson(),AdminLayerJson.document(current.wireJson().replace("\"a\":1","\"a\":9"),true),
            current.device,current.revision,current.hash,current.mode,current.approvalUntilMs,current.currentRevision,false)
        invalid {compare(base,badDocument,candidate)}
        invalid {AdminLayerComparison.compareDeviceDraft(base,current,candidate,"foreign",0)}
        invalid {AdminLayerComparison.compareDeviceDraft(base,current,candidate,"draft-a",AdminLayerValues.MAX)}
        val differentOwner=current.wireJson().replace(owner,Identity.random())
        val request=AdminLayerControl.inventory(device,Identity.random())
        val foreign=AdminLayerControl.parseReply(request,differentOwner,TimeWindow(now,now+1000)) as AdminLayerInventory
        invalid {compare(base,foreign,candidate)}
        val parentChange=AdminLayerControl.proposal(candidate.wireJson().replace("\"revision\":1","\"revision\":4"))
        invalid {compare(base,current,parentChange)}
        val root=current.document.root.jsonObject;val effective=root.getValue("effective").jsonObject
        val parentOrigin=AdminLayerJson.parse(origin("parent","template",2))
        val document=JsonObject(mapOf("settings" to AdminLayerJson.parse("""{"a":0,"b":0,"flag":true,"items":[1,2]}""")))
        val fields=JsonObject(listOf("a","b","flag","items").associate {"/settings/$it" to parentOrigin})
        val removed=JsonObject(root+mapOf("layers" to JsonArray(root.getValue("layers").jsonArray.dropLast(1)),
            "effective" to JsonObject(effective+mapOf("document" to document,"fields" to fields))))
        val noOwn=AdminLayerControl.parseReply(request,removed.toString(),TimeWindow(now,now+1000)) as AdminLayerInventory
        val deletion=compare(base,noOwn,candidate);assertFalse(deletion.ready)
        assertTrue(deletion.conflicts.any {it.code=="LAYER_REMOVED" && !it.resolvable})
    }
    @Test fun goStringEscapingRawCompactAndInputOutputBoundsRemainClosed() {
        assertEquals("\"\\u003c\\u0026\\u003eé\\u2028\\u2029\"",AdminLayerValues.quote("<&>é\u2028\u2029"))
        assertEquals("{\"s\":\"\\u0061\\u003c\",\"n\":1.00}",AdminLayerValues.rawCompact(" { \"s\" : \"\\u0061<\", \"n\" : 1.00 } "))
        assertEquals("\"\\b\\f\\n\\r\\t\\u0000\\\"\\\\\"",AdminLayerValues.quote("\b\u000c\n\r\t\u0000\"\\"))
        assertEquals("{\"\uE000\":0,\"\uD800\uDC00\":1}",AdminLayerValues.go(JsonObject(mapOf("\uD800\uDC00" to JsonPrimitive(1),"\uE000" to JsonPrimitive(0)))))
        val base=snapshot();val current=snapshot(parentRevision=2,ownRevision=AdminLayerValues.MAX,a=1,revision=3)
        val result=compare(base,current,local(base,a=3));assertFalse(result.ready);assertTrue(result.conflicts.any {it.code=="LIMIT"})
        assertTrue(compare(base,current,local(base,a=1)).ready)
        assertFalse(compare(base,snapshot(parentRevision=2,ownRevision=2,revision=AdminLayerValues.MAX),local(base)).ready)
        val unknown=layer("template","parent",1,listOf(change("/settings","{\"bad/key\":0}")))
        projectionFailure(AdminLayerProjectionCode.INVALID,listOf(unknown))
        val oversized=layer("template","parent",1,listOf(change("/text",JsonPrimitive("<".repeat(45_000)).toString())))
        projectionFailure(AdminLayerProjectionCode.INVALID,listOf(oversized))
        val grid=(0 until 64).joinToString(",","{","}"){g->
            "\"g%02d\":".format(g)+(0 until 64).joinToString(",","{","}"){leaf->"\"v%02d\":$leaf".format(leaf)}
        }
        assertEquals(4096,project(listOf(layer("template","parent",1,listOf(change("/grid",grid))))).fields.size)
        projectionFailure(AdminLayerProjectionCode.INVALID,listOf(layer("template","parent",1,listOf(change("/grid",grid.dropLast(1)+",\"extra\":1}")))))
    }
    @Test fun inheritanceDeletionAndPrefixConflictsKeepDistinctIntentAndRequireBoundRegionChoice() {
        val base=snapshot();val current=snapshot(parentRevision=2,ownRevision=2,b=2,revision=3)
        val inherited=compare(base,current,withChanges(local(base),emptyList()))
        assertTrue(inherited.ready);val inheritedDiff=checkNotNull(inherited.diff)
        assertEquals("0",inheritedDiff.entries.single {it.path=="/settings/a"}.afterJson())
        val deleted=compare(base,current,withChanges(local(base),listOf(change("/settings/a",null,"delete"))))
        assertTrue(deleted.ready);assertNull(checkNotNull(deleted.diff).entries.single {it.path=="/settings/a"}.afterJson())
        val replaced=withChanges(local(base),listOf(change("/settings","""{"a":3,"b":0,"flag":true,"items":[1,2]}""")))
        val overlap=compare(base,current,replaced);assertFalse(overlap.ready)
        val c=overlap.conflicts.single();assertEquals("OVERLAPPING_PATHS",c.code);assertEquals("/settings",c.path)
        val keep=AdminLayerComparison.resolveDeviceDraft(overlap,mapOf(c.id to AdminLayerResolution.KEEP_LOCAL))
        assertTrue(keep.ready);assertTrue(checkNotNull(keep.diff).afterJson().contains("\"b\":0"))
        val remote=AdminLayerComparison.resolveDeviceDraft(overlap,mapOf(c.id to AdminLayerResolution.CURRENT))
        assertTrue(remote.ready);assertTrue(checkNotNull(remote.diff).afterJson().contains("\"b\":2"))
    }
    @Test fun concurrentCrossKindShadowingConflictsWhileIdenticalIntentCanCoexist() {
        val base=snapshot();val current=snapshot(parentRevision=2,ownRevision=2,revision=3)
        val root=current.document.root.jsonObject;val old=root.getValue("effective").jsonObject
        val document=old.getValue("document").jsonObject
        val fields=old.getValue("fields").jsonObject
        val remoteLocal=AdminLayerJson.parse(layer("local",device,1,listOf(change("/settings/a","2"))))
        val settings=JsonObject(document.getValue("settings").jsonObject+mapOf("a" to JsonPrimitive(2)))
        val nextDocument=JsonObject(document+mapOf("settings" to settings))
        val nextFields=JsonObject(fields+mapOf("/settings/a" to AdminLayerJson.parse(origin(device,"local",1))))
        val nextEffective=JsonObject(old+mapOf("document" to nextDocument,"fields" to nextFields))
        val actual=JsonObject(root+mapOf("layers" to JsonArray(root.getValue("layers").jsonArray+remoteLocal),"effective" to nextEffective))
        val remote=AdminLayerControl.parseReply(AdminLayerControl.inventory(device,Identity.random()),actual.toString(),TimeWindow(now,now+1000)) as AdminLayerInventory
        val conflict=compare(base,remote,local(base,a=3));assertFalse(conflict.ready)
        val c=conflict.conflicts.single();assertEquals("CROSS_LAYER_OVERLAP",c.code);assertFalse(c.resolvable)
        invalid {AdminLayerComparison.resolveDeviceDraft(conflict,mapOf(c.id to AdminLayerResolution.CURRENT))}
        val same=compare(base,remote,local(base,a=2));assertTrue(same.ready)
        assertEquals("2",AdminLayerJson.parse(checkNotNull(same.diff).afterJson()).jsonObject.getValue("settings").jsonObject.getValue("a").jsonPrimitive.content)
    }
    @Test fun newCurrentPermissionsCanBlockMergedIntentWithoutBecomingAClientGrant() {
        val base=snapshot();val current=snapshot(parentRevision=2,ownRevision=2,a=0,revision=3,locked=true)
        val result=compare(base,current,local(base,a=1,b=3))
        assertFalse(result.ready);assertNull(result.proposal);assertNull(result.diff)
        assertTrue(result.conflicts.any {it.kind=="projection" && it.code=="LOCKED" && !it.resolvable})
    }
    @Test fun projectionDocumentsMatchAcceptedGo55ScenariosWithoutChangingTheGoldenResource() {
        val bytes=checkNotNull(javaClass.getResourceAsStream("/admin-layer-wire.json")).use {it.readBytes()}
        val sha=java.security.MessageDigest.getInstance("SHA-256").digest(bytes).joinToString(""){"%02x".format(it)}
        assertEquals("a70a87e162484e2dbe77e81659080af25f6eef641330bbab582f1a193522b713",sha)
        val fixture=AdminLayerJson.parse(Policy.utf8(bytes)).jsonObject
        val catalogue=fixture.getValue("layers").jsonArray.associate {row->val item=row.jsonObject
            item.getValue("name").jsonPrimitive.content to item.getValue("layerWire").jsonPrimitive.content}
        val scenarios=fixture.getValue("scenarios").jsonArray;assertEquals(4,scenarios.size)
        for(s in scenarios) {
            val scenario=s.jsonObject
            val raw=scenario.getValue("layerNames").jsonArray.joinToString(",","[","]"){catalogue.getValue(it.jsonPrimitive.content)}
            val doc=AdminLayerJson.document(raw)
            val projected=AdminLayerProjector.project(doc,doc.root.jsonArray,"fixture-device")
            assertEquals(scenario.getValue("effectiveWire").jsonPrimitive.content,projected.documentJson())
            assertTrue(projected.fields.isNotEmpty());assertEquals(4,projected.restrictions.size)
        }
    }
    @Test fun preparedReviewDiffAndConfigurationFactBindingRemainValuesWithoutCasOrLeaseAuthority() {
        val base=snapshot();val candidate=AdminLayerControl.prepareDeviceDraft(base,local(base,a=3),"draft-a",7)
        val before=candidate.wireJson()
        val diff=AdminLayerComparison.diffPreparedDeviceDraft(base,candidate)
        assertEquals("1",diff.entries.single {it.path=="/settings/a"}.beforeJson())
        assertEquals("3",diff.entries.single {it.path=="/settings/a"}.afterJson())
        assertEquals(before,candidate.wireJson());assertEquals(8L,candidate.draftRevision)
        val facts=AdminLayerComparison.configurationBinding(base)
        val leaseOnly=base.wireJson().replace("\"policyRevision\":0","\"policyRevision\":7")
        val renewed=AdminLayerControl.parseReply(AdminLayerControl.inventory(device,Identity.random()),leaseOnly,TimeWindow(now,now+1000)) as AdminLayerInventory
        assertEquals(facts,AdminLayerComparison.configurationBinding(renewed))
        assertNotEquals(facts,AdminLayerComparison.configurationBinding(snapshot(a=2)))
        assertNotEquals(facts,AdminLayerComparison.configurationBinding(snapshot(mode="home_wifi")))
        assertNotEquals(facts,AdminLayerComparison.configurationBinding(snapshot(revision=3)))
        invalid {AdminLayerComparison.configurationBinding(snapshot(historical=true))}
        invalid {AdminLayerComparison.diffPreparedDeviceDraft(snapshot(revision=3),candidate)}
        val raw=base.wireJson().replace("\"a\":1,\"b\":0","\"a\":9,\"b\":0")
        val forged=AdminLayerControl.parseReply(AdminLayerControl.inventory(device,Identity.random()),raw,TimeWindow(now,now+1000)) as AdminLayerInventory
        invalid {AdminLayerComparison.configurationBinding(forged)}
    }
    @Test fun allAcceptedGoProjectionOutcomesChosenRebaseProjectionsAndGridHashesConform() {
        fun sha(bytes:ByteArray)=java.security.MessageDigest.getInstance("SHA-256").digest(bytes).joinToString(""){"%02x".format(it)}
        val bytes=checkNotNull(javaClass.getResourceAsStream("/admin-layer-projection.json")).use {it.readBytes()}
        val manifest=AdminLayerJson.parse(checkNotNull(javaClass.getResourceAsStream("/admin-layer-projection-source.json")).use {Policy.utf8(it.readBytes())}).jsonObject
        assertEquals("d4d9a4d774a6b1bc404563af648d547b92399af4",manifest.getValue("sourceCommit").jsonPrimitive.content)
        assertEquals(43956602201L,manifest.getValue("run").jsonPrimitive.long)
        assertEquals("7187eb00ad98742b1043c867b2c3d909e34cd9764d8149d69f6565df89c6a135",sha(bytes))
        assertEquals(sha(bytes),manifest.getValue("fixtureSha256").jsonPrimitive.content)
        val fixture=AdminLayerJson.parse(Policy.utf8(bytes)).jsonObject
        assertEquals(setOf("schemaVersion","hashAlgorithm","layers","projections","rebases","bounds"),fixture.keys)
        assertEquals(1,fixture.getValue("schemaVersion").jsonPrimitive.int)
        assertEquals("sha256-lowercase-hex",fixture.getValue("hashAlgorithm").jsonPrimitive.content)
        val catalogue=linkedMapOf<String,String>()
        for(item in fixture.getValue("layers").jsonArray) {
            val row=item.jsonObject;assertEquals(setOf("name","layerWire","globalLayerHash"),row.keys)
            val name=row.getValue("name").jsonPrimitive.content;assertTrue(name.isNotEmpty());assertFalse(catalogue.containsKey(name))
            val raw=row.getValue("layerWire").jsonPrimitive.content
            assertEquals(row.getValue("globalLayerHash").jsonPrimitive.content,sha(raw.toByteArray(Charsets.UTF_8)))
            catalogue[name]=raw
        }
        assertEquals(59,catalogue.size)
        fun names(value:JsonElement)=value.jsonArray.map {it.jsonPrimitive.content.also {name->assertTrue(name in catalogue)}}
        fun outcome(label:String,rows:List<String>,expected:String,wire:String):AdminLayerProjection? {
            val actual=try {project(rows)}catch(e:AdminLayerProjectionException) {
                val code=when(e.code){AdminLayerProjectionCode.INVALID->"configuration_invalid";AdminLayerProjectionCode.LOCKED->"configuration_field_locked";AdminLayerProjectionCode.CONFLICT->"configuration_conflict"}
                assertEquals(label,expected,code);assertEquals(label,"",wire);return null
            }
            assertEquals(label,"ok",expected)
            val expectedTree=AdminLayerJson.parse("{\"effective\":"+wire+"}",inventory=true).jsonObject.getValue("effective")
            val actualTree=AdminLayerJson.parse("{\"effective\":"+actual.wireJson()+"}",inventory=true).jsonObject.getValue("effective")
            assertTrue(label,AdminLayerValues.lexicalSame(expectedTree,actualTree))
            return actual
        }
        val projections=fixture.getValue("projections").jsonArray;assertEquals(41,projections.size)
        assertEquals(41,projections.map {it.jsonObject.getValue("name").jsonPrimitive.content}.toSet().size)
        for(item in projections) {
            val row=item.jsonObject;assertEquals(setOf("name","layerNames","expectedCode","effectiveWire"),row.keys)
            val label=row.getValue("name").jsonPrimitive.content;assertTrue(label.isNotEmpty())
            outcome(label,names(row.getValue("layerNames")).map(catalogue::getValue),row.getValue("expectedCode").jsonPrimitive.content,row.getValue("effectiveWire").jsonPrimitive.content)
        }
        val rebases=fixture.getValue("rebases").jsonArray;assertEquals(11,rebases.size)
        assertEquals(11,rebases.map {it.jsonObject.getValue("name").jsonPrimitive.content}.toSet().size)
        for(item in rebases) {
            val row=item.jsonObject;assertEquals(setOf("name","baseLayerNames","localLayerNames","remoteLayerNames","chosenLayerNames","resolution","expectedCode","effectiveWire"),row.keys)
            val label=row.getValue("name").jsonPrimitive.content;assertTrue(label.isNotEmpty())
            for(key in listOf("baseLayerNames","localLayerNames","remoteLayerNames"))assertTrue(project(names(row.getValue(key)).map(catalogue::getValue)).fields.isNotEmpty())
            val chosen=names(row.getValue("chosenLayerNames"));val code=row.getValue("expectedCode").jsonPrimitive.content
            if(row.getValue("resolution").jsonPrimitive.content=="conflict") {
                assertTrue(chosen.isEmpty());assertEquals("configuration_conflict",code);assertEquals("",row.getValue("effectiveWire").jsonPrimitive.content)
            } else {
                assertEquals("merged",row.getValue("resolution").jsonPrimitive.content);assertTrue(chosen.isNotEmpty())
                outcome(label,chosen.map(catalogue::getValue),code,row.getValue("effectiveWire").jsonPrimitive.content)
            }
        }
        val bounds=fixture.getValue("bounds").jsonArray;assertEquals(2,bounds.size)
        assertEquals(setOf("leaves-4096","leaves-4097"),bounds.map {it.jsonObject.getValue("name").jsonPrimitive.content}.toSet())
        for(item in bounds) {
            val row=item.jsonObject;assertEquals(setOf("name","generator","groups","leavesPerGroup","extraLeaves","globalLayerHash","expectedCode","expectedFieldCount"),row.keys)
            assertEquals("leaf-grid-v1",row.getValue("generator").jsonPrimitive.content)
            assertEquals(64,row.getValue("groups").jsonPrimitive.int);assertEquals(64,row.getValue("leavesPerGroup").jsonPrimitive.int)
            val extra=row.getValue("extraLeaves").jsonPrimitive.int;assertTrue(extra in 0..1)
            val groups=(0 until 64).map {g->"\"g"+g.toString().padStart(2,'0')+"\":"+(0 until 64).joinToString(",","{","}"){v->"\"v"+v.toString().padStart(2,'0')+"\":"+v}}
            val entries=if(extra==1)listOf("\"extra\":1")+groups else groups
            val raw=layer("template","projection-template",1,listOf(change("/grid",entries.joinToString(",","{","}"))))
            assertEquals(row.getValue("globalLayerHash").jsonPrimitive.content,sha(raw.toByteArray(Charsets.UTF_8)))
            if(extra==0) {
                assertEquals("ok",row.getValue("expectedCode").jsonPrimitive.content)
                assertEquals(row.getValue("expectedFieldCount").jsonPrimitive.int,project(listOf(raw)).fields.size);assertEquals(4096,row.getValue("expectedFieldCount").jsonPrimitive.int)
            } else {
                assertEquals("configuration_invalid",row.getValue("expectedCode").jsonPrimitive.content);assertEquals(0,row.getValue("expectedFieldCount").jsonPrimitive.int)
                projectionFailure(AdminLayerProjectionCode.INVALID,listOf(raw))
            }
        }
    }
    @Test fun computedSixteenKeyLeafPathsAllow1040WhileMutationPathsRemain512() {
        val keys=(0 until 16).map {"k"+it.toString().padStart(63,'0')}
        val leafPath=keys.joinToString("/","/");assertEquals(1040,leafPath.length)
        fun nested(names:List<String>,value:String)=names.asReversed().fold(value){body,key->"{\"$key\":$body}"}
        val parent=layer("template","parent",1,listOf(change("/"+keys.first(),nested(keys.drop(1),"1"))))
        val projected=project(listOf(parent));assertEquals(setOf(leafPath),projected.fields.keys)
        val inventoryRaw="""{"device":"$device","owner":"$owner","state":"assigned","revision":2,"hash":"${"a".repeat(64)}","policyRevision":0,"mode":"wifi","approvalUntilMs":${now+3_600_000},"layers":[$parent],"effective":${projected.wireJson()},"currentRevision":2}"""
        val inventory=AdminLayerControl.parseReply(AdminLayerControl.inventory(device,Identity.random()),inventoryRaw,TimeWindow(now,now+1000)) as AdminLayerInventory
        val edited=AdminLayerControl.editDevice(inventory,"draft-long","device",device,"/"+keys.first(),AdminLayerEdit.SET,nested(keys.drop(1),"2"),inventory.approvalUntilMs)
        val normalized=AdminLayerControl.prepareDeviceDraft(inventory,edited,"draft-long",0)
        val diff=AdminLayerComparison.diffPreparedDeviceDraft(inventory,normalized)
        assertEquals(leafPath,diff.entries.single().path);assertEquals("1",diff.entries.single().beforeJson());assertEquals("2",diff.entries.single().afterJson())
        invalid {AdminLayerControl.editDevice(inventory,"draft-long","device",device,leafPath,AdminLayerEdit.SET,"2",inventory.approvalUntilMs)}
        val tooLong=inventoryRaw.replace(AdminLayerValues.quote(leafPath),AdminLayerValues.quote(leafPath+"x"))
        invalid {AdminLayerControl.parseReply(AdminLayerControl.inventory(device,Identity.random()),tooLong,TimeWindow(now,now+1000))}
        projectionFailure(AdminLayerProjectionCode.INVALID,listOf(layer("template","parent",1,listOf(change("/root",nested(listOf("k".repeat(65)),"1"))))))
        projectionFailure(AdminLayerProjectionCode.INVALID,listOf(layer("template","parent",1,listOf(change("/root",nested(keys,"1"))))))
        val writeBoundary="/"+"a".repeat(64)+"/"+"b".repeat(64)+"/"+"c".repeat(64)+"/"+"d".repeat(64)+"/"+"e".repeat(64)+"/"+"f".repeat(64)+"/"+"g".repeat(64)+"/"+"h".repeat(56)
        assertEquals(512,writeBoundary.length)
        assertEquals(1L,AdminLayerControl.editDevice(inventory,"draft-write","device",device,writeBoundary,AdminLayerEdit.SET,"2",inventory.approvalUntilMs).draftRevision)
        invalid {AdminLayerControl.editDevice(inventory,"draft-write","device",device,writeBoundary+"x",AdminLayerEdit.SET,"2",inventory.approvalUntilMs)}
    }
}
