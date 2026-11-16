package io.syn443.android

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createComposeRule
import io.syn443.android.admin.*
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import java.util.Base64

/** Pure presentation only: no worker, JSON, RPC, storage, identity, server or VPN. */
class AdminComparisonUiTest {
    @get:Rule val compose=createComposeRule()
    private fun id(number:Int)=Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32).apply {
        this[30]=(number ushr 8).toByte();this[31]=number.toByte()
    })
    private fun row(number:Int=10,resolvable:Boolean=true,choice:String="",sides:List<AdminComparisonSide> = emptyList(),
        kind:String="device",code:String="VALUE_CHANGED")=AdminComparisonRow(id(number),kind,"/network/value$number",code,resolvable,choice,sides)
    private fun model(rows:List<AdminComparisonRow> = listOf(row()),binding:String=id(1),revision:Long=3,device:String="synthetic-device",
        section:AdminComparisonSection=AdminComparisonSection.CONFLICTS,total:Int=rows.size,offset:Int=0,ready:Boolean=false,
        detail:AdminComparisonDetail?=null,busy:Boolean=false,error:String="",readOnly:Boolean=false,baseRevision:Long=2,currentRevision:Long=4)=
        AdminComparisonModel(device,binding,revision,section,total,offset,rows,ready,detail,busy,error,readOnly,baseRevision=baseRevision,currentRevision=currentRevision)
    private fun scroll(tag:String)=compose.onNodeWithTag("comparison-content").performScrollToNode(hasTestTag(tag))

    @Test fun pagedConflictsAndDiffEmitOnlyExplicitBoundPageAndSideRequests() {
        val requests=mutableListOf<Pair<AdminComparisonSection,Int>>();val details=mutableListOf<Triple<String,AdminComparisonSide,Int>>()
        val rows=List(20) {row(it+10,sides=listOf(AdminComparisonSide.BASE))}
        val last=row(50,sides=listOf(AdminComparisonSide.BASE))
        val state=mutableStateOf(model(rows=rows,total=41))
        compose.setContent {MaterialTheme(colorScheme=darkColorScheme()) {AdminComparisonScreen(state.value,AdminComparisonActions(
            page={section,offset->requests+=section to offset},detail={r,s,p->details+=Triple(r,s,p)}))}}
        compose.onNodeWithTag("comparison-title").assertTextEquals("Сравнение конфигурации")
        scroll("comparison-head-revisions");compose.onNodeWithTag("comparison-head-revisions").assertTextEquals("Базовая ревизия: 2; сравниваемая ревизия: 4")
        scroll("comparison-count");compose.onNodeWithTag("comparison-count").assertTextEquals("Строки 1-20 из 41")
        compose.runOnIdle {assertTrue(requests.isEmpty());assertTrue(details.isEmpty())}
        scroll("comparison-page-previous");compose.onNodeWithTag("comparison-page-previous").assertIsNotEnabled()
        scroll("comparison-page-next");compose.onNodeWithTag("comparison-page-next").performClick()
        compose.runOnIdle {assertEquals(listOf(AdminComparisonSection.CONFLICTS to 20),requests)
            state.value=model(rows=List(20) {row(it+30,sides=listOf(AdminComparisonSide.BASE))},total=41,offset=20)}
        scroll("comparison-page-next");compose.onNodeWithTag("comparison-page-next").performClick()
        compose.runOnIdle {assertEquals(AdminComparisonSection.CONFLICTS to 40,requests.last())
            state.value=model(rows=listOf(last),total=41,offset=40)}
        scroll("comparison-page-next");compose.onNodeWithTag("comparison-page-next").assertIsNotEnabled()
        scroll("comparison-page-previous");compose.onNodeWithTag("comparison-page-previous").performClick()
        scroll("comparison-side-${last.id}-BASE");compose.onNodeWithTag("comparison-side-${last.id}-BASE").performClick()
        scroll("comparison-section-diff");compose.onNodeWithTag("comparison-section-diff").performClick()
        compose.runOnIdle {
            assertEquals(listOf(AdminComparisonSection.CONFLICTS to 20,AdminComparisonSection.CONFLICTS to 40,
                AdminComparisonSection.CONFLICTS to 20,AdminComparisonSection.DIFF to 0),requests)
            assertEquals(listOf(Triple(last.id,AdminComparisonSide.BASE,0)),details)
        }
        compose.onNodeWithTag("comparison-detail-text").assertDoesNotExist()
        compose.onNodeWithTag("editor-publish").assertDoesNotExist()
    }

    @Test fun resolvableChoicesUseLatestRowAndNeverApplyOrSelectAutomatically() {
        val chosen=mutableListOf<Pair<String,String>>();var apply=0
        val first=row();val blocked=row(11,resolvable=false)
        val state=mutableStateOf(model(rows=listOf(first,blocked)))
        compose.setContent {MaterialTheme(colorScheme=darkColorScheme()) {AdminComparisonScreen(state.value,AdminComparisonActions(
            choose={r,c->chosen+=r to c},apply={_,_->apply++}))}}
        compose.runOnIdle {assertTrue(chosen.isEmpty());assertEquals(0,apply)}
        scroll("comparison-choose-${first.id}-LOCAL");compose.onNodeWithTag("comparison-choose-${first.id}-LOCAL").performClick()
        compose.runOnIdle {assertEquals(listOf(first.id to "LOCAL"),chosen)
            state.value=model(rows=listOf(row(choice="LOCAL"),blocked),binding=id(2))}
        scroll("comparison-choose-${first.id}-LOCAL");compose.onNodeWithTag("comparison-choose-${first.id}-LOCAL").assertIsNotEnabled()
        scroll("comparison-choose-${first.id}-CURRENT");compose.onNodeWithTag("comparison-choose-${first.id}-CURRENT").performClick()
        scroll("comparison-unresolvable-${blocked.id}");compose.onNodeWithTag("comparison-unresolvable-${blocked.id}").assertIsDisplayed()
        compose.onNodeWithTag("comparison-choose-${blocked.id}-LOCAL").assertDoesNotExist()
        compose.runOnIdle {state.value=model(rows=listOf(first,blocked),binding=id(3),total=3,busy=true)}
        scroll("comparison-choose-${first.id}-CURRENT");compose.onNodeWithTag("comparison-choose-${first.id}-CURRENT").assertIsNotEnabled()
        scroll("comparison-apply");compose.onNodeWithTag("comparison-apply").assertIsNotEnabled()
        scroll("comparison-page-next");compose.onNodeWithTag("comparison-page-next").assertIsNotEnabled()
        scroll("comparison-back");compose.onNodeWithTag("comparison-back").assertIsNotEnabled()
        scroll("comparison-reload");compose.onNodeWithTag("comparison-reload").assertIsNotEnabled()
        scroll("comparison-full-web");compose.onNodeWithTag("comparison-full-web").assertIsNotEnabled()
        compose.runOnIdle {assertEquals(listOf(first.id to "LOCAL",first.id to "CURRENT"),chosen);assertEquals(0,apply)}
    }

    @Test fun detailViewerExposesOnlyOneExplicitValueOrOriginChunkWithBoundedPaging() {
        val requests=mutableListOf<Triple<String,AdminComparisonSide,Int>>()
        val r=row(resolvable=false,kind="setting",code="ORIGIN_CHANGED",sides=listOf(AdminComparisonSide.BEFORE,AdminComparisonSide.AFTER,
            AdminComparisonSide.BEFORE_ORIGIN,AdminComparisonSide.AFTER_ORIGIN))
        val state=mutableStateOf(model(rows=listOf(r),section=AdminComparisonSection.DIFF))
        compose.setContent {MaterialTheme(colorScheme=darkColorScheme()) {AdminComparisonScreen(state.value,
            AdminComparisonActions(detail={row,side,page->requests+=Triple(row,side,page)}))}}
        compose.onNodeWithText("private synthetic origin chunk").assertDoesNotExist()
        scroll("comparison-side-${r.id}-BEFORE_ORIGIN");compose.onNodeWithTag("comparison-side-${r.id}-BEFORE_ORIGIN").performClick()
        compose.runOnIdle {assertEquals(listOf(Triple(r.id,AdminComparisonSide.BEFORE_ORIGIN,0)),requests)
            state.value=model(rows=listOf(r),section=AdminComparisonSection.DIFF,
                detail=AdminComparisonDetail(r.id,AdminComparisonSide.BEFORE_ORIGIN,0,256,"private synthetic origin chunk"))}
        scroll("comparison-detail-text");compose.onNodeWithTag("comparison-detail-text").assertTextEquals("private synthetic origin chunk")
        scroll("comparison-detail-count");compose.onNodeWithTag("comparison-detail-count").assertTextEquals("Фрагмент 1 из 256")
        scroll("comparison-detail-previous");compose.onNodeWithTag("comparison-detail-previous").assertIsNotEnabled()
        scroll("comparison-detail-next");compose.onNodeWithTag("comparison-detail-next").performClick()
        compose.runOnIdle {state.value=model(rows=listOf(r),section=AdminComparisonSection.DIFF,
            detail=AdminComparisonDetail(r.id,AdminComparisonSide.BEFORE_ORIGIN,255,256,"{\"synthetic\":\"\uD83D\uDE00\u2028\"}"))}
        scroll("comparison-detail-text");compose.onNodeWithTag("comparison-detail-text").assertTextEquals("{\"synthetic\":\"\uD83D\uDE00\u2028\"}")
        compose.onNodeWithText("private synthetic origin chunk").assertDoesNotExist()
        scroll("comparison-detail-next");compose.onNodeWithTag("comparison-detail-next").assertIsNotEnabled()
        scroll("comparison-detail-previous");compose.onNodeWithTag("comparison-detail-previous").performClick()
        scroll("comparison-side-${r.id}-AFTER");compose.onNodeWithTag("comparison-side-${r.id}-AFTER").performClick()
        compose.runOnIdle {assertEquals(listOf(Triple(r.id,AdminComparisonSide.BEFORE_ORIGIN,0),
            Triple(r.id,AdminComparisonSide.BEFORE_ORIGIN,1),Triple(r.id,AdminComparisonSide.BEFORE_ORIGIN,254),Triple(r.id,AdminComparisonSide.AFTER,0)),requests)}
    }

    @Test fun localApplyRequiresReadyAndOneExplicitConfirmationWithoutPublicationOrAutomaticReplay() {
        val calls=mutableListOf<Pair<String,Long>>();val mounted=mutableStateOf(true);val state=mutableStateOf(model())
        compose.setContent {MaterialTheme(colorScheme=darkColorScheme()) {if(mounted.value)AdminComparisonScreen(state.value,AdminComparisonActions(apply={b,r->calls+=b to r}))}}
        scroll("comparison-apply");compose.onNodeWithTag("comparison-apply").assertIsNotEnabled()
        compose.runOnIdle {state.value=model(ready=true)}
        scroll("comparison-apply");compose.onNodeWithTag("comparison-apply").performClick()
        compose.onNodeWithTag("comparison-confirm-dialog").assertIsDisplayed()
        compose.runOnIdle {assertTrue(calls.isEmpty())}
        compose.onNodeWithTag("comparison-confirm-cancel").performClick()
        compose.runOnIdle {assertTrue(calls.isEmpty())}
        scroll("comparison-apply");compose.onNodeWithTag("comparison-apply").performClick()
        compose.onNodeWithTag("comparison-confirm-apply").performClick()
        compose.runOnIdle {assertEquals(listOf(id(1) to 3L),calls)}
        compose.onNodeWithTag("comparison-confirm-dialog").assertDoesNotExist()
        scroll("comparison-apply");compose.onNodeWithTag("comparison-apply").assertIsNotEnabled()
        compose.onNodeWithTag("editor-publish").assertDoesNotExist();compose.onNodeWithTag("vpn-connect").assertDoesNotExist()
        compose.runOnIdle {mounted.value=false}
        compose.runOnIdle {mounted.value=true}
        compose.runOnIdle {assertEquals(listOf(id(1) to 3L),calls)}
        compose.onNodeWithTag("comparison-confirm-dialog").assertDoesNotExist()
    }

    @Test fun changedResolutionBindingRevisionDeviceAndBusyCannotConfirmAnOldSnapshot() {
        val calls=mutableListOf<Pair<String,Long>>();val state=mutableStateOf(model(ready=true))
        compose.setContent {MaterialTheme(colorScheme=darkColorScheme()) {AdminComparisonScreen(state.value,AdminComparisonActions(apply={b,r->calls+=b to r}))}}
        scroll("comparison-apply");compose.onNodeWithTag("comparison-apply").performClick()
        compose.runOnIdle {state.value=model(binding=id(2),ready=true)}
        compose.onNodeWithTag("comparison-confirm-dialog").assertDoesNotExist()
        scroll("comparison-apply");compose.onNodeWithTag("comparison-apply").performClick()
        compose.runOnIdle {state.value=model(binding=id(2),revision=4,ready=true)}
        compose.onNodeWithTag("comparison-confirm-dialog").assertDoesNotExist()
        scroll("comparison-apply");compose.onNodeWithTag("comparison-apply").performClick()
        compose.runOnIdle {state.value=model(binding=id(2),revision=4,device="another-synthetic-device",ready=true)}
        compose.onNodeWithTag("comparison-confirm-dialog").assertDoesNotExist()
        scroll("comparison-apply");compose.onNodeWithTag("comparison-apply").performClick()
        compose.runOnIdle {state.value=model(binding=id(2),revision=4,device="another-synthetic-device",ready=true,busy=true)}
        compose.onNodeWithTag("comparison-confirm-apply").assertIsNotEnabled()
        compose.runOnIdle {state.value=model(binding=id(3),revision=4,ready=false)}
        compose.onNodeWithTag("comparison-confirm-dialog").assertDoesNotExist()
        scroll("comparison-apply");compose.onNodeWithTag("comparison-apply").assertIsNotEnabled()
        compose.runOnIdle {state.value=model(binding=id(3),revision=4,ready=true,error="SESSION_EXPIRED")}
        scroll("comparison-apply");compose.onNodeWithTag("comparison-apply").assertIsNotEnabled()
        compose.runOnIdle {assertTrue(calls.isEmpty())}
    }

    @Test fun readOnlyDiffKeepsExplicitPagingAndLineageButHidesEveryChoiceAndApply() {
        val requests=mutableListOf<String>();val r=row(sides=listOf(AdminComparisonSide.AFTER_ORIGIN),kind="setting",code="ADDED")
        val state=mutableStateOf(model(rows=listOf(r),section=AdminComparisonSection.DIFF,total=2,ready=true,readOnly=true))
        compose.setContent {MaterialTheme(colorScheme=darkColorScheme()) {AdminComparisonScreen(state.value,AdminComparisonActions(
            page={s,o->requests+="page:$s:$o"},detail={_,s,p->requests+="detail:$s:$p"},choose={_,_->requests+="choose"},
            apply={_,_->requests+="apply"},back={requests+="back"}))}}
        scroll("comparison-read-only");compose.onNodeWithTag("comparison-read-only").assertIsDisplayed()
        compose.onNodeWithTag("comparison-apply").assertDoesNotExist();compose.onNodeWithTag("comparison-readiness").assertDoesNotExist()
        compose.onNodeWithTag("comparison-choose-${r.id}-LOCAL").assertDoesNotExist();compose.onNodeWithTag("comparison-reload").assertDoesNotExist()
        scroll("comparison-side-${r.id}-AFTER_ORIGIN");compose.onNodeWithTag("comparison-side-${r.id}-AFTER_ORIGIN").performClick()
        scroll("comparison-page-next");compose.onNodeWithTag("comparison-page-next").performClick()
        scroll("comparison-back");compose.onNodeWithTag("comparison-back").performClick()
        compose.runOnIdle {assertEquals(listOf("detail:AFTER_ORIGIN:0","page:DIFF:1","back"),requests)}
        compose.runOnIdle {state.value=model(rows=listOf(r),ready=true,readOnly=true)}
        compose.onNodeWithTag("comparison-apply").assertDoesNotExist()
        compose.onNodeWithTag("comparison-choose-${r.id}-LOCAL").assertDoesNotExist()
        compose.onNodeWithTag("comparison-choose-${r.id}-CURRENT").assertDoesNotExist()
        compose.runOnIdle {assertEquals(listOf("detail:AFTER_ORIGIN:0","page:DIFF:1","back"),requests)}
    }

    @Test fun modelBoundsCopySummariesAndRejectInvalidIdsUnicodeScopesAndHiddenRawLabels() {
        val sides=mutableListOf(AdminComparisonSide.BASE);val sourceRow=row(sides=sides)
        val rows=mutableListOf(sourceRow);val owned=model(rows=rows,total=2050)
        sides.clear();rows.clear();assertEquals(1,owned.rows.size);assertEquals(listOf(AdminComparisonSide.BASE),owned.rows.single().availableSides)
        assertThrows(UnsupportedOperationException::class.java) {(owned.rows as MutableList<*>).clear()}
        assertThrows(UnsupportedOperationException::class.java) {(sourceRow.availableSides as MutableList<*>).clear()}
        val detail=AdminComparisonDetail(sourceRow.id,AdminComparisonSide.BASE,255,256,"x".repeat(8190)+"\uD83D\uDE00")
        val computedPath=List(16) {"k".repeat(64)}.joinToString("/",prefix="/")
        assertEquals(1040,computedPath.length)
        for(path in listOf("", "mode", "approvalUntilMs", "revision", "/a_B-1", computedPath)) {
            assertEquals(path,AdminComparisonRow(id(4),"setting",path,"VALUE_CHANGED",availableSides=emptyList()).path)
        }
        for(value in listOf(owned,sourceRow,detail)) {assertTrue(value.toString().contains("[redacted]"));assertFalse(value.toString().contains(sourceRow.id))}
        for(action in listOf<()->Unit>(
            {AdminComparisonRow("A".repeat(42)+"B","device","","VALUE_CHANGED",availableSides=emptyList())},
            {row(sides=listOf(AdminComparisonSide.BASE,AdminComparisonSide.BASE))},
            {AdminComparisonRow(id(4),"device","\uD800","VALUE_CHANGED",availableSides=emptyList())},
            {AdminComparisonRow(id(4),"device","x".repeat(513),"VALUE_CHANGED",availableSides=emptyList())},
            {AdminComparisonRow(id(4),"setting","/"+"k".repeat(65),"VALUE_CHANGED",availableSides=emptyList())},
            {AdminComparisonRow(id(4),"setting",List(17) {"k"}.joinToString("/",prefix="/"),"VALUE_CHANGED",availableSides=emptyList())},
            {AdminComparisonRow(id(4),"setting","/k\u0000","VALUE_CHANGED",availableSides=emptyList())},
            {AdminComparisonRow(id(4),"setting","/кириллица","VALUE_CHANGED",availableSides=emptyList())},
            {AdminComparisonRow(id(4),"setting","/k//v","VALUE_CHANGED",availableSides=emptyList())},
            {AdminComparisonRow(id(4),"setting","/1key","VALUE_CHANGED",availableSides=emptyList())},
            {AdminComparisonRow(id(4),"unknown","","VALUE_CHANGED",availableSides=emptyList())},
            {AdminComparisonRow(id(4),"device","","UNKNOWN",availableSides=emptyList())},
            {AdminComparisonDetail(id(4),AdminComparisonSide.BASE,256,256,"")},
            {AdminComparisonDetail(id(4),AdminComparisonSide.BASE,0,257,"")},
            {AdminComparisonDetail(id(4),AdminComparisonSide.BASE,0,1,"\uD800")},
            {AdminComparisonDetail(id(4),AdminComparisonSide.BASE,0,1,"x".repeat(8193))},
            {model(rows=List(21) {row(it+10)},total=21)}, {model(rows=listOf(sourceRow,sourceRow),total=2)},
            {model(binding="A".repeat(42)+"B")}, {model(total=2051)}, {model(section=AdminComparisonSection.DIFF,total=8195)},
            {model(device="x".repeat(65))},
            {model(total=1,offset=1)}, {model(revision=9_007_199_254_740_992L)},
            {model(baseRevision=-1)}, {model(currentRevision=9_007_199_254_740_992L)},
            {model(detail=AdminComparisonDetail(id(999),AdminComparisonSide.BASE,0,1,"private synthetic body"))},
            {model(detail=AdminComparisonDetail(sourceRow.id,AdminComparisonSide.AFTER,0,1,"private synthetic body"))})) {
            assertThrows(IllegalArgumentException::class.java,action)
        }
        val maximum=model(rows=List(20) {row(it+10)},section=AdminComparisonSection.DIFF,total=8194,offset=8174)
        assertEquals(8194,maximum.offset+maximum.rows.size)
        val state=mutableStateOf(model(rows=emptyList(),total=0,error="SYNTHETIC_PRIVATE_ERROR"))
        compose.setContent {MaterialTheme(colorScheme=darkColorScheme()) {AdminComparisonScreen(state.value,AdminComparisonActions())}}
        scroll("comparison-error");compose.onNodeWithTag("comparison-error").assertTextEquals(adminComparisonErrorText("SYNTHETIC_PRIVATE_ERROR"))
        compose.onNodeWithText("SYNTHETIC_PRIVATE_ERROR").assertDoesNotExist()
        scroll("comparison-readiness");compose.onNodeWithTag("comparison-readiness").assertTextEquals("Локальное применение пока недоступно.")
    }
}
