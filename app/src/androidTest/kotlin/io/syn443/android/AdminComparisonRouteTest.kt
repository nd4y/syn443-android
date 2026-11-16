package io.syn443.android

import android.os.SystemClock
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.*
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.text.AnnotatedString
import androidx.lifecycle.Lifecycle
import io.syn443.android.admin.*
import io.syn443.android.vpn.AdminEditorCoordinator.Command
import io.syn443.android.vpn.AdminEditorCoordinator.ComparisonCommand
import io.syn443.android.vpn.AdminEditorCoordinator.ComparisonKind
import io.syn443.android.vpn.AdminEditorCoordinator.Kind
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import java.util.Base64
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger

/** Actual route/lifecycle, isolated value-only bridge. No Provider, account,
 * persisted bodies, HTTP, credentials, browser, native owner or VPN work. */
class AdminComparisonRouteTest {
    @get:Rule val compose=createAndroidComposeRule<ComponentActivity>()

    private class Bridge(initialPhase:AdminEditorPhase=AdminEditorPhase.CONFLICT):AdminUiBridge {
        val device="synthetic-device"
        val editorCommands=CopyOnWriteArrayList<Command>()
        val comparisonCommands=CopyOnWriteArrayList<ComparisonCommand>()
        val reads=CopyOnWriteArrayList<String>()
        val logins=AtomicInteger();val logouts=AtomicInteger();val cancelled=AtomicInteger();val webCalls=AtomicInteger()
        @Volatile var status=AdminUiStatus(8,AdminUiPhase.AUTHENTICATED)
        @Volatile var comparisonHook:(suspend (ComparisonCommand)->AdminComparisonModel)?=null
        @Volatile private var saved=prepared(initialPhase)
        @Volatile private var cached:AdminComparisonModel?=null
        fun snapshot()=saved
        private fun prepared(phase:AdminEditorPhase,pages:List<String> = listOf("{\"synthetic\":1}"),
            revision:Long=7,binding:String="document-7",review:String="",deadline:Long=0,comparison:String="")=
            AdminEditorModel(device=device,privateDraftRevision=2,desiredHeadRevision=4,localRevision=revision,phase=phase,
                documentBinding=binding,pages=pages,parents=listOf(AdminEditorParent("template","synthetic-template",1)),
                reviewBinding=review,reviewDeadlineElapsed=deadline,recipients=if(review.isEmpty())emptyList()else listOf(device),
                diffSummaries=if(review.isEmpty())emptyList()else listOf("device: /network (set)"),comparisonBinding=comparison)
        private fun view(readOnly:Boolean=false,choice:String="",binding:String=id(100),
            section:AdminComparisonSection=if(readOnly)AdminComparisonSection.DIFF else AdminComparisonSection.CONFLICTS,
            detail:AdminComparisonDetail?=null):AdminComparisonModel {
            val sides=if(section==AdminComparisonSection.CONFLICTS)listOf(AdminComparisonSide.BASE,AdminComparisonSide.LOCAL_VALUE,AdminComparisonSide.CURRENT)
                else listOf(AdminComparisonSide.BEFORE,AdminComparisonSide.AFTER,AdminComparisonSide.BEFORE_ORIGIN,AdminComparisonSide.AFTER_ORIGIN)
            val row=AdminComparisonRow(id(700),if(readOnly)"setting" else "device","/network","VALUE_CHANGED",!readOnly,choice,sides)
            return AdminComparisonModel(device=device,binding=binding,localRevision=saved.localRevision,section=section,total=1,rows=listOf(row),
                ready=!readOnly && choice.isNotEmpty(),detail=detail,readOnly=readOnly,baseRevision=4,currentRevision=5)
        }
        override suspend fun status():AdminUiStatus {reads+="status";return status}
        override suspend fun devices(generation:Long,after:String):AdminDevicesPage {
            check(generation==status.generation && after.isEmpty());reads+="devices"
            return AdminDevicesPage(listOf(AdminDeviceRow(device,4,4,"Последний отчёт; соединение неизвестно")),"",1000)
        }
        override suspend fun document(generation:Long,action:AdminReadAction,target:String):AdminDocument {
            check(generation==status.generation && target==device);reads+=action.name
            return AdminDocument(listOf("synthetic read-only ${action.name}"),"Последний отчёт; соединение неизвестно")
        }
        override suspend fun editor(generation:Long,command:Command):AdminEditorModel=withContext(Dispatchers.Default) {
            check(generation==status.generation && command.device==device);editorCommands+=command
            if(command.kind!=Kind.OPEN)check(command.binding==saved.documentBinding && command.localRevision==saved.localRevision)
            saved=when(command.kind) {
                Kind.OPEN->saved
                Kind.PREVIEW->{
                    cached=view(readOnly=true,binding=id(200))
                    prepared(AdminEditorPhase.REVIEW,saved.pages,saved.localRevision,saved.documentBinding,
                        "review-original",SystemClock.elapsedRealtime()+90_000,checkNotNull(cached).binding)
                }
                Kind.REBASE->{
                    val current=checkNotNull(cached)
                    check(!current.readOnly && current.ready && command.comparisonBinding==current.binding)
                    check(command.pages.isEmpty() && command.reviewBinding.isEmpty() && command.reviewDeadline==0L)
                    cached=null
                    prepared(AdminEditorPhase.LOCAL_DIRTY,listOf("{\"synthetic\":2}"),saved.localRevision+1,"document-${saved.localRevision+1}")
                }
                Kind.SAVE_LOCAL->{
                    cached=null;prepared(AdminEditorPhase.LOCAL_DIRTY,command.pages,saved.localRevision+1,"document-${saved.localRevision+1}")
                }
                else->error("unexpected_editor_mutation")
            }
            saved
        }
        override suspend fun comparison(generation:Long,command:ComparisonCommand):AdminComparisonModel=withContext(Dispatchers.Default) {
            check(generation==status.generation && command.device==device && command.documentBinding==saved.documentBinding &&
                command.localRevision==saved.localRevision)
            comparisonCommands+=command
            comparisonHook?.invoke(command)?:normalComparison(command)
        }
        fun normalComparison(command:ComparisonCommand):AdminComparisonModel {
            val before=cached
            if(command.kind!=ComparisonKind.LOAD)check(before!=null && command.comparisonBinding==before.binding)
            val next=when(command.kind) {
                ComparisonKind.LOAD->{check(command.comparisonBinding.isEmpty());view()}
                ComparisonKind.PAGE->{val current=checkNotNull(before);view(current.readOnly,current.rows.single().choice,current.binding,command.section)}
                ComparisonKind.DETAIL->{
                    val current=checkNotNull(before);val row=current.rows.single()
                    check(command.rowId==row.id && command.side in row.availableSides)
                    view(current.readOnly,row.choice,current.binding,current.section,
                        AdminComparisonDetail(row.id,command.side,command.page,2,"private comparison body ${command.side.name} ${command.page}"))
                }
                ComparisonKind.RESOLVE->{
                    val current=checkNotNull(before)
                    check(!current.readOnly && command.rowId==current.rows.single().id && command.choice in setOf("LOCAL","CURRENT"))
                    view(choice=command.choice,binding=id(101))
                }
            }
            cached=next;return next
        }
        override suspend fun login(generation:Long):Boolean {logins.incrementAndGet();return false}
        override suspend fun logout(generation:Long):Boolean {logouts.incrementAndGet();return false}
        override suspend fun browser(generation:Long):AdminBrowserLaunch=error("unexpected_browser")
        override suspend fun callback(raw:String) {error("unexpected_callback")}
        override suspend fun webPanel():String {webCalls.incrementAndGet();throw AdminUiFailure("UNAVAILABLE")}
    }
    private fun waitNode(tag:String) {
        compose.waitUntil(5000) {compose.onAllNodesWithTag(tag).fetchSemanticsNodes(atLeastOneRootRequired=false).isNotEmpty()}
    }
    private fun adminScroll(tag:String)=compose.onNodeWithTag("admin-content").performScrollToNode(hasTestTag(tag))
    private fun waitScroll(container:String,tag:String) {
        compose.waitUntil(5000) {
            if(compose.onAllNodesWithTag(container).fetchSemanticsNodes(atLeastOneRootRequired=false).size!=1)false else try {
                compose.onNodeWithTag(container).performScrollToNode(hasTestTag(tag))
                compose.onAllNodesWithTag(tag).fetchSemanticsNodes(atLeastOneRootRequired=false).size==1
            }catch(_:AssertionError){false}
        }
    }
    private fun editorScroll(tag:String)=waitScroll("editor-content",tag)
    private fun comparisonScroll(tag:String)=waitScroll("comparison-content",tag)
    private fun text(tag:String,value:String,comparison:Boolean=true) {
        if(comparison)comparisonScroll(tag) else editorScroll(tag)
        compose.waitUntil(5000) {
            val node=compose.onAllNodesWithTag(tag).fetchSemanticsNodes(atLeastOneRootRequired=false).singleOrNull()
            node!=null && node.config.contains(SemanticsProperties.Text) && node.config[SemanticsProperties.Text].map {it.text}==listOf(value)
        }
        compose.onNodeWithTag(tag).assertTextEquals(value)
    }
    private fun content(bridge:Bridge,mounted:State<Boolean> = mutableStateOf(true)) {
        compose.setContent {MaterialTheme(colorScheme=darkColorScheme()) {if(mounted.value)AdminRoute(bridge)}}
    }
    private fun open(bridge:Bridge) {
        val tag="admin-device-${bridge.device}"
        compose.waitUntil(5000) {
            if(compose.onAllNodesWithTag("admin-content").fetchSemanticsNodes(atLeastOneRootRequired=false).size!=1)false else try {
                adminScroll(tag)
                val row=compose.onAllNodesWithTag(tag).fetchSemanticsNodes(atLeastOneRootRequired=false).singleOrNull()
                row!=null && !row.config.contains(SemanticsProperties.Disabled)
            }catch(_:AssertionError){false}
        }
        compose.onNodeWithTag(tag).assertIsEnabled().performClick()
        adminScroll("admin-edit-configuration");compose.onNodeWithTag("admin-edit-configuration").assertIsEnabled().performClick()
        waitNode("editor-title")
        compose.waitUntil(5000) {bridge.editorCommands.lastOrNull()?.kind==Kind.OPEN}
        editorScroll("editor-page-input");compose.onNodeWithTag("editor-page-input").assertIsDisplayed()
    }
    private fun load() {
        editorScroll("editor-comparison");compose.onNodeWithTag("editor-comparison").assertIsEnabled().performClick()
        waitNode("comparison-title");comparisonScroll("comparison-row-${id(700)}")
        compose.onNodeWithTag("comparison-row-${id(700)}").assertIsDisplayed()
    }
    private fun assertInput(value:String) {
        editorScroll("editor-page-input")
        compose.onNodeWithTag("editor-page-input").assert(SemanticsMatcher.expectValue(SemanticsProperties.EditableText,AnnotatedString(value)))
    }
    private fun comparisonBack() {
        comparisonScroll("comparison-back");compose.onNodeWithTag("comparison-back").assertIsEnabled().performClick();waitNode("editor-title")
    }
    private fun editorBack() {
        editorScroll("editor-back");compose.onNodeWithTag("editor-back").assertIsEnabled().performClick();waitNode("admin-title")
    }
    private fun assertNoAutomaticAuthority(bridge:Bridge) {
        assertEquals(0,bridge.logins.get());assertEquals(0,bridge.logouts.get());assertEquals(0,bridge.webCalls.get())
        assertTrue(bridge.editorCommands.none {it.kind in setOf(Kind.SAVE_DRAFT,Kind.PUBLISH,Kind.RETRY_EXACT,Kind.POLL)})
    }

    @Test fun conflictLoadResolveDetailAndConfirmedApplyOnlySendBoundLocalRebase() {
        val bridge=Bridge();content(bridge);open(bridge);load()
        comparisonScroll("comparison-apply");compose.onNodeWithTag("comparison-apply").assertIsNotEnabled()
        comparisonScroll("comparison-side-${id(700)}-BASE");compose.onNodeWithTag("comparison-side-${id(700)}-BASE").performClick()
        text("comparison-detail-text","private comparison body BASE 0")
        comparisonScroll("comparison-detail-next");compose.onNodeWithTag("comparison-detail-next").performClick()
        text("comparison-detail-text","private comparison body BASE 1")
        comparisonScroll("comparison-choose-${id(700)}-LOCAL");compose.onNodeWithTag("comparison-choose-${id(700)}-LOCAL").performClick()
        text("comparison-choice-${id(700)}","Выбрана локальная версия.")
        comparisonScroll("comparison-apply");compose.onNodeWithTag("comparison-apply").assertIsEnabled().performClick()
        compose.onNodeWithTag("comparison-confirm-dialog").assertIsDisplayed()
        compose.runOnIdle {assertEquals(listOf(Kind.OPEN),bridge.editorCommands.map {it.kind})}
        compose.onNodeWithTag("comparison-confirm-cancel").performClick()
        comparisonScroll("comparison-apply");compose.onNodeWithTag("comparison-apply").performClick()
        compose.onNodeWithTag("comparison-confirm-apply").assertIsEnabled().performClick()
        waitNode("editor-title");assertInput("{\"synthetic\":2}")
        compose.onNodeWithTag("comparison-content").assertDoesNotExist()
        compose.runOnIdle {
            assertEquals(listOf(Kind.OPEN,Kind.REBASE),bridge.editorCommands.map {it.kind})
            val apply=bridge.editorCommands.last();assertEquals("document-7",apply.binding);assertEquals(7L,apply.localRevision)
            assertEquals(id(101),apply.comparisonBinding);assertEquals(8L,bridge.snapshot().localRevision)
            assertEquals(listOf(ComparisonKind.LOAD,ComparisonKind.DETAIL,ComparisonKind.DETAIL,ComparisonKind.RESOLVE),bridge.comparisonCommands.map {it.kind})
            assertTrue(bridge.comparisonCommands.drop(1).all {it.comparisonBinding==id(100)})
            assertEquals(listOf(0,1),bridge.comparisonCommands.filter {it.kind==ComparisonKind.DETAIL}.map {it.page})
            assertNoAutomaticAuthority(bridge)
        }
        compose.onNodeWithTag("vpn-connect").assertDoesNotExist();compose.onNodeWithTag("vpn-disconnect").assertDoesNotExist()
    }

    @Test fun readOnlyPreviewComparisonRetainsOriginalReviewAndDirtyEditorCannotOpenOldDiff() {
        val bridge=Bridge(AdminEditorPhase.EDITING);content(bridge);open(bridge)
        editorScroll("editor-preview");compose.onNodeWithTag("editor-preview").assertIsEnabled().performClick()
        editorScroll("editor-full-comparison")
        val review=bridge.snapshot()
        editorScroll("editor-full-comparison");compose.onNodeWithTag("editor-full-comparison").assertIsEnabled().performClick()
        waitNode("comparison-title");comparisonScroll("comparison-read-only");compose.onNodeWithTag("comparison-read-only").assertIsDisplayed()
        compose.onNodeWithTag("comparison-apply").assertDoesNotExist();compose.onNodeWithTag("comparison-reload").assertDoesNotExist()
        compose.onNodeWithTag("comparison-choose-${id(700)}-LOCAL").assertDoesNotExist()
        comparisonScroll("comparison-side-${id(700)}-AFTER_ORIGIN");compose.onNodeWithTag("comparison-side-${id(700)}-AFTER_ORIGIN").performClick()
        text("comparison-detail-text","private comparison body AFTER_ORIGIN 0")
        comparisonBack();assertInput("{\"synthetic\":1}")
        editorScroll("editor-publish");compose.onNodeWithTag("editor-publish").assertIsEnabled().performClick()
        compose.onNodeWithTag("editor-confirm-dialog").assertIsDisplayed()
        compose.onNodeWithTag("editor-confirm-cancel").performClick()
        compose.runOnIdle {
            assertSame(review,bridge.snapshot());assertEquals(7L,review.localRevision);assertEquals("document-7",review.documentBinding)
            assertEquals("review-original",review.reviewBinding);assertTrue(review.reviewDeadlineElapsed>0)
            assertEquals(listOf(Kind.OPEN,Kind.PREVIEW),bridge.editorCommands.map {it.kind})
            assertEquals(listOf(ComparisonKind.PAGE,ComparisonKind.DETAIL),bridge.comparisonCommands.map {it.kind})
            assertTrue(bridge.comparisonCommands.all {it.comparisonBinding==id(200) && it.localRevision==7L && it.documentBinding=="document-7"})
        }
        editorScroll("editor-page-input");compose.onNodeWithTag("editor-page-input").performTextReplacement("private unsaved replacement")
        editorScroll("editor-full-comparison");compose.onNodeWithTag("editor-full-comparison").assertIsNotEnabled()
        editorScroll("editor-publish");compose.onNodeWithTag("editor-publish").assertIsNotEnabled()
        assertInput("private unsaved replacement")
        compose.runOnIdle {assertEquals(2,bridge.comparisonCommands.size);assertNoAutomaticAuthority(bridge)}
        editorScroll("editor-save-local");compose.onNodeWithTag("editor-save-local").assertIsEnabled().performClick()
        text("editor-phase","Локальные изменения ещё не опубликованы",comparison=false)
        assertInput("private unsaved replacement");compose.onNodeWithTag("editor-full-comparison").assertDoesNotExist()
        compose.runOnIdle {
            val saved=bridge.snapshot();assertEquals(8L,saved.localRevision);assertEquals("",saved.reviewBinding)
            assertEquals(0L,saved.reviewDeadlineElapsed);assertEquals("",saved.comparisonBinding);assertNoAutomaticAuthority(bridge)
        }
    }

    @Test fun busyComparisonStopRapidResumeAndRemovalCannotRestoreLateValues() {
        val bridge=Bridge();val mounted=mutableStateOf(true);val held=CompletableDeferred<AdminComparisonModel>();val late=CompletableDeferred<AdminComparisonModel>()
        bridge.comparisonHook={command->if(command.kind==ComparisonKind.DETAIL)try {held.await()}catch(_:CancellationException) {
            bridge.cancelled.incrementAndGet();withContext(NonCancellable) {late.await()}
        } else bridge.normalComparison(command)}
        try {
            content(bridge,mounted);open(bridge);load()
            comparisonScroll("comparison-side-${id(700)}-BASE");compose.onNodeWithTag("comparison-side-${id(700)}-BASE").performClick()
            compose.waitUntil(5000) {bridge.comparisonCommands.count {it.kind==ComparisonKind.DETAIL}==1}
            comparisonScroll("comparison-back");compose.onNodeWithTag("comparison-back").assertIsNotEnabled()
            comparisonScroll("comparison-choose-${id(700)}-LOCAL");compose.onNodeWithTag("comparison-choose-${id(700)}-LOCAL").assertIsNotEnabled()
            comparisonScroll("comparison-apply");compose.onNodeWithTag("comparison-apply").assertIsNotEnabled()
            val pagesBefore=bridge.reads.count {it=="devices"}
            compose.activityRule.scenario.moveToState(Lifecycle.State.CREATED)
            compose.activityRule.scenario.moveToState(Lifecycle.State.RESUMED)
            compose.waitUntil(5000) {bridge.cancelled.get()==1 && bridge.reads.count {it=="devices"}==pagesBefore+1}
            late.complete(AdminComparisonModel(device=bridge.device,binding=id(999),localRevision=7,total=1,rows=listOf(
                AdminComparisonRow(id(999),"setting","/network","ADDED",availableSides=listOf(AdminComparisonSide.BASE))),
                detail=AdminComparisonDetail(id(999),AdminComparisonSide.BASE,0,1,"late private comparison body")))
            waitNode("admin-title");compose.onNodeWithTag("comparison-title").assertDoesNotExist();compose.onNodeWithTag("editor-title").assertDoesNotExist()
            compose.onNodeWithText("late private comparison body").assertDoesNotExist()
            bridge.comparisonHook=null
            open(bridge);load()
            val beforeRemoval=bridge.comparisonCommands.size
            compose.runOnIdle {mounted.value=false}
            assertTrue(compose.onAllNodesWithTag("comparison-content").fetchSemanticsNodes(atLeastOneRootRequired=false).isEmpty())
            compose.runOnIdle {mounted.value=true};waitNode("admin-title")
            compose.onNodeWithTag("comparison-title").assertDoesNotExist();compose.onNodeWithTag("editor-title").assertDoesNotExist()
            compose.runOnIdle {assertEquals(beforeRemoval,bridge.comparisonCommands.size)}
            open(bridge);load();val beforeRecreate=bridge.comparisonCommands.size
            compose.activityRule.scenario.recreate()
            compose.activityRule.scenario.onActivity {activity->activity.setContent {
                MaterialTheme(colorScheme=darkColorScheme()) {AdminRoute(bridge)}
            }}
            waitNode("admin-title");compose.onNodeWithTag("comparison-title").assertDoesNotExist();compose.onNodeWithTag("editor-title").assertDoesNotExist()
            compose.onNodeWithText("private comparison body BASE 0").assertDoesNotExist()
            compose.runOnIdle {
                assertEquals(beforeRecreate,bridge.comparisonCommands.size);assertEquals(3,bridge.editorCommands.size)
                assertTrue(bridge.editorCommands.all {it.kind==Kind.OPEN});assertNoAutomaticAuthority(bridge)
            }
        }finally {held.complete(AdminComparisonModel());late.complete(AdminComparisonModel())}
    }

    @Test fun staleAndFiniteComparisonErrorsRetainDraftButReauthenticationClearsPrivilegedRam() {
        val bridge=Bridge();content(bridge);open(bridge);load()
        comparisonScroll("comparison-side-${id(700)}-BASE");compose.onNodeWithTag("comparison-side-${id(700)}-BASE").performClick()
        text("comparison-detail-text","private comparison body BASE 0")
        bridge.comparisonHook={throw AdminUiFailure("COMPARISON_STALE")}
        comparisonScroll("comparison-side-${id(700)}-BASE");compose.onNodeWithTag("comparison-side-${id(700)}-BASE").performClick()
        text("comparison-error",adminComparisonErrorText("COMPARISON_STALE"))
        text("comparison-detail-text","private comparison body BASE 0")
        compose.onNodeWithTag("comparison-apply").assertDoesNotExist();comparisonBack();assertInput("{\"synthetic\":1}")
        editorBack();bridge.comparisonHook=null;open(bridge);load()
        bridge.comparisonHook={throw AdminUiFailure("synthetic-private-error-value")}
        comparisonScroll("comparison-side-${id(700)}-BASE");compose.onNodeWithTag("comparison-side-${id(700)}-BASE").performClick()
        text("comparison-error",adminComparisonErrorText("UNAVAILABLE"))
        compose.onNodeWithText("synthetic-private-error-value").assertDoesNotExist()
        compose.onNodeWithText("SYNTHETIC-PRIVATE-ERROR-VALUE").assertDoesNotExist()
        comparisonBack();assertInput("{\"synthetic\":1}");editorBack();bridge.comparisonHook=null;open(bridge);load()
        bridge.comparisonHook={throw AdminUiFailure("REAUTHENTICATE")}
        comparisonScroll("comparison-side-${id(700)}-BASE");compose.onNodeWithTag("comparison-side-${id(700)}-BASE").performClick()
        waitNode("admin-title");compose.onNodeWithTag("admin-status").assertTextEquals("Административная сессия истекла. Войдите снова.")
        adminScroll("admin-login");compose.onNodeWithTag("admin-login").assertIsEnabled()
        compose.onNodeWithTag("comparison-content").assertDoesNotExist();compose.onNodeWithTag("editor-page-input").assertDoesNotExist()
        compose.onNodeWithText("private comparison body BASE 0").assertDoesNotExist()
        compose.runOnIdle {
            assertEquals(7L,bridge.snapshot().localRevision);assertEquals(listOf("{\"synthetic\":1}"),bridge.snapshot().pages)
            assertEquals(3,bridge.editorCommands.size);assertTrue(bridge.editorCommands.all {it.kind==Kind.OPEN});assertNoAutomaticAuthority(bridge)
        }
    }

    companion object {
        private fun id(value:Int)=Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32).also {
            it[30]=(value ushr 8).toByte();it[31]=value.toByte()
        })
    }
}
