package io.syn443.android

import androidx.activity.ComponentActivity
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
import io.syn443.android.vpn.AdminEditorCoordinator.Kind
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import java.util.Base64
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/** Real route/lifecycle with a value-only fake bridge; no Provider, persisted
 * operation, account, native SDK, browser, network, device or VPN mutation. */
class AdminOperationRouteTest {
    @get:Rule val compose=createAndroidComposeRule<ComponentActivity>()
    private class Bridge:AdminUiBridge {
        val device="synthetic-device"
        val operation=Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32) {6})
        val text="{unfinished synthetic local text"
        val commands=CopyOnWriteArrayList<Command>();val reads=CopyOnWriteArrayList<String>()
        val logins=AtomicInteger();val logouts=AtomicInteger();val webCalls=AtomicInteger();val cancelled=AtomicInteger()
        @Volatile var status=AdminUiStatus(8,AdminUiPhase.AUTHENTICATED)
        @Volatile var intercept:(suspend (Command)->AdminEditorModel)?=null
        @Volatile private var saved=prepared()
        fun prepared(seal:Boolean=false,phase:AdminEditorPhase=AdminEditorPhase.UNCERTAIN,
            binding:String="document-9",revision:Long=9,body:String=text,outcome:String="UNKNOWN")=
            AdminEditorModel(device=device,privateDraftRevision=3,desiredHeadRevision=5,localRevision=revision,
                phase=phase,documentBinding=binding,pages=listOf(body),operationBinding=if(phase==AdminEditorPhase.UNCERTAIN)operation else "",
                operationOutcome=outcome,canSeal=seal,error=if(phase==AdminEditorPhase.UNCERTAIN)"OUTCOME_UNKNOWN" else "")
        override suspend fun status():AdminUiStatus {reads+="status";return status}
        override suspend fun devices(generation:Long,after:String):AdminDevicesPage {
            check(generation==status.generation && after.isEmpty());reads+="devices"
            return AdminDevicesPage(listOf(AdminDeviceRow(device,4,5,"Последний отчёт; соединение неизвестно")),"",1000)
        }
        override suspend fun document(generation:Long,action:AdminReadAction,target:String):AdminDocument {
            check(generation==status.generation && target==device);reads+=action.name
            return AdminDocument(listOf("synthetic ${action.name}"),"Последний отчёт; текущее соединение неизвестно")
        }
        override suspend fun editor(generation:Long,command:Command):AdminEditorModel=withContext(Dispatchers.Default) {
            check(generation==status.generation && command.device==device);commands+=command
            intercept?.invoke(command)?:normal(command)
        }
        fun normal(command:Command):AdminEditorModel {
            if(command.kind!=Kind.OPEN) {
                check(command.binding==saved.documentBinding && command.localRevision==saved.localRevision && command.operationBinding==operation)
                check(command.pages.isEmpty() && command.reviewBinding.isEmpty() && command.reviewDeadline==0L && command.comparisonBinding.isEmpty())
            }
            saved=when(command.kind) {
                Kind.OPEN->saved
                Kind.CHECK_OUTCOME->prepared(seal=true)
                Kind.SEAL_PENDING->{check(saved.canSeal);prepared(phase=AdminEditorPhase.LOCAL_DIRTY,binding="document-10",revision=10,outcome="NO_EFFECT")}
                else->error("unexpected_presentation_command")
            }
            return saved
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
    private fun scroll(container:String,tag:String)=compose.onNodeWithTag(container).performScrollToNode(hasTestTag(tag))
    private fun editorScroll(tag:String)=scroll("editor-content",tag)
    private fun waitEnabled(container:String,tag:String) {
        compose.waitUntil(5000) {
            if(compose.onAllNodesWithTag(container).fetchSemanticsNodes(atLeastOneRootRequired=false).size!=1)false else try {
                scroll(container,tag)
                val node=compose.onAllNodesWithTag(tag).fetchSemanticsNodes(atLeastOneRootRequired=false).singleOrNull()
                node!=null && !node.config.contains(SemanticsProperties.Disabled)
            }catch(_:AssertionError) {false}
        }
    }
    private fun content(bridge:Bridge,mounted:State<Boolean>) {
        compose.setContent {MaterialTheme(colorScheme=darkColorScheme()) {if(mounted.value)AdminRoute(bridge)}}
    }
    private fun open(bridge:Bridge) {
        val row="admin-device-${bridge.device}"
        waitEnabled("admin-content",row);compose.onNodeWithTag(row).performClick()
        waitEnabled("admin-content","admin-edit-configuration");compose.onNodeWithTag("admin-edit-configuration").performClick()
        waitEnabled("editor-content","editor-check-outcome")
    }
    private fun input(value:String) {
        editorScroll("editor-page-input")
        compose.onNodeWithTag("editor-page-input").assert(SemanticsMatcher.expectValue(SemanticsProperties.EditableText,AnnotatedString(value)))
    }
    private fun phase(value:String) {
        editorScroll("editor-phase")
        compose.waitUntil(5000) {
            val node=compose.onAllNodesWithTag("editor-phase").fetchSemanticsNodes(atLeastOneRootRequired=false).singleOrNull()
            node!=null && node.config.contains(SemanticsProperties.Text) && node.config[SemanticsProperties.Text].map {it.text}==listOf(value)
        }
    }

    @Test fun routeLookupThenConfirmedSealCarriesExactPendingDocumentAndCasWithoutPublication() {
        val bridge=Bridge();content(bridge,mutableStateOf(true));open(bridge)
        input(bridge.text)
        compose.runOnIdle {assertEquals(listOf(Kind.OPEN),bridge.commands.map {it.kind})}
        editorScroll("editor-check-outcome");compose.onNodeWithTag("editor-check-outcome").performClick()
        waitEnabled("editor-content","editor-seal-pending");input(bridge.text)
        editorScroll("editor-seal-pending");compose.onNodeWithTag("editor-seal-pending").performClick()
        compose.runOnIdle {assertEquals(listOf(Kind.OPEN,Kind.CHECK_OUTCOME),bridge.commands.map {it.kind})}
        compose.onNodeWithTag("editor-seal-cancel").performClick()
        editorScroll("editor-seal-pending");compose.onNodeWithTag("editor-seal-pending").performClick()
        compose.onNodeWithTag("editor-seal-confirm").performClick()
        phase("Локальные изменения ещё не опубликованы");input(bridge.text)
        compose.runOnIdle {
            assertEquals(listOf(Kind.OPEN,Kind.CHECK_OUTCOME,Kind.SEAL_PENDING),bridge.commands.map {it.kind})
            for(command in bridge.commands.drop(1)) {
                assertEquals("document-9",command.binding);assertEquals(9L,command.localRevision)
                assertEquals(bridge.operation,command.operationBinding);assertEquals(bridge.device,command.device)
                assertTrue(command.pages.isEmpty());assertTrue(command.reviewBinding.isEmpty());assertEquals(0L,command.reviewDeadline)
            }
            assertEquals(0,bridge.logins.get());assertEquals(0,bridge.logouts.get())
        }
        editorScroll("editor-back");compose.onNodeWithTag("editor-back").performClick();waitNode("admin-title")
        compose.runOnIdle {assertEquals(3,bridge.commands.size)}
        compose.onNodeWithTag("editor-seal-dialog").assertDoesNotExist()
    }

    @Test fun busyLookupStopAndRapidResumeDropLateSealPermissionWithoutAutomaticReplay() {
        val bridge=Bridge();val mounted=mutableStateOf(true);val held=CompletableDeferred<AdminEditorModel>()
        bridge.intercept={command->if(command.kind==Kind.CHECK_OUTCOME)try {held.await()}
            catch(error:CancellationException){bridge.cancelled.incrementAndGet();throw error}else bridge.normal(command)}
        content(bridge,mounted);open(bridge)
        editorScroll("editor-check-outcome");compose.onNodeWithTag("editor-check-outcome").performClick()
        compose.waitUntil(5000) {bridge.commands.count {it.kind==Kind.CHECK_OUTCOME}==1}
        editorScroll("editor-check-outcome");compose.onNodeWithTag("editor-check-outcome").assertIsNotEnabled()
        compose.activityRule.scenario.moveToState(Lifecycle.State.CREATED)
        compose.waitUntil(5000) {bridge.cancelled.get()==1}
        held.complete(bridge.prepared(seal=true,body="late private synthetic body"))
        val before=bridge.reads.count {it=="devices"}
        compose.activityRule.scenario.moveToState(Lifecycle.State.RESUMED)
        waitEnabled("admin-content","admin-device-${bridge.device}")
        compose.waitUntil(5000) {bridge.reads.count {it=="devices"}>before}
        compose.onNodeWithTag("editor-title").assertDoesNotExist();compose.onNodeWithTag("editor-seal-dialog").assertDoesNotExist()
        compose.onNodeWithText("late private synthetic body").assertDoesNotExist()
        compose.runOnIdle {mounted.value=false};compose.waitForIdle()
        compose.runOnIdle {mounted.value=true}
        waitEnabled("admin-content","admin-device-${bridge.device}")
        compose.runOnIdle {assertEquals(listOf(Kind.OPEN,Kind.CHECK_OUTCOME),bridge.commands.map {it.kind})}
        open(bridge);input(bridge.text)
        compose.runOnIdle {assertEquals(listOf(Kind.OPEN,Kind.CHECK_OUTCOME,Kind.OPEN),bridge.commands.map {it.kind})}
    }

    @Test fun failedLookupRetainsLocalTextAndWebFallbackWhileReauthenticationClearsOnlyUiRam() {
        val bridge=Bridge();val reauthenticate=AtomicBoolean(false)
        bridge.intercept={command->if(command.kind==Kind.CHECK_OUTCOME)
            throw AdminUiFailure(if(reauthenticate.get())"REAUTHENTICATE" else "TRANSPORT") else bridge.normal(command)}
        content(bridge,mutableStateOf(true));open(bridge)
        editorScroll("editor-check-outcome");compose.onNodeWithTag("editor-check-outcome").performClick()
        phase("Редактор временно недоступен");input(bridge.text)
        editorScroll("editor-error");compose.onNodeWithTag("editor-error").assertTextEquals(adminEditorErrorText("TRANSPORT"))
        editorScroll("editor-full-web");compose.onNodeWithTag("editor-full-web").assertIsEnabled().performClick()
        compose.waitUntil(5000) {bridge.webCalls.get()==1}
        phase("Редактор временно недоступен");input(bridge.text)
        waitEnabled("editor-content","editor-back");compose.onNodeWithTag("editor-back").performClick();waitNode("admin-title")
        compose.runOnIdle {reauthenticate.set(true)}
        open(bridge)
        editorScroll("editor-check-outcome");compose.onNodeWithTag("editor-check-outcome").performClick()
        waitNode("admin-title")
        compose.onNodeWithTag("admin-status").assertTextEquals("Административная сессия истекла. Войдите снова.")
        compose.onNodeWithTag("editor-title").assertDoesNotExist();compose.onNodeWithTag("editor-page-input").assertDoesNotExist()
        compose.runOnIdle {
            assertEquals(listOf(Kind.OPEN,Kind.CHECK_OUTCOME,Kind.OPEN,Kind.CHECK_OUTCOME),bridge.commands.map {it.kind})
            assertEquals(1,bridge.webCalls.get());assertEquals(0,bridge.logins.get());assertEquals(0,bridge.logouts.get())
        }
    }
}
