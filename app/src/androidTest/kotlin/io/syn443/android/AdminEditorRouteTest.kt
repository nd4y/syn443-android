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
import io.syn443.android.vpn.AdminEditorCoordinator.Kind
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/** Actual AdminRoute and lifecycle in the disposable Compose host. Only an
 * immutable fake bridge is used: no Provider, account, keys, server or VPN work. */
class AdminEditorRouteTest {
    @get:Rule val compose=createAndroidComposeRule<ComponentActivity>()

    private class Bridge:AdminUiBridge {
        val device="synthetic-device"
        val commands=CopyOnWriteArrayList<Command>()
        val reads=CopyOnWriteArrayList<String>()
        val logins=AtomicInteger();val logouts=AtomicInteger();val cancelled=AtomicInteger();val webCalls=AtomicInteger()
        @Volatile var status=AdminUiStatus(8,AdminUiPhase.AUTHENTICATED)
        @Volatile var intercept:(suspend (Command)->AdminEditorModel)?=null
        @Volatile private var saved=prepared()
        private fun prepared(phase:AdminEditorPhase=AdminEditorPhase.EDITING,pages:List<String> = listOf("{\"synthetic\":1}"),
            revision:Long=1,binding:String="document-1",review:String="",deadline:Long=0)=AdminEditorModel(
            device=device,privateDraftRevision=1,desiredHeadRevision=4,localRevision=revision,phase=phase,
            documentBinding=binding,pages=pages,parents=listOf(AdminEditorParent("template","synthetic-template",1)),
            reviewBinding=review,reviewDeadlineElapsed=deadline,
            recipients=if(review.isEmpty())emptyList() else listOf(device),
            diffSummaries=if(review.isEmpty())emptyList() else listOf("device: /synthetic (set)"))
        override suspend fun status():AdminUiStatus {reads+="status";return status}
        override suspend fun devices(generation:Long,after:String):AdminDevicesPage {
            check(generation==status.generation && after.isEmpty());reads+="devices"
            return AdminDevicesPage(listOf(AdminDeviceRow(device,4,4,"Последний отчёт; соединение неизвестно")),"",1000)
        }
        override suspend fun document(generation:Long,action:AdminReadAction,target:String):AdminDocument {
            check(generation==status.generation && target==device);reads+=action.name
            return AdminDocument(listOf("synthetic read-only ${action.name}"),"Последний отчёт; текущее соединение неизвестно")
        }
        override suspend fun editor(generation:Long,command:Command):AdminEditorModel=withContext(Dispatchers.Default) {
            check(generation==status.generation);commands+=command
            intercept?.invoke(command)?:normal(command)
        }
        fun normal(command:Command):AdminEditorModel {
            check(command.device==device)
            if(command.kind!=Kind.OPEN)check(command.binding==saved.documentBinding && command.localRevision==saved.localRevision)
            saved=when(command.kind) {
                Kind.OPEN->if(saved.localRevision==0L)prepared() else prepared(pages=saved.pages,revision=saved.localRevision,binding=saved.documentBinding)
                Kind.SAVE_LOCAL->prepared(AdminEditorPhase.LOCAL_DIRTY,command.pages,saved.localRevision+1,"document-${saved.localRevision+1}")
                Kind.SAVE_DRAFT->prepared(pages=saved.pages,revision=saved.localRevision+1,binding="document-${saved.localRevision+1}")
                Kind.PREVIEW->prepared(AdminEditorPhase.REVIEW,saved.pages,saved.localRevision,saved.documentBinding,
                    "review-${saved.localRevision}",SystemClock.elapsedRealtime()+90_000)
                Kind.PUBLISH->{
                    check(command.reviewBinding==saved.reviewBinding && command.reviewDeadline==saved.reviewDeadlineElapsed)
                    prepared(AdminEditorPhase.PUBLISHED,saved.pages,saved.localRevision+1,"document-${saved.localRevision+1}")
                }
                Kind.CLOSE->AdminEditorModel()
                else->error("unexpected_editor_command")
            }
            return saved
        }
        override suspend fun login(generation:Long):Boolean {logins.incrementAndGet();return false}
        override suspend fun logout(generation:Long):Boolean {logouts.incrementAndGet();return false}
        override suspend fun browser(generation:Long):AdminBrowserLaunch=error("unexpected_browser")
        override suspend fun callback(raw:String) {error("unexpected_callback")}
        override suspend fun webPanel():String {
            webCalls.incrementAndGet()
            // Admit only the route intention; this fixture never opens CCT or a real URL.
            throw AdminUiFailure("UNAVAILABLE")
        }
    }
    private fun waitNode(tag:String) {
        compose.waitUntil(5000) {compose.onAllNodesWithTag(tag).fetchSemanticsNodes(atLeastOneRootRequired=false).isNotEmpty()}
    }
    private fun adminScroll(tag:String) {compose.onNodeWithTag("admin-content").performScrollToNode(hasTestTag(tag))}
    private fun editorScroll(tag:String) {compose.onNodeWithTag("editor-content").performScrollToNode(hasTestTag(tag))}
    private fun phase(text:String) {
        editorScroll("editor-phase")
        compose.waitUntil(5000) {
            val node=compose.onAllNodesWithTag("editor-phase").fetchSemanticsNodes(atLeastOneRootRequired=false).singleOrNull()
            node!=null && node.config.contains(SemanticsProperties.Text) && node.config[SemanticsProperties.Text].map {it.text}==listOf(text)
        }
    }
    private fun content(bridge:Bridge,mounted:State<Boolean>) {
        compose.setContent {MaterialTheme(colorScheme=darkColorScheme()) {if(mounted.value)AdminRoute(bridge)}}
    }
    private fun open(bridge:Bridge) {
        waitNode("admin-title");adminScroll("admin-device-${bridge.device}")
        compose.onNodeWithTag("admin-device-${bridge.device}").assertIsEnabled().performClick()
        adminScroll("admin-edit-configuration");compose.onNodeWithTag("admin-edit-configuration").assertIsEnabled().performClick()
        waitNode("editor-title");phase("Локальная копия готова к редактированию")
    }
    private fun assertInput(value:String) {
        editorScroll("editor-page-input")
        compose.onNodeWithTag("editor-page-input").assert(SemanticsMatcher.expectValue(SemanticsProperties.EditableText,AnnotatedString(value)))
    }
    private fun change(value:String) {
        editorScroll("editor-page-input");compose.onNodeWithTag("editor-page-input").performTextReplacement(value)
    }

    @Test fun routeReadsDeviceAndExplicitlySavesPreviewsAndConfirmsOneBoundPublication() {
        val bridge=Bridge();content(bridge,mutableStateOf(true));open(bridge)
        compose.runOnIdle {
            assertEquals(listOf("CONFIGURATION","RUNTIME"),bridge.reads.filter {it in setOf("CONFIGURATION","RUNTIME")})
            assertEquals(listOf(Kind.OPEN),bridge.commands.map {it.kind})
        }
        change("{\"synthetic\":2}")
        editorScroll("editor-save-local");compose.onNodeWithTag("editor-save-local").assertIsEnabled().performClick()
        phase("Локальные изменения ещё не опубликованы")
        assertInput("{\"synthetic\":2}")
        editorScroll("editor-preview");compose.onNodeWithTag("editor-preview").assertIsEnabled().performClick()
        phase("Проверка готова; требуется подтверждение")
        editorScroll("editor-publish");compose.onNodeWithTag("editor-publish").assertIsEnabled().performClick()
        compose.onNodeWithTag("editor-confirm-dialog").assertIsDisplayed()
        compose.onNodeWithTag("editor-confirm-recipient-0").assertTextEquals(bridge.device)
        compose.runOnIdle {assertEquals(listOf(Kind.OPEN,Kind.SAVE_LOCAL,Kind.PREVIEW),bridge.commands.map {it.kind})}
        compose.onNodeWithTag("editor-confirm-publish").assertIsEnabled().performClick()
        phase("Получена квитанция публикации желаемой конфигурации")
        editorScroll("editor-published");compose.onNodeWithTag("editor-published").assertIsDisplayed()
        compose.runOnIdle {
            assertEquals(listOf(Kind.OPEN,Kind.SAVE_LOCAL,Kind.PREVIEW,Kind.PUBLISH),bridge.commands.map {it.kind})
            val local=bridge.commands[1];assertEquals("document-1",local.binding);assertEquals(1L,local.localRevision)
            assertEquals(listOf("{\"synthetic\":2}"),local.pages)
            val publish=bridge.commands.last();assertEquals("document-2",publish.binding);assertEquals(2L,publish.localRevision)
            assertEquals("review-2",publish.reviewBinding);assertTrue(publish.reviewDeadline>0)
            assertEquals(0,bridge.logins.get());assertEquals(0,bridge.logouts.get())
        }
        compose.onNodeWithTag("editor-confirm-dialog").assertDoesNotExist()
        editorScroll("editor-close");compose.onNodeWithTag("editor-close").performClick()
        compose.onNodeWithText("Закрыть локальную копию?").assertIsDisplayed()
        compose.runOnIdle {assertEquals(0,bridge.commands.count {it.kind==Kind.CLOSE})}
        compose.onNodeWithText("Продолжить работу").performClick()
        compose.runOnIdle {assertEquals(0,bridge.commands.count {it.kind==Kind.CLOSE})}
        editorScroll("editor-close");compose.onNodeWithTag("editor-close").performClick()
        compose.onNodeWithTag("editor-close-confirm").performClick()
        phase("Загружена конфигурация и её происхождение")
        compose.onNodeWithTag("editor-page-input").assertDoesNotExist()
        compose.runOnIdle {
            assertEquals(listOf(Kind.OPEN,Kind.SAVE_LOCAL,Kind.PREVIEW,Kind.PUBLISH,Kind.CLOSE),bridge.commands.map {it.kind})
            assertEquals("document-3",bridge.commands.last().binding);assertEquals(3L,bridge.commands.last().localRevision)
        }
        editorScroll("editor-back");compose.onNodeWithTag("editor-back").performClick();waitNode("admin-title")
        compose.onNodeWithTag("vpn-connect").assertDoesNotExist();compose.onNodeWithTag("vpn-disconnect").assertDoesNotExist()
    }

    @Test fun stopRemovalAndHostRecreationClearUnsavedRamWithoutAutomaticEditorCommands() {
        val bridge=Bridge();val mounted=mutableStateOf(true);content(bridge,mounted);open(bridge)
        change("private unsaved input before back")
        editorScroll("editor-back");compose.onNodeWithTag("editor-back").performClick()
        compose.onNodeWithText("Оставить несохранённый ввод?").assertIsDisplayed()
        compose.onNodeWithText("Продолжить редактирование").performClick()
        assertInput("private unsaved input before back")
        editorScroll("editor-back");compose.onNodeWithTag("editor-back").performClick()
        compose.onNodeWithTag("editor-leave-confirm").performClick();waitNode("admin-title")
        compose.runOnIdle {assertEquals(listOf(Kind.OPEN),bridge.commands.map {it.kind})}
        open(bridge);assertInput("{\"synthetic\":1}")
        change("private unsaved input before stop")
        editorScroll("editor-full-web");compose.onNodeWithTag("editor-full-web").performClick()
        compose.onNodeWithText("Оставить несохранённый ввод?").assertIsDisplayed()
        compose.runOnIdle {
            assertEquals(0,bridge.webCalls.get());assertEquals(listOf(Kind.OPEN,Kind.OPEN),bridge.commands.map {it.kind})
        }
        compose.onNodeWithText("Продолжить редактирование").performClick()
        assertInput("private unsaved input before stop")
        compose.runOnIdle {assertEquals(0,bridge.webCalls.get())}
        editorScroll("editor-full-web");compose.onNodeWithTag("editor-full-web").performClick()
        compose.onNodeWithTag("editor-leave-confirm").performClick()
        phase("Редактор временно недоступен")
        assertInput("private unsaved input before stop")
        compose.runOnIdle {
            assertEquals(1,bridge.webCalls.get());assertEquals(listOf(Kind.OPEN,Kind.OPEN),bridge.commands.map {it.kind})
        }
        compose.activityRule.scenario.moveToState(Lifecycle.State.CREATED)
        compose.activityRule.scenario.moveToState(Lifecycle.State.RESUMED)
        waitNode("admin-title");compose.onNodeWithTag("editor-title").assertDoesNotExist()
        compose.runOnIdle {assertEquals(listOf(Kind.OPEN,Kind.OPEN),bridge.commands.map {it.kind})}
        open(bridge);assertInput("{\"synthetic\":1}");change("private unsaved input before removal")
        compose.runOnIdle {mounted.value=false}
        assertTrue(compose.onAllNodesWithTag("editor-title").fetchSemanticsNodes(atLeastOneRootRequired=false).isEmpty())
        compose.runOnIdle {mounted.value=true}
        waitNode("admin-title");open(bridge);assertInput("{\"synthetic\":1}")
        change("private unsaved input before recreation")
        compose.activityRule.scenario.recreate()
        // A new disposable host explicitly installs the fake route. No production
        // activity, saved-state payload or controller/provider is involved.
        compose.activityRule.scenario.onActivity {activity->activity.setContent {
            MaterialTheme(colorScheme=darkColorScheme()) {AdminRoute(bridge)}
        }}
        waitNode("admin-title");compose.onNodeWithTag("editor-title").assertDoesNotExist()
        compose.runOnIdle {assertEquals(listOf(Kind.OPEN,Kind.OPEN,Kind.OPEN,Kind.OPEN),bridge.commands.map {it.kind})}
        open(bridge);assertInput("{\"synthetic\":1}")
        compose.runOnIdle {
            assertEquals(5,bridge.commands.size);assertTrue(bridge.commands.all {it.kind==Kind.OPEN})
            assertEquals(1,bridge.webCalls.get())
            assertEquals(0,bridge.logins.get());assertEquals(0,bridge.logouts.get())
        }
    }

    @Test fun busyPreviewBlocksDuplicatesAndStopCancelsItBeforeLateResultCanReopenEditor() {
        val bridge=Bridge();val held=CompletableDeferred<AdminEditorModel>()
        bridge.intercept={command->if(command.kind==Kind.PREVIEW)try {held.await()}catch(error:CancellationException) {
            bridge.cancelled.incrementAndGet();throw error
        } else bridge.normal(command)}
        content(bridge,mutableStateOf(true));open(bridge)
        editorScroll("editor-preview");compose.onNodeWithTag("editor-preview").performClick()
        compose.waitUntil(5000) {bridge.commands.count {it.kind==Kind.PREVIEW}==1}
        editorScroll("editor-preview");compose.onNodeWithTag("editor-preview").assertIsNotEnabled()
        editorScroll("editor-save-draft");compose.onNodeWithTag("editor-save-draft").assertIsNotEnabled()
        editorScroll("editor-back");compose.onNodeWithTag("editor-back").assertIsNotEnabled()
        compose.activityRule.scenario.moveToState(Lifecycle.State.CREATED)
        compose.waitUntil(5000) {bridge.cancelled.get()==1}
        held.complete(AdminEditorModel(device=bridge.device,phase=AdminEditorPhase.REVIEW,documentBinding="late-document",
            pages=listOf("late private body"),reviewBinding="late-review",reviewDeadlineElapsed=SystemClock.elapsedRealtime()+90_000,
            recipients=listOf(bridge.device)))
        compose.activityRule.scenario.moveToState(Lifecycle.State.RESUMED)
        waitNode("admin-title");compose.onNodeWithTag("editor-title").assertDoesNotExist()
        compose.onNodeWithText("late private body").assertDoesNotExist()
        compose.runOnIdle {
            assertEquals(listOf(Kind.OPEN,Kind.PREVIEW),bridge.commands.map {it.kind})
            assertEquals(0,bridge.logins.get());assertEquals(0,bridge.logouts.get())
        }
    }

    @Test fun finiteEditorErrorPreservesDisplayAndReauthenticationClearsPrivilegedRamWithoutAutoLogin() {
        val bridge=Bridge();val reauthenticate=AtomicBoolean(false)
        bridge.intercept={command->if(command.kind==Kind.PREVIEW)
            throw AdminUiFailure(if(reauthenticate.get())"REAUTHENTICATE" else "synthetic-private-error-value")
            else bridge.normal(command)}
        content(bridge,mutableStateOf(true));open(bridge)
        editorScroll("editor-preview");compose.onNodeWithTag("editor-preview").performClick()
        phase("Редактор временно недоступен")
        editorScroll("editor-error");compose.onNodeWithTag("editor-error").assertTextEquals(adminEditorErrorText("synthetic-private-error-value"))
        compose.onNodeWithText("synthetic-private-error-value").assertDoesNotExist()
        assertInput("{\"synthetic\":1}")
        editorScroll("editor-back");compose.onNodeWithTag("editor-back").performClick();waitNode("admin-title")
        compose.runOnIdle {reauthenticate.set(true)}
        open(bridge)
        editorScroll("editor-preview");compose.onNodeWithTag("editor-preview").performClick()
        waitNode("admin-title");compose.onNodeWithTag("admin-status").assertTextEquals("Административная сессия истекла. Войдите снова.")
        adminScroll("admin-login");compose.onNodeWithTag("admin-login").assertIsEnabled()
        compose.onNodeWithTag("editor-page-input").assertDoesNotExist();compose.onNodeWithTag("editor-title").assertDoesNotExist()
        compose.runOnIdle {
            assertEquals(listOf(Kind.OPEN,Kind.PREVIEW,Kind.OPEN,Kind.PREVIEW),bridge.commands.map {it.kind})
            assertEquals(0,bridge.logins.get());assertEquals(0,bridge.logouts.get())
        }
    }
}
