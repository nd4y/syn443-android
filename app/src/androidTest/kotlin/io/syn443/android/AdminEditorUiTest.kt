package io.syn443.android

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.text.AnnotatedString
import io.syn443.android.admin.*
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test

/** Presentation fixtures only. No controller, HTTP, credentials, storage, keys,
 * device/VPN state, browser authentication or real publication is exercised. */
class AdminEditorUiTest {
    @get:Rule val compose=createComposeRule()
    private fun model(phase:AdminEditorPhase=AdminEditorPhase.EDITING,busy:Boolean=false,readOnly:Boolean=false,
        unassigned:Boolean=false,pages:List<String> = listOf("{\"proposal\":\"synthetic\"}"),binding:String="document-a",
        review:String="review-a",deadline:Long=60_000,error:String="")=AdminEditorModel(
        device="device-a",privateDraftRevision=3,desiredHeadRevision=7,phase=phase,busy=busy,readOnly=readOnly,
        unassigned=unassigned,documentBinding=binding,pages=pages,
        parents=listOf(AdminEditorParent("template","template-a",2)),reviewBinding=review,
        reviewDeadlineElapsed=deadline,recipients=listOf("device-a","device-b"),
        diffSummaries=listOf("/network/dnsStrategy: изменение"),error=error)
    private fun scroll(tag:String)=compose.onNodeWithTag("editor-content").performScrollToNode(hasTestTag(tag))
    private fun input(value:String)=compose.onNodeWithTag("editor-page-input").assert(
        SemanticsMatcher.expectValue(SemanticsProperties.EditableText,AnnotatedString(value)))

    @Test fun smallEditorSeparatesLocalSaveServerDraftAndPreviewAndShowsParentProvenance() {
        val commands=mutableListOf<String>();val snapshots=mutableListOf<List<String>>()
        compose.setContent {MaterialTheme(colorScheme=darkColorScheme()) {AdminEditorScreen(model(),AdminEditorActions(
            edited={commands.add("edited")},saveLocal={snapshots.add(it);commands.add("local")},
            saveDraft={commands.add("draft")},preview={commands.add("preview")}),elapsed={1000})}}
        compose.onNodeWithTag("editor-title").assertTextEquals("Редактор конфигурации")
        compose.onNodeWithTag("editor-revisions").assertTextContains("черновика: 3",substring=true)
        scroll("editor-parent-0");compose.onNodeWithTag("editor-parent-0").assertTextContains("только чтение",substring=true)
        scroll("editor-save-draft");compose.onNodeWithTag("editor-save-draft").performClick()
        scroll("editor-preview");compose.onNodeWithTag("editor-preview").performClick()
        scroll("editor-page-input");compose.onNodeWithTag("editor-page-input").performTextReplacement("{invalid local input")
        input("{invalid local input")
        scroll("editor-save-draft");compose.onNodeWithTag("editor-save-draft").assertIsNotEnabled()
        scroll("editor-preview");compose.onNodeWithTag("editor-preview").assertIsNotEnabled()
        scroll("editor-save-local");compose.onNodeWithTag("editor-save-local").assertIsEnabled().performClick()
        compose.runOnIdle {
            assertEquals(listOf("draft","preview","edited","local"),commands)
            assertEquals(listOf("{invalid local input"),snapshots.single())
            assertThrows(UnsupportedOperationException::class.java){(snapshots.single() as MutableList<*>).clear()}
        }
        scroll("editor-page-input");input("{invalid local input")
        compose.onNodeWithTag("vpn-connect").assertDoesNotExist();compose.onNodeWithTag("vpn-disconnect").assertDoesNotExist()
    }

    @Test fun sixtyFourPagesExposeFullRangeWithoutTruncatingOrJoiningProposalOnMain() {
        val pages=List(64){index->("page-%02d:".format(index)+"x".repeat(8184)).take(8192)}
        val saved=mutableListOf<List<String>>()
        compose.setContent {MaterialTheme(colorScheme=darkColorScheme()) {AdminEditorScreen(model(pages=pages),AdminEditorActions(saveLocal={saved.add(it)}),elapsed={1000})}}
        scroll("editor-page-next")
        repeat(64) {index->
            compose.onNodeWithTag("editor-page-number").assertTextEquals("${index+1} / 64")
            input(pages[index])
            if(index<63)compose.onNodeWithTag("editor-page-next").assertIsEnabled().performClick()
        }
        compose.onNodeWithTag("editor-page-next").assertIsNotEnabled()
        scroll("editor-page-input");compose.onNodeWithTag("editor-page-input").performTextReplacement("last page changed")
        scroll("editor-page-previous");compose.onNodeWithTag("editor-page-previous").performClick();input(pages[62])
        compose.onNodeWithTag("editor-page-next").performClick();input("last page changed")
        scroll("editor-save-local");compose.onNodeWithTag("editor-save-local").performClick()
        compose.runOnIdle {assertEquals(64,saved.single().size);assertEquals(pages.take(63),saved.single().take(63));assertEquals("last page changed",saved.single().last())}
    }

    @Test fun localEditPermanentlyInvalidatesSameReviewAcrossAcknowledgementAndBusyPhaseUpdates() {
        val state=mutableStateOf(model(phase=AdminEditorPhase.REVIEW));val commands=mutableListOf<String>()
        compose.setContent {MaterialTheme(colorScheme=darkColorScheme()) {AdminEditorScreen(state.value,
            AdminEditorActions(edited={commands.add("edited")},publish={_,_->commands.add("publish")}),elapsed={1000})}}
        scroll("editor-publish");compose.onNodeWithTag("editor-publish").assertIsEnabled()
        scroll("editor-page-input");compose.onNodeWithTag("editor-page-input").performTextReplacement("changed")
        scroll("editor-publish");compose.onNodeWithTag("editor-publish").assertIsNotEnabled()
        compose.runOnIdle {state.value=model(phase=AdminEditorPhase.SAVING,busy=true)}
        scroll("editor-page-input");input("changed")
        compose.runOnIdle {state.value=model(phase=AdminEditorPhase.REVIEW,pages=listOf("changed"),binding="document-b")}
        scroll("editor-publish");compose.onNodeWithTag("editor-publish").assertIsNotEnabled()
        compose.runOnIdle {assertEquals(listOf("edited"),commands);state.value=model(phase=AdminEditorPhase.REVIEW,pages=listOf("changed"),binding="document-b",review="review-b")}
        scroll("editor-publish");compose.onNodeWithTag("editor-publish").assertIsEnabled()
    }

    @Test fun publicationNeedsExplicitRecipientConfirmationAndSendsOriginalBindingOnlyOnce() {
        val published=mutableListOf<Pair<String,Long>>()
        compose.setContent {MaterialTheme(colorScheme=darkColorScheme()) {AdminEditorScreen(model(phase=AdminEditorPhase.REVIEW),
            AdminEditorActions(publish={binding,deadline->published.add(binding to deadline)}),elapsed={1000})}}
        compose.runOnIdle {assertTrue(published.isEmpty())}
        scroll("editor-publish");compose.onNodeWithTag("editor-publish").performClick()
        compose.onNodeWithTag("editor-confirm-dialog").assertIsDisplayed()
        compose.onNodeWithTag("editor-confirm-recipient-0").assertTextEquals("device-a")
        compose.onNodeWithTag("editor-confirm-recipient-1").assertTextEquals("device-b")
        compose.onNodeWithText("Будет изменена желаемая конфигурация получателей. Это не подтверждение применения и не включение VPN.").assertExists()
        compose.onNodeWithTag("editor-confirm-cancel").performClick()
        compose.runOnIdle {assertTrue(published.isEmpty())}
        compose.onNodeWithTag("editor-publish").performClick()
        compose.onNodeWithTag("editor-confirm-publish").performClick()
        compose.onNodeWithTag("editor-confirm-dialog").assertDoesNotExist()
        compose.onNodeWithTag("editor-publish").assertIsNotEnabled()
        compose.runOnIdle {assertEquals(listOf("review-a" to 60_000L),published)}
        compose.onNodeWithText("Подключено").assertDoesNotExist()
    }

    @Test fun lateConfirmationExpiryAndSameBindingDeadlineExtensionNeverPublish() {
        var now=1000L;val state=mutableStateOf(model(phase=AdminEditorPhase.REVIEW));var published=0
        compose.setContent {MaterialTheme(colorScheme=darkColorScheme()) {AdminEditorScreen(state.value,AdminEditorActions(publish={_,_->published++}),elapsed={now})}}
        scroll("editor-publish");compose.onNodeWithTag("editor-publish").performClick()
        // Deliberately no model/recomposition before the click: the handler
        // must obtain time again instead of trusting dialog receipt time.
        compose.runOnIdle {now=60_001}
        compose.onNodeWithTag("editor-confirm-publish").performClick()
        compose.onNodeWithTag("editor-confirm-dialog").assertDoesNotExist()
        compose.runOnIdle {assertEquals(0,published);state.value=model(phase=AdminEditorPhase.REVIEW,deadline=120_000)}
        scroll("editor-publish");compose.onNodeWithTag("editor-publish").assertIsNotEnabled()
        compose.runOnIdle {state.value=model(phase=AdminEditorPhase.REVIEW,review="review-b",deadline=120_000)}
        scroll("editor-publish");compose.onNodeWithTag("editor-publish").assertIsEnabled().performClick()
        compose.runOnIdle {state.value=model(phase=AdminEditorPhase.REVIEW,review="review-c",deadline=120_000)}
        compose.onNodeWithTag("editor-confirm-publish").assertIsNotEnabled()
        compose.runOnIdle {assertEquals(0,published)}
    }

    @Test fun busyAndReadOnlyStatesBlockMutationWhilePhaseAndClockCannotBypassReview() {
        val state=mutableStateOf(model(busy=true));val commands=mutableListOf<String>();var now=1000L
        compose.setContent {MaterialTheme(colorScheme=darkColorScheme()) {AdminEditorScreen(state.value,AdminEditorActions(
            saveDraft={commands.add("draft")},preview={commands.add("preview")},publish={_,_->commands.add("publish")}),elapsed={now})}}
        scroll("editor-save-draft");compose.onNodeWithTag("editor-save-draft").assertIsNotEnabled()
        scroll("editor-preview");compose.onNodeWithTag("editor-preview").assertIsNotEnabled()
        scroll("editor-page-input");compose.onNodeWithTag("editor-page-input").assert(hasSetTextAction().not())
        compose.runOnIdle {state.value=model(readOnly=true)}
        scroll("editor-read-only");compose.onNodeWithTag("editor-read-only").assertExists()
        scroll("editor-preview");compose.onNodeWithTag("editor-preview").assertIsNotEnabled()
        compose.runOnIdle {state.value=model(phase=AdminEditorPhase.REVIEW,review="review-b")}
        scroll("editor-publish");compose.onNodeWithTag("editor-publish").performClick()
        compose.runOnIdle {now=999}
        compose.onNodeWithTag("editor-confirm-publish").performClick()
        compose.runOnIdle {assertTrue(commands.isEmpty())}
        compose.runOnIdle {state.value=model(phase=AdminEditorPhase.PUBLISHING)}
        compose.onNodeWithTag("editor-publish").assertDoesNotExist()
    }

    @Test fun reauthenticationRetainsUnacknowledgedDraftAndUnknownErrorsStayFinite() {
        val raw="synthetic-private-error";val state=mutableStateOf(model());var login=0
        compose.setContent {MaterialTheme(colorScheme=darkColorScheme()) {AdminEditorScreen(state.value,AdminEditorActions(login={login++}),elapsed={1000})}}
        scroll("editor-page-input");compose.onNodeWithTag("editor-page-input").performTextReplacement("unsaved local buffer")
        compose.runOnIdle {state.value=model(phase=AdminEditorPhase.NEEDS_REAUTH,error=raw)}
        scroll("editor-page-input");input("unsaved local buffer")
        scroll("editor-login");compose.onNodeWithTag("editor-login").assertIsEnabled().performClick()
        compose.onNodeWithText("Оставить несохранённый ввод?").assertIsDisplayed()
        compose.runOnIdle {assertEquals(0,login)}
        compose.onNodeWithText("Продолжить редактирование").performClick()
        scroll("editor-page-input");input("unsaved local buffer")
        compose.runOnIdle {assertEquals(0,login)}
        scroll("editor-login");compose.onNodeWithTag("editor-login").performClick()
        compose.onNodeWithTag("editor-leave-confirm").assertIsEnabled().performClick()
        compose.onNodeWithText(raw).assertDoesNotExist()
        compose.runOnIdle {assertEquals(1,login);assertEquals(adminEditorErrorText("unknown"),adminEditorErrorText(raw))}
        scroll("editor-error");compose.onNodeWithTag("editor-error").assertTextEquals("Данные временно недоступны. Проверьте состояние и повторите действие.")
        compose.onNodeWithTag("editor-save-draft").assertDoesNotExist();compose.onNodeWithTag("editor-publish").assertDoesNotExist()
    }

    @Test fun uncertainAndConflictRequireExplicitReconciliationAndNeverAutomaticallySend() {
        val state=mutableStateOf(model(phase=AdminEditorPhase.UNCERTAIN));val commands=mutableListOf<String>()
        compose.setContent {MaterialTheme(colorScheme=darkColorScheme()) {AdminEditorScreen(state.value,AdminEditorActions(
            poll={commands.add("poll")},retryExact={commands.add("retry")},comparison={commands.add("comparison")},rebase={commands.add("rebase")},
            preview={commands.add("preview")},publish={_,_->commands.add("publish")}),elapsed={1000})}}
        compose.runOnIdle {assertTrue(commands.isEmpty())}
        scroll("editor-poll");compose.onNodeWithTag("editor-poll").performClick()
        scroll("editor-retry-exact");compose.onNodeWithTag("editor-retry-exact").performClick()
        compose.onNodeWithTag("editor-preview").assertDoesNotExist();compose.onNodeWithTag("editor-publish").assertDoesNotExist()
        compose.runOnIdle {assertEquals(listOf("poll","retry"),commands);state.value=model(phase=AdminEditorPhase.CONFLICT)}
        scroll("editor-conflict");compose.onNodeWithTag("editor-conflict").assertTextContains("не устранён",substring=true)
        scroll("editor-comparison");compose.onNodeWithTag("editor-comparison").performClick()
        scroll("editor-rebase");compose.onNodeWithTag("editor-rebase").performClick()
        compose.runOnIdle {assertEquals(listOf("poll","retry","comparison","rebase"),commands)}
        compose.onNodeWithTag("editor-published").assertDoesNotExist()
    }

    @Test fun unassignedAndLimitedModesOfferFullPanelWithoutFirstConfigurationOrVpnClaims() {
        val state=mutableStateOf(model(unassigned=true));var web=0
        compose.setContent {MaterialTheme(colorScheme=darkColorScheme()) {AdminEditorScreen(state.value,AdminEditorActions(web={web++}),elapsed={1000})}}
        scroll("editor-unassigned");compose.onNodeWithTag("editor-unassigned").assertTextContains("пока",substring=true)
        compose.onNodeWithTag("editor-page-input").assertDoesNotExist();compose.onNodeWithTag("editor-save-draft").assertDoesNotExist()
        scroll("editor-full-web");compose.onNodeWithTag("editor-full-web").performClick()
        compose.runOnIdle {state.value=model(phase=AdminEditorPhase.LIMITED,readOnly=true)}
        scroll("editor-page-input");compose.onNodeWithTag("editor-page-input").assert(hasSetTextAction().not())
        compose.onNodeWithTag("editor-preview").assertDoesNotExist()
        scroll("editor-full-web");compose.onNodeWithTag("editor-full-web").performClick()
        compose.runOnIdle {assertEquals(2,web);state.value=model(phase=AdminEditorPhase.PUBLISHED)}
        scroll("editor-published");compose.onNodeWithTag("editor-published").assertTextContains("проверяются отдельно",substring=true)
        compose.onNodeWithTag("vpn-connect").assertDoesNotExist();compose.onNodeWithText("Подключено").assertDoesNotExist()
    }

    @Test fun presentationModelOwnsBoundedPagesAndRejectsInvalidUtf16BeforeRendering() {
        val pages=mutableListOf("source");val recipients=mutableListOf("device-a")
        val value=AdminEditorModel(device="device-a",documentBinding="owned",pages=pages,recipients=recipients)
        pages[0]="changed";recipients.clear();assertEquals(listOf("source"),value.pages);assertEquals(listOf("device-a"),value.recipients)
        assertFalse(value.toString().contains("source"));assertFalse(AdminEditorParent("template","private-id",1).toString().contains("private-id"))
        assertThrows(UnsupportedOperationException::class.java){(value.pages as MutableList<*>).clear()}
        assertThrows(IllegalArgumentException::class.java){model(pages=List(65){"x"})}
        assertThrows(IllegalArgumentException::class.java){model(pages=listOf("x".repeat(8193)))}
        assertThrows(IllegalArgumentException::class.java){model(pages=listOf(0xd800.toChar().toString()))}
        assertThrows(IllegalArgumentException::class.java){model(pages=listOf(0xdc00.toChar().toString()))}
        assertNotNull(model(pages=listOf("x".repeat(8190)+"\uD83D\uDE00")))
        assertNotNull(AdminEditorModel(recipients=List(64){"device-$it"}))
        assertThrows(IllegalArgumentException::class.java){AdminEditorModel(recipients=List(65){"device-$it"})}
        assertThrows(IllegalArgumentException::class.java){AdminEditorModel(recipients=listOf("same","same"))}
        assertThrows(IllegalArgumentException::class.java){AdminEditorModel(parents=List(21){AdminEditorParent("template","p$it",1)})}
        assertThrows(IllegalArgumentException::class.java){AdminEditorModel(diffSummaries=List(65){"changed"})}
        assertThrows(IllegalArgumentException::class.java){AdminEditorModel(diffSummaries=listOf("x".repeat(513)))}
        assertThrows(IllegalArgumentException::class.java){AdminEditorModel(device="invalid/device")}
        assertThrows(IllegalArgumentException::class.java){AdminEditorModel(documentBinding="",pages=listOf("x"))}
        assertEquals(adminEditorErrorText("unknown"),adminEditorErrorText("private".repeat(1000)))
    }
}
