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
import java.util.Base64

/** Value-only presentation. No Provider, session, persisted operation or HTTP. */
class AdminOperationUiTest {
    @get:Rule val compose=createComposeRule()
    private fun digest(value:Int)=Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32) {value.toByte()})
    private fun model(phase:AdminEditorPhase=AdminEditorPhase.UNCERTAIN,operation:String=digest(1),
        outcome:String="UNKNOWN",seal:Boolean=false,busy:Boolean=false,document:String="document-a",
        error:String="",readOnly:Boolean=false)=AdminEditorModel(device="synthetic-device",privateDraftRevision=3,
        desiredHeadRevision=5,localRevision=7,phase=phase,busy=busy,readOnly=readOnly,documentBinding=document,
        pages=listOf("{\"synthetic\":1}"),operationBinding=operation,operationOutcome=outcome,canSeal=seal,error=error)
    private fun scroll(tag:String)=compose.onNodeWithTag("editor-content").performScrollToNode(hasTestTag(tag))
    private fun absent(tag:String) {
        assertThrows(AssertionError::class.java) {scroll(tag)}
        compose.onNodeWithTag(tag).assertDoesNotExist()
    }
    private fun input(value:String) {
        scroll("editor-page-input")
        compose.onNodeWithTag("editor-page-input").assert(SemanticsMatcher.expectValue(SemanticsProperties.EditableText,AnnotatedString(value)))
    }

    @Test fun explicitLookupPrecedesSeparateBoundSealConfirmationWithoutPublishing() {
        val state=mutableStateOf(model());val calls=mutableListOf<String>()
        compose.setContent {MaterialTheme(colorScheme=darkColorScheme()) {AdminEditorScreen(state.value,AdminEditorActions(
            checkOutcome={calls+="lookup"},sealPending={calls+="seal:$it"},publish={_,_->calls+="publish"},
            retryExact={calls+="retry"},saveDraft={calls+="draft"}),elapsed={1000})}}
        absent("editor-seal-pending")
        compose.runOnIdle {assertTrue(calls.isEmpty())}
        scroll("editor-check-outcome");compose.onNodeWithTag("editor-check-outcome").performClick()
        compose.runOnIdle {assertEquals(listOf("lookup"),calls);state.value=model(seal=true)}
        scroll("editor-seal-pending");compose.onNodeWithTag("editor-seal-pending").performClick()
        compose.onNodeWithTag("editor-seal-dialog").assertIsDisplayed()
        compose.onNodeWithText("Зафиксировать отсутствие операции?").assertIsDisplayed()
        compose.runOnIdle {assertEquals(listOf("lookup"),calls)}
        compose.onNodeWithTag("editor-seal-cancel").performClick()
        compose.onNodeWithTag("editor-seal-dialog").assertDoesNotExist()
        scroll("editor-seal-pending");compose.onNodeWithTag("editor-seal-pending").performClick()
        compose.onNodeWithTag("editor-seal-confirm").assertIsEnabled().performClick()
        compose.onNodeWithTag("editor-seal-dialog").assertDoesNotExist()
        scroll("editor-seal-pending");compose.onNodeWithTag("editor-seal-pending").assertIsNotEnabled()
        compose.runOnIdle {assertEquals(listOf("lookup","seal:${digest(1)}"),calls)}
        absent("editor-publish")
    }

    @Test fun changedPendingOrDocumentAndBusyOrWithdrawnSealCannotDispatchStaleDialog() {
        val state=mutableStateOf(model(seal=true));val seals=mutableListOf<String>()
        compose.setContent {MaterialTheme(colorScheme=darkColorScheme()) {AdminEditorScreen(state.value,
            AdminEditorActions(sealPending={seals+=it}),elapsed={1000})}}
        fun open() {scroll("editor-seal-pending");compose.onNodeWithTag("editor-seal-pending").performClick()}
        open();compose.runOnIdle {state.value=model(operation=digest(2),seal=true)}
        compose.onNodeWithTag("editor-seal-dialog").assertDoesNotExist()
        open();compose.runOnIdle {state.value=model(operation=digest(2),seal=true,busy=true)}
        compose.onNodeWithTag("editor-seal-confirm").assertIsNotEnabled()
        compose.onNodeWithTag("editor-seal-cancel").performClick()
        scroll("editor-check-outcome");compose.onNodeWithTag("editor-check-outcome").assertIsNotEnabled()
        scroll("editor-seal-pending");compose.onNodeWithTag("editor-seal-pending").assertIsNotEnabled()
        compose.runOnIdle {state.value=model(operation=digest(2),seal=true)}
        open();compose.runOnIdle {state.value=model(operation=digest(2),seal=false)}
        compose.onNodeWithTag("editor-seal-confirm").assertIsNotEnabled()
        compose.onNodeWithTag("editor-seal-cancel").performClick()
        absent("editor-seal-pending")
        compose.runOnIdle {state.value=model(operation=digest(2),seal=true)}
        open();compose.runOnIdle {state.value=model(operation=digest(2),seal=true,document="document-b")}
        compose.onNodeWithTag("editor-seal-dialog").assertDoesNotExist()
        compose.runOnIdle {assertTrue(seals.isEmpty())}
    }

    @Test fun lookupAndNoEffectPresentationRetainUnacknowledgedTextWithoutAutoSave() {
        val state=mutableStateOf(model(AdminEditorPhase.EDITING,operation="",outcome=""));val calls=mutableListOf<String>()
        compose.setContent {MaterialTheme(colorScheme=darkColorScheme()) {AdminEditorScreen(state.value,AdminEditorActions(
            edited={calls+="edited"},checkOutcome={calls+="lookup"},sealPending={calls+="seal:$it"},
            saveLocal={calls+="save"},saveDraft={calls+="draft"},publish={_,_->calls+="publish"}),elapsed={1000})}}
        scroll("editor-page-input");compose.onNodeWithTag("editor-page-input").performTextReplacement("{unfinished local text")
        compose.runOnIdle {state.value=model(error="OUTCOME_UNKNOWN")}
        input("{unfinished local text")
        scroll("editor-check-outcome");compose.onNodeWithTag("editor-check-outcome").performClick()
        compose.runOnIdle {state.value=model(seal=true)}
        input("{unfinished local text")
        scroll("editor-seal-pending");compose.onNodeWithTag("editor-seal-pending").performClick()
        compose.onNodeWithTag("editor-seal-confirm").performClick()
        compose.runOnIdle {state.value=model(AdminEditorPhase.LOCAL_DIRTY,operation="",outcome="NO_EFFECT")}
        input("{unfinished local text")
        compose.runOnIdle {assertEquals(listOf("edited","lookup","seal:${digest(1)}"),calls)}
    }

    @Test fun unavailableRecordedResultAndUnknownErrorStayFiniteWithExplicitWebFallback() {
        val state=mutableStateOf(model(outcome="RECORDED_RESULT_UNAVAILABLE",error="RESULT_UNAVAILABLE",readOnly=true))
        val calls=mutableListOf<String>()
        compose.setContent {MaterialTheme(colorScheme=darkColorScheme()) {AdminEditorScreen(state.value,AdminEditorActions(
            checkOutcome={calls+="lookup"},sealPending={calls+="seal"},web={calls+="web"},publish={_,_->calls+="publish"}),elapsed={1000})}}
        scroll("editor-error");compose.onNodeWithTag("editor-error").assertTextEquals(adminEditorErrorText("RESULT_UNAVAILABLE"))
        absent("editor-seal-pending");input("{\"synthetic\":1}")
        scroll("editor-full-web");compose.onNodeWithTag("editor-full-web").performClick()
        compose.runOnIdle {state.value=model(AdminEditorPhase.UNAVAILABLE,outcome="RECORDED_RESULT_UNAVAILABLE",
            error="SYNTHETIC_PRIVATE_FAILURE",readOnly=true)}
        scroll("editor-error");compose.onNodeWithTag("editor-error").assertTextEquals(adminEditorErrorText("UNAVAILABLE"))
        compose.onNodeWithText("SYNTHETIC_PRIVATE_FAILURE").assertDoesNotExist()
        input("{\"synthetic\":1}")
        scroll("editor-full-web");compose.onNodeWithTag("editor-full-web").assertIsEnabled().performClick()
        compose.runOnIdle {assertEquals(listOf("web","web"),calls)}
    }

    @Test fun recompositionAndBackNeverAutomaticallyLookupSealRetryOrCreatePublication() {
        val state=mutableStateOf(model());val mounted=mutableStateOf(true);val calls=mutableListOf<String>()
        compose.setContent {MaterialTheme(colorScheme=darkColorScheme()) {if(mounted.value)AdminEditorScreen(state.value,
            AdminEditorActions(checkOutcome={calls+="lookup"},sealPending={calls+="seal"},poll={calls+="poll"},
                retryExact={calls+="retry"},saveDraft={calls+="draft"},publish={_,_->calls+="publish"},back={calls+="back"}),elapsed={1000})}}
        repeat(3) {compose.runOnIdle {state.value=model(error="OUTCOME_UNKNOWN")};compose.waitForIdle()}
        compose.runOnIdle {mounted.value=false};compose.waitForIdle()
        compose.runOnIdle {mounted.value=true};compose.waitForIdle()
        compose.runOnIdle {assertTrue(calls.isEmpty())}
        scroll("editor-back");compose.onNodeWithTag("editor-back").performClick()
        compose.runOnIdle {assertEquals(listOf("back"),calls)}
    }
}
