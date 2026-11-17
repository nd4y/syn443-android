package io.syn443.android.admin

import android.os.SystemClock
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.delay
import java.util.Collections

/** Presentation only. No RPC, JSON parsing, storage, OAuth or VPN action. */
@Composable
internal fun AdminEditorScreen(model:AdminEditorModel,actions:AdminEditorActions,elapsed:()->Long={SystemClock.elapsedRealtime()}) {
    val latestModel by rememberUpdatedState(model)
    val latestActions by rememberUpdatedState(actions)
    val latestElapsed by rememberUpdatedState(elapsed)
    // A worker acknowledgement/reload changes this binding. Phase/reauth/busy
    // updates alone cannot erase unacknowledged local input.
    val pages=remember(model.device,model.documentBinding) {model.pages.toMutableStateList()}
    var dirty by remember(model.device,model.documentBinding) {mutableStateOf(false)}
    var page by remember(model.device,model.documentBinding) {mutableIntStateOf(0)}
    var confirmation by remember(model.device,model.documentBinding) {mutableStateOf<EditorConfirmation?>(null)}
    val originalReviewDeadline=remember(model.reviewBinding) {model.reviewDeadlineElapsed}
    val reviewDocumentBinding=remember(model.reviewBinding) {model.documentBinding}
    val reviewObservedAt=remember(model.reviewBinding) {elapsed()}
    var expired by remember(model.reviewBinding) {mutableStateOf(false)}
    var reviewSubmitted by remember(model.reviewBinding) {mutableStateOf(false)}
    var reviewInvalidated by remember(model.reviewBinding) {mutableStateOf(false)}
    var localError by remember(model.device,model.documentBinding,model.reviewBinding) {mutableStateOf("")}
    var leaveConfirmation by remember(model.device,model.documentBinding) {mutableStateOf(false)}
    var leaveTarget by remember(model.device,model.documentBinding) {mutableStateOf("BACK")}
    var closeConfirmation by remember(model.device,model.documentBinding) {mutableStateOf(false)}
    var sealConfirmation by remember(model.device,model.documentBinding,model.operationBinding) {mutableStateOf<String?>(null)}
    var sealSubmitted by remember(model.device,model.documentBinding,model.operationBinding) {mutableStateOf(false)}
    LaunchedEffect(model.operationBinding,model.canSeal,model.busy) {if(model.canSeal && !model.busy)sealSubmitted=false}
    val activeBusy=editorBusy(model)
    val editable=editorEditable(model) && !activeBusy && pages.isNotEmpty()
    fun proceed(target:String) {when(target){"WEB"->latestActions.web();"LOGIN"->latestActions.login();else->latestActions.back()}}
    fun navigate(target:String) {
        if(dirty){leaveTarget=target;leaveConfirmation=true} else proceed(target)
    }
    BackHandler {if(!activeBusy)navigate("BACK")}
    fun reviewAllowed(current:AdminEditorModel,now:Long)=!dirty && !expired && !reviewSubmitted && !reviewInvalidated && !editorBusy(current) && !current.readOnly && !current.unassigned &&
        current.phase==AdminEditorPhase.REVIEW && current.reviewBinding.isNotEmpty() && current.recipients.isNotEmpty() && reviewObservedAt>=0 && now>=reviewObservedAt &&
        current.documentBinding==reviewDocumentBinding && current.reviewDeadlineElapsed==originalReviewDeadline && now<originalReviewDeadline
    LaunchedEffect(model.reviewBinding) {
        if(model.reviewBinding.isNotEmpty()) {
            val now=latestElapsed()
            val remaining=if(now<0 || now>=originalReviewDeadline)0 else originalReviewDeadline-now
            if(remaining>0)delay(remaining)
            // One local expiry wakeup; this never polls or calls a callback.
            expired=true
        }
    }
    LazyColumn(Modifier.fillMaxSize().safeDrawingPadding().padding(horizontal=20.dp).testTag("editor-content"),
        verticalArrangement=Arrangement.spacedBy(12.dp),contentPadding=PaddingValues(vertical=20.dp)) {
        item {Text("Редактор конфигурации",Modifier.testTag("editor-title"),style=MaterialTheme.typography.headlineMedium)}
        item {TextButton(onClick={navigate("BACK")},enabled=!activeBusy,
            modifier=Modifier.testTag("editor-back")) {Text("К устройствам")}}
        item {Text("Устройство: ${model.device.ifEmpty {"не выбрано"}}",Modifier.testTag("editor-device"),fontFamily=FontFamily.Monospace)}
        item {Text("Ревизия частного черновика: ${model.privateDraftRevision}; желаемая ревизия устройства: ${model.desiredHeadRevision}",Modifier.testTag("editor-revisions"))}
        item {Text(editorPhaseText(model.phase),Modifier.testTag("editor-phase"))}
        if(activeBusy)item {LinearProgressIndicator(Modifier.fillMaxWidth().testTag("editor-progress"))}
        if(model.error.isNotEmpty() || localError.isNotEmpty())item {
            Text(adminEditorErrorText(localError.ifEmpty {model.error}),Modifier.testTag("editor-error"),color=MaterialTheme.colorScheme.error)
        }
        if(dirty)item {Text("Есть несохранённый локальный ввод. Предыдущая проверка больше не подходит для публикации.",Modifier.testTag("editor-dirty"))}
        if(model.phase==AdminEditorPhase.NEEDS_REAUTH)item {
            Button(onClick={navigate("LOGIN")},enabled=!activeBusy,modifier=Modifier.testTag("editor-login")) {Text("Подтвердить доступ, сохранив черновик")}
        }
        if(model.unassigned)item {
            Text("Устройство ещё не имеет конфигурации. Первую конфигурацию пока создайте в полной веб-панели.",Modifier.testTag("editor-unassigned"))
        } else if(pages.isNotEmpty()) {
            item {HorizontalDivider();Text("Полное переносимое предложение",style=MaterialTheme.typography.titleMedium)}
            item {Text("Родительские слои сохраняются отдельно. Редактор не заменяет их плоской итоговой конфигурацией.",Modifier.testTag("editor-provenance"))}
            itemsIndexed(model.parents,key={index,_->"parent-$index"}) {index,parent->
                Text("${parent.kind} / ${parent.id} / ревизия ${parent.revision} (только чтение)",
                    Modifier.testTag("editor-parent-$index"),style=MaterialTheme.typography.bodySmall)
            }
            item {Row(horizontalArrangement=Arrangement.spacedBy(8.dp)) {
                TextButton(onClick={if(page>0)page--},enabled=page>0,modifier=Modifier.testTag("editor-page-previous")) {Text("Предыдущая")}
                Text("${page+1} / ${pages.size}",Modifier.testTag("editor-page-number"))
                TextButton(onClick={if(page<pages.lastIndex)page++},enabled=page<pages.lastIndex,modifier=Modifier.testTag("editor-page-next")) {Text("Следующая")}
            }}
            item {OutlinedTextField(value=pages[page],onValueChange={value->
                if(editable && value.length<=8192 && editorUnicode(value) && value!=pages[page]) {
                    pages[page]=value;confirmation=null;localError="";reviewInvalidated=true
                    if(!dirty){dirty=true;actions.edited()}
                }
            },readOnly=!editable,modifier=Modifier.fillMaxWidth().testTag("editor-page-input"),
                label={Text("Страница предложения ${page+1}")},textStyle=MaterialTheme.typography.bodySmall.copy(fontFamily=FontFamily.Monospace),minLines=8,maxLines=16)}
            if(model.readOnly)item {Text("Для этой конфигурации доступно только чтение.",Modifier.testTag("editor-read-only"))}
            if(model.phase !in setOf(AdminEditorPhase.UNCERTAIN,AdminEditorPhase.CONFLICT,AdminEditorPhase.NEEDS_REAUTH,AdminEditorPhase.LIMITED,AdminEditorPhase.UNAVAILABLE)) {
                item {Button(onClick={if(dirty && editable)actions.saveLocal(Collections.unmodifiableList(ArrayList(pages)))},
                    enabled=dirty && editable,modifier=Modifier.fillMaxWidth().testTag("editor-save-local")) {Text("Сохранить локальную копию")}}
                item {OutlinedButton(onClick={if(editorMutationAllowed(latestModel) && !dirty)latestActions.saveDraft()},
                    enabled=editorMutationAllowed(model) && !dirty,modifier=Modifier.fillMaxWidth().testTag("editor-save-draft")) {Text("Сохранить черновик на сервере")}}
                item {OutlinedButton(onClick={if(editorMutationAllowed(latestModel) && !dirty)latestActions.preview()},
                    enabled=editorMutationAllowed(model) && !dirty,modifier=Modifier.fillMaxWidth().testTag("editor-preview")) {Text("Проверить предложение")}}
            }
        } else if(!model.unassigned)item {Text("Предложение ещё не загружено.",Modifier.testTag("editor-no-document"))}
        if(model.phase==AdminEditorPhase.REVIEW && !model.unassigned) {
            item {Text("Проверьте получателей и изменения перед публикацией.",Modifier.testTag("editor-review"))}
            if(model.comparisonBinding.isNotEmpty())item {
                OutlinedButton(onClick={if(!dirty && !editorBusy(latestModel))latestActions.viewComparison()},enabled=!activeBusy && !dirty,
                    modifier=Modifier.fillMaxWidth().testTag("editor-full-comparison")) {Text("Показать полное сравнение изменений")}
            }
            if(expired)item {Text(adminEditorErrorText("REVIEW_EXPIRED"),Modifier.testTag("editor-review-expired"))}
            item {Button(onClick={val current=latestModel;val now=latestElapsed()
                if(reviewAllowed(current,now))confirmation=EditorConfirmation(current.reviewBinding,current.reviewDeadlineElapsed,now)
                else localError="REVIEW_EXPIRED"
            },enabled=reviewAllowed(model,elapsed()),modifier=Modifier.fillMaxWidth().testTag("editor-publish")) {Text("Опубликовать после подтверждения")}}
        }
        if(model.phase==AdminEditorPhase.UNCERTAIN) {
            item {Text("Ответ предыдущей операции неизвестен. Повтор использует только её прежние тело и ID; новая публикация не создаётся.",Modifier.testTag("editor-uncertain"))}
            if(model.operationBinding.isNotEmpty())item {Button(onClick={if(!editorBusy(latestModel))latestActions.checkOutcome()},
                enabled=!activeBusy,modifier=Modifier.fillMaxWidth().testTag("editor-check-outcome")) {Text("Узнать результат на сервере")}}
            if(model.canSeal)item {OutlinedButton(onClick={val current=latestModel
                if(current.canSeal && !editorBusy(current) && !sealSubmitted)sealConfirmation=current.operationBinding},
                enabled=!activeBusy && !sealSubmitted,modifier=Modifier.fillMaxWidth().testTag("editor-seal-pending")) {Text("Зафиксировать отсутствие операции")}}
            item {Button(onClick={actions.poll()},enabled=!activeBusy,modifier=Modifier.fillMaxWidth().testTag("editor-poll")) {Text("Проверить предыдущую операцию")}}
            item {OutlinedButton(onClick={actions.retryExact()},enabled=!activeBusy,modifier=Modifier.fillMaxWidth().testTag("editor-retry-exact")) {Text("Повторить ту же операцию")}}
        }
        if(model.phase==AdminEditorPhase.CONFLICT) {
            item {Text("Конфликт не устранён. Загрузите сравнение версий и подготовьте новое предложение.",Modifier.testTag("editor-conflict"))}
            item {Button(onClick={actions.comparison()},enabled=!activeBusy,modifier=Modifier.fillMaxWidth().testTag("editor-comparison")) {Text("Загрузить сравнение")}}
            item {OutlinedButton(onClick={actions.rebase()},enabled=!activeBusy && !model.readOnly,modifier=Modifier.fillMaxWidth().testTag("editor-rebase")) {Text("Подготовить перенос изменений")}}
        }
        if(model.phase==AdminEditorPhase.PUBLISHED)item {
            Text("Желаемая конфигурация опубликована. Применение на устройстве и работа VPN проверяются отдельно.",Modifier.testTag("editor-published"))
        }
        item {TextButton(onClick={navigate("WEB")},enabled=!activeBusy,modifier=Modifier.testTag("editor-full-web")) {Text("Полная веб-панель")}}
        if(model.localRevision>0 && model.phase !in setOf(AdminEditorPhase.UNCERTAIN,AdminEditorPhase.NEEDS_REAUTH))item {
            TextButton(onClick={closeConfirmation=true},enabled=!activeBusy,modifier=Modifier.testTag("editor-close")) {Text("Закрыть локальную копию")}
        }
    }
    if(leaveConfirmation)AlertDialog(onDismissRequest={leaveConfirmation=false},
        title={Text("Оставить несохранённый ввод?")},text={Text("Изменения после последнего локального сохранения будут потеряны. Сохранённый черновик останется на устройстве.")},
        confirmButton={TextButton(onClick={if(!editorBusy(latestModel)){leaveConfirmation=false;proceed(leaveTarget)}},
            enabled=!activeBusy,modifier=Modifier.testTag("editor-leave-confirm")) {Text("Оставить ввод")}},
        dismissButton={TextButton(onClick={leaveConfirmation=false}) {Text("Продолжить редактирование")}})
    if(closeConfirmation)AlertDialog(onDismissRequest={closeConfirmation=false},
        title={Text("Закрыть локальную копию?")},text={Text("Локальный ввод будет удалён. Серверный черновик и опубликованная конфигурация сохранятся. После этого можно открыть редактор другого устройства.")},
        confirmButton={TextButton(onClick={closeConfirmation=false;latestActions.close()},modifier=Modifier.testTag("editor-close-confirm")) {Text("Закрыть копию")}},
        dismissButton={TextButton(onClick={closeConfirmation=false}) {Text("Продолжить работу")}})
    sealConfirmation?.let {captured->
        val valid=model.phase==AdminEditorPhase.UNCERTAIN && model.canSeal && model.operationBinding==captured && !activeBusy && !sealSubmitted
        AlertDialog(onDismissRequest={sealConfirmation=null},modifier=Modifier.testTag("editor-seal-dialog"),
            title={Text("Зафиксировать отсутствие операции?")},
            text={Text("Сервер проверит прежний запрос и запретит его запоздалое выполнение, если он ещё не зарегистрирован. Локальная копия сохранится. Уже зарегистрированная операция будет проверена без новой публикации.")},
            confirmButton={Button(onClick={val current=latestModel
                sealConfirmation=null
                if(current.phase==AdminEditorPhase.UNCERTAIN && current.canSeal && current.operationBinding==captured && !editorBusy(current) && !sealSubmitted) {
                    sealSubmitted=true;latestActions.sealPending(captured)
                }
            },enabled=valid,modifier=Modifier.testTag("editor-seal-confirm")) {Text("Проверить и зафиксировать")}},
            dismissButton={TextButton(onClick={sealConfirmation=null},modifier=Modifier.testTag("editor-seal-cancel")) {Text("Отмена")}})
    }
    confirmation?.let {captured->
        val current=model
        val currentTime=elapsed()
        val valid=reviewAllowed(current,currentTime) && currentTime>=captured.openedAt && captured.binding==current.reviewBinding && captured.deadline==current.reviewDeadlineElapsed
        AlertDialog(onDismissRequest={confirmation=null},modifier=Modifier.testTag("editor-confirm-dialog"),
            title={Text("Подтвердить публикацию?")},text={Column(Modifier.heightIn(max=320.dp).verticalScroll(rememberScrollState()),verticalArrangement=Arrangement.spacedBy(8.dp)) {
                Text("Будет изменена желаемая конфигурация получателей. Это не подтверждение применения и не включение VPN.")
                Text("Получатели",style=MaterialTheme.typography.titleSmall)
                current.recipients.forEachIndexed {index,id->Text(id,Modifier.testTag("editor-confirm-recipient-$index"),fontFamily=FontFamily.Monospace)}
                Text("Изменения",style=MaterialTheme.typography.titleSmall)
                if(current.diffSummaries.isEmpty())Text("Краткое описание отсутствует; сверяйте полное предложение.")
                current.diffSummaries.forEachIndexed {index,text->Text(text,Modifier.testTag("editor-confirm-diff-$index"))}
            }},confirmButton={Button(onClick={
                val latest=latestModel;val now=latestElapsed()
                val allowed=reviewAllowed(latest,now) && now>=captured.openedAt && captured.binding==latest.reviewBinding && captured.deadline==latest.reviewDeadlineElapsed
                confirmation=null
                if(allowed){reviewSubmitted=true;latestActions.publish(captured.binding,captured.deadline)} else localError="REVIEW_EXPIRED"
            },enabled=valid,modifier=Modifier.testTag("editor-confirm-publish")) {Text("Опубликовать желаемую конфигурацию")}},
            dismissButton={TextButton(onClick={confirmation=null},modifier=Modifier.testTag("editor-confirm-cancel")) {Text("Отмена")}})
    }
}

private class EditorConfirmation(val binding:String,val deadline:Long,val openedAt:Long)
private fun editorBusy(model:AdminEditorModel)=model.busy || model.phase in setOf(AdminEditorPhase.SAVING,AdminEditorPhase.PREVIEWING,AdminEditorPhase.PUBLISHING)
private fun editorEditable(model:AdminEditorModel)=!model.readOnly && !model.unassigned && model.phase in setOf(
    AdminEditorPhase.INVENTORY,AdminEditorPhase.EDITING,AdminEditorPhase.LOCAL_DIRTY,AdminEditorPhase.REVIEW,AdminEditorPhase.PUBLISHED)
private fun editorMutationAllowed(model:AdminEditorModel)=!model.readOnly && !model.unassigned && !editorBusy(model) && model.pages.isNotEmpty() &&
    model.phase in setOf(AdminEditorPhase.INVENTORY,AdminEditorPhase.EDITING,AdminEditorPhase.LOCAL_DIRTY)
private fun editorPhaseText(phase:AdminEditorPhase)=when(phase) {
    AdminEditorPhase.INVENTORY->"Загружена конфигурация и её происхождение"
    AdminEditorPhase.EDITING->"Локальная копия готова к редактированию"
    AdminEditorPhase.LOCAL_DIRTY->"Локальные изменения ещё не опубликованы"
    AdminEditorPhase.SAVING->"Сохранение черновика"
    AdminEditorPhase.PREVIEWING->"Сервер проверяет предложение"
    AdminEditorPhase.REVIEW->"Проверка готова; требуется подтверждение"
    AdminEditorPhase.PUBLISHING->"Публикация желаемой конфигурации"
    AdminEditorPhase.PUBLISHED->"Получена квитанция публикации желаемой конфигурации"
    AdminEditorPhase.UNCERTAIN->"Результат предыдущей операции неизвестен"
    AdminEditorPhase.CONFLICT->"Версии конфигурации конфликтуют"
    AdminEditorPhase.NEEDS_REAUTH->"Нужно подтвердить административный доступ"
    AdminEditorPhase.LIMITED->"Доступен ограниченный режим"
    AdminEditorPhase.UNAVAILABLE->"Редактор временно недоступен"
}
