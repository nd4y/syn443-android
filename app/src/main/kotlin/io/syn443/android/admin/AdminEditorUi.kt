package io.syn443.android.admin

import androidx.compose.runtime.Immutable
import java.util.Collections
import java.util.Base64

internal enum class AdminEditorPhase {
    INVENTORY, EDITING, LOCAL_DIRTY, SAVING, PREVIEWING, REVIEW, PUBLISHING,
    PUBLISHED, UNCERTAIN, CONFLICT, NEEDS_REAUTH, LIMITED, UNAVAILABLE
}

/** Worker-prepared value snapshots. Construction/whole-document validation must
 * happen off Main; the screen never parses or concatenates the proposal. */
@Immutable
internal class AdminEditorModel(
    val device:String="",val privateDraftRevision:Long=0,val desiredHeadRevision:Long=0,val localRevision:Long=0,
    val phase:AdminEditorPhase=AdminEditorPhase.INVENTORY,val busy:Boolean=false,
    val readOnly:Boolean=false,val unassigned:Boolean=false,val documentBinding:String="",
    pages:List<String> = emptyList(),parents:List<AdminEditorParent> = emptyList(),
    val reviewBinding:String="",val reviewDeadlineElapsed:Long=0,
    recipients:List<String> = emptyList(),diffSummaries:List<String> = emptyList(),
    val error:String="",val comparisonBinding:String="",val operationBinding:String="",val operationOutcome:String="",val canSeal:Boolean=false
) {
    val pages:List<String> = Collections.unmodifiableList(ArrayList(pages))
    val parents:List<AdminEditorParent> = Collections.unmodifiableList(ArrayList(parents))
    val recipients:List<String> = Collections.unmodifiableList(ArrayList(recipients))
    val diffSummaries:List<String> = Collections.unmodifiableList(ArrayList(diffSummaries))
    init {
        require(device.isEmpty() || editorId.matches(device))
        require(privateDraftRevision in 0..EDITOR_MAX_INTEGER && desiredHeadRevision in 0..EDITOR_MAX_INTEGER && localRevision in 0..EDITOR_MAX_INTEGER)
        require(pages.size<=64 && pages.all {it.length<=8192 && editorUnicode(it)})
        require(documentBinding.isEmpty() || editorBinding.matches(documentBinding))
        require(pages.isEmpty() || documentBinding.isNotEmpty())
        require(parents.size<=20)
        require(reviewBinding.isEmpty() || editorBinding.matches(reviewBinding))
        require(comparisonBinding.isEmpty() || editorDigest(comparisonBinding))
        require(operationBinding.isEmpty() || editorDigest(operationBinding))
        require(operationOutcome in setOf("","UNKNOWN","NO_EFFECT","RECORDED","RECORDED_RESULT_UNAVAILABLE"))
        require(!canSeal || operationBinding.isNotEmpty() && operationOutcome=="UNKNOWN" && phase==AdminEditorPhase.UNCERTAIN)
        require(reviewDeadlineElapsed>=0 && recipients.size<=64 && recipients.all {editorId.matches(it)} && recipients.toSet().size==recipients.size)
        require(diffSummaries.size<=64 && diffSummaries.all {it.length<=512 && editorUnicode(it)})
    }
    override fun toString()="AdminEditorModel([redacted])"
}

@Immutable
internal class AdminEditorParent(val kind:String,val id:String,val revision:Long) {
    init {
        require(kind in setOf("template","group","user","device","local") && editorId.matches(id) && revision in 1..EDITOR_MAX_INTEGER)
    }
    override fun toString()="AdminEditorParent([redacted])"
}

/** Callbacks are explicit user intentions only, never automatic network work. */
internal class AdminEditorActions(
    val edited:()->Unit={},val saveLocal:(List<String>)->Unit={},val saveDraft:()->Unit={},
    val preview:()->Unit={},val publish:(String,Long)->Unit={_,_->},
    val poll:()->Unit={},val retryExact:()->Unit={},val login:()->Unit={},
    val comparison:()->Unit={},val rebase:()->Unit={},val web:()->Unit={},val back:()->Unit={},val close:()->Unit={},val viewComparison:()->Unit={},
    val checkOutcome:()->Unit={},val sealPending:(String)->Unit={}
)

internal fun AdminEditorModel.withBusy(value:Boolean)=AdminEditorModel(device,privateDraftRevision,desiredHeadRevision,localRevision,
    phase,value,readOnly,unassigned,documentBinding,pages,parents,reviewBinding,reviewDeadlineElapsed,recipients,diffSummaries,error,comparisonBinding,operationBinding,operationOutcome,canSeal)
internal fun AdminEditorModel.withFailure(code:String)=AdminEditorModel(device,privateDraftRevision,desiredHeadRevision,localRevision,
    AdminEditorPhase.UNAVAILABLE,false,true,unassigned,documentBinding,pages,parents,error=code)

internal fun adminEditorErrorText(code:String):String=when(if(code.length in 1..64)code.uppercase() else "") {
    "DENIED","ACCESS_DENIED"->"Недостаточно прав для этой операции."
    "CONFLICT","CONFIGURATION_CONFLICT"->"Конфигурация изменилась на сервере. Сначала сравните версии."
    "INVALID_PROPOSAL","INVALID_REPLY"->"Не удалось проверить предложение. Исправьте локальную копию или загрузите данные заново."
    "REAUTHENTICATE","REAUTHENTICATION_REQUIRED","SESSION_EXPIRED"->"Нужно снова подтвердить административный доступ. Локальная копия сохранена."
    "REVIEW_EXPIRED"->"Срок проверки истёк. Запросите новую проверку перед публикацией."
    "BUSY"->"Предыдущая операция ещё выполняется."
    "OUTCOME_UNKNOWN"->"Сервер пока не подтвердил результат. Исходные запрос и локальная копия сохранены."
    "OUTCOME_CHECK_REQUIRED"->"Сначала проверьте результат этой операции."
    "RESULT_UNAVAILABLE"->"Сервер зарегистрировал операцию, но её результат уже недоступен. Сверьте текущую конфигурацию в панели; автоматический повтор не выполняется."
    else->"Данные временно недоступны. Проверьте состояние и повторите действие."
}

private const val EDITOR_MAX_INTEGER=9_007_199_254_740_991L
private val editorId=Regex("[A-Za-z0-9_-]{1,64}")
private val editorBinding=Regex("[A-Za-z0-9_-]{1,128}")
internal fun editorDigest(value:String):Boolean {
    if(!value.matches(Regex("[A-Za-z0-9_-]{43}")))return false
    val raw=try {Base64.getUrlDecoder().decode(value)}catch(_:IllegalArgumentException){return false}
    return try {raw.size==32 && Base64.getUrlEncoder().withoutPadding().encodeToString(raw)==value}finally {raw.fill(0)}
}
internal fun editorUnicode(value:String):Boolean {
    var at=0
    while(at<value.length) {
        if(value[at].isHighSurrogate()) {
            if(at+1>=value.length || !value[at+1].isLowSurrogate())return false
            at++
        } else if(value[at].isLowSurrogate())return false
        at++
    }
    return true
}
