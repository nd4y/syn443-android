package io.syn443.android.admin

import androidx.compose.runtime.Immutable
import java.util.Base64
import java.util.Collections

internal enum class AdminComparisonSection { CONFLICTS, DIFF }
internal enum class AdminComparisonSide { BASE, LOCAL_VALUE, CURRENT, BEFORE, AFTER, BEFORE_ORIGIN, AFTER_ORIGIN }

private const val COMPARISON_MAX_INTEGER=9_007_199_254_740_991L
private val comparisonId=Regex("[A-Za-z0-9_-]{1,64}")
private val comparisonCode=Regex("[A-Z][A-Z0-9_]{0,63}")
private val comparisonPath=Regex("(?:/[A-Za-z][A-Za-z0-9_-]{0,63}){1,16}")
private val comparisonKinds=setOf("device","local","device->local","local->device","metadata","layers","projection","setting")
private val comparisonCodes=setOf("","VALUE_CHANGED","CROSS_LAYER_OVERLAP","LAYER_REMOVED","OVERLAPPING_PATHS",
    "INVALID_OVERLAP","LIMIT","APPROVAL_EXCEEDS_CURRENT","LIMIT_OR_SHAPE","INVALID","LOCKED","CONFLICT",
    "ADDED","REMOVED","ORIGIN_CHANGED")
private fun <T> comparisonCopy(values:List<T>,maximum:Int):List<T> {
    require(values.size in 0..maximum)
    val owned=ArrayList<T>(values.size)
    for(value in values) {require(owned.size<maximum);owned.add(value)}
    return Collections.unmodifiableList(owned)
}
private fun comparisonHash(raw:String):Boolean {
    if(!raw.matches(Regex("[A-Za-z0-9_-]{43}")))return false
    val decoded=try {Base64.getUrlDecoder().decode(raw)}catch(_:IllegalArgumentException) {return false}
    return try {decoded.size==32 && Base64.getUrlEncoder().withoutPadding().encodeToString(decoded)==raw}
    finally {decoded.fill(0)}
}

/** Bounded worker-prepared summary only. Raw values enter the UI through DETAIL. */
@Immutable
internal class AdminComparisonRow(val id:String,val kind:String,val path:String,val code:String,
    val resolvable:Boolean=false,val choice:String="",availableSides:List<AdminComparisonSide>) {
    val availableSides:List<AdminComparisonSide> = comparisonCopy(availableSides,AdminComparisonSide.entries.size)
    init {
        require(comparisonHash(id) && kind.length<=32 && kind in comparisonKinds)
        require(path.length<=1040 && (path.isEmpty() || path in setOf("mode","approvalUntilMs","revision") || comparisonPath.matches(path)))
        require(code.length<=64 && code in comparisonCodes)
        require(choice in setOf("","LOCAL","CURRENT") && (choice.isEmpty() || resolvable))
        require(this.availableSides.toSet().size==this.availableSides.size)
    }
    override fun toString()="AdminComparisonRow([redacted])"
}

@Immutable
internal class AdminComparisonDetail(val rowId:String,val side:AdminComparisonSide,val page:Int,
    val totalPages:Int,val text:String) {
    init {require(comparisonHash(rowId) && totalPages in 1..256 && page in 0 until totalPages && text.length<=8192 && editorUnicode(text))}
    override fun toString()="AdminComparisonDetail([redacted])"
}

/** Current-account value, never a role, current lease, preview or publication grant.
 * Binding identifies the complete resolution state, including choices and Store CAS. */
@Immutable
internal class AdminComparisonModel(val device:String="",val binding:String="",val localRevision:Long=0,
    val section:AdminComparisonSection=AdminComparisonSection.CONFLICTS,val total:Int=0,val offset:Int=0,
    rows:List<AdminComparisonRow> = emptyList(),val ready:Boolean=false,val detail:AdminComparisonDetail?=null,
    val busy:Boolean=false,val error:String="",val readOnly:Boolean=false,val baseRevision:Long=0,val currentRevision:Long=0) {
    val rows:List<AdminComparisonRow> = comparisonCopy(rows,20)
    init {
        require(device.isEmpty() || comparisonId.matches(device))
        require(binding.isEmpty() || comparisonHash(binding))
        require(listOf(localRevision,baseRevision,currentRevision).all {it in 0..COMPARISON_MAX_INTEGER})
        val maximum=if(section==AdminComparisonSection.CONFLICTS)2050 else 8194
        require(total in 0..maximum && offset in 0..total && offset+this.rows.size<=total)
        require(this.rows.map {it.id}.toSet().size==this.rows.size)
        require(detail==null || this.rows.any {it.id==detail.rowId && detail.side in it.availableSides})
        require(error.isEmpty() || comparisonCode.matches(error))
    }
    override fun toString()="AdminComparisonModel([redacted])"
}

internal fun AdminComparisonModel.withBusy(value:Boolean)=AdminComparisonModel(device=device,binding=binding,localRevision=localRevision,
    section=section,total=total,offset=offset,rows=rows,ready=ready,detail=detail,busy=value,error=error,readOnly=readOnly,
    baseRevision=baseRevision,currentRevision=currentRevision)
internal fun AdminComparisonModel.withFailure(code:String)=AdminComparisonModel(device=device,binding=binding,localRevision=localRevision,
    section=section,total=total,offset=offset,rows=rows,ready=false,detail=detail,busy=false,error=code.takeIf(comparisonCode::matches)?:"UNAVAILABLE",readOnly=true,
    baseRevision=baseRevision,currentRevision=currentRevision)

/** Explicit user intentions only. No callback is invoked by construction/render. */
internal class AdminComparisonActions(
    val page:(AdminComparisonSection,Int)->Unit={_,_->},val detail:(String,AdminComparisonSide,Int)->Unit={_,_,_->},
    val choose:(String,String)->Unit={_,_->},val apply:(String,Long)->Unit={_,_->},val back:()->Unit={},
    val reload:()->Unit={},val web:()->Unit={}
) {override fun toString()="AdminComparisonActions([redacted])"}

internal fun adminComparisonErrorText(code:String):String=when(code) {
    "REAUTHENTICATE","SESSION_EXPIRED","ACCOUNT_CHANGED"->"Подтвердите административный доступ заново. Локальная копия сохранена."
    "CONFLICT","CONFIGURATION_CONFLICT","STALE"->"Сравнение устарело. Загрузите текущую конфигурацию заново."
    "ACCESS_DENIED","DENIED"->"Недостаточно прав для сравнения или применения локальной копии."
    "BUSY"->"Предыдущая операция ещё выполняется."
    "LIMIT","LIMITED"->"Достигнут предел сравнения. Проверьте конфигурацию в полной панели."
    else->"Сравнение временно недоступно. Локальная копия сохранена."
}
internal fun adminComparisonCodeText(code:String):String=when(code) {
    "VALUE_CHANGED"->"Значение изменилось с обеих сторон."
    "CROSS_LAYER_OVERLAP","OVERLAPPING_PATHS","INVALID_OVERLAP"->"Изменения пересекаются по пути или слоям."
    "LAYER_REMOVED"->"В сравниваемой версии отсутствует прежний слой."
    "APPROVAL_EXCEEDS_CURRENT"->"Запрошенный срок превышает текущий разрешённый срок."
    "LOCKED"->"Текущие ограничения запрещают выбранные изменения."
    "CONFLICT"->"Выбранные слои конфликтуют."
    "INVALID","LIMIT_OR_SHAPE"->"Выбранные изменения не прошли локальную проверку структуры."
    "LIMIT"->"Достигнут предел локального сравнения."
    "ADDED"->"Добавлено значение."
    "REMOVED"->"Удалено значение."
    "ORIGIN_CHANGED"->"Изменился источник поля."
    else->"Изменение поля."
}
internal fun adminComparisonSideText(side:AdminComparisonSide):String=when(side) {
    AdminComparisonSide.BASE->"Исходная версия"
    AdminComparisonSide.LOCAL_VALUE->"Локальная версия"
    AdminComparisonSide.CURRENT->"Сравниваемая версия сервера"
    AdminComparisonSide.BEFORE->"Значение до"
    AdminComparisonSide.AFTER->"Значение после"
    AdminComparisonSide.BEFORE_ORIGIN->"Источник до"
    AdminComparisonSide.AFTER_ORIGIN->"Источник после"
}
