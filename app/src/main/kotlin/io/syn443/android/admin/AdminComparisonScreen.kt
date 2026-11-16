package io.syn443.android.admin

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp

/** Pure presentation: no JSON, I/O, RPC, timer, saved state or automatic intent. */
@Composable
internal fun AdminComparisonScreen(model:AdminComparisonModel,actions:AdminComparisonActions) {
    val latestModel by rememberUpdatedState(model)
    val latestActions by rememberUpdatedState(actions)
    var confirmation by remember(model.binding,model.localRevision,model.device,model.readOnly) {mutableStateOf<ComparisonConfirmation?>(null)}
    var submitted by remember(model.binding,model.localRevision,model.device,model.readOnly) {mutableStateOf(false)}
    fun query(current:AdminComparisonModel)=!current.busy && current.binding.isNotEmpty()
    fun applyAllowed(current:AdminComparisonModel)=query(current) && !current.readOnly && current.ready &&
        current.device.isNotEmpty() && current.localRevision>0 && current.error.isEmpty() && !submitted
    BackHandler {if(!latestModel.busy)latestActions.back()}
    LazyColumn(Modifier.fillMaxSize().safeDrawingPadding().padding(horizontal=20.dp).testTag("comparison-content"),
        verticalArrangement=Arrangement.spacedBy(12.dp),contentPadding=PaddingValues(vertical=20.dp)) {
        item {Text("Сравнение конфигурации",Modifier.testTag("comparison-title"),style=MaterialTheme.typography.headlineMedium)}
        item {TextButton(onClick={if(!latestModel.busy)latestActions.back()},enabled=!model.busy,
            modifier=Modifier.testTag("comparison-back")) {Text("В редактор")}}
        item {Text("Локальная проекция слоёв. Окончательную проверку, права и публикацию выполняет сервер.",Modifier.testTag("comparison-local-warning"))}
        item {Text("Устройство: ${model.device.ifEmpty {"не выбрано"}}; локальная ревизия: ${model.localRevision}",Modifier.testTag("comparison-scope"))}
        item {Text("Базовая ревизия: ${model.baseRevision.takeIf {it>0}?.toString()?:"не указана"}; сравниваемая ревизия: ${model.currentRevision.takeIf {it>0}?.toString()?:"не указана"}",
            Modifier.testTag("comparison-head-revisions"))}
        if(model.readOnly)item {Text("Только просмотр. Вернитесь в редактор, чтобы начать новое сравнение.",Modifier.testTag("comparison-read-only"))}
        if(model.busy)item {LinearProgressIndicator(Modifier.fillMaxWidth().testTag("comparison-progress"))}
        if(model.error.isNotEmpty())item {Text(adminComparisonErrorText(model.error),Modifier.testTag("comparison-error"),color=MaterialTheme.colorScheme.error)}
        item {Row(horizontalArrangement=Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick={val current=latestModel;if(query(current) && current.section!=AdminComparisonSection.CONFLICTS)latestActions.page(AdminComparisonSection.CONFLICTS,0)},
                enabled=query(model) && model.section!=AdminComparisonSection.CONFLICTS,modifier=Modifier.testTag("comparison-section-conflicts")) {Text("Конфликты")}
            OutlinedButton(onClick={val current=latestModel;if(query(current) && current.section!=AdminComparisonSection.DIFF)latestActions.page(AdminComparisonSection.DIFF,0)},
                enabled=query(model) && model.section!=AdminComparisonSection.DIFF,modifier=Modifier.testTag("comparison-section-diff")) {Text("Изменения")}
        }}
        item {Text(if(model.section==AdminComparisonSection.CONFLICTS)"Конфликты" else "Различия локальной проекции",
            Modifier.testTag("comparison-section"),style=MaterialTheme.typography.titleLarge)}
        item {Text(if(model.rows.isEmpty())"Показано 0 из ${model.total}" else "Строки ${model.offset+1}-${model.offset+model.rows.size} из ${model.total}",Modifier.testTag("comparison-count"))}
        if(model.rows.isEmpty())item {Text(if(model.total==0)"В этом разделе строк нет." else "Страница пуста. Обновите сравнение.",Modifier.testTag("comparison-empty"))}
        items(model.rows,key={it.id}) {row->
            Card(Modifier.fillMaxWidth().testTag("comparison-row-${row.id}")) {Column(Modifier.padding(12.dp),verticalArrangement=Arrangement.spacedBy(8.dp)) {
                Text(comparisonKindText(row.kind),style=MaterialTheme.typography.titleMedium)
                SelectionContainer {Text(row.path.ifEmpty {"Параметры слоя"},Modifier.testTag("comparison-path-${row.id}"),fontFamily=FontFamily.Monospace)}
                Text(adminComparisonCodeText(row.code),Modifier.testTag("comparison-code-${row.id}"))
                if(model.section==AdminComparisonSection.CONFLICTS && !model.readOnly) {
                    if(row.resolvable) {
                        Text(when(row.choice) {"LOCAL"->"Выбрана локальная версия.";"CURRENT"->"Выбрана сравниваемая версия сервера.";else->"Выберите версию для локального результата."},
                            Modifier.testTag("comparison-choice-${row.id}"))
                        Row(horizontalArrangement=Arrangement.spacedBy(8.dp)) {
                            for(choice in listOf("LOCAL","CURRENT"))OutlinedButton(onClick={
                                val current=latestModel;val present=current.rows.singleOrNull {it.id==row.id}
                                if(query(current) && !current.readOnly && current.section==AdminComparisonSection.CONFLICTS && present?.resolvable==true && present.choice!=choice)
                                    latestActions.choose(present.id,choice)
                            },enabled=query(model) && row.choice!=choice,modifier=Modifier.testTag("comparison-choose-${row.id}-$choice")) {Text(if(choice=="LOCAL")"Локальная" else "Серверная")}
                        }
                    } else Text("Выбор стороны недоступен. Обновите сравнение или откройте полную панель.",Modifier.testTag("comparison-unresolvable-${row.id}"))
                }
                for(side in row.availableSides)TextButton(onClick={
                    val current=latestModel;val present=current.rows.singleOrNull {it.id==row.id}
                    if(query(current) && present!=null && side in present.availableSides)latestActions.detail(present.id,side,0)
                },enabled=query(model),modifier=Modifier.testTag("comparison-side-${row.id}-${side.name}")) {Text(adminComparisonSideText(side))}
            }}
        }
        item {Row(horizontalArrangement=Arrangement.spacedBy(8.dp)) {
            TextButton(onClick={val current=latestModel;if(query(current) && current.offset>0)latestActions.page(current.section,maxOf(0,current.offset-20))},enabled=query(model) && model.offset>0,
                modifier=Modifier.testTag("comparison-page-previous")) {Text("Предыдущая страница")}
            TextButton(onClick={val current=latestModel;if(query(current) && current.rows.isNotEmpty() && current.offset+current.rows.size<current.total)
                latestActions.page(current.section,current.offset+current.rows.size)},
                enabled=query(model) && model.rows.isNotEmpty() && model.offset+model.rows.size<model.total,
                modifier=Modifier.testTag("comparison-page-next")) {Text("Следующая страница")}
        }}
        model.detail?.let {detail->
            item {
                HorizontalDivider();Text(adminComparisonSideText(detail.side),Modifier.testTag("comparison-detail-side"),style=MaterialTheme.typography.titleMedium)
                Text("Фрагмент ${detail.page+1} из ${detail.totalPages}",Modifier.testTag("comparison-detail-count"))
                SelectionContainer {Text(detail.text,Modifier.fillMaxWidth().heightIn(max=360.dp).verticalScroll(rememberScrollState()).testTag("comparison-detail-text"),
                    fontFamily=FontFamily.Monospace,style=MaterialTheme.typography.bodySmall)}
            }
            item {Row(horizontalArrangement=Arrangement.spacedBy(8.dp)) {
                for(direction in listOf(-1,1))TextButton(onClick={
                    val current=latestModel;val selected=current.detail
                    if(query(current) && selected!=null && selected.rowId==detail.rowId && selected.side==detail.side && selected.page==detail.page &&
                        selected.page+direction in 0 until selected.totalPages)latestActions.detail(selected.rowId,selected.side,selected.page+direction)
                },enabled=query(model) && detail.page+direction in 0 until detail.totalPages,
                    modifier=Modifier.testTag(if(direction<0)"comparison-detail-previous" else "comparison-detail-next")) {Text(if(direction<0)"Предыдущий фрагмент" else "Следующий фрагмент")}
            }}
        }
        if(!model.readOnly) {
            item {Text(if(model.ready)"Локальный результат готов к применению." else if(model.section==AdminComparisonSection.CONFLICTS && model.total>0)
                "Разрешите доступные конфликты. Ограничения слоёв проверяются отдельно." else "Локальное применение пока недоступно.",Modifier.testTag("comparison-readiness"))}
            item {Button(onClick={val current=latestModel;if(applyAllowed(current))confirmation=ComparisonConfirmation(current.binding,current.localRevision,current.device)},
                enabled=applyAllowed(model),modifier=Modifier.fillMaxWidth().testTag("comparison-apply")) {Text("Применить к локальной копии")}}
            item {TextButton(onClick={if(!latestModel.busy)latestActions.reload()},enabled=!model.busy,
                modifier=Modifier.testTag("comparison-reload")) {Text("Загрузить сравнение заново")}}
        }
        item {TextButton(onClick={if(!latestModel.busy)latestActions.web()},enabled=!model.busy,
            modifier=Modifier.testTag("comparison-full-web")) {Text("Полная веб-панель")}}
    }
    confirmation?.let {captured->
        fun valid(current:AdminComparisonModel)=applyAllowed(current) && current.binding==captured.binding &&
            current.localRevision==captured.revision && current.device==captured.device
        AlertDialog(onDismissRequest={confirmation=null},modifier=Modifier.testTag("comparison-confirm-dialog"),
            title={Text("Применить локальную копию?")},text={Column(verticalArrangement=Arrangement.spacedBy(8.dp)) {
                Text("Изменения будут сохранены локально. Отправка серверного черновика и публикация выполняются отдельно.")
                Text("Устройство: ${captured.device}; локальная ревизия: ${captured.revision}",Modifier.testTag("comparison-confirm-scope"))
            }},confirmButton={Button(onClick={
                val current=latestModel
                if(valid(current)) {submitted=true;confirmation=null;latestActions.apply(captured.binding,captured.revision)}
            },enabled=valid(model),modifier=Modifier.testTag("comparison-confirm-apply")) {Text("Применить локально")}},
            dismissButton={TextButton(onClick={confirmation=null},modifier=Modifier.testTag("comparison-confirm-cancel")) {Text("Отмена")}})
    }
}

private class ComparisonConfirmation(val binding:String,val revision:Long,val device:String) {
    override fun toString()="ComparisonConfirmation([redacted])"
}
private fun comparisonKindText(kind:String):String=when(kind) {
    "device"->"Слой устройства";"local"->"Локальный слой";"metadata"->"Метаданные"
    "layers"->"Набор слоёв";"projection"->"Локальная проекция";"setting"->"Параметр"
    else->"Пересечение слоёв"
}
