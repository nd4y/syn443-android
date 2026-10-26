package io.syn443.android

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import io.syn443.decision.Coordinator
import io.syn443.decision.Decision
import io.syn443.decision.Request
import kotlinx.serialization.json.*

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val fixture = assets.open("decision-vectors.json").bufferedReader().use { it.readText() }
        val input = Decision.json.parseToJsonElement(fixture).jsonObject["cases"]!!.jsonArray.first().jsonObject["input"]!!
        val request = Decision.decode(input.toString())
        setContent {
            MaterialTheme(colorScheme = darkColorScheme()) {
                Surface(Modifier.fillMaxSize()) { Prototype(request, intent.getLongExtra("syn443.consentGeneration", -1)) }
            }
        }
    }
}

@Composable
private fun Prototype(request: Request, consentGeneration: Long = -1) {
    val coordinator = remember { Coordinator(request.context) }
    var state by remember { mutableStateOf(coordinator.snapshot()) }
    var pending by remember { mutableStateOf<Request?>(null) }
    var outcome by remember { mutableStateOf("Проверка ещё не запускалась") }
    Column(
        Modifier.fillMaxSize().safeDrawingPadding().verticalScroll(rememberScrollState()).padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("SYN443", style = MaterialTheme.typography.headlineLarge)
        Text("Secure Your Network")
        io.syn443.android.vpn.LoginControls()
        io.syn443.android.vpn.VpnControls(consentGeneration)
        Text("Модель выбора маршрута (тестовые данные).", Modifier.testTag("prototype"))
        Text("Эпоха сети: " + state.context.networkEpoch, Modifier.testTag("epoch"))
        Text(if (state.desiredOn) "Модель запущена" else "Остановлено", Modifier.testTag("state"))
        Text(outcome, Modifier.testTag("outcome"))
        Button(onClick = {
            val dispatchContext = coordinator.start()
            // Only synthetic fixture templates are restamped here. Real probe evidence
            // must keep its original dispatch context through completion.
            pending = request.copy(
                context = dispatchContext,
                candidates = request.candidates.map { it.copy(context = dispatchContext) },
            )
            state = coordinator.snapshot()
            outcome = "Результат ожидает применения"
        }, modifier = Modifier.testTag("start")) { Text("Запустить проверку") }
        Button(onClick = {
            coordinator.networkChanged()
            state = coordinator.snapshot()
            outcome = "Сеть изменена"
        }, modifier = Modifier.testTag("network")) { Text("Сменить сеть в модели") }
        Button(onClick = {
            val job = pending
            val selected = job?.let { Decision.select(it).selectedPathId }
            val accepted = if (job != null && selected != null) coordinator.tryApply(job.context, selected) else false
            state = coordinator.snapshot()
            outcome = if (accepted) "Выбран тестовый маршрут: " + selected else "Устаревший результат отклонён"
        }, modifier = Modifier.testTag("apply")) { Text("Применить результат") }
        Button(onClick = {
            coordinator.stop()
            state = coordinator.snapshot()
            outcome = "Остановлено пользователем"
        }, modifier = Modifier.testTag("stop")) { Text("Стоп") }
    }
}

