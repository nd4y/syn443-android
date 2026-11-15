package io.syn443.android

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.unit.dp
import io.syn443.android.chat.SupportActivity
import io.syn443.android.vpn.LoginControls
import io.syn443.android.vpn.VpnControls
import io.syn443.decision.Coordinator
import io.syn443.decision.Decision
import io.syn443.decision.Request
import kotlinx.serialization.json.*

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme(colorScheme = darkColorScheme()) {
                Surface(Modifier.fillMaxSize()) { Home(intent.getLongExtra("syn443.consentGeneration", -1)) }
            }
        }
    }
}

@Composable
private fun Home(consentGeneration: Long) {
    val context = LocalContext.current
    Column(
        Modifier.fillMaxSize().safeDrawingPadding().verticalScroll(rememberScrollState()).padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("SYN443", style = MaterialTheme.typography.headlineLarge)
        Text("Secure Your Network")
        VpnControls(consentGeneration) { vpnStopped ->
            LoginControls(vpnStopped)
            TextButton(
                onClick = { context.startActivity(Intent(context, EnrollmentActivity::class.java)) },
                modifier = Modifier.testTag("manual-enrollment"),
            ) { Text("Привязать по приглашению или QR") }
            TextButton(
                onClick = { context.startActivity(Intent(context, SupportActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_REORDER_TO_FRONT)) },
                modifier = Modifier.testTag("support-chat"),
            ) { Text("Чат с администратором") }
        }
        if (BuildConfig.DEBUG) {
            var demoOpen by rememberSaveable { mutableStateOf(false) }
            TextButton(
                onClick = { demoOpen = !demoOpen },
                modifier = Modifier.testTag("developer-tools").semantics {
                    stateDescription = if (demoOpen) "Раскрыто" else "Свёрнуто"
                },
            ) { Text(if (demoOpen) "Скрыть модель маршрутизации" else "Модель маршрутизации для разработчиков") }
            if (demoOpen) {
                val request = remember {
                    val fixture = context.assets.open("decision-vectors.json").bufferedReader().use { it.readText() }
                    val input = Decision.json.parseToJsonElement(fixture).jsonObject["cases"]!!.jsonArray.first().jsonObject["input"]!!
                    Decision.decode(input.toString())
                }
                RoutePrototype(request)
            }
        }
    }
}

@Composable
private fun RoutePrototype(request: Request) {
    val coordinator = remember { Coordinator(request.context) }
    var state by remember { mutableStateOf(coordinator.snapshot()) }
    var pending by remember { mutableStateOf<Request?>(null) }
    var outcome by remember { mutableStateOf("Проверка ещё не запускалась") }
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
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

