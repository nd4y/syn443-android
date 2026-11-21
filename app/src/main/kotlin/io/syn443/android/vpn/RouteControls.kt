package io.syn443.android.vpn

import android.content.Intent
import android.provider.Settings
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.material3.Button
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import io.syn443.recovery.RouteFailureCause
import org.json.JSONObject

@Composable fun RouteControls(status:JSONObject,command:(String,String?)->Unit) {
    val context=LocalContext.current
    Column(verticalArrangement=Arrangement.spacedBy(6.dp)) {
        Text("Маршруты",Modifier.testTag("routes-title"))
        val health=status.optJSONObject("routeHealth")
        val routes=health?.optJSONArray("routes")
        health?.optJSONObject("decisionShadow")?.let { comparison ->
            val result=when(comparison.optString("outcome")) {
                "agree" -> "решения совпадают"
                "reference_only" -> "базовый алгоритм предложил переключение раньше"
                "live_only" -> "активный алгоритм предложил переключение раньше"
                "different_reserve" -> "алгоритмы выбрали разные резервные маршруты"
                else -> null
            }
            if(result!=null) Text("Сравнение с базовым алгоритмом · серий проверок ${comparison.optLong("comparedBatches")} · $result",
                Modifier.testTag("route-decision-shadow"))
        }
        if(routes==null || routes.length()==0)Text("Список маршрутов ещё не получен")
        if(routes!=null)for(i in 0 until routes.length()) {
            val row=routes.getJSONObject(i)
            Text("${row.getString("id")}: ${row.getString("label")} (${row.getString("type")})",Modifier.testTag("route-${i+1}-title"))
            Text(when(row.getString("state")) {
                "working"->"Проверка назначенной цели успешна"
                "failed"->"Проверка назначенной цели не прошла"
                "checking"->"Проверяется"
                "stale"->"Результат устарел"
                "incomplete"->"Проверка не завершена"
                "off"->"VPN выключен"
                "unavailable"->"Движок или сеть недоступны"
                else->"Маршрут ещё не проверен"
            },Modifier.testTag("route-${i+1}-state"))
            row.optJSONObject("search")?.let {search->
                Text(when(search.optString("state")) {
                    "VERIFIED"->"Выбранный маршрут подтверждён свежей проверкой"
                    "SEARCHING"->"Поиск маршрута продолжается"
                    "BUDGET_WAIT"->"Поиск временно приостановлен и продолжится автоматически"
                    "WAITING_CONTEXT"->"Поиск ожидает подключения к сети и VPN"
                    else->"Поиск ещё не завершён"
                },Modifier.testTag("route-${i+1}-search"))
            }
            if(!row.getBoolean("configured"))Text("Профиль проверки не назначен; доступность не подтверждена")
            row.optJSONObject("checkPlan")?.let {plan->
                Text("План проверки ${plan.optString("id")}: "+checkPlanOutcomeLabel(plan.optString("outcome")),Modifier.testTag("route-${i+1}-check-plan"))
                val leaves=plan.optJSONArray("leaves")
                if(leaves!=null && leaves.length() in 1..4)for(n in 0 until leaves.length()) {
                    val leaf=leaves.getJSONObject(n)
                    Text("${n+1}/${leaves.length()} ${leaf.optString("id")}: "+checkPlanOutcomeLabel(leaf.optString("outcome")),Modifier.testTag("route-${i+1}-check-leaf-${n+1}"))
                }
            }
            if(row.getBoolean("required"))Text("Обязательный маршрут")
            when(row.optString("selectionState")) {
                "quarantined"->Text("Временно исключён из выбора. Повторная проверка через ${(row.getLong("retryInMs")+999)/1000} с")
                "revalidate","half_open"->Text("Для возврата в выбор нужна новая успешная проверка")
            }
            if (!row.isNull("ageMs")) {
                val age = row.getLong("ageMs") / 1000
                val duration = if (row.isNull("latencyMs")) "длительность неизвестна" else "длительность ${row.getLong("latencyMs")} мс"
                Text("Возраст проверки ${age} с · $duration", Modifier.testTag("route-${i+1}-timing"))
            }
            val path=row.optJSONArray("measuredPath")
            if (path != null && path.length() > 0) {
                val title = when (row.getString("state")) {
                    "working" -> "Проверенный путь"
                    "failed", "incomplete" -> "Путь последней попытки"
                    else -> "Путь предыдущей проверки"
                }
                Text(title + " · " + (0 until path.length()).joinToString(" → ") { path.getString(it) },
                    Modifier.testTag("route-${i+1}-path"))
            }
            val reason=row.optString("reason")
            if(reason !in setOf("ok","not_checked")){
                val cause=RouteFailureCause.fromWire(reason,row.optString("cause"))
                Text(routeFailureLabel(reason,cause),Modifier.testTag("route-${i+1}-reason"))
            }
        }
        val enabled=status.optBoolean("desiredOn") && status.optBoolean("engineActive") && routes!=null && (0 until routes.length()).any {routes.getJSONObject(it).optBoolean("configured")}
        Button(onClick={command("routes-check",null)},enabled=enabled && health?.optBoolean("running")!=true,modifier=Modifier.testTag("routes-check")){Text("Проверить маршруты")}
        if(health?.optBoolean("running")==true)Button(onClick={command("routes-cancel",null)},modifier=Modifier.testTag("routes-cancel")){Text("Отменить проверку маршрутов")}
        val os=status.optJSONObject("osPolicy")
        Text(if(os?.optBoolean("known")==true)"Android: Always-on=${os.optBoolean("alwaysOn")}; блокировка без VPN=${os.optBoolean("lockdown")}" else "Android: состояние Always-on/lockdown неизвестно без активного VPN",Modifier.testTag("os-vpn-policy"))
        Text("Stop сохраняет выключенное намерение. Системный lockdown при этом может блокировать сеть.")
        Button(onClick={context.startActivity(Intent(Settings.ACTION_VPN_SETTINGS))},modifier=Modifier.testTag("vpn-system-settings")){Text("Настройки VPN в Android")}
    }
}
internal fun routeFailureLabel(reason: String, cause: RouteFailureCause?): String = when (cause) {
    RouteFailureCause.DNS_NOT_FOUND -> "DNS не нашёл имя узла"
    RouteFailureCause.DNS_TIMEOUT -> "Истекло время ожидания ответа DNS"
    RouteFailureCause.DNS_FAILED -> "Ошибка разрешения имени в DNS"
    RouteFailureCause.CONNECTION_REFUSED -> "Получен отказ в TCP-соединении"
    RouteFailureCause.CERTIFICATE_NAME_MISMATCH -> "Имя узла отсутствует в сертификате TLS"
    RouteFailureCause.CERTIFICATE_UNTRUSTED -> "Не удалось подтвердить доверие к сертификату TLS"
    RouteFailureCause.CERTIFICATE_NOT_CURRENT -> "Текущая дата вне срока действия сертификата TLS"
    RouteFailureCause.TIMEOUT -> if (reason=="tls_failed") "Истекло время ожидания рукопожатия TLS" else "Истекло время ожидания соединения"
    null -> when (reason) {
        "dial_failed" -> "Не удалось установить соединение"
        "tls_failed" -> "Не удалось установить защищённое соединение TLS"
        "exit_country_mismatch" -> "Страна выхода не соответствует назначенному классу"
        "exit_mismatch" -> "Выход не соответствует назначенной проверке"
        "exit_ip_mismatch" -> "IP-адрес выхода отличается от ожидаемого"
        "exit_evidence_invalid" -> "Сервис проверки вернул некорректные сведения о выходе"
        else -> "Причина: $reason"
    }
}
internal fun checkPlanOutcomeLabel(value:String)=when(value) {
    "TRUE"->"условие подтверждено"
    "FALSE"->"условие не выполнено"
    "SKIPPED"->"проверка не выполнялась"
    else->"результат не определён"
}
