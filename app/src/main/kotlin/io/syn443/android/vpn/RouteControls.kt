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
import org.json.JSONObject

@Composable fun RouteControls(status:JSONObject,command:(String,String?)->Unit) {
    val context=LocalContext.current
    Column(verticalArrangement=Arrangement.spacedBy(6.dp)) {
        Text("Маршруты",Modifier.testTag("routes-title"))
        val health=status.optJSONObject("routeHealth")
        val routes=health?.optJSONArray("routes")
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
            if(!row.getBoolean("configured"))Text("Профиль проверки не назначен; доступность не подтверждена")
            if(row.getBoolean("required"))Text("Обязательный маршрут")
            when(row.optString("selectionState")) {
                "quarantined"->Text("Временно исключён из выбора. Повторная проверка через ${(row.getLong("retryInMs")+999)/1000} с")
                "revalidate","half_open"->Text("Для возврата в выбор нужна новая успешная проверка")
            }
            if(!row.isNull("ageMs"))Text("Возраст проверки: ${row.getLong("ageMs")/1000} с; время: ${row.optLong("latencyMs")} мс")
            val path=row.optJSONArray("measuredPath")
            if(path!=null && path.length()>0)Text("Проверенный путь: "+(0 until path.length()).joinToString(" → "){path.getString(it)})
            if(row.optString("reason") !in setOf("ok","not_checked"))Text("Причина: ${row.optString("reason")}")
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
