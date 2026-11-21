package io.syn443.android

import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.test.assertTextEquals
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import io.syn443.android.vpn.RouteControls
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Rule
import org.junit.Test

class RouteFailureLabelTest {
    @get:Rule val compose = createComposeRule()

    @Test fun routeScreenExplainsEachFailureAndClearsItAfterRecovery() {
        fun status(reason: String, cause: String): JSONObject {
            val row = JSONObject().put("id", "route-1").put("label", "Fixture").put("type", "direct")
                .put("configured", true).put("required", false).put("state", if (reason == "ok") "working" else "failed")
                .put("reason", reason).put("cause", cause)
            return JSONObject().put("routeHealth", JSONObject().put("routes", JSONArray().put(row)))
        }
        val model = mutableStateOf(status("ok", ""))
        compose.setContent { MaterialTheme { RouteControls(model.value) { _, _ -> error("unexpected command") } } }
        val cases = listOf(
            Triple("dial_failed", "dns_not_found", "DNS не нашёл имя узла"),
            Triple("dial_failed", "dns_timeout", "Истекло время ожидания ответа DNS"),
            Triple("dial_failed", "dns_failed", "Ошибка разрешения имени в DNS"),
            Triple("dial_failed", "connection_refused", "Получен отказ в TCP-соединении"),
            Triple("tls_failed", "certificate_name_mismatch", "Имя узла отсутствует в сертификате TLS"),
            Triple("tls_failed", "certificate_untrusted", "Не удалось подтвердить доверие к сертификату TLS"),
            Triple("tls_failed", "certificate_not_current", "Текущая дата вне срока действия сертификата TLS"),
            Triple("dial_failed", "timeout", "Истекло время ожидания соединения"),
            Triple("tls_failed", "timeout", "Истекло время ожидания рукопожатия TLS"),
            Triple("tls_failed", "private.invalid", "Не удалось установить защищённое соединение TLS")
        )
        for ((reason, cause, label) in cases) {
            compose.runOnIdle { model.value = status(reason, cause) }
            compose.onNodeWithTag("route-1-reason").assertTextEquals(label)
        }
        compose.runOnIdle { model.value = status("ok", "") }
        compose.onNodeWithTag("route-1-reason").assertDoesNotExist()
    }
}
