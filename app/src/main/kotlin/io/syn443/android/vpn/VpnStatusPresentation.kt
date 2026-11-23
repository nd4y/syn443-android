package io.syn443.android.vpn

import org.json.JSONObject

internal fun JSONObject.hasBlockedAccountPolicy(): Boolean =
    optJSONObject("policy")?.let { it.optString("source") == "account" && it.optString("phase") == "blocked" } == true

internal fun vpnTileIntent(status: JSONObject?): Boolean? =
    status?.takeUnless { it.optString("phase") == "NeedsUnlock" }?.opt("desiredOn") as? Boolean

internal fun vpnStatusLabel(status: JSONObject, available: Boolean?, accountPolicyBlocked: Boolean): String {
    val known = status.optBoolean("engineStateKnown")
    val active = status.optBoolean("engineActive")
    val phase = status.optString("phase")
    val checking = "Проверяем состояние VPN"
    return when {
        available == null -> checking
        !available -> "Состояние VPN временно недоступно"
        phase == "NeedsUnlock" -> "Нужно разблокировать телефон"
        status.opt("desiredOn") == false -> when {
            known && active -> "Останавливаем VPN"
            !known -> checking
            accountPolicyBlocked -> "Ожидаем конфигурацию от сервера"
            else -> "Отключён"
        }
        status.opt("desiredOn") != true -> checking
        else -> when (phase) {
            "Online" -> if (known && active) "Работает" else checking
            "Degraded" -> if (known && active) "Частично работает" else checking
            "BlockedByPolicy", "Blocked" -> "Доступ ограничен политикой"
            "NoNetwork" -> if (status.optString("reason") == "captive_portal") "Войдите в сеть Wi-Fi" else "Ожидание сети"
            "Recovering" -> "Восстанавливаем соединение"
            "Starting", "Connecting" -> "Подключаемся"
            "NeedsPermission" -> "Нужно разрешение Android на VPN"
            "NeedsAction" -> "Требуется действие пользователя"
            "NeedsLogin" -> "Требуется вход в аккаунт"
            else -> checking
        }
    }
}
