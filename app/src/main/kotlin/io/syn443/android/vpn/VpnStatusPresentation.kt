package io.syn443.android.vpn

import org.json.JSONObject

internal fun JSONObject.vpnIntentGeneration(): Long? =
    when (val value = opt("generation")) {
        is Int -> value.toLong()
        is Long -> value
        else -> null
    }?.takeIf { it >= 0 }

/** Intent acknowledgements can change the action immediately, but only a
 * current controller observation supplies live status and diagnostics. */
internal class VpnHomeStatus private constructor(
    val status: JSONObject,
    val available: Boolean?,
    private val generationFloor: Long,
) {
    constructor() : this(JSONObject(), null, -1)

    fun awaitingPoll(): VpnHomeStatus = VpnHomeStatus(status, null, generationFloor)

    fun afterPoll(reply: JSONObject?): VpnHomeStatus {
        if (reply != null) {
            if (reply.isLockedObservation())
                return VpnHomeStatus(LifecycleAccess.lockedStatus(), true, generationFloor)
            val generation = reply.vpnIntentGeneration()
            val phase = reply.opt("phase")
            // An initial unlocked state may omit phase before the first command.
            if (generation != null && generation >= generationFloor && reply.opt("desiredOn") is Boolean &&
                (phase == null || phase is String) && phase != "NeedsUnlock")
                return VpnHomeStatus(reply, true, generation)
        }
        return VpnHomeStatus(status, false, generationFloor)
    }

    fun afterIntent(reply: JSONObject): VpnHomeStatus {
        val generation = reply.vpnIntentGeneration() ?: return this
        val desiredOn = reply.opt("desiredOn") as? Boolean ?: return this
        if (generation < generationFloor) return this
        val intent = JSONObject().put("generation", generation).put("desiredOn", desiredOn)
        return VpnHomeStatus(intent, null, generation)
    }

    private fun JSONObject.isLockedObservation(): Boolean =
        opt("phase") == "NeedsUnlock" && opt("reason") == "credential_storage_locked" &&
            opt("generation") === JSONObject.NULL && opt("desiredOn") === JSONObject.NULL &&
            opt("desiredOnKnown") == false && opt("engineActive") == false &&
            optJSONObject("osPolicy")?.let { it.opt("unlocked") == false && it.opt("known") == false } == true
}

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
