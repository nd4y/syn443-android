package io.syn443.android.vpn

import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import org.json.JSONObject

@Composable
internal fun PhysicalLinkDetails(link: JSONObject?) {
    val transport = when (link?.optString("transport")) {
        "WIFI" -> "Wi-Fi"
        "CELLULAR" -> "Мобильная сеть"
        "OTHER" -> "Другая сеть"
        else -> null
    }
    if (transport == null || link == null) {
        Text("Ожидание данных о сети VPN", Modifier.testTag("physical-link-pending"))
        return
    }
    Text("Сеть подключения VPN - $transport", Modifier.testTag("physical-link-transport"))
    for ((family, prefix) in listOf("IPv4" to "ipv4", "IPv6" to "ipv6")) {
        val address = link.opt(prefix + "Address") as? Boolean
        val route = link.opt(prefix + "Default") as? Boolean
        val description = when {
            address == null || route == null -> "нет данных"
            address && route -> "есть адрес и маршрут по умолчанию"
            address -> "есть адрес, нет маршрута по умолчанию"
            route -> "есть маршрут по умолчанию, нет адреса"
            else -> "нет адреса и маршрута по умолчанию"
        }
        Text("$family - $description", Modifier.testTag("physical-link-$prefix"))
    }
}
