package io.syn443.android.vpn

import android.net.InetAddresses
import com.google.re2j.Pattern
import com.google.re2j.PatternSyntaxException
import org.json.JSONArray
import org.json.JSONObject
import java.util.Locale

internal class LocalRouteQuery private constructor(
    val domain: String?, val ip: ByteArray?, val application: String?,
    val network: String?, val port: Int?, val dnsType: String?,
) {
    override fun toString() = "LocalRouteQuery([redacted])"

    companion object {
        private val label = Regex("[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
        private val packageName = Regex("[A-Za-z_][A-Za-z_0-9]*(?:\\.[A-Za-z_][A-Za-z_0-9]*)+")
        fun parse(raw: String): LocalRouteQuery {
            val obj = JSONObject(raw)
            require(obj.keys().asSequence().all { it in setOf("domain", "address", "application", "port", "network", "dnsType") })
            fun field(key: String): String? = if (obj.has(key)) (obj.get(key) as String).trim().ifEmpty { null } else null
            val domain = field("domain")?.let {
                require(it.all { c -> c.code < 128 })
                it.removeSuffix(".").lowercase(Locale.ROOT).also { host ->
                    require(host.length in 1..253 && host.split('.').all(label::matches) && !InetAddresses.isNumericAddress(host))
                }
            }
            val ip = field("address")?.let {
                require(it.length <= 45 && '%' !in it)
                InetAddresses.parseNumericAddress(it).address
            }
            val app = field("application")?.also { require(it.length <= 255 && packageName.matches(it)) }
            require(domain != null || ip != null || app != null)
            val network = field("network")?.lowercase(Locale.ROOT)?.also { require(it in setOf("tcp", "udp")) }
            val port = field("port")?.let { it.toInt().also { n -> require(n in 1..65535) } }
            val dns = field("dnsType")?.uppercase(Locale.ROOT)?.also {
                require(it in setOf("A","AAAA","CNAME","MX","TXT","PTR","SRV","HTTPS","SVCB","NS","SOA"))
            }
            return LocalRouteQuery(domain, ip, app, network, port, dns)
        }
    }
}

/** Ordered evaluation of the portable subset of the config returned by the normal permission check.
 * Unsupported native conditions remain indeterminate. No hostname resolution or probe occurs here. */
internal object LocalRouteExplanation {
    private enum class Match { NO, UNKNOWN, YES }
    private fun known(value: Boolean) = if (value) Match.YES else Match.NO
    private val alias = Regex("[A-Za-z0-9_-][A-Za-z0-9_.-]{0,63}")
    private val hostKeys = setOf("domain", "domain_suffix", "domain_keyword", "domain_regex")
    private val dnsKeys = hostKeys + setOf("query_type", "action", "server")
    private val routeKeys = hostKeys + setOf("ip_cidr", "package_name", "network", "port", "port_range", "action", "method", "outbound")

    private fun values(rule: JSONObject, key: String): List<String> = when (val v = rule.opt(key)) {
        null -> emptyList()
        is JSONArray -> {
            require(v.length() in 1..256)
            List(v.length()) { v.get(it).let { item -> require(item is String || item is Number); item.toString() } }
        }
        is String, is Number -> listOf(v.toString())
        else -> throw IllegalArgumentException()
    }
    private fun listed(options: List<String>, value: String?): Match = when {
        options.isEmpty() -> Match.YES
        value == null -> Match.UNKNOWN
        else -> known(value in options)
    }
    private fun contains(prefix: String, address: ByteArray): Boolean {
        val parts = prefix.split('/', limit = 2)
        require('%' !in parts[0])
        val base = InetAddresses.parseNumericAddress(parts[0]).address
        val bits = if (parts.size == 1) base.size * 8 else parts[1].toInt()
        require(bits in 0..base.size * 8)
        return base.size == address.size && (0 until bits).all { index ->
            ((base[index / 8].toInt() xor address[index / 8].toInt()) and (128 ushr (index % 8))) == 0
        }
    }
    private fun destination(rule: JSONObject, q: LocalRouteQuery): Match {
        val hasDomain = hostKeys.any(rule::has)
        val prefixes = values(rule, "ip_cidr")
        if (!hasDomain && prefixes.isEmpty()) return Match.YES
        var result = Match.NO
        if (q.domain != null) {
            val host = q.domain
            if (host in values(rule, "domain") || values(rule, "domain_keyword").any(host::contains) ||
                values(rule, "domain_suffix").any { host == it || host.endsWith("." + it.removePrefix(".")) }) return Match.YES
            val patterns = values(rule, "domain_regex")
            if (patterns.size > 16) result = Match.UNKNOWN else for (pattern in patterns) {
                if (pattern.length !in 1..512) {
                    result = Match.UNKNOWN
                    continue
                }
                try {
                    if (Pattern.compile(pattern).matcher(host).find()) return Match.YES
                } catch (_: PatternSyntaxException) {
                    result = Match.UNKNOWN
                }
            }
        } else if (q.ip == null && hasDomain) result = Match.UNKNOWN
        if (prefixes.isNotEmpty()) {
            if (q.ip == null) result = Match.UNKNOWN else if (prefixes.any { contains(it, q.ip) }) return Match.YES
        }
        return result
    }
    private fun port(rule: JSONObject, value: Int?): Match {
        val singles = values(rule, "port")
        val ranges = values(rule, "port_range")
        if (singles.isEmpty() && ranges.isEmpty()) return Match.YES
        if (value == null) return Match.UNKNOWN
        return known(value.toString() in singles || ranges.any {
            val ends = it.split(':', limit = 2)
            require(ends.size == 2)
            value in ends[0].toInt()..ends[1].toInt()
        })
    }
    private fun matches(rule: JSONObject, q: LocalRouteQuery, dns: Boolean): Match {
        if (rule.keys().asSequence().any { it !in (if (dns) dnsKeys else routeKeys) }) return Match.UNKNOWN
        val host = destination(rule, q)
        if (dns) return minOf(host, listed(values(rule, "query_type"), q.dnsType))
        return minOf(host, listed(values(rule, "package_name"), q.application), listed(values(rule, "network"), q.network),
            port(rule, q.port))
    }
    private fun path(config: JSONObject, target: String): String {
        val nodes = mutableMapOf<String, JSONObject>()
        for (key in listOf("outbounds", "endpoints")) {
            val list = config.optJSONArray(key) ?: continue
            require(list.length() <= 512)
            for (i in 0 until list.length()) {
                val node = list.getJSONObject(i)
                val name = node.optString("tag")
                if (name.isNotEmpty()) require(nodes.put(name, node) == null)
            }
        }
        val hops = mutableListOf<String>()
        var current = target
        var dynamic = false
        while (current.isNotEmpty()) {
            if (!alias.matches(current) || current in hops || hops.size >= 16) return "цепочка не определена"
            val node = nodes[current] ?: return "цепочка не определена"
            hops.add(current)
            if (node.optString("type") in setOf("selector", "urltest", "syn443-adaptive")) dynamic = true
            current = node.optString("detour")
        }
        val order = hops.asReversed().joinToString(" → ")
        return if (dynamic) "$order · выбор участника зависит от состояния группы" else "$order · выход по конфигурации $target"
    }
    private fun choice(config: JSONObject, q: LocalRouteQuery, dns: Boolean, selected: (String) -> Unit = {}): String {
        if (dns && q.domain == null) return if (q.ip != null) "для IP-адреса не требуется" else "для проверки нужен домен"
        val section = config.optJSONObject(if (dns) "dns" else "route") ?: return "не задано"
        val rules = section.optJSONArray("rules") ?: JSONArray()
        require(rules.length() <= 256)
        var selection = section.optString("final")
        var source = "По умолчанию"
        for (i in 0 until rules.length()) {
            val rule = rules.getJSONObject(i)
            when (matches(rule, q, dns)) {
                Match.NO -> continue
                Match.UNKNOWN -> return "Правило №${i + 1} · недостаточно данных для решения"
                Match.YES -> {
                    source = "Правило №${i + 1}"
                    when (rule.optString("action", "route")) {
                        "route" -> selection = rule.optString(if (dns) "server" else "outbound")
                        "reject" -> return "$source · блокировка"
                        else -> return "$source · действие не определено"
                    }
                    break
                }
            }
        }
        if (!alias.matches(selection)) return "$source · назначение не определено"
        if (dns) return "$source · $selection"
        selected(selection)
        return "$source · " + path(config, selection)
    }
    fun describe(raw: String, q: LocalRouteQuery, selected: (String) -> Unit = {}): String {
        require(raw.length <= 1_048_576)
        val config = JSONObject(raw)
        return "Маршрут: " + choice(config, q, false, selected) + "\nDNS: " + choice(config, q, true)
    }
}
