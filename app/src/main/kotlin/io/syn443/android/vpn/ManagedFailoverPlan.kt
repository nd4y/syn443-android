package io.syn443.android.vpn

import android.net.InetAddresses
import io.syn443.decision.ExitClass
import org.json.JSONArray
import org.json.JSONObject

/** A first managed failover scope: one explicit internal route on Wi-Fi. */
internal data class ManagedFailoverPlan(val selector:String,val intent:ExitClass,val members:List<String>) {
    companion object {
        private val tag=Regex("[a-z0-9][a-z0-9._-]{0,63}")
        private fun rows(list:JSONArray)=(0 until list.length()).map(list::getJSONObject)
        private fun strings(list:JSONArray)=(0 until list.length()).map(list::getString)
        private val destinationFields = setOf("domain", "domain_suffix", "ip_cidr")
        private val scopedRuleFields = destinationFields + setOf(
            "type", "action", "outbound", "invert", "network", "package_name", "port", "port_range",
        )
        private val domainLabel = Regex("[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?")

        private fun values(rule: JSONObject, field: String): List<String> = when (val value = rule.opt(field)) {
            null -> emptyList()
            is String -> listOf(value)
            is JSONArray -> (0 until value.length()).map { value.get(it) as String }
            else -> error("invalid_failover_destination")
        }

        private fun explicitDestination(field: String, value: String): Boolean {
            if (field == "ip_cidr") {
                val address = value.substringBefore('/')
                val bits = value.substringAfter('/', "").toIntOrNull() ?: return false
                val maximum = if (':' in address) 128 else 32
                return bits in 1..maximum && '%' !in address && InetAddresses.isNumericAddress(address)
            }
            val host = if (field == "domain_suffix") value.removePrefix(".") else value
            return host.length in 1..253 && host.split('.').all(domainLabel::matches)
        }

        private fun JSONObject.rejectAliases(vararg fields: String) {
            require(keys().asSequence().none { key -> fields.any { it != key && it.equals(key, ignoreCase = true) } })
        }

        fun read(config:JSONObject):ManagedFailoverPlan? {
            if(!config.has("route_failover"))return null
            val plan=config.getJSONObject("route_failover")
            require(plan.keys().asSequence().toSet()==setOf("selector","network_mode","intent","members"))
            val declaredIntent=plan.getString("intent")
            require(plan.getString("network_mode")=="wifi" && declaredIntent=="INTERNAL")
            val intent=ExitClass.valueOf(declaredIntent)
            val selector=plan.getString("selector")
            val members=strings(plan.getJSONArray("members"))
            require(tag.matches(selector) && members.size in 2..8 && members.toSet().size==members.size &&
                members.all(tag::matches) && selector !in members)
            val outbounds=rows(config.getJSONArray("outbounds")).associateBy {it.getString("tag")}
            val group=outbounds.getValue(selector)
            require(group.getString("type")=="selector" && !group.optBoolean("interrupt_exist_connections") &&
                strings(group.getJSONArray("outbounds"))==members)
            for(outbound in outbounds.values) {
                outbound.rejectAliases("tag", "detour", "outbounds", "interrupt_exist_connections")
                require(outbound.optString("detour")!=selector &&
                    outbound.optJSONArray("outbounds")?.let {selector !in strings(it)}!=false)
            }
            val route=config.getJSONObject("route")
            route.rejectAliases("final", "rules")
            val final = route.getString("final")
            require(final in outbounds && final != selector)
            val matching = rows(route.getJSONArray("rules")).filter { rule ->
                rule.rejectAliases("outbound")
                rule.optString("outbound") == selector
            }
            val rule = matching.single()
            require(rule.keys().asSequence().all(scopedRuleFields::contains) &&
                rule.optString("type", "default") == "default" && rule.optString("action") == "route" &&
                (!rule.has("invert") || rule.opt("invert") == false))
            val destinations = destinationFields.flatMap { field -> values(rule, field).map { field to it } }
            require(destinations.isNotEmpty() && destinations.all { (field, value) -> explicitDestination(field, value) })
            config.optJSONObject("dns")?.let { dns ->
                dns.rejectAliases("servers")
                dns.optJSONArray("servers")?.let { servers ->
                    require(rows(servers).none { server ->
                        server.rejectAliases("detour", "outbound")
                        server.optString("detour") == selector || server.optString("outbound") == selector
                    })
                }
            }
            val probes=rows(config.getJSONArray("route_checks")).associateBy {it.getString("outbound")}
            val groupProbe=probes.getValue(selector)
            require(groupProbe.optBoolean("required"))
            fun checks(row:JSONObject)=rows(row.getJSONArray("checks")).map {it.getString("method") to it.getString("target")}
            val expected=checks(groupProbe)
            require(expected.none { (method, _) -> method == "https_exit_ip" })
            for(member in members) {
                val check=probes.getValue(member)
                require(!check.optBoolean("required") && checks(check)==expected)
                val visited=mutableSetOf<String>()
                var current=member
                while(current.isNotEmpty()) {
                    require(visited.size<4 && visited.add(current))
                    val hop=outbounds.getValue(current)
                    require(hop.getString("type") in setOf("http","socks","vless","ssh"))
                    current=hop.optString("detour")
                }
            }
            return ManagedFailoverPlan(selector,intent,members)
        }
    }
}
