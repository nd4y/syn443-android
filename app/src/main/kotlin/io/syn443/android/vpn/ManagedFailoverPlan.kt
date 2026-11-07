package io.syn443.android.vpn

import io.syn443.decision.ExitClass
import org.json.JSONArray
import org.json.JSONObject

/** A first managed failover scope: one explicit internal route on Wi-Fi. */
internal data class ManagedFailoverPlan(val selector:String,val intent:ExitClass,val members:List<String>) {
    companion object {
        private val tag=Regex("[a-z0-9][a-z0-9._-]{0,63}")
        private fun rows(list:JSONArray)=(0 until list.length()).map(list::getJSONObject)
        private fun strings(list:JSONArray)=(0 until list.length()).map(list::getString)
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
                require(outbound.optString("detour")!=selector &&
                    outbound.optJSONArray("outbounds")?.let {selector !in strings(it)}!=false)
            }
            val route=config.getJSONObject("route")
            require(route.getString("final")!=selector)
            val matching=rows(route.getJSONArray("rules")).filter {it.optString("outbound")==selector}
            require(matching.size==1 && matching.single().let {
                it.optString("action")=="route" && listOf("domain","domain_suffix","ip_cidr").any {field->
                    when(val value=it.opt(field)) {
                        is String -> value.isNotEmpty()
                        is JSONArray -> value.length()>0 && strings(value).all(String::isNotEmpty)
                        else -> false
                    }
                } &&
                    !it.has("domain_keyword") && !it.has("domain_regex")
            })
            require(config.optJSONObject("dns")?.optJSONArray("servers")?.let {dns->
                rows(dns).none {it.optString("detour")==selector}
            }!=false)
            val probes=rows(config.getJSONArray("route_checks")).associateBy {it.getString("outbound")}
            val groupProbe=probes.getValue(selector)
            require(groupProbe.optBoolean("required"))
            fun checks(row:JSONObject)=rows(row.getJSONArray("checks")).map {it.getString("method") to it.getString("target")}
            val expected=checks(groupProbe)
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
