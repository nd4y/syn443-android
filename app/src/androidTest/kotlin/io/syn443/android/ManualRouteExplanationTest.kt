package io.syn443.android

import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.assertTextContains
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextReplacement
import io.syn443.android.vpn.LocalRouteExplanation
import io.syn443.android.vpn.LocalRouteQuery
import io.syn443.android.vpn.ManualRouteControl
import io.syn443.android.vpn.ManualRouteAnswer
import io.syn443.android.vpn.RouteSnapshot
import io.syn443.android.vpn.AdaptiveSearchState
import io.syn443.recovery.RouteScope
import io.syn443.policy.Policy
import kotlinx.coroutines.CompletableDeferred
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test

class ManualRouteExplanationTest {
    @get:Rule val compose = createComposeRule()

    private val config = """{
        "route":{"final":"direct","rules":[
          {"package_name":["org.example.client"],"domain_suffix":[".example.invalid"],"ip_cidr":["2001:db8::/48"],
           "port":[443],"port_range":["8000:8100"],"network":["tcp"],"outbound":"exit"},
          {"domain_regex":["^api[0-9]+[.]test$"],"action":"reject"}
        ]},
        "dns":{"final":"system","rules":[{"domain_suffix":["example.invalid"],"query_type":["AAAA"],"server":"internal"}]},
        "outbounds":[{"type":"direct","tag":"direct"},{"type":"http","tag":"entry"},
          {"type":"vless","tag":"exit","detour":"entry","server":"hidden.example.invalid"}]
    }"""

    private fun check(raw: String, vararg pairs: Pair<String, String>): String {
        val query = JSONObject().apply { pairs.forEach { (k,v) -> put(k,v) } }
        return LocalRouteExplanation.describe(raw, LocalRouteQuery.parse(query.toString()))
    }

    @Test fun explainsCompiledPathAndDnsWithoutReturningTheTarget() {
        val name = "Abc.Example.Invalid."
        val facts = arrayOf("application" to "org.example.client", "port" to "8050", "network" to "TCP", "dnsType" to "AAAA")
        val answer = check(config, "domain" to name, *facts)
        assertTrue(answer.contains("Правило №1 · entry → exit · выход по конфигурации exit"))
        assertTrue(answer.contains("DNS: Правило №1 · internal"))
        assertFalse(answer.contains("example", ignoreCase = true))
        val apex = check(config, "domain" to "example.invalid", "address" to "192.0.2.2", *facts)
        assertTrue(apex.contains("По умолчанию · direct"))
        assertTrue(apex.contains("Правило №1 · internal"))
        val regex = check(config, "domain" to "api42.test", "application" to "org.example.other")
        assertTrue(regex.contains("Правило №2 · блокировка"))
    }

    @Test fun unknownPredicatesNeverClaimAFinalAndLiteralsUseNoDns() {
        val missing = check(config, "application" to "org.example.client")
        assertTrue(missing.contains("Правило №1 · недостаточно данных"))
        assertFalse(missing.contains("По умолчанию"))
        val literal = check(config, "address" to "2001:db8::123", "application" to "org.example.client",
            "port" to "443", "network" to "tcp")
        assertTrue(literal.contains("entry → exit"))
        assertTrue(literal.contains("для IP-адреса не требуется"))
        val unknown = check("""{"route":{"rules":[{"rule_set":["dynamic"],"outbound":"work"}],"final":"direct"}}""", "domain" to "host.test")
        assertTrue(unknown.contains("Правило №1 · недостаточно данных"))
        val dynamic = check("""{"route":{"final":"group"},"outbounds":[{"type":"selector","tag":"group","default":"proxy"}]}""", "domain" to "host.test")
        assertTrue(dynamic.contains("зависит от состояния группы"))
        assertFalse(dynamic.contains("proxy"))
        assertTrue(runCatching { LocalRouteQuery.parse("""{"address":"do-not-resolve.invalid"}""") }.isFailure)
    }

    @Test fun selectedProxyMeasurementRequiresSuccessfulCurrentOwnerAndConfig() {
        val raw = """{"outbounds":[{"tag":"pool","type":"selector","outbounds":["exit"]},{"tag":"exit","type":"vless","detour":"entry"},{"tag":"entry","type":"http"}],"route":{"final":"pool"},"route_checks":[{"outbound":"pool","checks":[{"method":"tcp","target":"192.0.2.1:443"}]}]}"""
        val revision = Policy.hash(raw)
        val scope = RouteScope(12, 7, 2, "fixture-one", revision)
        val status = JSONObject().put("generation",12).put("networkEpoch",7).put("desiredOn",true).put("engineActive",true).put("configRevision",revision)
        var selected: String? = null
        val query = LocalRouteQuery.parse("""{"domain":"private.example.invalid"}""")
        val description = LocalRouteExplanation.describe(raw, query) { selected = it }
        val answer = ManualRouteAnswer(description, selected, revision)
        assertEquals("pool", selected)
        RouteSnapshot.owner(null)
        RouteSnapshot.configure(raw, revision)
        RouteSnapshot.owner(scope)
        try {
            assertNull(answer.measurement(RouteSnapshot.view(status)))
            val request = JSONObject(checkNotNull(RouteSnapshot.request(scope, force=true)))
            val row = JSONObject().put("id","route-1").put("complete",true).put("ok",true).put("code","ok")
                .put("elapsedMs",10).put("sampledElapsedMs",android.os.SystemClock.elapsedRealtime())
                .put("path", JSONArray(listOf("route-1","route-2","route-3")))
            val report = JSONObject().put("request",request.getString("request")).put("running",false).put("results",JSONArray().put(row))
            assertTrue(RouteSnapshot.update(scope,report.toString()))
            val measured = checkNotNull(answer.measurement(RouteSnapshot.view(status)))
            assertTrue(measured.contains("entry → exit · узел выхода exit"))
            assertFalse(measured.contains("private.example.invalid"))
            for ((field, value) in listOf("configRevision" to "retired", "engineActive" to false,
                "desiredOn" to false, "generation" to 13, "networkEpoch" to 8)) {
                assertNull(answer.measurement(RouteSnapshot.view(JSONObject(status.toString()).put(field,value))))
            }
            val retry = JSONObject(checkNotNull(RouteSnapshot.request(scope, force=true)))
            assertNull(answer.measurement(RouteSnapshot.view(status)))
            row.put("ok",false).put("code","dial_failed")
            assertTrue(RouteSnapshot.update(scope,report.put("request",retry.getString("request")).toString()))
            assertNull(answer.measurement(RouteSnapshot.view(status)))
        } finally {
            RouteSnapshot.owner(null)
        }
    }

    @Test fun adaptiveExplanationNeedsCommittedPathAndUsesEntryToExitGraphOrder() {
        val raw = """{"outbounds":[{"tag":"managed","type":"syn443-adaptive"}],"route":{"final":"managed"}}"""
        val revision = Policy.hash(raw)
        val scope = RouteScope(20, 11, 3, "fixture-two", revision)
        val status = JSONObject().put("generation",20).put("networkEpoch",11).put("desiredOn",true).put("engineActive",true).put("configRevision",revision)
        val answer = ManualRouteAnswer("Маршрут", "managed", revision)
        RouteSnapshot.owner(null)
        RouteSnapshot.configure(raw, revision)
        RouteSnapshot.owner(scope)
        try {
            RouteSnapshot.adaptive(scope,"managed",true,"ok",16,listOf("first","last"))
            assertNull(answer.measurement(RouteSnapshot.view(status)))
            RouteSnapshot.adaptiveSearch(scope,mapOf("managed" to AdaptiveSearchState.VERIFIED))
            assertTrue(checkNotNull(answer.measurement(RouteSnapshot.view(status))).contains("first → last · узел выхода last"))
            RouteSnapshot.adaptiveSearch(scope,mapOf("managed" to AdaptiveSearchState.SEARCH_INCOMPLETE))
            assertNull(answer.measurement(RouteSnapshot.view(status)))
        } finally {
            RouteSnapshot.owner(null)
        }
    }

    @Test fun openFormRetiresRuntimeEvidenceWithoutResendingTheEnteredTarget() {
        fun health(state: String) = JSONObject().put("measurementRevision","test-revision").put("routes",JSONArray().put(
            JSONObject().put("label","proxy").put("id","route-1").put("type","ssh").put("state",state)
                .put("reason","ok").put("measuredPath",JSONArray(listOf("route-1")))))
        val latest = mutableStateOf(health("working"))
        var calls = 0
        compose.setContent { MaterialTheme {
            ManualRouteControl(latest.value) {
                calls++
                ManualRouteAnswer("По умолчанию · proxy","proxy","test-revision")
            }
        } }
        compose.onNodeWithTag("manual-route-open").performClick()
        compose.onNodeWithTag("manual-route-domain").performScrollTo().performTextReplacement("private.example.invalid")
        compose.onNodeWithTag("manual-route-measurement").assertDoesNotExist()
        compose.onNodeWithTag("manual-route-run").performScrollTo().performClick()
        val detail = compose.onNodeWithTag("manual-route-measurement")
        detail.assertTextContains("узел выхода proxy",substring=true)
        compose.runOnIdle { latest.value = health("stale") }
        detail.assertTextContains("нет свежего",substring=true)
        compose.runOnIdle { assertEquals(1,calls) }
    }

    @Test fun onlyExplicitRequestsRunAndEditedOrDismissedInputsLeaveNoResult() {
        val release = CompletableDeferred<Unit>()
        var calls = 0
        compose.setContent {
            MaterialTheme {
                ManualRouteControl {
                    calls++
                    if (calls == 1) release.await()
                    ManualRouteAnswer("DNS: system")
                }
            }
        }
        val open = compose.onNodeWithTag("manual-route-open")
        val domain = compose.onNodeWithTag("manual-route-domain")
        val run = compose.onNodeWithTag("manual-route-run")
        val result = compose.onNodeWithTag("manual-route-result")
        open.performClick()
        run.performScrollTo().assertIsNotEnabled()
        domain.performScrollTo().performTextReplacement("one.invalid")
        compose.runOnIdle { assertEquals(0,calls) }
        run.performScrollTo().performClick()
        compose.runOnIdle { assertEquals(1,calls) }
        domain.performScrollTo().performTextReplacement("two.invalid")
        compose.runOnIdle { release.complete(Unit) }
        result.assertDoesNotExist()
        run.performScrollTo().performClick()
        result.assertTextContains("DNS: system")
        compose.onNodeWithText("Закрыть").performClick()
        open.performClick()
        run.performScrollTo().assertIsNotEnabled()
        result.assertDoesNotExist()
        compose.runOnIdle { assertEquals(2,calls) }
    }
}
