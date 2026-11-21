package io.syn443.android

import androidx.compose.material3.MaterialTheme
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
import kotlinx.coroutines.CompletableDeferred
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

    @Test fun onlyExplicitRequestsRunAndEditedOrDismissedInputsLeaveNoResult() {
        val release = CompletableDeferred<Unit>()
        var calls = 0
        compose.setContent {
            MaterialTheme {
                ManualRouteControl {
                    calls++
                    if (calls == 1) release.await()
                    "DNS: system"
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
