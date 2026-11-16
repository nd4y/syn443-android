package io.syn443.android

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createComposeRule
import io.syn443.android.admin.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test

/** Pure presentation/decoder fixtures. No controller, account, keys, device
 * identity, browser, server, VPN state or settings are mutated by these cases. */
class AdminNativeUiTest {
    @get:Rule val compose=createComposeRule()
    private val signedOut=AdminUiStatus(7,AdminUiPhase.SIGNED_OUT)
    private val authenticated=AdminUiStatus(8,AdminUiPhase.AUTHENTICATED)
    private fun scroll(tag:String)=compose.onNodeWithTag("admin-content").performScrollToNode(hasTestTag(tag))

    @Test fun signedOutOffersSeparateAdminLoginAndFullPanelWithoutVpnActions() {
        val commands=mutableListOf<String>()
        compose.setContent {MaterialTheme(colorScheme=darkColorScheme()) {
            AdminScreen(AdminUiModel(status=signedOut),AdminUiActions(login={commands+="login"},web={commands+="web"}))
        }}
        compose.onNodeWithTag("admin-title").assertTextEquals("Администрирование")
        compose.onNodeWithTag("admin-login").assertIsEnabled().performClick()
        compose.onNodeWithTag("admin-full-web").performClick()
        compose.onNodeWithTag("vpn-connect").assertDoesNotExist()
        compose.onNodeWithTag("vpn-disconnect").assertDoesNotExist()
        compose.runOnIdle {assertEquals(listOf("login","web"),commands)}
    }
    @Test fun authorizedPageUsesExplicitNextCursorAndReadOnlyDeviceSelection() {
        val selected=mutableListOf<String>();val pages=mutableListOf<String>()
        val rows=(0 until 32).map {AdminDeviceRow("device-%02d".format(it),2,3,"Получен отчёт о применении")}
        val model=AdminUiModel(status=authenticated,page=AdminDevicesPage(rows,"device-31",1000))
        compose.setContent {MaterialTheme(colorScheme=darkColorScheme()) {
            AdminScreen(model,AdminUiActions(select={selected+=it},page={pages+=it}))
        }}
        scroll("admin-device-device-00")
        compose.onNodeWithTag("admin-device-device-00").performClick()
        scroll("admin-devices-next")
        compose.onNodeWithTag("admin-devices-next").performClick()
        compose.onNodeWithTag("admin-devices-first").assertDoesNotExist()
        compose.onNodeWithText("Подключено").assertDoesNotExist()
        compose.runOnIdle {assertEquals(listOf("device-00"),selected);assertEquals(listOf("device-31"),pages)}
    }
    @Test fun configurationAndStaleRuntimeStayReadOnlyCollapsedAndExplicitlyLastReported() {
        val state=mutableStateOf(AdminUiModel(status=authenticated,
            page=AdminDevicesPage(listOf(AdminDeviceRow("device-a",2,3,"Исторический отчёт о применении")),"",1000),
            selected="device-a",configuration=AdminDocument(listOf("synthetic configuration text"),"Конфигурация сервера. Применение политики не подтверждает текущее соединение."),
            runtime=AdminDocument(listOf("synthetic runtime text"),"Последний отчёт устройства устарел. Текущее состояние неизвестно.")))
        compose.setContent {MaterialTheme(colorScheme=darkColorScheme()) {
            AdminScreen(state.value,AdminUiActions(
                toggleConfiguration={state.value=state.value.copy(showConfiguration=!state.value.showConfiguration)},
                toggleRuntime={state.value=state.value.copy(showRuntime=!state.value.showRuntime)}))
        }}
        compose.onNodeWithText("synthetic configuration text").assertDoesNotExist()
        compose.onNodeWithText("synthetic runtime text").assertDoesNotExist()
        scroll("admin-config-toggle");compose.onNodeWithTag("admin-config-toggle").performClick()
        scroll("admin-config-chunk-0");compose.onNodeWithTag("admin-config-chunk-0").assertTextEquals("synthetic configuration text")
        scroll("admin-runtime-summary");compose.onNodeWithTag("admin-runtime-summary").assertTextContains("устарел")
        scroll("admin-runtime-toggle");compose.onNodeWithTag("admin-runtime-toggle").performClick()
        scroll("admin-runtime-chunk-0");compose.onNodeWithTag("admin-runtime-chunk-0").assertTextEquals("synthetic runtime text")
        compose.onNodeWithText("Подключено").assertDoesNotExist()
        compose.onNodeWithText("Опубликовать").assertDoesNotExist()
        compose.onNodeWithText("Сохранить").assertDoesNotExist()
    }
    @Test fun busyReadBlocksAnotherReadButLeavesAdministrativeLogoutAvailable() {
        var logout=0
        val model=mutableStateOf(AdminUiModel(status=authenticated,working=true,
            page=AdminDevicesPage(listOf(AdminDeviceRow("device-a",1,1,"Ожидается отчёт о применении")),"",1000),selected="device-a"))
        compose.setContent {MaterialTheme(colorScheme=darkColorScheme()) {AdminScreen(model.value,AdminUiActions(logout={logout++}))}}
        compose.onNodeWithTag("admin-refresh").assertIsNotEnabled()
        scroll("admin-device-device-a");compose.onNodeWithTag("admin-device-device-a").assertIsNotEnabled()
        scroll("admin-runtime-unknown");compose.onNodeWithTag("admin-runtime-unknown").assertTextContains("неизвестно")
        scroll("admin-logout");compose.onNodeWithTag("admin-logout").assertIsEnabled().performClick()
        compose.runOnIdle {assertEquals(1,logout)}
        compose.runOnIdle {model.value=model.value.copy(working=false,status=authenticated.copy(busy=true))}
        scroll("admin-refresh");compose.onNodeWithTag("admin-refresh").assertIsEnabled()
        scroll("admin-device-device-a");compose.onNodeWithTag("admin-device-device-a").assertIsNotEnabled()
    }
    @Test fun unknownErrorsRenderFiniteRussianTextWithoutRawControllerReason() {
        val reason="synthetic-private-error-value"
        assertEquals(adminErrorText("TRANSPORT"),adminErrorText("transport"))
        assertEquals("REAUTHENTICATE",AdminUiFailure("reauthenticate").code)
        compose.setContent {MaterialTheme(colorScheme=darkColorScheme()) {
            AdminScreen(AdminUiModel(status=AdminUiStatus(8,AdminUiPhase.UNAVAILABLE,reason=reason)),AdminUiActions())
        }}
        compose.onNodeWithTag("admin-reason").assertTextEquals("Данные временно недоступны. Обновите состояние и повторите попытку.")
        compose.onNodeWithText(reason).assertDoesNotExist()
        compose.onNodeWithTag("admin-login").assertDoesNotExist()
        compose.onNodeWithTag("admin-refresh").assertIsEnabled()
    }
    @Test fun documentDecoderBoundsUtf8AndSplitsFullTextOffMainWithoutBreakingSurrogates():Unit=runBlocking(Dispatchers.IO) {
        val prefix="{\"device\":\"device-a\",\"data\":\"";val suffix="\"}"
        val nearBoundary=prefix+"x".repeat(2047-prefix.length)+"\uD83D\uDE00"+"tail"+suffix
        val unicode=AdminWire.document(nearBoundary.toByteArray(),AdminReadAction.CONFIGURATION,"device-a")
        assertEquals(nearBoundary,unicode.chunks.joinToString(""))
        assertTrue(unicode.chunks.all {it.length<=2048 && !it.last().isHighSurrogate() && !it.first().isLowSurrogate()})
        val full=prefix+"x".repeat(AdminWire.MAX_BODY-prefix.length-suffix.length)+suffix
        val document=AdminWire.document(full.toByteArray(),AdminReadAction.CONFIGURATION,"device-a")
        assertEquals(AdminWire.MAX_BODY,full.toByteArray().size);assertEquals(full,document.chunks.joinToString(""))
        assertTrue(document.chunks.size<=512)
        assertEquals("AdminDocument([redacted])",document.toString())
        assertThrows(IllegalArgumentException::class.java) {AdminWire.document(ByteArray(AdminWire.MAX_BODY+1),AdminReadAction.CONFIGURATION,"device-a")}
        assertThrows(Exception::class.java) {AdminWire.document(byteArrayOf(0xc3.toByte(),0x28),AdminReadAction.RUNTIME,"device-a")}
        assertThrows(IllegalArgumentException::class.java) {AdminWire.document("{\"device\":\"foreign\"}".toByteArray(),AdminReadAction.CONFIGURATION,"device-a")}
    }
    @Test fun devicePageDecoderKeepsThirtyTwoRowBoundOrderingAndCursor():Unit=runBlocking(Dispatchers.IO) {
        fun page(count:Int,next:String):ByteArray {
            val rows=JSONArray()
            repeat(count) {index->rows.put(JSONObject().put("device","device-%02d".format(index)).put("policyRevision",1)
                .put("desiredRevision",2).put("report",JSONObject().put("state","reported")))}
            return JSONObject().put("devices",rows).put("next",next).put("observedAtMs",1000).toString().toByteArray()
        }
        val accepted=AdminWire.page(page(32,"device-31"),"")
        assertEquals(32,accepted.devices.size);assertEquals("device-31",accepted.next)
        assertTrue(accepted.devices.all {it.report=="Получен отчёт о применении"})
        assertThrows(IllegalArgumentException::class.java) {AdminWire.page(page(33,"device-32"),"")}
        assertThrows(IllegalArgumentException::class.java) {AdminWire.page(page(31,"device-30"),"")}
        assertThrows(IllegalArgumentException::class.java) {AdminWire.page(page(32,"foreign"),"")}
        assertThrows(IllegalArgumentException::class.java) {AdminWire.page(page(1,""),"device-00")}
    }
}
