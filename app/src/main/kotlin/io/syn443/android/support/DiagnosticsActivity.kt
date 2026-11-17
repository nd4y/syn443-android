package io.syn443.android.support

import android.os.Bundle
import android.net.Uri
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.core.net.toUri
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.json.JSONObject

class DiagnosticsActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { MaterialTheme(colorScheme = darkColorScheme()) { Surface(Modifier.fillMaxSize()) { DiagnosticsRoute() } } }
    }
}

@Composable
internal fun DiagnosticsRoute(
    rpc: (suspend (String, String?) -> JSONObject)? = null,
    exporter: (suspend (String, Uri, String, Int) -> Unit)? = null,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var bundleId by rememberSaveable { mutableStateOf("") }
    var state by remember { mutableStateOf(JSONObject().put("state", "idle")) }
    var busy by remember { mutableStateOf(false) }
    var cancelling by remember { mutableStateOf(false) }
    var uiEpoch by remember { mutableLongStateOf(0L) }
    var message by remember { mutableStateOf("") }
    var pendingExportId by rememberSaveable { mutableStateOf("") }
    var pendingExportHash by rememberSaveable { mutableStateOf("") }
    var pendingExportBytes by rememberSaveable { mutableIntStateOf(0) }
    var pendingExportDestination by rememberSaveable { mutableStateOf("") }
    val invoke: suspend (String, String?) -> JSONObject = rpc ?: { method, argument -> SupportBundleClient.call(context, method, argument) }
    fun operation(block: suspend () -> Unit) {
        if (busy || pendingExportId.isNotEmpty()) return
        busy = true; message = ""
        scope.launch {
            try { block() }
            catch (cancelled: CancellationException) { throw cancelled }
            catch (_: Exception) { message = "Операция не завершена. Можно обновить состояние." }
            finally { busy = false }
        }
    }
    LaunchedEffect(Unit) {
        if (bundleId.matches(Regex("[a-f0-9]{32}"))) {
            busy = true
            try { state = invoke("bundle-status", bundleId) }
            catch (cancelled: CancellationException) { throw cancelled }
            catch (_: Exception) { message = "Состояние недоступно" }
            finally { busy = false }
        }
    }
    val destination = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/zip")) { uri ->
        if (uri != null) pendingExportDestination = uri.toString()
        else {
            pendingExportId = ""; pendingExportHash = ""; pendingExportBytes = 0; pendingExportDestination = ""
        }
    }
    // A result can arrive while a restored status read still owns the UI slot.
    // Keep the reviewed request until export is actually admitted, rather than
    // clearing it and losing the user's selected document when operation is busy.
    LaunchedEffect(pendingExportDestination, busy) {
        if (pendingExportDestination.isEmpty() || pendingExportId.isEmpty() || busy) return@LaunchedEffect
        val target = pendingExportDestination.toUri()
        val reviewedId = pendingExportId
        val reviewedHash = pendingExportHash
        val reviewedBytes = pendingExportBytes
        pendingExportId = ""; pendingExportHash = ""; pendingExportBytes = 0; pendingExportDestination = ""
        operation {
            if (exporter != null) exporter(reviewedId, target, reviewedHash, reviewedBytes)
            else SupportBundleClient.export(context, reviewedId, target, reviewedHash, reviewedBytes)
            message = "Файл сохранён. В SYN443 не отправлен."
        }
    }
    Column(Modifier.fillMaxSize().safeDrawingPadding().verticalScroll(rememberScrollState()).padding(20.dp)) {
        DiagnosticBundleControls(state, busy || pendingExportId.isNotEmpty(), message,
            collect = { operation {
                val epoch = ++uiEpoch
                val started = invoke("bundle-collect", null)
                if (epoch != uiEpoch) return@operation
                val id = started.opt("id") as? String ?: error("invalid_bundle_reply")
                require(id.matches(Regex("[a-f0-9]{32}")))
                require(started.optString("state") in setOf("collecting", "busy", "ready"))
                // Admission may already say ready, but carries no manifest.
                // Always obtain actual metadata before offering an export.
                bundleId = id; state = JSONObject().put("state", "collecting").put("id", id)
                var attempts = 0
                while (state.optString("state") in setOf("collecting", "busy") && attempts < 64) {
                    if (attempts++ > 0) delay(500)
                    val next = invoke("bundle-status", id)
                    if (epoch != uiEpoch) return@operation
                    require(next.optString("id") == id)
                    state = next
                }
            } },
            refresh = { operation {
                val epoch = uiEpoch
                val next = invoke("bundle-status", bundleId)
                if (epoch == uiEpoch) state = next
            } },
            cancel = {
                if (!cancelling && bundleId.matches(Regex("[a-f0-9]{32}"))) {
                    val captured = bundleId
                    ++uiEpoch
                    cancelling = true
                    scope.launch {
                        try {
                            val next = invoke("bundle-cancel", captured)
                            if (bundleId == captured) state = next
                        } catch (cancelled: CancellationException) { throw cancelled }
                        catch (_: Exception) { message = "Отмена не подтверждена. Обновите состояние." }
                        finally { cancelling = false }
                    }
                }
            },
            export = {
                if (!busy && pendingExportId.isEmpty() && validBundlePreview(state) && state.optString("id") == bundleId) {
                    pendingExportId = bundleId
                    pendingExportHash = state.getString("sha256")
                    pendingExportBytes = state.getInt("bytes")
                    try { destination.launch("syn443-support.zip") }
                    catch (_: Exception) {
                        pendingExportId = ""; pendingExportHash = ""; pendingExportBytes = 0; pendingExportDestination = ""
                        message = "Не удалось открыть выбор файла"
                    }
                }
            },
            cancelling = cancelling,
        )
    }
}
