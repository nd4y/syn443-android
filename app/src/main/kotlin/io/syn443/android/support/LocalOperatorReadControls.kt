package io.syn443.android.support

import android.os.SystemClock
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.platform.LocalContext
import androidx.core.net.toUri
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.LifecycleOwner
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.json.JSONObject

@Composable
internal fun LocalOperatorReadControls() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val updates = remember { Mutex() }
    val lifecycle = (context as? LifecycleOwner)?.lifecycle
    var deadline by remember { mutableLongStateOf(0L) }
    var loaded by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf("") }
    suspend fun refresh(action: String) = updates.withLock {
        busy = true
        try {
            val started = SystemClock.elapsedRealtime()
            val remaining = withContext(Dispatchers.IO) {
                val reply = checkNotNull(context.contentResolver.call("content://io.syn443.control".toUri(),
                    "operator-read-access", action, null))
                check(reply.getBoolean("ok"))
                JSONObject(checkNotNull(reply.getString("json"))).getLong("remainingMs").also { require(it in 0..900_000L) }
            }
            deadline = if (remaining > 0) started + remaining else 0
            loaded = true
            message = ""
        } catch (e: CancellationException) { throw e }
        catch (_: Exception) {
            deadline = 0
            loaded = false
            message = "Не удалось проверить доступ."
        } finally { busy = false }
    }
    DisposableEffect(lifecycle) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME) scope.launch { refresh("inspect") }
        }
        if (lifecycle == null) scope.launch { refresh("inspect") } else lifecycle.addObserver(observer)
        onDispose { lifecycle?.removeObserver(observer) }
    }
    LaunchedEffect(deadline) {
        if (deadline > 0) {
            delay((deadline - SystemClock.elapsedRealtime()).coerceAtLeast(0))
            refresh("inspect")
        }
    }
    Text("Чтение через ADB")
    Text("Компьютер с разрешённой отладкой сможет прочитать состояние VPN и каждого маршрута, способ подключения NetBird и очищенные технические события.")
    if (deadline > 0) Text("Доступ разрешён на ограниченное время.")
    if (message.isNotEmpty()) Text(message)
    OutlinedButton(enabled = !busy, onClick = {
        val action = if (!loaded) "inspect" else if (deadline > 0) "revoke" else "grant"
        scope.launch { refresh(action) }
    }) { Text(if (!loaded) "Проверить доступ" else if (deadline > 0) "Отозвать доступ" else "Разрешить на 15 минут") }
}
