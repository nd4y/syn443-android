package io.syn443.android.update

import io.syn443.android.Syn443Theme
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.lifecycleScope
import io.syn443.android.BuildConfig
import io.syn443.identity.BootstrapTrust
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.runInterruptible
import java.util.concurrent.atomic.AtomicReference

internal class UpdateModel : ViewModel() {
    var channel by mutableStateOf<String?>(null)
    var offer by mutableStateOf<UpdateOffer?>(null)
    var staged by mutableStateOf<StagedUpdate?>(null)
    var busy by mutableStateOf(false)
    var handed by mutableStateOf(false)
    var message by mutableStateOf("")
    fun clear() {
        if (!handed) staged?.close()
        staged = null
        offer = null
    }
    override fun onCleared() { clear() }
}

class UpdateActivity : ComponentActivity() {
    private val model by lazy { ViewModelProvider(this)[UpdateModel::class.java] }
    private val verifier by lazy { VerifiedUpdate(applicationContext) }
    private val selectEnvelope = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) request {
            model.clear()
            model.offer = runInterruptible(Dispatchers.IO) { verifier.preview(verifier.readEnvelope(uri)) }
            model.message = ""
        }
    }
    private val selectApk = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        val offer = model.offer
        if (uri != null && offer != null) request {
            model.staged?.close()
            model.staged = null
            val pending = AtomicReference<StagedUpdate?>()
            try {
                val candidate = runInterruptible(Dispatchers.IO) { verifier.stage(offer, uri).also(pending::set) }
                model.staged = candidate
                pending.set(null)
                model.message = "Подпись, версия и содержимое APK проверены."
            } finally {
                pending.getAndSet(null)?.close()
            }
        }
    }
    private val openInstaller = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        model.handed = false
        model.clear()
        model.message = "Окно установки закрыто."
    }
    private val allowSource = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        model.message = if (packageManager.canRequestPackageInstalls()) "Можно перейти к установке."
                        else "Установка из SYN443 требует разрешения Android."
    }

    private fun request(operation: suspend () -> Unit) {
        if (model.busy || model.handed) return
        model.busy = true
        lifecycleScope.launch {
            try {
                operation()
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
                model.message = "Обновление не принято. Проверьте файл, вход в SYN443 и действующую политику."
            } finally {
                model.busy = false
            }
        }
    }

    private fun install(update: StagedUpdate) = request {
        if (!packageManager.canRequestPackageInstalls()) {
            allowSource.launch(Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.fromParts("package", packageName, null)))
            return@request
        }
        val intent = runInterruptible(Dispatchers.IO) { verifier.installer(update) }
        if (!lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED) || model.staged !== update) return@request
        openInstaller.launch(intent)
        model.handed = true
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        lifecycleScope.launch {
            model.channel = runInterruptible(Dispatchers.IO) {
                verifier.pruneAbandoned()
                runCatching { BootstrapTrust.installationProfile(BuildConfig.INSTALLATION_PROFILE).releaseAuthority?.channel }.getOrNull()
            }
        }
        setContent {
            Syn443Theme {
                Surface(Modifier.fillMaxSize()) {
                    Column(Modifier.fillMaxSize().safeDrawingPadding().verticalScroll(rememberScrollState()).padding(24.dp),
                           verticalArrangement = Arrangement.spacedBy(12.dp)) {
                        Text("Обновление приложения", style = MaterialTheme.typography.headlineSmall)
                        Text("Установлена версия " + BuildConfig.VERSION_NAME)
                        val channel = model.channel
                        if (channel == null) Text("В этой сборке канал обновлений не настроен.")
                        else {
                            Text("Канал " + channel)
                            val enabled = !model.busy && !model.handed
                            OutlinedButton(enabled = enabled, onClick = { selectEnvelope.launch(arrayOf("*/*")) }) {
                                Text("Выбрать манифест обновления")
                            }
                            model.offer?.let { offer ->
                                Text("К установке доступна сборка " + offer.release.apk.versionCode)
                                OutlinedButton(enabled = enabled, onClick = { selectApk.launch(arrayOf("*/*")) }) {
                                    Text("Выбрать APK")
                                }
                            }
                            model.staged?.let { update ->
                                Button(enabled = enabled, onClick = { install(update) }) { Text("Перейти к установке") }
                            }
                        }
                        if (model.busy) LinearProgressIndicator()
                        if (model.message.isNotEmpty()) Text(model.message)
                        TextButton(onClick = { finish() }) { Text("Закрыть") }
                    }
                }
            }
        }
    }
}
