package io.syn443.android

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.material3.Button
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.MultiFormatReader
import com.google.zxing.ReaderException
import com.google.zxing.Result
import com.google.zxing.qrcode.QRCodeReader
import com.journeyapps.barcodescanner.BarcodeView
import com.journeyapps.barcodescanner.CameraPreview
import com.journeyapps.barcodescanner.DecoderFactory
import com.journeyapps.barcodescanner.MixedDecoder
import io.syn443.identity.BootstrapTrust

internal fun scannedInvitation(text: String?): String? {
    if (text == null || text.length > BootstrapTrust.MAX_LINK) return null
    return text.takeIf { runCatching { BootstrapTrust.parse(it) }.isSuccess }
}

internal fun invitationQrDecoder() = DecoderFactory { baseHints ->
    val detector = MultiFormatReader().apply {
        setHints(baseHints + mapOf(
            DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE),
            DecodeHintType.TRY_HARDER to true
        ))
    }
    object : MixedDecoder(detector) {
        private val cleanReader = QRCodeReader()
        private val cleanHints = mapOf(DecodeHintType.PURE_BARCODE to true)

        override fun decode(bitmap: BinaryBitmap): Result? {
            super.decode(bitmap)?.let { return it }
            // Reuse the same cropped, binarized frame and its current polarity.
            // A flat QR can still be sampled when the finder detector misses it.
            return try {
                cleanReader.decode(bitmap, cleanHints)
            } catch (_: ReaderException) {
                null
            }
        }
    }
}

class InvitationScannerActivity : ComponentActivity() {
    companion object {
        const val EXTRA_LINK = "io.syn443.android.scanned_invitation"
    }

    private lateinit var camera: BarcodeView
    private var foreground = false
    private var scanning = false
    private var hint by mutableStateOf("Наведите камеру на QR-код приглашения.")
    private val permission = registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        if (granted) startIfReady() else finish()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setResult(RESULT_CANCELED)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        camera = BarcodeView(this).apply {
            decoderFactory = invitationQrDecoder()
            addStateListener(object : CameraPreview.StateListener {
                override fun cameraError(error: Exception) {
                    if (scanning && !isFinishing) finish()
                }
                override fun previewSized() = Unit
                override fun previewStarted() = Unit
                override fun previewStopped() = Unit
                override fun cameraClosed() = Unit
            })
        }
        setContent {
            Syn443Theme {
                Surface(Modifier.fillMaxSize()) {
                    Column(Modifier.safeDrawingPadding().padding(16.dp)) {
                        Text(hint, Modifier.padding(bottom = 12.dp))
                        AndroidView(factory = { camera }, modifier = Modifier.weight(1f).fillMaxWidth())
                        Button(onClick = { finish() }) { Text("Отмена") }
                    }
                }
            }
        }
        if (savedInstanceState == null && checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
            permission.launch(Manifest.permission.CAMERA)
        }
    }

    override fun onResume() {
        super.onResume()
        foreground = true
        startIfReady()
    }

    private fun startIfReady() {
        if (!foreground || scanning || isFinishing ||
            checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) return
        scanning = true
        camera.decodeContinuous { result ->
            if (foreground && scanning && !isFinishing) {
                val link = scannedInvitation(result.text)
                if (link == null) {
                    hint = "Нужен QR-код приглашения SYN443."
                } else {
                    camera.stopDecoding()
                    setResult(RESULT_OK, Intent().putExtra(EXTRA_LINK, link))
                    finish()
                }
            }
        }
        camera.resume()
    }

    override fun onPause() {
        foreground = false
        if (scanning) {
            scanning = false
            camera.stopDecoding()
            camera.pause()
        }
        super.onPause()
    }
}
