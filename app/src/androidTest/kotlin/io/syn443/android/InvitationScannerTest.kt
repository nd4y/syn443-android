package io.syn443.android

import android.app.Activity
import android.app.Instrumentation
import android.content.ComponentName
import android.content.Intent
import android.graphics.Color
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextInput
import androidx.test.core.app.ActivityScenario
import androidx.test.platform.app.InstrumentationRegistry
import com.google.zxing.BarcodeFormat
import com.google.zxing.DecodeHintType
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.qrcode.QRCodeWriter
import io.syn443.identity.BootstrapTrust
import io.syn443.identity.Identity
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test

class InvitationScannerTest {
    @get:Rule val compose = createEmptyComposeRule()
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private fun invitation() = "syn443://enroll/v1?service=service-a&origin=https%3A%2F%2Fapi.example.invalid&code=${Identity.random()}&bootstrap=x.y.z"

    @Test fun liveDecoderRecognizesBothPolaritiesAndRejectsForeignPayloads() {
        val link = invitation()
        val qr = QRCodeWriter().encode(link, BarcodeFormat.QR_CODE, 640, 640)
        val pixels = IntArray(qr.width * qr.height) { index ->
            if (qr[index % qr.width, index / qr.width]) Color.BLACK else Color.WHITE
        }
        val frame = RGBLuminanceSource(qr.width, qr.height, pixels)
        for (source in listOf(frame, frame.invert())) {
            val decoder = invitationQrDecoder().createDecoder(emptyMap<DecodeHintType, Any>())
            val decoded = decoder.decode(source) ?: decoder.decode(source)
            assertEquals(link, scannedInvitation(decoded?.text))
        }
        assertNull(scannedInvitation("https://foreign.example.invalid"))
        assertNull(scannedInvitation(link + "&code=duplicate"))
        assertNull(scannedInvitation("x".repeat(BootstrapTrust.MAX_LINK + 1)))
    }

    private fun withScannerReply(code: Int, data: Intent?, check: () -> Unit) {
        val name = InvitationScannerActivity::class.java
        assertFalse(context.packageManager.getActivityInfo(ComponentName(context, name), 0).exported)
        val monitor = instrumentation.addMonitor(name.name, Instrumentation.ActivityResult(code, data), true)
        try {
            ActivityScenario.launch<EnrollmentActivity>(Intent(context, EnrollmentActivity::class.java)).use {
                compose.onNodeWithTag("invite-preview").assertIsNotEnabled()
                compose.onNodeWithTag("invite-camera").performScrollTo().performClick()
                compose.waitUntil(8_000) { monitor.hits == 1 &&
                    runCatching { compose.onNodeWithTag("invite-message").fetchSemanticsNode() }.isSuccess }
                check()
                compose.onNodeWithTag("invite-confirm").assertDoesNotExist()
            }
        } finally {
            instrumentation.removeMonitor(monitor)
        }
    }

    @Test fun validCameraResultOnlyEnablesLocalInvitationReview() {
        withScannerReply(Activity.RESULT_OK, Intent().putExtra(InvitationScannerActivity.EXTRA_LINK, invitation())) {
            compose.onNodeWithTag("invite-preview").assertIsEnabled()
        }
    }

    @Test fun canceledScannerKeepsPasteAndImageAvailable() {
        withScannerReply(Activity.RESULT_CANCELED, null) {
            compose.onNodeWithTag("invite-preview").assertIsNotEnabled()
            compose.onNodeWithTag("invite-image").assertIsEnabled()
            compose.onNodeWithTag("invite-link").performScrollTo().performTextInput(invitation())
            compose.onNodeWithTag("invite-preview").assertIsEnabled()
        }
    }
}
