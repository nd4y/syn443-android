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
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.EncodeHintType
import com.google.zxing.MultiFormatReader
import com.google.zxing.NotFoundException
import com.google.zxing.common.HybridBinarizer
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
    private fun invitation(code:String=Identity.random()) = "syn443://enroll/v1?service=service-a&origin=https%3A%2F%2Fapi.example.invalid&code=$code&bootstrap=x.y.z"

    private fun frame(link:String,mask:Int,missingFinder:Boolean=false):RGBLuminanceSource {
        val margin=4
        val raw=QRCodeWriter().encode(link,BarcodeFormat.QR_CODE,0,0,mapOf(
            EncodeHintType.QR_VERSION to 8,EncodeHintType.QR_MASK_PATTERN to mask,EncodeHintType.MARGIN to margin))
        val scale=8
        val width=raw.width*scale
        val pixels=IntArray(width*width) { i->
            val x=i%width/scale;val y=i/width/scale
            val covered=missingFinder && y in margin until margin+7 &&
                x in raw.width-margin-7 until raw.width-margin
            if(!covered && raw[x,y])Color.BLACK else Color.WHITE
        }
        return RGBLuminanceSource(width,width,pixels)
    }

    private fun readBoth(frame:RGBLuminanceSource,link:String) {
        assertEquals(link,scannedInvitation(link))
        for(source in listOf(frame,frame.invert())) {
            val decoder=invitationQrDecoder().createDecoder(emptyMap<DecodeHintType,Any>())
            val decoded=decoder.decode(source) ?: decoder.decode(source)
            assertEquals(link,scannedInvitation(decoded?.text))
        }
    }

    @Test fun liveDecoderRecognizesBothPolaritiesAndRejectsForeignPayloads() {
        for(mask in 0..7) {
            val code=Identity.encode(ByteArray(32) { ((mask+1)*(it+1)).toByte() })
            val link=invitation(code)
            readBoth(frame(link,mask),link)
        }
        val link=invitation()
        assertNull(scannedInvitation("https://foreign.example.invalid"))
        assertNull(scannedInvitation(link + "&code=duplicate"))
        assertNull(scannedInvitation("x".repeat(BootstrapTrust.MAX_LINK + 1)))
    }

    @Test fun liveCameraReadsCleanFrameWhenTheOrdinaryFinderCannotLocateItsThirdMarker() {
        val link=invitation(Identity.encode(ByteArray(32) {it.toByte()}))
        val source=frame(link,3,missingFinder=true)
        val usual=MultiFormatReader()
        assertThrows(NotFoundException::class.java) {
            usual.decode(BinaryBitmap(HybridBinarizer(source)),mapOf(
                DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE),DecodeHintType.TRY_HARDER to true))
        }
        readBoth(source,link)
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
