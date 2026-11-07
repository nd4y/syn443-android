package io.syn443.android

import android.content.Intent
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.core.net.toUri
import io.syn443.identity.BootstrapTrust
import io.syn443.identity.Identity
import org.junit.Assert.assertNull
import org.junit.Rule
import org.junit.Test

class EnrollmentAppLinkTest {
    @get:Rule val compose = createAndroidComposeRule<EnrollmentActivity>()

    @Test fun repeatViewIntentsPreviewOnlyAndClearTheirCarrier() {
        val code=Identity.random()
        val direct="syn443://enroll/v1?service=service-a&origin=https%3A%2F%2Fapi.example.invalid&code=$code&bootstrap=x.y.z"
        val activity=compose.activity
        fun open(raw:String) {
            compose.runOnUiThread {
                activity.startActivity(Intent(activity,EnrollmentActivity::class.java)
                    .setAction(Intent.ACTION_VIEW).setData(raw.toUri()).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP))
            }
        }
        val preview=compose.onNodeWithTag("invite-preview")
        preview.assertIsNotEnabled()
        open("https://"+BuildConfig.ENROLLMENT_LINK_HOST+BootstrapTrust.APP_LINK_PATH+"#"+direct)
        preview.assertIsEnabled()
        compose.onNodeWithTag("invite-confirm").assertDoesNotExist()
        compose.runOnIdle {assertNull(activity.intent.data)}
        open("https://unverified."+BuildConfig.ENROLLMENT_LINK_HOST+BootstrapTrust.APP_LINK_PATH+"#"+direct)
        preview.assertIsNotEnabled()
        compose.runOnIdle {assertNull(activity.intent.data)}
        open(direct)
        preview.assertIsEnabled()
        compose.onNodeWithTag("invite-confirm").assertDoesNotExist()
    }
}
