package io.syn443.android

import android.content.Intent
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.core.net.toUri
import androidx.test.core.app.ActivityScenario
import androidx.test.platform.app.InstrumentationRegistry
import io.syn443.identity.BootstrapTrust
import io.syn443.identity.Identity
import org.junit.Assert.assertNull
import org.junit.Rule
import org.junit.Test

class EnrollmentAppLinkTest {
    @get:Rule val compose = createEmptyComposeRule()

    @Test fun repeatViewIntentsPreviewOnlyAndClearTheirCarrier() {
        val code=Identity.random()
        val direct="syn443://enroll/v1?service=service-a&origin=https%3A%2F%2Fapi.example.invalid&code=$code&bootstrap=x.y.z"
        val context=InstrumentationRegistry.getInstrumentation().targetContext
        // ActivityScenario matches action/categories/data to its launch intent.
        // Begin with the same bare component used by the Activity after scrubbing.
        ActivityScenario.launch<EnrollmentActivity>(Intent(context,EnrollmentActivity::class.java)).use {scenario->
            val preview=compose.onNodeWithTag("invite-preview")
            fun open(raw:String,enabled:Boolean) {
                scenario.onActivity {activity->
                    activity.startActivity(Intent(activity,EnrollmentActivity::class.java)
                        .setAction(Intent.ACTION_VIEW).setData(raw.toUri()).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP))
                }
                compose.waitUntil(timeoutMillis=5_000) {
                    val disabled=preview.fetchSemanticsNode().config.contains(SemanticsProperties.Disabled)
                    disabled!=enabled
                }
                scenario.onActivity {assertNull(it.intent.data)}
            }
            preview.assertIsNotEnabled()
            open("https://"+BuildConfig.ENROLLMENT_LINK_HOST+BootstrapTrust.APP_LINK_PATH+"#"+direct,true)
            compose.onNodeWithTag("invite-confirm").assertDoesNotExist()
            open("https://unverified."+BuildConfig.ENROLLMENT_LINK_HOST+BootstrapTrust.APP_LINK_PATH+"#"+direct,false)
            preview.assertIsNotEnabled()
            open(direct,true)
            preview.assertIsEnabled()
            compose.onNodeWithTag("invite-confirm").assertDoesNotExist()
        }
    }
}
