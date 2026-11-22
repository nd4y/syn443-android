package io.syn443.android

import android.content.Intent
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.assertTextContains
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import androidx.compose.ui.test.performTextClearance
import androidx.compose.ui.test.onNodeWithTag
import androidx.core.net.toUri
import androidx.test.core.app.ActivityScenario
import androidx.test.platform.app.InstrumentationRegistry
import io.syn443.identity.BootstrapTrust
import io.syn443.identity.Identity
import org.junit.Assert.assertEquals
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
            val help=compose.onNodeWithTag("invite-network-help")
            help.assertTextContains("доступ к серверу SYN443", substring=true)
            help.assertTextContains("Для входа через Keycloak", substring=true)
            val preview=compose.onNodeWithTag("invite-preview")
            fun open(raw:String,enabled:Boolean) {
                scenario.onActivity {activity->
                    activity.startActivity(Intent(activity,EnrollmentActivity::class.java)
                        .setAction(Intent.ACTION_VIEW).setData(raw.toUri()).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP))
                }
                compose.waitUntil(timeoutMillis=5_000) {
                    runCatching {
                        val disabled=preview.fetchSemanticsNode().config.contains(SemanticsProperties.Disabled)
                        disabled!=enabled
                    }.getOrDefault(false)
                }
                scenario.onActivity {assertNull(it.intent.data)}
            }
            compose.waitUntil(timeoutMillis=8_000) {runCatching {preview.fetchSemanticsNode()}.isSuccess}
            preview.assertIsNotEnabled()
            open("https://"+BuildConfig.ENROLLMENT_LINK_HOST+BootstrapTrust.APP_LINK_PATH+"#"+direct,true)
            compose.onNodeWithTag("invite-confirm").assertDoesNotExist()
            open("https://unverified."+BuildConfig.ENROLLMENT_LINK_HOST+BootstrapTrust.APP_LINK_PATH+"#"+direct,false)
            preview.assertIsNotEnabled()
            open(direct,true)
            preview.assertIsEnabled()
            open(direct + "&code=duplicate", false)
            preview.assertIsNotEnabled()
            compose.onNodeWithTag("invite-message").assertExists()
            compose.onNodeWithTag("invite-confirm").assertDoesNotExist()
        }
    }

    @Test fun browsableColdLaunchShowsOnlyLocalReviewAndDropsTheCarrier() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        val link = "syn443://enroll/v1?service=service-a&origin=https%3A%2F%2Fapi.example.invalid&code=" +
            Identity.random() + "&bootstrap=x.y.z"
        val launch = Intent(Intent.ACTION_VIEW, link.toUri()).addCategory(Intent.CATEGORY_BROWSABLE)
            .setPackage(context.packageName).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        val monitor = instrumentation.addMonitor(EnrollmentActivity::class.java.name, null, false)
        var activity: EnrollmentActivity? = null
        try {
            context.startActivity(launch)
            val owner = requireNotNull(instrumentation.waitForMonitorWithTimeout(monitor, 8_000) as? EnrollmentActivity)
            activity = owner
            instrumentation.runOnMainSync { assertNull(owner.intent.data) }
            compose.onNodeWithTag("invite-preview").assertIsEnabled()
            compose.onNodeWithTag("invite-confirm").assertDoesNotExist()
        } finally {
            instrumentation.removeMonitor(monitor)
            instrumentation.runOnMainSync { activity?.finish() }
            instrumentation.waitForIdleSync()
        }
    }

    @Test fun redeliveredInvitationKeepsEditsAndDifferentLinkStartsItsOwnReview() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        fun invitation() = "syn443://enroll/v1?service=service-a&origin=https%3A%2F%2Fapi.example.invalid&code=" +
            Identity.random() + "&bootstrap=x.y.z"
        fun view(raw: String) = Intent(Intent.ACTION_VIEW, raw.toUri())
            .addCategory(Intent.CATEGORY_BROWSABLE).setPackage(context.packageName)
        val first = invitation()
        val second = invitation()
        val entry = view(first)
        assertEquals(EnrollmentActivity::class.java.name, entry.resolveActivity(context.packageManager)?.className)
        ActivityScenario.launch<EnrollmentActivity>(Intent(context, EnrollmentActivity::class.java)).use { scenario ->
            fun deliver(intent: Intent) {
                scenario.onActivity {
                    instrumentation.callActivityOnNewIntent(it, intent)
                    assertNull(it.intent.data)
                }
                compose.waitForIdle()
            }
            val preview = compose.onNodeWithTag("invite-preview")
            deliver(entry)
            preview.assertIsEnabled()
            compose.onNodeWithTag("invite-link").performTextClearance()
            preview.assertIsNotEnabled()
            deliver(view("https://" + BuildConfig.ENROLLMENT_LINK_HOST + BootstrapTrust.APP_LINK_PATH + "#" + first))
            preview.assertIsNotEnabled()
            deliver(view(second))
            preview.assertIsEnabled()
            compose.onNodeWithTag("invite-confirm").assertDoesNotExist()
        }
    }
}
