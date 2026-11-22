package io.syn443.android

import android.widget.TextView
import androidx.core.content.FileProvider
import io.syn443.android.chat.ChatLimits
import io.syn443.android.chat.ChatMedia
import io.syn443.android.chat.ChatScratch
import java.io.File
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertFalse
import androidx.compose.foundation.text.BasicText
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.ComposeView
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.test.ComposeTimeoutException
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.runner.lifecycle.ActivityLifecycleMonitorRegistry
import androidx.test.runner.lifecycle.Stage
import androidx.core.net.toUri
import android.content.Intent
import android.os.SystemClock
import io.syn443.android.chat.SupportActivity
import org.json.JSONObject
import java.lang.ref.WeakReference
import java.util.UUID
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertTrue
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Rule
import org.junit.Test

class ChatUiTest {
    @get:Rule val compose=createAndroidComposeRule<SupportActivity>()
    @Test fun existingChatAcceptsIncidentEntryAndDismissalSurvivesRecreation() {
        assertReady()
        val scenario = compose.activityRule.scenario
        scenario.onActivity { activity ->
            activity.startActivity(Intent(activity, SupportActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP).putExtra(SupportActivity.REPORT_PROBLEM, true))
        }
        compose.waitUntil(10_000) { compose.onAllNodesWithTag("incident-preview").fetchSemanticsNodes().isNotEmpty() }
        scenario.recreate()
        compose.waitUntil(10_000) { compose.onAllNodesWithTag("incident-cancel").fetchSemanticsNodes().isNotEmpty() }
        compose.onNodeWithTag("incident-cancel").performClick()
        scenario.recreate()
        assertReady()
        compose.onNodeWithTag("incident-preview").assertDoesNotExist()
    }

    @Test fun reopeningChatPreservesActiveFilesAndReclaimsOnlyEarlierChatWork() {
        assertReady()
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val cache = context.cacheDir
        val fixtureDir = File(cache, "chat-test").apply { mkdirs() }
        val source = File(fixtureDir, "message-${ChatLimits.id()}.txt")
        val download = ChatScratch.download(cache)
        val output = ChatScratch.output(cache)
        val legacy = File(cache, "chat-${ChatLimits.id()}.input")
        val previous = File(cache, "chat-download-${ChatLimits.id()}-${ChatLimits.id()}")
        val other = File(cache, "chat-foreign-${ChatLimits.id()}.output")
        val files = listOf(source, download, output, legacy, previous, other)
        try {
            files.forEach { it.writeText("attachment fixture") }
            val uri = FileProvider.getUriForFile(context, "io.syn443.chat.fixture", source)
            val prepared = runBlocking { ChatMedia.prepare(context, uri, false) {} }
            prepared.use {
                compose.activityRule.scenario.recreate()
                assertReady()
                for (kept in listOf(it.file, source, download, output, other)) {
                    assertEquals("attachment fixture", kept.readText())
                }
                assertFalse(legacy.exists())
                assertFalse(previous.exists())
            }
            assertFalse(prepared.file.exists())
        } finally {
            files.forEach { it.delete() }
        }
    }

    @Test fun supportChatHasVisibleTitleAndConnectionStatus() {
        assertReady()
    }
    @Test fun chatReadinessRejectsMissingRootTitleAndStatus() {
        assertReady()
        val scenario=compose.activityRule.scenario
        val instrumentation=InstrumentationRegistry.getInstrumentation()
        try {
            scenario.onActivity {activity->
                activity.setContentView(TextView(activity).apply {text="Readiness fixture without Compose"})
            }
            instrumentation.waitForIdleSync()
            val missingRoot=runCatching {assertReady()}.exceptionOrNull()
            assertEquals("Missing Compose must exhaust the bounded readiness wait",
                ComposeTimeoutException::class.java,missingRoot?.javaClass)
            scenario.recreate()
            assertReady()
            scenario.onActivity {activity->
                activity.setContentView(ComposeView(activity).apply {
                    setContent {BasicText("Readiness fixture title",Modifier.testTag("chat-title"))}
                })
            }
            instrumentation.waitForIdleSync()
            val missingStatus=runCatching {assertReady()}.exceptionOrNull()
            assertTrue("A title without connection status must not become ready",missingStatus is AssertionError)
        } finally {
            scenario.recreate()
            assertReady()
        }
    }
    @Test fun supportChatKeepsItsRootAcrossRepeatedRecreation() {
        assertReady()
        repeat(5) {
            compose.activityRule.scenario.recreate()
            assertReady()
        }
    }
    @Test fun supportChatResumesAfterRepeatedBackgroundTransitions() {
        assertReady()
        val instrumentation=InstrumentationRegistry.getInstrumentation()
        val scenario=compose.activityRule.scenario
        val stopped=AtomicInteger();val resumed=AtomicInteger()
        val observer=LifecycleEventObserver {_,event->when(event) {
            Lifecycle.Event.ON_STOP->stopped.incrementAndGet()
            Lifecycle.Event.ON_RESUME->resumed.incrementAndGet()
            else->Unit
        }}
        lateinit var original:WeakReference<SupportActivity>
        scenario.onActivity {activity->original=WeakReference(activity);activity.lifecycle.addObserver(observer)}
        val initialResumes=resumed.get()
        val before=vpnIntent()
        val coverKey="io.syn443.test.chat.background"
        val token=UUID.randomUUID().toString()
        fun finishOwnedCover()=instrumentation.runOnMainSync {
            val monitor=ActivityLifecycleMonitorRegistry.getInstance()
            Stage.values().filter {it!=Stage.DESTROYED}
                .flatMap {monitor.getActivitiesInStage(it).toList()}.distinct()
                .filter {it is MainActivity && it.intent?.getStringExtra(coverKey)==token}
                .forEach {it.finish()}
        }
        try {
            repeat(5) {index->
                // A real foreground Activity in the same task produces ON_STOP.
                // Do not depend on a library facilitator's NEW_TASK/broadcast
                // transition, which failed to stop the target on an API35 run.
                scenario.onActivity {activity->
                    assertSame("Background cycles must retain the SupportActivity instance",original.get(),activity)
                    activity.startActivity(Intent(activity,MainActivity::class.java).putExtra(coverKey,token))
                }
                awaitTransition {stopped.get()>index}
                assertEquals(index+1,stopped.get())
                scenario.onActivity {activity->
                    assertSame(original.get(),activity)
                    assertEquals(Lifecycle.State.CREATED,activity.lifecycle.currentState)
                }
                scenario.moveToState(Lifecycle.State.CREATED)
                instrumentation.runOnMainSync {
                    val covers=ActivityLifecycleMonitorRegistry.getInstance().getActivitiesInStage(Stage.RESUMED)
                        .filter {it is MainActivity && it.intent?.getStringExtra(coverKey)==token}
                    assertEquals("Exactly the owned cover must be resumed",1,covers.size)
                }
                finishOwnedCover()
                awaitTransition {resumed.get()>initialResumes+index}
                assertEquals(initialResumes+index+1,resumed.get())
                scenario.moveToState(Lifecycle.State.RESUMED)
                scenario.onActivity {activity->
                    assertSame(original.get(),activity)
                    assertEquals(Lifecycle.State.RESUMED,activity.lifecycle.currentState)
                }
                assertReady()
                assertEquals("Background navigation must preserve VPN intent",before,vpnIntent())
            }
            assertEquals(5,stopped.get())
        } finally {
            finishOwnedCover()
            instrumentation.runOnMainSync {original.get()?.lifecycle?.removeObserver(observer)}
        }
    }
    private fun awaitTransition(predicate:()->Boolean) {
        val deadline=SystemClock.elapsedRealtime()+10_000
        while(!predicate()) {
            assertTrue("Real chat lifecycle transition deadline exceeded",SystemClock.elapsedRealtime()<deadline)
            Thread.sleep(50)
        }
    }
    private fun vpnIntent():List<Any?> {
        val context=InstrumentationRegistry.getInstrumentation().targetContext
        val reply=checkNotNull(context.contentResolver.call("content://io.syn443.control".toUri(),"status",null,null))
        assertTrue("Read-only VPN status must be available",reply.getBoolean("ok"))
        val state=JSONObject(checkNotNull(reply.getString("json")))
        assertTrue("VPN generation must be present and numeric",state.has("generation") && state.get("generation") is Number)
        assertTrue("VPN desired intent must be present and boolean",state.has("desiredOn") && state.get("desiredOn") is Boolean)
        assertTrue("VPN generation must be nonnegative",state.getLong("generation")>=0)
        // A fresh installation legitimately has no configuration revision.
        // Preserve that absence too; MainActivity must not invent a config.
        return listOf(state.getLong("generation"),state.getBoolean("desiredOn"),
            state.has("configRevision"),state.opt("configRevision"))
    }
    private fun assertReady() {
        compose.activityRule.scenario.onActivity {activity->
            val root=activity.findViewById<android.view.ViewGroup>(android.R.id.content)
            assertTrue("SupportActivity must install its content root during startup",root.childCount>0)
        }
        compose.waitUntil(5000) {compose.onAllNodesWithTag("chat-title").fetchSemanticsNodes(atLeastOneRootRequired=false).isNotEmpty()}
        compose.onNodeWithTag("chat-title").assertIsDisplayed()
        compose.onNodeWithTag("chat-status").assertIsDisplayed()
    }
}
