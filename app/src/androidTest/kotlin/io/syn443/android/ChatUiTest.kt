package io.syn443.android

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
    @Test fun supportChatHasVisibleTitleAndConnectionStatus() {
        assertReady()
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
        val state=JSONObject(checkNotNull(reply.getString("json")))
        return listOf("generation","desiredOn","configRevision").map {state.opt(it)}
    }
    private fun assertReady() {
        compose.activityRule.scenario.onActivity {activity->
            val root=activity.findViewById<android.view.ViewGroup>(android.R.id.content)
            assertTrue("SupportActivity must install its content root during startup",root.childCount>0)
        }
        compose.waitUntil(5000) {compose.onAllNodesWithTag("chat-title").fetchSemanticsNodes().isNotEmpty()}
        compose.onNodeWithTag("chat-title").assertIsDisplayed()
        compose.onNodeWithTag("chat-status").assertIsDisplayed()
    }
}
