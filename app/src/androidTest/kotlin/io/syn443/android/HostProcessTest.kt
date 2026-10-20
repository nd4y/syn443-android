package io.syn443.android

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Bundle
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Message
import android.os.Messenger
import android.os.Process as AndroidProcess
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Test
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit

/** Real Binder/process tests, intentionally restricted to the synthetic debug harness. */
class HostProcessTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    private inner class Host : AutoCloseable {
        val session = UUID.randomUUID().toString().replace("-", "")
        private val ready = CountDownLatch(1)
        val died = CountDownLatch(1)
        private val responses = LinkedBlockingQueue<Message>()
        private var bound = false
        lateinit var binder: IBinder
        private val reply = Messenger(Handler(Looper.getMainLooper()) { message ->
            responses.offer(Message.obtain(message))
            true
        })
        private val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName, service: IBinder) {
                binder = service
                service.linkToDeath({ died.countDown() }, 0)
                ready.countDown()
            }
            override fun onServiceDisconnected(name: ComponentName) = Unit
        }

        fun bind(): Host {
            val intent = Intent().setComponent(ComponentName(context, "io.syn443.android.HostProbeService"))
                .putExtra("session", session)
            bound = context.bindService(intent, connection, Context.BIND_AUTO_CREATE)
            assertTrue("Diagnostic host bind rejected", bound)
            assertTrue("Diagnostic host did not connect", ready.await(10, TimeUnit.SECONDS))
            return this
        }

        fun send(code: Int, token: String = session) {
            Messenger(binder).send(Message.obtain(null, code, 7, 0).apply {
                replyTo = reply
                data = Bundle().apply { putString("session", token) }
            })
        }

        fun expect(code: Int): Message {
            val response = responses.poll(5, TimeUnit.SECONDS)
            assertNotNull("Diagnostic host response missing", response)
            checkNotNull(response)
            assertEquals(code, response.what)
            assertEquals(7, response.arg1)
            assertEquals(session, response.data.getString("session"))
            return response
        }

        fun assertSilent() {
            assertNull("Wedged worker unexpectedly answered", responses.poll(250, TimeUnit.MILLISECONDS))
        }

        fun assertDead() {
            assertTrue("Diagnostic host death was not observed", died.await(5, TimeUnit.SECONDS))
            assertFalse("Dead diagnostic binder is still alive", binder.isBinderAlive)
        }

        override fun close() {
            if (bound) {
                // Cancel Android's automatic rebinding before creating another host.
                context.unbindService(connection)
                bound = false
            }
        }
    }

    @Test fun workerRunsInSeparateProcessAndStops() {
        Host().use { host ->
            host.bind()
            host.send(1)
            val response = host.expect(2)
            val pid = response.data.getInt("pid")
            assertTrue("Worker is not in a separate process", pid > 0 && pid != AndroidProcess.myPid())
            host.send(3)
            host.assertDead()
        }
    }

    @Test fun wedgedWorkerCanBeTerminatedAndRebound() {
        Host().use { host ->
            host.bind()
            host.send(4)
            host.expect(5)
            host.send(1)
            host.assertSilent()
            host.send(6)
            host.assertDead()
        }
        Host().use { replacement ->
            replacement.bind()
            replacement.send(1)
            replacement.expect(2)
            replacement.send(3)
            replacement.assertDead()
        }
    }

    @Test fun foreignSessionCannotTerminateHost() {
        Host().use { host ->
            host.bind()
            host.send(6, "foreign-session")
            host.send(1)
            host.expect(2)
            assertTrue("Foreign session terminated diagnostic host", host.binder.isBinderAlive)
            host.send(3)
            host.assertDead()
        }
    }
}
