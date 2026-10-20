package io.syn443.android

import android.app.Service
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.HandlerThread
import android.os.IBinder
import android.os.Looper
import android.os.Message
import android.os.Messenger
import android.os.Process as AndroidProcess
import android.os.RemoteException
import java.util.concurrent.CountDownLatch

/** Debug-only process fault harness. No engine, TUN, network access or production supervisor. */
class HostProbeService : Service() {
    private lateinit var workerThread: HandlerThread
    private lateinit var worker: Handler
    private lateinit var control: Messenger
    private var session: String? = null

    override fun onCreate() {
        super.onCreate()
        workerThread = HandlerThread("syn443-probe-worker").apply { start() }
        worker = Handler(workerThread.looper)
        // Separate control and worker loopers let tests simulate a wedged engine worker
        // while retaining a cooperative process termination channel.
        control = Messenger(Handler(Looper.getMainLooper()) { message ->
            if (session != null && message.data.getString(SESSION) == session) {
                // Android recycles Message after this callback. Capture immutable fields
                // before dispatching any work to the other looper.
                val destination = message.replyTo
                val requestId = message.arg1
                when (message.what) {
                    PROBE -> worker.post { reply(destination, requestId, PONG) }
                    STOP -> worker.post { AndroidProcess.killProcess(AndroidProcess.myPid()) }
                    TERMINATE -> AndroidProcess.killProcess(AndroidProcess.myPid())
                    HANG_WORKER -> {
                        worker.post { CountDownLatch(1).await() }
                        reply(destination, requestId, HANG_QUEUED)
                    }
                }
            }
            true
        })
    }

    override fun onBind(intent: Intent?): IBinder? {
        val requested = intent?.getStringExtra(SESSION) ?: return null
        if (!requested.matches(Regex("[a-f0-9]{32}"))) return null
        if (session != null && requested != session) return null
        session = requested
        return control.binder
    }

    private fun reply(destination: Messenger?, requestId: Int, code: Int) {
        val reply = Message.obtain(null, code, requestId, 0).apply {
            data = Bundle().apply {
                putString(SESSION, session)
                putInt("pid", AndroidProcess.myPid())
            }
        }
        try {
            destination?.send(reply)
        } catch (_: RemoteException) {
            // Caller died. The unbind path terminates this dedicated diagnostic process.
        }
    }

    override fun onUnbind(intent: Intent?): Boolean {
        AndroidProcess.killProcess(AndroidProcess.myPid())
        return false
    }

    override fun onDestroy() {
        workerThread.quitSafely()
        super.onDestroy()
    }

    companion object {
        const val SESSION = "session"
        const val PROBE = 1
        const val PONG = 2
        const val STOP = 3
        const val HANG_WORKER = 4
        const val HANG_QUEUED = 5
        const val TERMINATE = 6
    }
}
