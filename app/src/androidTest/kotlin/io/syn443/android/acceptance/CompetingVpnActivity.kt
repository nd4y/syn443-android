package io.syn443.android.acceptance

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView

/** Test APK only. Physical phones always use a visible button and ordinary consent. */
class CompetingVpnActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (android.os.Build.HARDWARE in setOf("ranchu", "goldfish")) {
            if (intent.getBooleanExtra("ci-stop", false)) { stopPeer(); finish(); return }
            if (intent.getBooleanExtra("ci-start", false)) {
                check(VpnService.prepare(this) == null)
                startPeer(); finish(); return
            }
        }
        setContentView(LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(32, 64, 32, 32)
            addView(TextView(context).apply { text = "Temporary SYN443 VPN handover test. Only documentation-network addresses are routed. Stop the test when finished." })
            addView(Button(context).apply {
                text = "Start acceptance VPN"
                setOnClickListener {
                    val consent = VpnService.prepare(this@CompetingVpnActivity)
                    if (consent == null) startPeer() else @Suppress("DEPRECATION") startActivityForResult(consent, 41)
                }
            })
            addView(Button(context).apply { text = "Stop acceptance VPN"; setOnClickListener { stopPeer() } })
        })
    }
    private fun startPeer() { startForegroundService(Intent(this, CompetingVpnService::class.java)) }
    private fun stopPeer() { stopService(Intent(this, CompetingVpnService::class.java)) }
    @Deprecated("Test fixture uses platform consent result for API29 compatibility")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == 41 && resultCode == RESULT_OK) startPeer()
    }
}
