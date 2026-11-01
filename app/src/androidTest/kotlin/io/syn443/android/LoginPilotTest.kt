package io.syn443.android

import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.SystemClock
import androidx.core.net.toUri
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.syn443.android.vpn.DeviceKey
import io.syn443.identity.Bootstrap
import io.syn443.identity.Identity
import io.syn443.identity.LoginRecovery
import io.syn443.policy.Canonical
import kotlinx.serialization.encodeToString
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import java.util.Base64

/** Disposable emulator only. These tests never authenticate with or enroll into an external service. */
@RunWith(AndroidJUnit4::class)
class LoginPilotTest {
    private val context=ApplicationProvider.getApplicationContext<Context>()
    private val uri="content://io.syn443.control".toUri()
    private fun call(method:String,arg:String?=null)=checkNotNull(context.contentResolver.call(uri,method,arg,null))
    private fun auth()=JSONObject(checkNotNull(call("auth-status").getString("json")))
    private fun vpn()=JSONObject(checkNotNull(call("status").getString("json")))
    private fun shell(command:String) {
        val fd=InstrumentationRegistry.getInstrumentation().uiAutomation.executeShellCommand(command)
        android.os.ParcelFileDescriptor.AutoCloseInputStream(fd).use {it.readBytes()}
    }
    private fun until(predicate:()->Boolean) {
        val end=SystemClock.elapsedRealtime()+20_000
        while(!runCatching(predicate).getOrDefault(false)) {check(SystemClock.elapsedRealtime()<end) {"login pilot timed out"};Thread.sleep(100)}
    }
    private fun fixture(block:(Long,String,String)->Unit) {
        check(Build.HARDWARE in setOf("ranchu","goldfish"))
        assertTrue(call("disconnect").getBoolean("ok"))
        until {!vpn().optBoolean("engineActive") && !vpn().getBoolean("desiredOn")}
        val config=vpn().optString("configRevision")
        val setup=File(context.noBackupFilesDir,"identity-bootstrap.json")
        val operator=File(context.noBackupFilesDir,"operator-identity.json")
        check(!setup.exists() && !operator.exists())
        val pair=KeyPairGenerator.getInstance("EC").apply {initialize(ECGenParameterSpec("secp256r1"))}.generateKeyPair()
        val b=Bootstrap("synthetic","https://identity.example.invalid/realms/test","test","https://api.example.invalid",
            mapOf("root" to Base64.getEncoder().encodeToString(pair.public.encoded)))
        try {
            operator.writeText(Canonical.json.encodeToString(b))
            shell("content call --uri content://io.syn443.control --method auth-bootstrap-file")
            until {auth().optBoolean("configured") && !auth().optBoolean("busy")}
            val generation=auth().getLong("generation")
            assertTrue(call("auth-start",generation.toString()).getBoolean("ok"))
            until {auth().optBoolean("browserReady") && !auth().optBoolean("busy")}
            val next=auth().getLong("generation");assertEquals(generation+1,next)
            val url=checkNotNull(call("auth-browser",next.toString()).getString("url"))
            val intent=LoginRecovery.decode(File(context.noBackupFilesDir,"login/device-login-v1/intent.json").readText())
            assertFalse(call("connect").getBoolean("ok"))
            assertFalse(vpn().getBoolean("desiredOn"))
            block(next,url,intent.keyAlias)
        } finally {
            // Callback UI belongs to this fixture. Retire it before killing its
            // provider: Android may also kill clients with stable provider refs.
            val instrumentation=InstrumentationRegistry.getInstrumentation()
            instrumentation.runOnMainSync {
                val monitor=androidx.test.runner.lifecycle.ActivityLifecycleMonitorRegistry.getInstance()
                androidx.test.runner.lifecycle.Stage.values()
                    .filter {it!=androidx.test.runner.lifecycle.Stage.DESTROYED}
                    .flatMap {monitor.getActivitiesInStage(it).toList()}.distinct().forEach {it.finish()}
            }
            instrumentation.waitForIdleSync()
            assertTrue(call("auth-cancel").getBoolean("ok"))
            until {auth().optString("phase")=="SIGNED_OUT" && !auth().optBoolean("busy")}
            assertFalse(vpn().getBoolean("desiredOn"));assertTrue(config==vpn().optString("configRevision"))
            assertTrue(!setup.exists() || setup.delete());operator.delete()
            shell("content call --uri content://io.syn443.control --method fault-controller")
            Thread.sleep(300)
            until {!auth().optBoolean("configured") && !auth().optBoolean("busy")}
        }
    }
    @Test fun browserReservationAndCancellationPreserveVpnAndDeleteTheKey() = fixture {generation,url,alias->
        assertTrue(url.startsWith("https://identity.example.invalid/realms/test/protocol/openid-connect/auth?"))
        assertNotNull(DeviceKey.open(alias).publicKey)
        assertTrue(call("auth-cancel").getBoolean("ok"))
        until {auth().optString("phase")=="SIGNED_OUT"}
        assertTrue(auth().getLong("generation")>generation)
        assertThrows(IllegalStateException::class.java) {DeviceKey.open(alias)}
        assertFalse(File(context.noBackupFilesDir,"login/device-login-v1/protected.bin").exists())
        val retiredGeneration=auth().getLong("generation")
        assertFalse(call("auth-start",generation.toString()).getBoolean("ok"))
        until {!auth().optBoolean("busy")}
        assertEquals("SIGNED_OUT",auth().getString("phase"));assertEquals(retiredGeneration,auth().getLong("generation"))
        assertFalse(call("auth-browser",generation.toString()).getBoolean("ok"))
    }
    @Test fun controllerRestartResumesSameBrowserGenerationWithoutANewKey() = fixture {generation,url,alias->
        val thumb=Identity.thumbprint(DeviceKey.open(alias).publicKey)
        shell("content call --uri content://io.syn443.control --method fault-controller")
        Thread.sleep(300)
        until {auth().optBoolean("browserReady") && !auth().optBoolean("busy")}
        assertEquals(generation,auth().getLong("generation"))
        assertTrue(url==call("auth-browser",generation.toString()).getString("url"))
        assertTrue(thumb==Identity.thumbprint(DeviceKey.open(alias).publicKey))
    }
    @Test fun exactErrorCallbackIsSingleUseAndNeverConnectsVpn() = fixture {generation,url,_->
        val state=checkNotNull(url.toUri().getQueryParameter("state"))
        val invalid=Identity.callback+"?"+Identity.form(mapOf("state" to "invalid","iss" to "https://identity.example.invalid/realms/test","error" to "access_denied"))
        assertTrue(call("auth-callback",invalid).getBoolean("ok"))
        until {!auth().optBoolean("busy")}
        assertEquals("BROWSER",auth().getString("phase"))
        val valid=Identity.callback+"?"+Identity.form(mapOf("state" to state,"iss" to "https://identity.example.invalid/realms/test","error" to "access_denied"))
        context.startActivity(Intent(context,LoginCallbackActivity::class.java).setAction(Intent.ACTION_VIEW).setData(valid.toUri()).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        until {auth().optString("phase")=="NEEDS_REAUTH" && !auth().optBoolean("busy")}
        assertEquals(generation,auth().getLong("generation"))
        assertFalse(call("auth-callback",valid).getBoolean("ok"));assertFalse(vpn().getBoolean("desiredOn"))
    }
}
