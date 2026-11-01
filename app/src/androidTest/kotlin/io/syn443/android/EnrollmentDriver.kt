package io.syn443.android

import androidx.test.runner.AndroidJUnitRunner
import android.net.Uri
import android.os.Bundle
import android.os.SystemClock
import org.json.JSONObject
import java.net.URL
import java.security.KeyStore
import java.security.cert.CertificateFactory
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory

/** Test APK only. Ordinary runs retain AndroidJUnitRunner; explicit fixture runs enroll by own UID. */
class EnrollmentDriver:AndroidJUnitRunner() {
    private var fixtureArguments:Bundle?=null
    override fun onCreate(args:Bundle?) {
        fixtureArguments=args?.takeIf {it.containsKey("fixturePort")}
        super.onCreate(args)
    }
    override fun onStart() {
        if(fixtureArguments==null) {super.onStart();return}
        val arguments=checkNotNull(fixtureArguments)
        var stage="preflight"
        val ok=runCatching {
            require(BuildConfig.DEBUG && android.os.Build.HARDWARE in setOf("ranchu","goldfish"))
            val port=arguments.getString("fixturePort")!!.toInt();require(port in 1024..65535)
            val origin="https://127.0.0.1:$port"
            val cert=CertificateFactory.getInstance("X.509").generateCertificate(java.util.Base64.getDecoder().decode(arguments.getString("fixtureCa")).inputStream())
            val trust=KeyStore.getInstance(KeyStore.getDefaultType()).apply {load(null);setCertificateEntry("synthetic",cert)}
            val managers=TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply {init(trust)}
            val factory=SSLContext.getInstance("TLS").apply {init(null,managers.trustManagers,null)}.socketFactory
            val uri=Uri.parse("content://io.syn443.control")
            fun call(method:String,arg:String?=null):Bundle = checkNotNull(targetContext.contentResolver.call(uri,method,arg,null)).also {check(it.getBoolean("ok"))}
            fun status()=JSONObject(checkNotNull(call("auth-status").getString("json")))
            fun await(predicate:(JSONObject)->Boolean):JSONObject {
                val end=SystemClock.elapsedRealtime()+30_000
                while(true) {val value=status();if(predicate(value))return value;check(SystemClock.elapsedRealtime()<end);Thread.sleep(50)}
            }
            stage="signed_out"
            val before=await {it.getString("phase")=="SIGNED_OUT" && !it.getBoolean("busy")}
            stage="authorization_start"
            call("auth-start",before.getLong("generation").toString())
            val pending=await {it.getString("phase")=="BROWSER" && it.getBoolean("browserReady") && !it.getBoolean("busy")}
            stage="authorization_url"
            val url=checkNotNull(call("auth-browser",pending.getLong("generation").toString()).getString("url"))
            require(java.net.URI(url).rawAuthority==java.net.URI(origin).rawAuthority && url.startsWith(origin+"/realms/test/"))
            stage="browser_tls"
            val connection=URL(url).openConnection() as HttpsURLConnection
            val callback=try {
                connection.sslSocketFactory=factory;connection.instanceFollowRedirects=false
                connection.connectTimeout=5000;connection.readTimeout=5000
                check(connection.responseCode==302);checkNotNull(connection.getHeaderField("Location"))
            } finally {connection.disconnect()}
            stage="callback"
            require(callback.startsWith("syn443://oauth/callback?"));call("auth-callback",callback)
            targetContext.startActivity(android.content.Intent(targetContext,MainActivity::class.java).addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK))
            stage="assignment"
            val registered=await {it.getString("phase")=="POLICY_CACHED" && !it.getBoolean("busy")}
            stage="candidate_validated"
            check(registered.getJSONObject("assignedPolicy").getBoolean("candidateValidated"))
            check(!JSONObject(checkNotNull(call("status").getString("json"))).getBoolean("desiredOn"))
        }.isSuccess
        finish(if(ok)-1 else 0,Bundle().apply {
            putString("result",if(ok)"synthetic_enrollment_verified" else "synthetic_enrollment_failed")
            putString("stage",stage)
        })
    }
}
