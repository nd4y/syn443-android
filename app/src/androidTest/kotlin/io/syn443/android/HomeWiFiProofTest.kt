package io.syn443.android

import io.syn443.android.vpn.HomeProofScope
import io.syn443.android.vpn.HomeWiFiHandshake
import io.syn443.android.vpn.HomeWiFiMonitor
import io.syn443.policy.HomeWiFiProof
import io.syn443.policy.Policy
import io.syn443.recovery.RouteScope
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketAddress
import java.security.MessageDigest
import java.util.Base64
import mockwebserver3.MockWebServer
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import org.junit.Assert.*
import org.junit.Test

class HomeWiFiProofTest {
    @Test fun actualTLSRequiresBoundSocketTrustedHostnameAndMatchingLeafPin(){
        val hostname="proof.example.invalid"
        val cert=HeldCertificate.Builder().addSubjectAlternativeName(hostname).build()
        val serverTLS=HandshakeCertificates.Builder().heldCertificate(cert).build()
        val trust=HandshakeCertificates.Builder().addTrustedCertificate(cert.certificate).build()
        val pin=Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(cert.certificate.publicKey.encoded))
        val address=listOf(10,51,1,6).joinToString(".")
        MockWebServer().use { server ->
            server.useHttps(serverTLS.sslSocketFactory())
            server.start(InetAddress.getLoopbackAddress(),0)
            fun check(name:String,hash:String,binding:Boolean=true,systemRoots:Boolean=false):Boolean {
                val proof=HomeWiFiProof.parse(Policy.json.parseToJsonElement(
                    """{"hostname":"$name","port":443,"address":"$address","spkiSha256":"$hash"}"""))
                var bound=false
                // Route exactly this assigned synthetic IP/port to the loopback TLS fixture.
                val socket=object:Socket(){
                    override fun connect(endpoint:SocketAddress,timeout:Int){
                        kotlin.check(bound && endpoint==InetSocketAddress(proof.socketAddress(),443))
                        super.connect(InetSocketAddress(InetAddress.getLoopbackAddress(),server.port),timeout)
                    }
                }
                return HomeWiFiHandshake(proof,{ kotlin.check(binding && !it.isConnected);bound=true },
                    if(systemRoots)null else trust.sslSocketFactory(),socket).verify()
            }
            assertTrue(check(hostname,pin))
            assertFalse(check("other.example.invalid",pin))
            assertFalse(check(hostname,Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32))))
            assertFalse(check(hostname,pin,binding=false))
            assertFalse(check(hostname,pin,systemRoots=true))
            assertEquals(0,server.requestCount)
        }
    }

    @Test fun staleHomeProofCannotCrossLinkAuthorityTimeOrRetryBudget(){
        var now=500L
        val state=HomeWiFiMonitor{now}
        val scope=HomeProofScope(RouteScope(1,2,3,"engine","config"),4,5,"authority",1)
        val next=scope.copy(networkHandle=7)
        state.observe(scope)
        val old=checkNotNull(state.begin(scope))
        var canceled=false
        old.cancel={canceled=true}
        state.observe(next);state.observe(scope)
        assertTrue(canceled);assertNull(state.begin(scope))
        state.finish(old,true,now);assertEquals(0L,state.deadline(scope))
        val active=checkNotNull(state.begin(scope));active.cancel={}
        state.finish(active,true,now)
        assertEquals(180500L,state.deadline(scope));assertEquals(0L,state.deadline(next))
        now=120499;assertNull(state.begin(scope));now++
        val refresh=checkNotNull(state.begin(scope));refresh.cancel={}
        now=180500;assertEquals(0L,state.deadline(scope))
        state.finish(refresh,true,now);assertEquals(0L,state.deadline(scope));assertNull(state.begin(scope))
        now+=30000;val retry=checkNotNull(state.begin(scope));retry.cancel={}
        state.observe(scope.copy(revision=6));state.finish(retry,true,now)
        assertEquals(0L,state.deadline(scope));assertEquals(0L,state.deadline(scope.copy(revision=6)))
    }
}
