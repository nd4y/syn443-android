package io.syn443.identity

import org.junit.Assert.*
import org.junit.Test
import org.junit.BeforeClass
import org.junit.AfterClass
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.file.Files
import java.security.KeyStore
import java.util.concurrent.*
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ssl.*
import io.syn443.policy.Canonical
import kotlinx.serialization.json.*

class BoundedHttpTest {
    companion object {
        private val directory=Files.createTempDirectory("syn443-identity-tls")
        private val file=directory.resolve("fixture.p12")
        private val password="synthetic-test-fixture".toCharArray()
        private lateinit var serverContext:SSLContext
        private lateinit var trusted:SSLSocketFactory
        @BeforeClass @JvmStatic fun prepare() {
            val process=ProcessBuilder(java.nio.file.Path.of(System.getProperty("java.home"),"bin","keytool").toString(),
                "-genkeypair","-alias","fixture","-keyalg","EC","-groupname","secp256r1","-storetype","PKCS12",
                "-keystore",file.toString(),"-storepass",String(password),"-dname","CN=localhost","-ext","SAN=dns:localhost","-validity","1","-noprompt")
                .redirectOutput(ProcessBuilder.Redirect.DISCARD).redirectError(ProcessBuilder.Redirect.DISCARD).start()
            assertTrue(process.waitFor(15,TimeUnit.SECONDS));assertEquals(0,process.exitValue())
            val store=KeyStore.getInstance("PKCS12").apply {Files.newInputStream(file).use {load(it,password)}}
            val km=KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply {init(store,password)}
            val tm=TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply {init(store)}
            serverContext=SSLContext.getInstance("TLS").apply {init(km.keyManagers,null,null)}
            trusted=SSLContext.getInstance("TLS").apply {init(null,tm.trustManagers,null)}.socketFactory
        }
        @AfterClass @JvmStatic fun clean() {Files.deleteIfExists(file);Files.deleteIfExists(directory)}
        private fun reply(raw:String,max:Int=65536)=response(raw.byteInputStream(Charsets.US_ASCII),max)
        private fun rejected(raw:String) {assertThrows(Exception::class.java) {reply(raw)}}
    }
    @Test fun strictHttpFramingBoundsAndContentArePreserved() {
        assertEquals("test",String(reply("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ntest").body))
        assertEquals("test",String(reply("HTTP/1.0 200\r\n\r\ntest").body))
        assertEquals("test",String(reply("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nte\r\n2\r\nst\r\n0\r\n\r\n").body))
        assertEquals(0,reply("HTTP/1.1 204 No Content\r\n\r\n").body.size)
        assertEquals(302,reply("HTTP/1.1 302 Found\r\nLocation: https://other.example.invalid\r\nContent-Length: 0\r\n\r\n").status)
        val value=reply("HTTP/1.1 401 Unauthorized\r\nDPoP-Nonce: challenge\r\nContent-Length: 0\r\n\r\n")
        assertEquals("challenge",value.single("dpop-nonce"));assertNull(value.single("absent"))
        val trailers=reply("HTTP/1.1 401 Unauthorized\r\nDPoP-Nonce: initial\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nDPoP-Nonce: ignored\r\n\r\n")
        assertEquals("initial",trailers.single("dpop-nonce"))
    }
    @Test fun ambiguousMalformedAndOversizedFramesCannotBecomeSuccess() {
        for(raw in listOf("HTTP/1.1 200 OK\n\n","HTTP/1.1 200 OK\r\nDPoP-Nonce: invalid\rbare\r\n\r\n","HTTP/1.1 100 Continue\r\n\r\n","HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\nok",
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n","HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n","HTTP/1.1 200 OK\r\n bad: folded\r\n\r\n","HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nshort".dropLast(2),
            "HTTP/1.1 204 No Content\r\nContent-Length: 1\r\n\r\nx","HTTP/1.1 200 OK\r\nX-Large: "+"x".repeat(16384)+"\r\n\r\n",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nz\r\n","HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nxBAD\r\n0\r\n\r\n")) rejected(raw)
        assertThrows(DeliveryException::class.java) {reply("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n12345",4)}
        assertThrows(DeliveryException::class.java) {reply("HTTP/1.1 200 OK\r\n\r\n12345",4)}
        assertThrows(DeliveryException::class.java) {reply("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n12345\r\n0\r\n\r\n",4)}
        assertThrows(DeliveryException::class.java) {reply("HTTP/1.1 401 Unauthorized\r\nDPoP-Nonce: first\r\nDPoP-Nonce: second\r\n\r\n").single("dpop-nonce")}
    }
    private fun tlsRequest(host:String="localhost",factory:SSLSocketFactory=trusted,status:Int=200,body:ByteArray?=null):Reply {
        val server=serverContext.serverSocketFactory.createServerSocket(0,2,InetAddress.getByName("127.0.0.1")) as SSLServerSocket
        val worker=Executors.newSingleThreadExecutor {r->Thread(r).apply {isDaemon=true}}
        val serving=worker.submit {runCatching {server.accept().use {socket->socket.soTimeout=2000
            val input=socket.inputStream.buffered();var size=0;var first=true;var length=0
            fun line():String {val text=StringBuilder();while(true){val c=input.read();require(c>=0 && ++size<32768);if(c==10)return text.toString().trimEnd('\r');text.append(c.toChar())}}
            while(true) {val text=line();if(first){assertTrue(text.startsWith((if(body==null)"GET" else "POST")+" /test HTTP/1.1"));first=false};if(text.startsWith("Content-Length: "))length=text.substringAfter(": ").toInt();if(text.isEmpty())break}
            if(body!=null) {assertEquals(body.size,length);assertArrayEquals(body,input.readNBytes(length))}
            socket.outputStream.write("HTTP/1.1 $status Test\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".toByteArray())
        }}}
        return try {BoundedHttp().use {it.exchange(if(body==null)"GET" else "POST","https://$host:${server.localPort}/test",body=body,factory=factory)}}
        finally {server.close();serving.get(4,TimeUnit.SECONDS);worker.shutdownNow()}
    }
    @Test fun actualTlsUsesTrustAndHostnameVerificationAndDoesNotFollowRedirects() {
        assertEquals("ok",String(tlsRequest().body))
        assertEquals("ok",String(tlsRequest(body="Привет".toByteArray(Charsets.UTF_8)).body))
        assertEquals(302,tlsRequest(status=302).status)
        assertEquals(DeliveryFailure.TLS,assertThrows(DeliveryException::class.java){tlsRequest(factory=SSLSocketFactory.getDefault() as SSLSocketFactory)}.reason)
        assertEquals(DeliveryFailure.TLS,assertThrows(DeliveryException::class.java){tlsRequest(host="127.0.0.1")}.reason)
    }
    @Test fun absoluteDeadlineAndExplicitCancelCloseAStalledTlsSocket() {
        for(cancel in listOf(false,true)) {
            val server=ServerSocket(0,2,InetAddress.getByName("127.0.0.1"));val accepted=CountDownLatch(1);val stop=CountDownLatch(1)
            val serving=Executors.newSingleThreadExecutor {r->Thread(r).apply {isDaemon=true}}
            val task=serving.submit {server.accept().use {accepted.countDown();stop.await(3,TimeUnit.SECONDS)}}
            val caller=Executors.newSingleThreadExecutor();val scope=BoundedHttp.Scope()
            try {BoundedHttp().use {client->
                val result=caller.submit<DeliveryFailure> {try {client.exchange("GET","https://localhost:${server.localPort}/",scope=scope,timeoutMs=if(cancel)2000 else 200);error("stall passed")}catch(e:DeliveryException){e.reason}}
                assertTrue(accepted.await(2,TimeUnit.SECONDS));val start=System.nanoTime();if(cancel)scope.cancel()
                assertEquals(if(cancel)DeliveryFailure.CANCELLED else DeliveryFailure.DEADLINE,result.get(800,TimeUnit.MILLISECONDS))
                assertTrue(TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-start)<750)
            }} finally {scope.cancel();stop.countDown();server.close();task.get(4,TimeUnit.SECONDS);serving.shutdownNow();caller.shutdownNow()}
        }
    }
    @Test fun nonInterruptibleResolutionCannotGrowWorkersOrRetainWaitingRetries() {
        val active=AtomicInteger();val peak=AtomicInteger();val entered=CountDownLatch(2);val release=CountDownLatch(1)
        val callers=Executors.newFixedThreadPool(2)
        BoundedHttp().use {client->
            val connector:(Socket,java.net.URI,Int)->Unit={_,_,_->val n=active.incrementAndGet();peak.accumulateAndGet(n,::maxOf);entered.countDown();while(release.count>0)try{release.await()}catch(_:InterruptedException){};active.decrementAndGet();throw java.net.UnknownHostException("synthetic")}
            try {
                val a=callers.submit<DeliveryFailure>{try{client.exchange("GET","https://dns.example.invalid/",timeoutMs=150,connect=connector);error("DNS passed")}catch(e:DeliveryException){e.reason}}
                val b=callers.submit<DeliveryFailure>{try{client.exchange("GET","https://dns.example.invalid/",timeoutMs=150,connect=connector);error("DNS passed")}catch(e:DeliveryException){e.reason}}
                assertTrue(entered.await(2,TimeUnit.SECONDS));assertEquals(DeliveryFailure.DEADLINE,a.get(1,TimeUnit.SECONDS));assertEquals(DeliveryFailure.DEADLINE,b.get(1,TimeUnit.SECONDS))
                val queuedScope=BoundedHttp.Scope()
                val queued=callers.submit<DeliveryFailure>{try{client.exchange("GET","https://dns.example.invalid/",scope=queuedScope,timeoutMs=1000,connect=connector);error("queued DNS passed")}catch(e:DeliveryException){e.reason}}
                val until=System.nanoTime()+TimeUnit.MILLISECONDS.toNanos(300)
                while(client.waitingRequests==0 && System.nanoTime()<until)Thread.yield()
                assertEquals(1,client.waitingRequests)
                assertEquals(DeliveryFailure.CAPACITY,assertThrows(DeliveryException::class.java){client.exchange("GET","https://dns.example.invalid/",timeoutMs=30,connect=connector)}.reason)
                queuedScope.cancel();assertEquals(DeliveryFailure.CANCELLED,queued.get(1,TimeUnit.SECONDS))
                repeat(3) {assertEquals(DeliveryFailure.DEADLINE,assertThrows(DeliveryException::class.java){client.exchange("GET","https://dns.example.invalid/",timeoutMs=30,connect=connector)}.reason)}
                assertEquals(2,peak.get())
            } finally {release.countDown();callers.shutdownNow()}
        }
    }
    @Test fun callerInputsAndResponseAuthorityHeadersAreBounded() {
        BoundedHttp().use {client->
            for(header in listOf(mapOf("Host" to "other"),mapOf("DPoP" to "a\r\nb"),mapOf("DPoP" to "a","dpop" to "b")))
                assertThrows(IllegalArgumentException::class.java){client.exchange("GET","https://api.example.invalid/",headers=header)}
            assertThrows(IllegalArgumentException::class.java){client.exchange("GET","https://api.example.invalid/",body=byteArrayOf())}
            assertThrows(IllegalArgumentException::class.java){client.exchange("POST","https://api.example.invalid/",body=ByteArray(8193))}
            val scope=BoundedHttp.Scope();scope.cancel()
            assertEquals(DeliveryFailure.CANCELLED,assertThrows(DeliveryException::class.java){client.exchange("GET","https://api.example.invalid/",scope=scope)}.reason)
        }
    }
    @Test fun workerFailuresAreFixedCategoriesAndCallerInterruptionIsPreserved() {
        BoundedHttp().use {client->
            for((cause,expected) in listOf(java.net.UnknownHostException("sensitive fixture detail") to DeliveryFailure.DNS,
                java.net.SocketTimeoutException("sensitive fixture detail") to DeliveryFailure.DEADLINE,
                java.io.EOFException("sensitive fixture detail") to DeliveryFailure.EOF,
                java.io.IOException("sensitive fixture detail") to DeliveryFailure.TRANSPORT,
                DeliveryException(DeliveryFailure.PROTOCOL) to DeliveryFailure.PROTOCOL)) {
                val error=assertThrows(DeliveryException::class.java) {client.exchange("GET","https://api.example.invalid/",connect={_,_,_->throw cause})}
                assertEquals(expected,error.reason);assertEquals(expected.name,error.message);assertNull(error.cause)
            }
            try {
                Thread.currentThread().interrupt()
                val error=assertThrows(DeliveryException::class.java){client.exchange("GET","https://api.example.invalid/",connect={_,_,_->throw java.io.IOException("synthetic")})}
                assertEquals(DeliveryFailure.CANCELLED,error.reason);assertTrue(Thread.currentThread().isInterrupted)
            } finally {Thread.interrupted()}
        }
    }
    @Test fun issuerDiscoveryUsesFreshSocketScopesThroughRealTlsRequests() {
        val ec=java.security.KeyPairGenerator.getInstance("EC").apply {initialize(java.security.spec.ECGenParameterSpec("secp256r1"))}.generateKeyPair()
        val rsa=java.security.KeyPairGenerator.getInstance("RSA").apply {initialize(2048)}.generateKeyPair().public as java.security.interfaces.RSAPublicKey
        val key=object:ProofKey {
            override val publicKey=ec.public as java.security.interfaces.ECPublicKey
            override fun sign(input:ByteArray)=error("Discovery must not request a device signature")
        }
        val server=serverContext.serverSocketFactory.createServerSocket(0,2,InetAddress.getByName("127.0.0.1")) as SSLServerSocket
        val issuer="https://localhost:${server.localPort}/realms/test"
        val bootstrap=Bootstrap("tls-fixture",issuer,"syn443-android","https://api.example.invalid",
            mapOf("test-root" to java.util.Base64.getEncoder().encodeToString(ec.public.encoded)))
        val discovery=Canonical.encode(buildJsonObject {
            put("issuer",issuer);put("authorization_endpoint",issuer+"/protocol/openid-connect/auth")
            put("token_endpoint",issuer+"/protocol/openid-connect/token");put("jwks_uri",issuer+"/protocol/openid-connect/certs")
            put("id_token_signing_alg_values_supported",JsonArray(listOf(JsonPrimitive("RS256"))))
            put("dpop_signing_alg_values_supported",JsonArray(listOf(JsonPrimitive("ES256"))))
            put("code_challenge_methods_supported",JsonArray(listOf(JsonPrimitive("S256"))))
        })
        val keys=Canonical.encode(buildJsonObject {putJsonArray("keys") {add(buildJsonObject {
            put("kid","fixture");put("kty","RSA");put("alg","RS256");put("use","sig");put("e","AQAB")
            put("n",Identity.encode(rsa.modulus.toByteArray().let {if(it.first()==0.toByte())it.drop(1).toByteArray() else it}))
        })}})
        val worker=Executors.newSingleThreadExecutor()
        val serving=worker.submit {
            for((path,body) in listOf("/realms/test/.well-known/openid-configuration" to discovery,"/realms/test/protocol/openid-connect/certs" to keys)) {
                server.accept().use {socket->
                    socket.soTimeout=2000;val reader=socket.inputStream.bufferedReader(Charsets.US_ASCII)
                    assertEquals("GET $path HTTP/1.1",reader.readLine());var lines=0
                    while(!reader.readLine().isNullOrEmpty())check(++lines<=20)
                    val date=java.time.format.DateTimeFormatter.ofPattern("EEE, dd MMM uuuu HH:mm:ss 'GMT'",java.util.Locale.US)
                        .withZone(java.time.ZoneOffset.UTC).format(java.time.Instant.now())
                    val data=body.toByteArray(Charsets.UTF_8)
                    socket.outputStream.write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nDate: $date\r\nContent-Length: ${data.size}\r\n\r\n".toByteArray(Charsets.US_ASCII))
                    socket.outputStream.write(data);socket.outputStream.flush()
                }
            }
        }
        try {BoundedHttp().use {transport->
            val client=AuthProtocol(bootstrap,key,IdentityExchange {m,u,h,body,scope,max->transport.exchange(m,u,h,body,scope,factory=trusted,maxBody=max)},
                {2},{System.nanoTime()/1_000_000})
            val scope=IdentityScope();assertEquals(setOf("fixture"),client.discover(scope).keys.keys)
            scope.cancel();assertEquals(AuthFailure.CANCELLED,assertThrows(AuthException::class.java){client.discover(scope)}.reason)
            serving.get(5,TimeUnit.SECONDS)
        }} finally {server.close();worker.shutdownNow()}
    }
}
