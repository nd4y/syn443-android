package io.syn443.identity

import org.junit.AfterClass
import org.junit.Assert.*
import org.junit.BeforeClass
import org.junit.Test
import java.io.IOException
import java.net.InetAddress
import java.net.Socket
import java.nio.file.Files
import java.security.KeyStore
import java.util.concurrent.*
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.*

/** Actual disposable loopback TLS resource/framing tests, not administrative
 * authorization or live API evidence. No external address or account is used. */
class AdminOperationHttpTest {
    private data class Request(val target:String,val headers:Map<String,String>,val body:ByteArray)
    private class Peer(count:Int=1,answer:(Request,SSLSocket)->Unit):AutoCloseable {
        val server=serverContext.serverSocketFactory.createServerSocket(0,2,loopback) as SSLServerSocket
        val origin="https://localhost:${server.localPort}"
        val requests=CopyOnWriteArrayList<Request>()
        val accepted=AtomicInteger()
        private val sockets=CopyOnWriteArrayList<SSLSocket>()
        private val closing=AtomicBoolean()
        private val failure=AtomicReference<Throwable?>()
        private val workers=Executors.newFixedThreadPool(maxOf(1,count+1)) {work->Thread(work,"syn443-operation-tls-fixture").apply {isDaemon=true}}
        private val tasks=CopyOnWriteArrayList<Future<*>>()
        private val accepting=workers.submit {
            try {repeat(count) {
                val socket=server.accept() as SSLSocket;sockets+=socket;accepted.incrementAndGet()
                tasks+=workers.submit {
                    try {
                        socket.soTimeout=5000
                        val input=socket.inputStream.buffered();var budget=32768
                        fun line():String {
                            val text=StringBuilder()
                            while(true) {
                                require(--budget>=0);val value=input.read();require(value>=0)
                                if(value==10){require(text.endsWith("\r"));return text.dropLast(1).toString()}
                                text.append(value.toChar())
                            }
                        }
                        val target=line();val headers=linkedMapOf<String,String>()
                        while(true) {
                            val value=line();if(value.isEmpty())break
                            val key=value.substringBefore(':').lowercase();require(key !in headers)
                            headers[key]=value.substringAfter(':').trim()
                        }
                        val length=headers.getValue("content-length").toInt();require(length in 1..524_288)
                        val body=input.readNBytes(length);require(body.size==length)
                        val request=Request(target,headers.toMap(),body);requests+=request;answer(request,socket)
                    }catch(error:Throwable) {if(!closing.get())failure.compareAndSet(null,error)}
                    finally {runCatching {socket.close()}}
                }
            }}catch(error:Throwable) {if(!closing.get())failure.compareAndSet(null,error)}
        }
        fun finish() {
            accepting.get(5,TimeUnit.SECONDS);tasks.forEach {it.get(5,TimeUnit.SECONDS)}
            failure.get()?.let {throw AssertionError("Owned TLS peer failed",it)}
        }
        override fun close() {
            closing.set(true);runCatching {server.close()};sockets.forEach {runCatching {it.close()}}
            workers.shutdownNow();assertTrue("Owned TLS fixture did not exit",workers.awaitTermination(5,TimeUnit.SECONDS))
        }
    }
    private class Route:HttpRoute {
        val hosts=CopyOnWriteArrayList<String>()
        val sockets=CopyOnWriteArrayList<Socket>()
        val checks=AtomicInteger();val valid=AtomicBoolean(true)
        var resolving:(()->Unit)?=null
        var checking:(()->Unit)?=null
        override fun resolve(host:String):List<InetAddress> {
            hosts+=host
            if(host!="localhost")throw IOException("Unowned fixture host")
            resolving?.invoke();return listOf(loopback)
        }
        override fun bind(socket:Socket) {assertFalse(socket.isConnected);sockets+=socket}
        override fun check() {
            checks.incrementAndGet();checking?.invoke()
            if(!valid.get())throw IOException("Captured fixture route changed")
        }
    }
    private fun send(socket:SSLSocket,raw:ByteArray) {socket.outputStream.write(raw);socket.outputStream.flush()}
    private fun frame(body:ByteArray,status:Int=200)=
        "HTTP/1.1 $status Fixture\r\nContent-Type: application/octet-stream\r\nContent-Length: ${body.size}\r\nConnection: close\r\n\r\n".toByteArray(Charsets.US_ASCII)+body
    private fun failure(action:()->Unit)=assertThrows(DeliveryException::class.java,action).reason

    @Test fun fixedReconcileTlsUsesCapturedRouteAndExactScopedRequestAndReplyBounds() {
        val requestBody=ByteArray(524_288) {(it%251).toByte()};val expected=requestBody.copyOf()
        val responseBody=ByteArray(1_048_576) {((it+1)%251).toByte()}
        val entered=CountDownLatch(1);val proceed=CountDownLatch(1);val route=Route()
        route.resolving={entered.countDown();check(proceed.await(5,TimeUnit.SECONDS))}
        val headers=linkedMapOf("Content-Type" to "application/json","X-Snapshot" to "captured")
        Peer {request,socket->
            assertEquals("POST ${AdminOperationReconcile.PATH} HTTP/1.1",request.target)
            assertEquals("localhost:${socket.localPort}",request.headers["host"])
            assertEquals("524288",request.headers["content-length"]);assertEquals("identity",request.headers["accept-encoding"])
            assertEquals("close",request.headers["connection"]);assertEquals("captured",request.headers["x-snapshot"])
            assertArrayEquals(expected,request.body);send(socket,frame(responseBody))
        }.use {peer->BoundedHttp().use {http->
            // Both old generic ceilings reject before the captured route can resolve.
            assertThrows(IllegalArgumentException::class.java) {
                http.exchange("POST",peer.origin+AdminOperationReconcile.PATH,body=byteArrayOf(1),maxBody=1_048_576,factory=trusted,route=route)
            }
            assertThrows(IllegalArgumentException::class.java) {
                http.exchange("POST",peer.origin+AdminOperationReconcile.PATH,body=requestBody,maxRequestBody=524_288,factory=trusted,route=route)
            }
            assertTrue(route.hosts.isEmpty());assertTrue(route.sockets.isEmpty());assertEquals(0,peer.accepted.get())
            val caller=Executors.newSingleThreadExecutor()
            try {
                val result=caller.submit<Reply> {http.configurationReconcile(peer.origin,headers,requestBody,timeoutMs=10_000,factory=trusted,route=route)}
                assertTrue(entered.await(3,TimeUnit.SECONDS));requestBody.fill(0);headers["X-Snapshot"]="changed"
                proceed.countDown()
                val reply=result.get(10,TimeUnit.SECONDS);assertEquals(200,reply.status);assertArrayEquals(responseBody,reply.body)
                peer.finish();assertEquals(1,peer.accepted.get());assertEquals(listOf("localhost"),route.hosts.toList())
                assertEquals(1,route.sockets.size);assertTrue(route.sockets.all {it.isClosed});assertTrue(route.checks.get()>=6)
            }finally {proceed.countDown();caller.shutdownNow();assertTrue(caller.awaitTermination(5,TimeUnit.SECONDS))}
        }}
    }

    @Test fun reconcileTlsRejectsOversizeOriginAndAmbiguousFramingWithoutFallbackDispatch() {
        Peer(count=0) {_,_->error("Preflight must not accept")}.use {peer->BoundedHttp().use {http->
            val route=Route()
            for(origin in listOf(peer.origin+"/foreign",peer.origin+"/",peer.origin+"?query=1",peer.origin+"#fragment",
                peer.origin.replace("https://","http://"),peer.origin.replace("localhost","user@localhost"))) {
                assertThrows(IllegalArgumentException::class.java) {
                    http.configurationReconcile(origin,emptyMap(),byteArrayOf(1),factory=trusted,route=route)
                }
            }
            for(headers in listOf(mapOf("Origin" to "https://foreign.example.invalid"),mapOf("origin" to ""),
                mapOf("Host" to "foreign"),mapOf("Content-Length" to "1"),mapOf("DPoP" to "a","dpop" to "b"))) {
                assertThrows(IllegalArgumentException::class.java) {
                    http.configurationReconcile(peer.origin,headers,byteArrayOf(1),factory=trusted,route=route)
                }
            }
            for(body in listOf(ByteArray(0),ByteArray(524_289)))assertThrows(IllegalArgumentException::class.java) {
                http.configurationReconcile(peer.origin,emptyMap(),body,factory=trusted,route=route)
            }
            assertTrue(route.hosts.isEmpty());assertTrue(route.sockets.isEmpty());assertEquals(0,peer.accepted.get())
            // A canonical but unowned origin is denied by the captured resolver;
            // the transport is not itself an administrator-origin authorization.
            assertEquals(DeliveryFailure.TRANSPORT,failure {
                http.configurationReconcile("https://unowned.example.invalid",emptyMap(),byteArrayOf(1),factory=trusted,route=route)
            })
            assertEquals(listOf("unowned.example.invalid"),route.hosts.toList());assertTrue(route.sockets.isEmpty());assertEquals(0,peer.accepted.get())
        }}
        val malformed=listOf(
            "HTTP/1.1 200 OK\r\nContent-Length: 1048577\r\n\r\n",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n100001\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx",
            "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\nx",
            "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 0\r\n\r\n",
            "HTTP/1.1 200 OK\nContent-Length: 0\n\n",
            "HTTP/1.1 200 OK\r\n folded: header\r\nContent-Length: 0\r\n\r\n")
        for(raw in malformed)Peer {_,socket->send(socket,raw.toByteArray(Charsets.US_ASCII))}.use {peer->
            BoundedHttp().use {http->
                val route=Route()
                assertEquals(DeliveryFailure.PROTOCOL,failure {
                    http.configurationReconcile(peer.origin,emptyMap(),byteArrayOf(1),timeoutMs=5000,factory=trusted,route=route)
                })
                assertEquals(1,peer.accepted.get());assertEquals(1,peer.requests.size)
                assertEquals(listOf("localhost"),route.hosts.toList());assertEquals(1,route.sockets.size)
                assertTrue(route.sockets.all {it.isClosed})
            }
        }
        // Exercise the actual byte-count ceiling as well as declared lengths:
        // a close-delimited peer really sends the extra byte over owned TLS.
        Peer {_,socket->send(socket,"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n".toByteArray()+ByteArray(1_048_577) {'x'.code.toByte()})}.use {peer->
            BoundedHttp().use {http->
                val route=Route()
                assertEquals(DeliveryFailure.PROTOCOL,failure {
                    http.configurationReconcile(peer.origin,emptyMap(),byteArrayOf(1),timeoutMs=5000,factory=trusted,route=route)
                })
                assertEquals(1,peer.accepted.get());assertEquals(1,peer.requests.size);assertEquals(listOf("localhost"),route.hosts.toList())
                assertTrue(route.sockets.single().isClosed)
            }
        }
        Peer {_,_->error("Untrusted TLS cannot deliver an HTTP request")}.use {peer->
            BoundedHttp().use {http->
                val route=Route()
                assertEquals(DeliveryFailure.TLS,failure {
                    http.configurationReconcile(peer.origin,emptyMap(),byteArrayOf(1),timeoutMs=5000,
                        factory=SSLSocketFactory.getDefault() as SSLSocketFactory,route=route)
                })
                assertEquals(1,peer.accepted.get());assertTrue(peer.requests.isEmpty());assertEquals(listOf("localhost"),route.hosts.toList())
                assertTrue(route.sockets.single().isClosed)
            }
        }
        Peer {_,socket->send(socket,"HTTP/1.1 302 Found\r\nLocation: https://unowned.example.invalid/\r\nContent-Length: 0\r\n\r\n".toByteArray())}.use {peer->
            BoundedHttp().use {http->
                val route=Route();val reply=http.configurationReconcile(peer.origin,emptyMap(),byteArrayOf(1),factory=trusted,route=route)
                assertEquals(302,reply.status);assertTrue(reply.body.isEmpty());peer.finish()
                assertEquals(1,peer.accepted.get());assertEquals(listOf("localhost"),route.hosts.toList())
            }
        }
    }

    @Test fun cancelledOrInvalidatedTlsReadsRetainActualWorkerOwnershipUntilExit() {
        for(cancel in listOf(true,false)) {
            val partial=CountDownLatch(1);val finishBody=CountDownLatch(1);val scope=BoundedHttp.Scope();val route=Route()
            Peer {_,socket->
                send(socket,"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nx".toByteArray());partial.countDown()
                check(finishBody.await(5,TimeUnit.SECONDS));send(socket,byteArrayOf('y'.code.toByte()))
            }.use {peer->BoundedHttp().use {http->
                val caller=Executors.newSingleThreadExecutor()
                try {
                    val result=caller.submit<DeliveryFailure> {failure {http.configurationReconcile(peer.origin,emptyMap(),byteArrayOf(1),scope,5000,trusted,route)}}
                    assertTrue(partial.await(3,TimeUnit.SECONDS));assertFalse(result.isDone)
                    if(cancel)scope.cancel() else {route.valid.set(false);finishBody.countDown()}
                    assertEquals(if(cancel)DeliveryFailure.CANCELLED else DeliveryFailure.TRANSPORT,result.get(3,TimeUnit.SECONDS))
                    assertEquals(1,peer.accepted.get());assertEquals(1,route.sockets.size);assertTrue(route.sockets.single().isClosed)
                }finally {scope.cancel();finishBody.countDown();caller.shutdownNow();assertTrue(caller.awaitTermination(5,TimeUnit.SECONDS))}
            }}
        }
        val partial=CountDownLatch(2);val finishBodies=CountDownLatch(1);val finalChecks=CountDownLatch(2);val releaseOwners=CountDownLatch(1)
        val ownersExited=CountDownLatch(2);val active=AtomicInteger();val peak=AtomicInteger()
        val armed=List(2) {AtomicBoolean()};val scopes=List(2) {BoundedHttp.Scope()}
        val routes=List(2) {index->Route().apply {checking={
            if(armed[index].get()) {
                val count=active.incrementAndGet();peak.accumulateAndGet(count,::maxOf);finalChecks.countDown()
                try {while(releaseOwners.count>0)try {releaseOwners.await()}catch(_:InterruptedException) {}}
                finally {active.decrementAndGet();ownersExited.countDown()}
            }
        }}}
        Peer(count=2) {request,socket->
            val owner=request.headers.getValue("x-owner").toInt();armed[owner].set(true)
            send(socket,"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nx".toByteArray());partial.countDown()
            check(finishBodies.await(5,TimeUnit.SECONDS));send(socket,byteArrayOf('y'.code.toByte()))
        }.use {peer->BoundedHttp().use {http->
            val callers=Executors.newFixedThreadPool(3);val queuedScope=BoundedHttp.Scope();val resolutions=AtomicInteger()
            val empty=object:HttpRoute {
                override fun resolve(host:String):List<InetAddress> {resolutions.incrementAndGet();return emptyList()}
                override fun bind(socket:Socket) {error("Empty owned route cannot bind")}
                override fun check()=Unit
            }
            try {
                val running=(0..1).map {index->callers.submit<DeliveryFailure> {failure {
                    http.configurationReconcile(peer.origin,mapOf("X-Owner" to index.toString()),byteArrayOf(1),scopes[index],10_000,trusted,routes[index])
                }}}
                assertTrue(partial.await(3,TimeUnit.SECONDS));assertTrue(running.none {it.isDone})
                finishBodies.countDown();assertTrue(finalChecks.await(3,TimeUnit.SECONDS));assertEquals(2,active.get())
                scopes.forEach {it.cancel()};running.forEach {assertEquals(DeliveryFailure.CANCELLED,it.get(2,TimeUnit.SECONDS))}
                assertEquals(2,active.get());assertEquals(2,peak.get())
                val queued=callers.submit<DeliveryFailure> {failure {http.configurationReconcile(peer.origin,emptyMap(),byteArrayOf(1),queuedScope,5000,trusted,empty)}}
                val until=System.nanoTime()+TimeUnit.SECONDS.toNanos(1)
                while(http.waitingRequests==0 && System.nanoTime()<until)Thread.yield()
                assertEquals(1,http.waitingRequests);assertEquals(0,resolutions.get())
                assertEquals(DeliveryFailure.CAPACITY,failure {http.configurationReconcile(peer.origin,emptyMap(),byteArrayOf(1),timeoutMs=100,factory=trusted,route=empty)})
                queuedScope.cancel();assertEquals(DeliveryFailure.CANCELLED,queued.get(2,TimeUnit.SECONDS))
                repeat(2) {assertEquals(DeliveryFailure.DEADLINE,failure {http.configurationReconcile(peer.origin,emptyMap(),byteArrayOf(1),timeoutMs=50,factory=trusted,route=empty)})}
                assertEquals(0,resolutions.get());assertEquals(2,active.get());assertEquals(2,peer.accepted.get())
                releaseOwners.countDown();assertTrue(ownersExited.await(3,TimeUnit.SECONDS))
                repeat(2) {assertEquals(DeliveryFailure.DNS,failure {http.configurationReconcile(peer.origin,emptyMap(),byteArrayOf(1),timeoutMs=3000,factory=trusted,route=empty)})}
                assertEquals(2,resolutions.get());assertEquals(0,active.get());assertTrue(routes.flatMap {it.sockets}.all {it.isClosed})
            }finally {
                finishBodies.countDown();releaseOwners.countDown();scopes.forEach {it.cancel()};queuedScope.cancel()
                callers.shutdownNow();assertTrue(callers.awaitTermination(5,TimeUnit.SECONDS))
            }
        }}
    }

    companion object {
        private val loopback=InetAddress.getByAddress(byteArrayOf(127,0,0,1))
        private val directory=Files.createTempDirectory("syn443-operation-http")
        private val file=directory.resolve("fixture.p12")
        private val password="synthetic-test-fixture".toCharArray()
        private lateinit var serverContext:SSLContext
        private lateinit var trusted:SSLSocketFactory
        @BeforeClass @JvmStatic fun prepare() {
            val process=ProcessBuilder(java.nio.file.Path.of(System.getProperty("java.home"),"bin","keytool").toString(),
                "-genkeypair","-alias","fixture","-keyalg","EC","-groupname","secp256r1","-storetype","PKCS12",
                "-keystore",file.toString(),"-storepass",String(password),"-dname","CN=localhost","-ext","SAN=dns:localhost","-validity","1","-noprompt")
                .redirectOutput(ProcessBuilder.Redirect.DISCARD).redirectError(ProcessBuilder.Redirect.DISCARD).start()
            val finished=process.waitFor(15,TimeUnit.SECONDS)
            if(!finished){process.destroyForcibly();process.waitFor(5,TimeUnit.SECONDS)}
            assertTrue(finished);assertEquals(0,process.exitValue())
            val store=KeyStore.getInstance("PKCS12").apply {Files.newInputStream(file).use {load(it,password)}}
            val km=KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply {init(store,password)}
            val tm=TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply {init(store)}
            serverContext=SSLContext.getInstance("TLS").apply {init(km.keyManagers,null,null)}
            trusted=SSLContext.getInstance("TLS").apply {init(null,tm.trustManagers,null)}.socketFactory
        }
        @AfterClass @JvmStatic fun clean() {Files.deleteIfExists(file);Files.deleteIfExists(directory)}
    }
}
