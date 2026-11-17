package io.syn443.identity

import org.junit.Assert.*
import org.junit.Test
import java.io.EOFException
import java.io.IOException
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/** Actual loopback I/O and existing Scope/route injection only. No TLS trust,
 * default DNS, private field access or production worker replacement seam. */
class BoundedHttpCancellationRaceTest {
    private class OwnedSocket:AutoCloseable {
        private val loopback=InetAddress.getByAddress(byteArrayOf(127,0,0,1))
        private val listener=ServerSocket(0,2,loopback)
        private val connection=Socket(loopback,listener.localPort)
        val peer:Socket=listener.accept()
        val closing=CountDownLatch(1)
        val releaseClose=CountDownLatch(1)
        val gatedCancelThread=AtomicReference<Thread?>()
        val socket=object:Socket() {
            override fun getInputStream()=connection.getInputStream()
            override fun close() {
                try {connection.close();super.close()}
                finally {
                    // The HTTP worker's finally must never wait on this gate.
                    if(Thread.currentThread()===gatedCancelThread.get()) {
                        closing.countDown()
                        check(releaseClose.await(5,TimeUnit.SECONDS)) {"fixture_cancel_close_deadline"}
                    }
                }
            }
        }
        val isClosed:Boolean get()=connection.isClosed
        override fun close() {
            releaseClose.countDown();socket.close();peer.close();listener.close()
        }
    }
    private class ReadRoute(private val socket:Socket,private val retire:()->Unit={}) :HttpRoute {
        val entered=CountDownLatch(1)
        val ioFailure=AtomicReference<IOException?>()
        override fun resolve(host:String):List<InetAddress> = error("fixture_read_must_fail_before_dns")
        override fun bind(socket:Socket)=error("fixture_read_must_fail_before_bind")
        override fun check() {
            entered.countDown()
            try {
                if(socket.getInputStream().read()<0)throw EOFException("fixture_eof")
                error("fixture_unexpected_data")
            } catch(error:IOException) {
                ioFailure.set(error);throw error
            } finally {retire()}
        }
    }
    private fun call(client:BoundedHttp,scope:BoundedHttp.Scope,route:HttpRoute):DeliveryFailure = try {
        client.exchange("GET","https://socket-race.example.invalid/",scope=scope,route=route,timeoutMs=10_000)
        error("fixture_read_unexpected_success")
    }catch(error:DeliveryException) {error.reason}
    private fun reached(latch:CountDownLatch)=assertTrue("owned barrier not reached",latch.await(2,TimeUnit.SECONDS))
    private fun until(predicate:()->Boolean) {
        val deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(2)
        while(System.nanoTime()<deadline) {if(predicate())return;Thread.yield()}
        assertTrue("owned state deadline",predicate())
    }
    private fun callerWaiting(thread:AtomicReference<Thread?>) = until {
        // Worker entry can precede Scope.bind. Waiting in the real caller's
        // Future.get proves the bind completed; no stack values are logged.
        val frames=thread.get()?.stackTrace?:emptyArray()
        frames.any {it.className=="java.util.concurrent.FutureTask" && it.methodName=="get"} &&
            frames.any {it.className=="io.syn443.identity.BoundedHttp" && it.methodName=="exchangeUri"}
    }

    @Test fun cancelledSocketFailureCannotOvertakeExplicitCancelBeforeFutureCancellation() {
        OwnedSocket().use {owned->BoundedHttp().use {client->
            val scope=BoundedHttp.Scope();scope.attach(owned.socket)
            val route=ReadRoute(owned.socket)
            val caller=Executors.newSingleThreadExecutor();val canceller=Executors.newSingleThreadExecutor()
            val thread=AtomicReference<Thread?>()
            var cancellation:Future<*>?=null
            try {
                val result=caller.submit<DeliveryFailure> {thread.set(Thread.currentThread());call(client,scope,route)}
                reached(route.entered);callerWaiting(thread)
                val cancellationTask=canceller.submit {owned.gatedCancelThread.set(Thread.currentThread());scope.cancel()}
                cancellation=cancellationTask
                reached(owned.closing)
                // The raw socket has actually closed; the cancel thread is
                // still inside close and cannot yet call Future.cancel.
                assertEquals(DeliveryFailure.CANCELLED,result.get(2,TimeUnit.SECONDS))
                assertTrue(route.ioFailure.get() is SocketException)
                assertTrue(owned.isClosed);assertFalse(cancellationTask.isDone)
                owned.releaseClose.countDown();cancellationTask.get(2,TimeUnit.SECONDS)
            }finally {
                owned.releaseClose.countDown();scope.cancel();cancellation?.get(2,TimeUnit.SECONDS)
                caller.shutdownNow();canceller.shutdownNow()
                assertTrue(caller.awaitTermination(2,TimeUnit.SECONDS));assertTrue(canceller.awaitTermination(2,TimeUnit.SECONDS))
            }
        }}
    }
    @Test fun uncancelledSocketResetKeepsTransportClassificationAndDoesNotInventCancellation() {
        OwnedSocket().use {owned->BoundedHttp().use {client->
            val scope=BoundedHttp.Scope();scope.attach(owned.socket)
            val route=ReadRoute(owned.socket);val caller=Executors.newSingleThreadExecutor()
            val thread=AtomicReference<Thread?>()
            try {
                val result=caller.submit<DeliveryFailure> {thread.set(Thread.currentThread());call(client,scope,route)}
                reached(route.entered);callerWaiting(thread)
                owned.peer.setSoLinger(true,0);owned.peer.close()
                assertEquals(DeliveryFailure.TRANSPORT,result.get(2,TimeUnit.SECONDS))
                assertTrue(route.ioFailure.get() is SocketException);assertTrue(owned.isClosed)
            }finally {
                scope.cancel();caller.shutdownNow();assertTrue(caller.awaitTermination(2,TimeUnit.SECONDS))
            }
        }}
    }
    @Test fun cancelledButUnretiredSocketWorkersRetainBothPermitsAndQueuedCapacity() {
        val first=OwnedSocket();val second=OwnedSocket();val client=BoundedHttp()
        val scopes=listOf(BoundedHttp.Scope(),BoundedHttp.Scope())
        val enteredRetirement=CountDownLatch(2);val releaseRetirement=CountDownLatch(1);val exited=CountDownLatch(2)
        val actualWorkers=AtomicInteger();val startedWorkers=AtomicInteger();val unexpectedReplacement=AtomicInteger()
        val callers=Executors.newFixedThreadPool(3)
        val queuedScope=BoundedHttp.Scope()
        fun retire() {
            enteredRetirement.countDown()
            try {
                val deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(5)
                while(releaseRetirement.count>0) {
                    check(System.nanoTime()<deadline) {"fixture_retirement_deadline"}
                    try {releaseRetirement.await(25,TimeUnit.MILLISECONDS)}catch(_:InterruptedException) { /* Actual owner remains. */ }
                }
            }finally {actualWorkers.decrementAndGet();exited.countDown()}
        }
        val routes=listOf(first,second).map {owned->
            val read=ReadRoute(owned.socket,::retire)
            object:HttpRoute {
                override fun resolve(host:String)=read.resolve(host)
                override fun bind(socket:Socket)=read.bind(socket)
                override fun check() {startedWorkers.incrementAndGet();actualWorkers.incrementAndGet();read.check()}
            } to read
        }
        try {
            val results=listOf(first,second).mapIndexed {index,owned->
                scopes[index].attach(owned.socket)
                callers.submit<DeliveryFailure> {call(client,scopes[index],routes[index].first)}
            }
            routes.forEach {reached(it.second.entered)}
            scopes.forEach {it.cancel()};reached(enteredRetirement)
            results.forEach {assertEquals(DeliveryFailure.CANCELLED,it.get(2,TimeUnit.SECONDS))}
            assertEquals(2,actualWorkers.get());assertEquals(2L,exited.count)
            assertTrue(first.isClosed && second.isClosed)
            val unexpected=object:HttpRoute {
                override fun resolve(host:String):List<InetAddress> = error("fixture_queued_dns")
                override fun bind(socket:Socket)=error("fixture_queued_bind")
                override fun check() {unexpectedReplacement.incrementAndGet();throw IOException("fixture_replacement")}
            }
            val queued=callers.submit<DeliveryFailure> {call(client,queuedScope,unexpected)}
            until {client.waitingRequests==1}
            assertEquals(DeliveryFailure.CAPACITY,call(client,BoundedHttp.Scope(),unexpected))
            queuedScope.cancel();assertEquals(DeliveryFailure.CANCELLED,queued.get(2,TimeUnit.SECONDS))
            until {client.waitingRequests==0}
            assertEquals(2,startedWorkers.get());assertEquals(2,actualWorkers.get());assertEquals(0,unexpectedReplacement.get())
            releaseRetirement.countDown();reached(exited)
        }finally {
            releaseRetirement.countDown();queuedScope.cancel();scopes.forEach {it.cancel()}
            callers.shutdownNow();client.close();first.close();second.close()
            assertTrue(callers.awaitTermination(2,TimeUnit.SECONDS));reached(exited)
        }
    }
}
