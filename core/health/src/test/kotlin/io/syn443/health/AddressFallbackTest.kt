package io.syn443.health

import io.syn443.policy.Check
import org.junit.Assert.*
import org.junit.Test
import java.io.ByteArrayInputStream
import java.net.*
import java.util.concurrent.*
import java.util.concurrent.atomic.AtomicInteger

class AddressFallbackTest {
    private val check=Check("banner","tcp_banner","probe.example.invalid",443,"HELLO")
    private val v4=InetAddress.getByAddress(byteArrayOf(127,0,0,1))
    private val v6=InetAddress.getByAddress(ByteArray(16).apply {this[15]=1})
    private class ScriptedSocket(val attempt:(SocketAddress,Int)->Unit):Socket() {
        override fun connect(endpoint:SocketAddress,timeout:Int)=attempt(endpoint,timeout)
        override fun getInputStream()=ByteArrayInputStream("HELLO".toByteArray())
    }
    @Test fun unavailableFirstFamilyFallsBackWithoutExtraWorkersOrLeakedSockets() {
        val endpoints=mutableListOf<InetAddress>();val sockets=mutableListOf<Socket>()
        val anotherV6=InetAddress.getByAddress(ByteArray(16).apply {this[15]=2})
        val probe=NetworkProbe(resolve={listOf(v6,anotherV6,v4)},socketFactory={
            ScriptedSocket {endpoint,timeout->
                val address=(endpoint as InetSocketAddress).address;endpoints+=address
                if(address==v6) {assertEquals(500,timeout);throw SocketTimeoutException()}
            }.also {sockets+=it}
        })
        ProbePool().use {pool->
            assertEquals(Outcome.PASS,CheckJob(pool,probe).run(listOf(check)).outcomes.single())
            assertTrue(pool.counters().getValue("workers")<=2)
        }
        assertEquals(listOf(v6,v4),endpoints);assertEquals(2,sockets.size);assertTrue(sockets.all {it.isClosed})
    }
    @Test fun connectionFailureTriesOnlyFourDistinctAddressesAndKeepsFailureAttribution() {
        val sockets=mutableListOf<Socket>();val visited=mutableListOf<InetAddress>()
        val answers=(1..20).map {InetAddress.getByAddress(byteArrayOf(198.toByte(),51,100,it.toByte()))}
        ProbePool().use {pool->
            val job=CheckJob(pool,NetworkProbe(resolve={listOf(answers[0])+answers},socketFactory={
                ScriptedSocket {endpoint,timeout->visited+=(endpoint as InetSocketAddress).address
                    assertTrue(timeout in 1..3_000);throw ConnectException()}.also {sockets+=it}
            }))
            assertEquals(Outcome.FAIL,job.run(listOf(check)).outcomes.single())
            assertEquals(Stage.CONNECT,job.failureStage);assertEquals(Failure.TRANSPORT,job.failure)
        }
        assertEquals(answers.take(4),visited);assertTrue(sockets.all {it.isClosed})
    }
    @Test fun emptyDnsResultDoesNotAllocateSocketAndRemainsDnsFailure() {
        ProbePool().use {pool->
            val job=CheckJob(pool,NetworkProbe(resolve={emptyList()},socketFactory={error("no resolved address")}))
            assertEquals(Outcome.FAIL,job.run(listOf(check)).outcomes.single())
            assertEquals(Failure.DNS,job.failure);assertEquals(Stage.RESOLVE,job.failureStage)
        }
    }
    @Test fun cancellationClosesCurrentAttemptAndCannotStartAnAlternative() {
        val entered=CountDownLatch(1);val release=CountDownLatch(1);val created=AtomicInteger()
        val first=ScriptedSocket {_,_->entered.countDown();release.await()}
        val caller=Executors.newSingleThreadExecutor()
        ProbePool().use {pool->
            val job=CheckJob(pool,NetworkProbe(resolve={listOf(v6,v4)},socketFactory={created.incrementAndGet();first}))
            try {
                val result=caller.submit<Batch> {job.run(listOf(check))}
                assertTrue(entered.await(2,TimeUnit.SECONDS));job.cancel()
                assertEquals(Outcome.CANCELLED,result.get(2,TimeUnit.SECONDS).outcomes.single())
                assertTrue(first.isClosed);assertEquals(1,created.get())
            } finally {release.countDown();caller.shutdownNow()}
        }
    }
    @Test fun releasingAnOldOrForeignSocketCannotDetachTheCurrentAttempt() {
        val scope=ProbeScope();val old=Socket();val current=Socket();val foreign=Socket()
        try {
            scope.attach(old);scope.release(old);assertTrue(old.isClosed)
            scope.attach(current);scope.release(old);scope.release(foreign)
            assertFalse(current.isClosed);assertFalse(foreign.isClosed)
            scope.cancel();assertTrue(current.isClosed)
        } finally {foreign.close();scope.cancel()}
    }
    @Test fun unexpectedConnectionFailureClosesOnlyItsSocketAndNeverStartsAnAlternative() {
        val scope=ProbeScope();val created=AtomicInteger()
        val failed=ScriptedSocket {_,_->throw AssertionError("unexpected connection failure")}
        val probe=NetworkProbe(resolve={listOf(v6,v4)},socketFactory={created.incrementAndGet();failed})
        assertThrows(AssertionError::class.java) {probe.run(check,scope)}
        assertTrue(failed.isClosed);assertEquals(1,created.get())
        val foreign=Socket();val fresh=Socket();val occupied=ProbeScope();occupied.attach(foreign)
        try {
            assertThrows(IllegalStateException::class.java) {NetworkProbe(resolve={listOf(v4)},socketFactory={fresh}).run(check,occupied)}
            assertTrue(fresh.isClosed);assertFalse(foreign.isClosed)
        } finally {occupied.cancel();scope.cancel()}
    }
}
