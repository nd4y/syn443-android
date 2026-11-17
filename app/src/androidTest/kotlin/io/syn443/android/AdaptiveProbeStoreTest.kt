package io.syn443.android

import android.content.Context
import android.content.ContextWrapper
import android.os.Handler
import android.os.Looper
import androidx.test.core.app.ApplicationProvider
import androidx.test.platform.app.InstrumentationRegistry
import io.syn443.android.vpn.AdaptiveStartAdmission
import io.syn443.android.vpn.DurableAdaptiveProbeBudget
import io.syn443.android.vpn.ImmediateAdaptiveStartAdmission
import io.syn443.decision.AdaptiveProbeBudget
import io.syn443.policy.Canonical
import kotlinx.serialization.json.*
import org.junit.Assert.*
import org.junit.Test
import java.io.Closeable
import java.io.File
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

/** Counter metadata only. These DEBUG isolated paths never enroll, open a key,
 * touch the controller singleton, send packets or change device settings. */
class AdaptiveProbeStoreTest {
    private class Fixture:Closeable {
        val context=ApplicationProvider.getApplicationContext<Context>()
        val namespace="test-"+UUID.randomUUID().toString().replace("-","")
        val directory=File(context.noBackupFilesDir,"probe-admission-$namespace")
        val file=File(directory,"adaptive-v1.json")
        val now=AtomicLong(1_000)
        val boot=AtomicInteger(7)
        val main=Handler(Looper.getMainLooper())
        val actors=mutableListOf<DurableAdaptiveProbeBudget>()
        val cleanup=Executors.newSingleThreadExecutor()
        fun create(ownedContext:Context=context,io:(DurableAdaptiveProbeBudget.IoStage)->Unit={})=
            DurableAdaptiveProbeBudget.isolatedForTest(ownedContext,namespace,main,now::get,boot::get,io).also {actors+=it}
        fun close(actor:DurableAdaptiveProbeBudget) {
            cleanup.submit {actor.shutdownForTest()}.get(15,TimeUnit.SECONDS);actors.remove(actor)
        }
        fun ready(actor:DurableAdaptiveProbeBudget) {
            val end=System.nanoTime()+TimeUnit.SECONDS.toNanos(10)
            while(actor.busyForTest()) {check(System.nanoTime()<end);Thread.sleep(10)}
        }
        fun request(actor:DurableAdaptiveProbeBudget,routine:Boolean=false,sample:Long=now.get()):AdaptiveStartAdmission.Result {
            val done=CountDownLatch(1);val result=AtomicReference<AdaptiveStartAdmission.Result>()
            assertTrue(actor.request(sample,routine) {value->
                result.set(value);done.countDown()
            })
            assertTrue(done.await(10,TimeUnit.SECONDS));ready(actor);return checkNotNull(result.get())
        }
        override fun close() {
            try {
                actors.toList().forEach(::close)
                cleanup.submit {
                    check(directory.parentFile==context.noBackupFilesDir && directory.name=="probe-admission-$namespace")
                    directory.listFiles()?.forEach {owned->
                        check(owned.name in setOf("adaptive-v1.json","adaptive-v1.json.new","adaptive-v1.json.bak","owner.lock"))
                        check(owned.isFile && owned.delete())
                    }
                    check(!directory.exists() || directory.delete())
                }.get(15,TimeUnit.SECONDS)
            }finally {cleanup.shutdownNow();check(cleanup.awaitTermination(5,TimeUnit.SECONDS))}
        }
    }
    private fun checkpoint(observed:Long,entries:List<AdaptiveProbeBudget.Entry>,sealed:Boolean=false,boot:Int=7):ByteArray=
        Canonical.encode(buildJsonObject {
            put("version",1);put("bootCount",boot)
            put("checkpoint",buildJsonObject {
                put("observedAtMs",observed);put("clockSealed",sealed)
                put("entries",buildJsonArray {entries.forEach {entry->add(buildJsonObject {
                    put("ageMs",entry.ageMs);put("routine",entry.routine)
                })}})
            })
        }).toByteArray(Charsets.UTF_8)
    private fun sealed(file:File)=Canonical.parse(file.readText()).jsonObject.getValue("checkpoint").jsonObject.getValue("clockSealed").jsonPrimitive.boolean
    private fun entries(file:File)=Canonical.parse(file.readText()).jsonObject.getValue("checkpoint").jsonObject.getValue("entries").jsonArray
    private fun awaitIgnoringInterrupt(latch:CountDownLatch) {
        val end=System.nanoTime()+TimeUnit.SECONDS.toNanos(10)
        while(latch.count>0) {
            val left=end-System.nanoTime();check(left>0)
            try {check(latch.await(left,TimeUnit.NANOSECONDS))}catch(_:InterruptedException) { /* Actual blocked owner stays blocked. */ }
        }
    }

    @Test fun firstLoadAndAdmissionAreDurableBeforeOneBoundedMainCallback() {
        Fixture().use {f->
            val syncs=AtomicInteger();val reads=AtomicInteger()
            val actor=f.create {stage->
                assertNotEquals(Looper.getMainLooper(),Looper.myLooper())
                assertFalse(Thread.currentThread().name.startsWith("Binder:"))
                if(stage==DurableAdaptiveProbeBudget.IoStage.BEFORE_FILE_SYNC)syncs.incrementAndGet()
                if(stage==DurableAdaptiveProbeBudget.IoStage.BEFORE_READBACK)reads.incrementAndGet()
            }
            f.ready(actor);assertTrue(f.file.isFile);assertTrue(actor.canStart(1_000,false))
            assertEquals(1,syncs.get());assertEquals(1,reads.get())
            val done=CountDownLatch(1);val callback=AtomicReference<AdaptiveStartAdmission.Result>();val callbacks=AtomicInteger()
            assertTrue(actor.request(1_000,false) {result->
                assertEquals(Looper.getMainLooper(),Looper.myLooper())
                assertEquals(2,reads.get())
                callback.set(result);callbacks.incrementAndGet();done.countDown()
            })
            assertTrue(done.await(10,TimeUnit.SECONDS));f.ready(actor)
            InstrumentationRegistry.getInstrumentation().runOnMainSync {}
            val result=checkNotNull(callback.get());assertTrue(result.allowed)
            assertEquals(1,entries(f.file).size)
            assertEquals(1_000L,result.observedAtMs);assertEquals(2_000L,result.latestStartMs)
            assertEquals(1,callbacks.get());assertEquals(-1_000L,entries(f.file).single().jsonObject.getValue("ageMs").jsonPrimitive.long)
            assertFalse(actor.canStart(6_999,false));assertTrue(actor.canStart(7_000,false))
            assertFalse(actor.invalidated());assertFalse(f.file.readText().contains("target"))
        }
    }
    @Test fun sameBootReopenKeepsSpacingMinuteAndHourDebtAndNewBootCarriesAges() {
        Fixture().use {f->
            var actor=f.create();f.ready(actor);assertTrue(f.request(actor).allowed);f.close(actor)
            f.now.set(3_000);actor=f.create();f.ready(actor)
            assertFalse(actor.canStart(6_999,false));assertTrue(actor.canStart(7_000,false));f.close(actor)
            val minuteObserved=100_000L
            f.file.writeBytes(checkpoint(minuteObserved,(8 downTo 1).map {AdaptiveProbeBudget.Entry(it*5_000L,false)}))
            f.now.set(minuteObserved);actor=f.create();f.ready(actor)
            assertFalse(actor.canStart(minuteObserved,false));assertTrue(actor.canStart(minuteObserved+20_000,false));f.close(actor)
            val routineStarts=(0 until 96).map {index->(index/6)*60_000L+(index%6)*5_000L}
            val routineObserved=930_000L
            f.file.writeBytes(checkpoint(routineObserved,routineStarts.map {AdaptiveProbeBudget.Entry(routineObserved-it,true)}))
            f.now.set(routineObserved);actor=f.create();f.ready(actor)
            assertFalse(actor.canStart(routineObserved,true));assertTrue(actor.canStart(routineObserved,false));f.close(actor)
            val starts=(0 until 128).map {index->(index/8)*60_000L+(index%8)*5_000L}
            val observed=940_000L
            f.file.writeBytes(checkpoint(observed,starts.map {AdaptiveProbeBudget.Entry(observed-it,false)}))
            f.now.set(observed);actor=f.create();f.ready(actor)
            val before=f.file.readBytes();assertFalse(f.request(actor).allowed);assertArrayEquals(before,f.file.readBytes());f.close(actor)
            f.boot.incrementAndGet();f.now.set(1_000);actor=f.create();f.ready(actor)
            assertFalse(actor.canStart(1_000,false));assertEquals(128,entries(f.file).size)
            assertFalse(actor.canStart(2_660_999,false));assertTrue(actor.canStart(2_661_000,false))
            f.now.set(2_661_000);assertTrue(f.request(actor).allowed)
        }
    }
    @Test fun sameBootRollbackPersistsClockSealAndRebootPreservesReservedDebt() {
        Fixture().use {f->
            var actor=f.create();f.ready(actor);assertTrue(f.request(actor).allowed)
            f.now.set(3_000);assertFalse(f.request(actor).allowed)
            f.now.set(2_500);assertFalse(f.request(actor).allowed);assertTrue(actor.invalidated());assertTrue(sealed(f.file))
            f.close(actor);f.now.set(4_000);actor=f.create();f.ready(actor);assertTrue(actor.invalidated())
            assertFalse(f.request(actor).allowed);f.close(actor)
            f.boot.incrementAndGet();f.now.set(1_000);actor=f.create();f.ready(actor)
            assertFalse(actor.invalidated());assertFalse(sealed(f.file));assertFalse(actor.canStart(4_999,false))
            assertTrue(actor.canStart(5_000,false));assertEquals(1,entries(f.file).size)
        }
    }
    @Test fun malformedMissingPartialAndOversizeExistingStateNeverResetAnOwner() {
        val good=String(checkpoint(1_000,emptyList()),Charsets.UTF_8)
        val invalid=listOf(good.replace("\"version\":1","\"version\":1,\"version\":1"),
            good.replace("\"bootCount\":7","\"bootCount\":7.0"),good.replace("\"version\":1","\"version\":2"),
            good.replace("\"bootCount\":7","\"BootCount\":7"),
            good.replace("\"version\":1","\"version\":1,\"\\u0076ersion\":1"),
            good.replace("\"clockSealed\":false","\"clockSealed\":null"),
            good.replace("\"clockSealed\":false","\"clockSealed\":\"false\""),
            good.replace("\"observedAtMs\":1000","\"observedAtMs\":1e3"),
            good.replace("\"entries\":[]","\"entries\":[{\"ageMs\":-1001,\"routine\":false}]"),
            good.dropLast(1),good+" ".repeat(16_384))
        for((index,raw)in invalid.withIndex())Fixture().use {f->
            assertTrue(f.directory.mkdir());f.file.writeText(raw)
            val actor=f.create();f.ready(actor)
            assertFalse("invalid_case_$index",actor.canStart(10_000,false));assertFalse(actor.invalidated())
            assertFalse(actor.request(10_000,false) {fail("unavailable_callback_$index")})
            assertEquals(raw,f.file.readText())
        }
        for(newOnly in listOf(false,true))Fixture().use {f->
            assertTrue(f.directory.mkdir())
            if(newOnly)File(f.directory,"adaptive-v1.json.new").writeText(good)
            val actor=f.create();f.ready(actor)
            assertFalse(actor.canStart(1_000,false));assertFalse(actor.invalidated());assertFalse(f.file.exists())
        }
        Fixture().use {f->
            val initial=f.create();f.ready(initial);f.close(initial);assertTrue(f.file.delete())
            val missing=f.create();f.ready(missing)
            assertFalse(missing.canStart(1_000,false));assertFalse(missing.invalidated());assertFalse(f.file.exists())
        }
        Fixture().use {f->
            assertTrue(f.directory.mkdir());val malformed=byteArrayOf(0xc3.toByte(),0x28)
            f.file.writeBytes(malformed);val actor=f.create();f.ready(actor)
            assertFalse(actor.canStart(1_000,false));assertFalse(actor.invalidated());assertArrayEquals(malformed,f.file.readBytes())
        }
    }
    @Test fun syncDirectoryAndExactReadbackFailuresGrantNothingAndNeverRefundLiveDebt() {
        for(stage in DurableAdaptiveProbeBudget.IoStage.entries)Fixture().use {f->
            val armed=AtomicBoolean(false)
            val actor=f.create {at->if(armed.get() && at==stage)throw java.io.IOException("synthetic_storage_failure")}
            f.ready(actor);armed.set(true)
            assertFalse(f.request(actor).allowed);assertFalse(actor.invalidated())
            f.now.set(20_000);assertFalse(actor.canStart(20_000,false));assertFalse(actor.request(20_000,false) {})
            f.close(actor)
            if(stage!=DurableAdaptiveProbeBudget.IoStage.BEFORE_FILE_SYNC) {
                f.now.set(3_000);val restored=f.create();f.ready(restored)
                assertEquals(1,entries(f.file).size);assertFalse(restored.canStart(6_999,false))
            }
        }
        Fixture().use {f->
            val armed=AtomicBoolean(false)
            val actor=f.create {at->if(armed.get() && at==DurableAdaptiveProbeBudget.IoStage.BEFORE_READBACK) {
                // Actual valid JSON readback differs from the completed write.
                f.file.appendText(" ")
            }}
            f.ready(actor);armed.set(true);assertFalse(f.request(actor).allowed)
            assertFalse(actor.invalidated());assertFalse(actor.canStart(20_000,false))
        }
    }
    @Test fun blockedSyncRetainsOneActualOwnerAndExpiredHandoffCannotDispatch() {
        Fixture().use {f->
            val entered=CountDownLatch(1);val release=CountDownLatch(1);val armed=AtomicBoolean(false)
            val actor=f.create {stage->if(armed.get() && stage==DurableAdaptiveProbeBudget.IoStage.BEFORE_FILE_SYNC) {
                entered.countDown();awaitIgnoringInterrupt(release)
            }}
            f.ready(actor);armed.set(true)
            val done=CountDownLatch(1);val result=AtomicReference<AdaptiveStartAdmission.Result>()
            try {
                assertTrue(actor.request(1_000,false) {result.set(it);done.countDown()})
                assertTrue(entered.await(10,TimeUnit.SECONDS));f.now.set(5_000)
                assertTrue(actor.busyForTest());assertFalse(actor.canStart(5_000,false))
                repeat(3) {assertFalse(actor.request(5_000,false) {fail("second_owner")})}
                release.countDown();assertTrue(done.await(10,TimeUnit.SECONDS));f.ready(actor)
                assertFalse(checkNotNull(result.get()).allowed);assertEquals(2_000L,result.get().latestStartMs)
                assertEquals(5_000L,result.get().observedAtMs);assertEquals(1,entries(f.file).size)
                assertFalse(actor.canStart(6_999,false));assertTrue(actor.canStart(7_000,false))
            }finally {release.countDown()}
        }
    }
    @Test fun copiedPreviewAndStaleCallerSamplesCannotSealOrReplenishTheWorker() {
        Fixture().use {f->
            val actor=f.create();f.ready(actor);assertTrue(f.request(actor).allowed)
            val raw=f.file.readBytes()
            assertFalse(actor.canStart(0,false));assertFalse(actor.canStart(-1,false));assertFalse(actor.invalidated())
            assertArrayEquals(raw,f.file.readBytes())
            f.now.set(7_000);val result=f.request(actor,sample=1_000)
            assertTrue(result.allowed);assertEquals(8_000L,result.latestStartMs);assertEquals(2,entries(f.file).size)
            assertEquals(600_000L,actor.routineCadence(16));assertFalse(actor.invalidated())
            val immediate=ImmediateAdaptiveStartAdmission(AdaptiveProbeBudget());var inline=false
            assertTrue(immediate.request(0,false) {inline=true;assertTrue(it.allowed);assertEquals(0L,it.latestStartMs)})
            assertTrue(inline);assertFalse(immediate.canStart(4_999,false));assertTrue(immediate.canStart(5_000,false))
        }
    }
    @Test fun competingActorsCannotReplaceTheLifetimeFileOwnerOrEraseAnInterruptedStore() {
        Fixture().use {f->
            val first=f.create();f.ready(first)
            val second=f.create();f.ready(second)
            assertFalse(second.canStart(1_000,false));assertFalse(second.invalidated());assertFalse(second.request(1_000,false) {})
            assertTrue(f.request(first).allowed);assertEquals(1,entries(f.file).size)
            f.close(second);f.close(first)
            assertTrue(f.file.renameTo(File(f.directory,"adaptive-v1.json.bak")))
            f.now.set(3_000);val reopened=f.create();f.ready(reopened)
            assertTrue(f.file.isFile);assertFalse(File(f.directory,"adaptive-v1.json.bak").exists())
            assertFalse(reopened.canStart(6_999,false));assertTrue(reopened.canStart(7_000,false))
        }
    }
    @Test fun mainAndBinderEntryOnlyScheduleWorkerIoAndLateMainDeliveryKeepsItsOriginalFence() {
        Fixture().use {f->
            val pathReads=AtomicInteger()
            val guarded=object:ContextWrapper(f.context) {
                override fun getNoBackupFilesDir():File {
                    check(Looper.myLooper()!=Looper.getMainLooper() && !Thread.currentThread().name.startsWith("Binder:"))
                    pathReads.incrementAndGet();return super.getNoBackupFilesDir()
                }
            }
            val owner=AtomicReference<DurableAdaptiveProbeBudget>()
            InstrumentationRegistry.getInstrumentation().runOnMainSync {owner.set(f.create(ownedContext=guarded))}
            val actor=checkNotNull(owner.get());f.ready(actor);assertTrue(pathReads.get()>0)
            val entered=CountDownLatch(1);val release=CountDownLatch(1);val callback=CountDownLatch(1)
            val result=AtomicReference<AdaptiveStartAdmission.Result>()
            f.main.post {entered.countDown();awaitIgnoringInterrupt(release)}
            try {
                assertTrue(entered.await(10,TimeUnit.SECONDS))
                val name=Thread.currentThread().name
                try {Thread.currentThread().name="Binder:synthetic-admission";assertTrue(actor.request(1_000,false) {result.set(it);callback.countDown()})}
                finally {Thread.currentThread().name=name}
                f.ready(actor);assertEquals(1,entries(f.file).size);f.now.set(3_000);release.countDown()
                assertTrue(callback.await(10,TimeUnit.SECONDS));assertFalse(checkNotNull(result.get()).allowed)
                assertEquals(2_000L,result.get().latestStartMs);assertEquals(3_000L,result.get().observedAtMs)
            }finally {release.countDown()}
            assertThrows(IllegalArgumentException::class.java) {DurableAdaptiveProbeBudget.isolatedForTest(f.context,"adaptive-v1",f.main,f.now::get,f.boot::get)}
        }
    }
    @Test fun ordinaryDenialsDoNotWriteAndAFailedClockSealNeverBecomesAProxyFailureOrFreshBudget() {
        Fixture().use {f->
            val writes=AtomicInteger();val fail=AtomicBoolean(false)
            val actor=f.create {stage->if(stage==DurableAdaptiveProbeBudget.IoStage.BEFORE_FILE_SYNC) {
                writes.incrementAndGet();if(fail.get())throw java.io.IOException("synthetic_seal_sync")
            }}
            f.ready(actor);assertTrue(f.request(actor).allowed);val before=f.file.readBytes();assertEquals(2,writes.get())
            for(at in listOf(3_000L,4_000L,5_000L)) {f.now.set(at);assertFalse(f.request(actor).allowed)}
            assertEquals(2,writes.get());assertArrayEquals(before,f.file.readBytes())
            fail.set(true);f.now.set(4_500);assertFalse(f.request(actor).allowed)
            assertEquals(3,writes.get());assertTrue(actor.invalidated());assertFalse(actor.canStart(20_000,false))
            assertArrayEquals(before,f.file.readBytes());assertFalse(actor.request(20_000,false) {})
        }
    }
}
