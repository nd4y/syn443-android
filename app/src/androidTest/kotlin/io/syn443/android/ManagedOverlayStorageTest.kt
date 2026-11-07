package io.syn443.android

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.syn443.android.vpn.*
import io.syn443.identity.Identity
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.io.RandomAccessFile
import java.nio.file.Files
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class ManagedOverlayStorageTest {
    private val context=ApplicationProvider.getApplicationContext<Context>()
    private inner class Fixture:AutoCloseable {
        val area="test-"+UUID.randomUUID().toString()
        val root=File(context.noBackupFilesDir,area).canonicalFile
        val storage=ManagedOverlayStorage(context,area)
        val namespace="managed-netbird/"+Identity.hash(area.toByteArray())
        val directory=storage.directory(namespace)
        val evidence=Identity.hash("synthetic SDK public keys".toByteArray())
        fun populate(initialized:Boolean=true) {
            check(directory.mkdirs())
            File(directory,"syn443-managed-identity.json").writeText("""{"schemaVersion":1,"namespace":"$namespace","initialized":$initialized,"identityEvidence":"${if(initialized)evidence else ""}"}""")
            File(directory,"identity.lock").writeText("")
            File(directory,"config.json").writeText("synthetic app-private SDK state")
            File(directory,"nested").mkdir()
            File(directory,"nested/state.json").writeText("synthetic state")
        }
        override fun close() {
            check(root.parentFile==context.noBackupFilesDir.canonicalFile && root.name==area && area.startsWith("test-"))
            // Test teardown never follows a malicious link created by a case.
            fun remove(file:File) {
                if(Files.isSymbolicLink(file.toPath()))check(file.delete())
                else if(file.isDirectory){checkNotNull(file.listFiles()).forEach(::remove);check(file.delete())}
                else if(file.exists())check(file.delete())
            }
            if(root.exists())remove(root)
        }
    }
    @Test fun ownedNamespaceRetiresUnderLockAndLeavesEverySiblingAndOperatorFileUntouched() {
        Fixture().use{f->
            f.populate()
            val sibling=f.storage.directory("managed-netbird/"+Identity.hash("other identity".toByteArray()))
            check(sibling.mkdirs());val siblingFile=File(sibling,"config.json").apply{writeText("sibling")}
            val operator=File(f.root,"netbird/operator").apply{check(mkdirs())};val operatorFile=File(operator,"config.json").apply{writeText("operator")}
            assertTrue(f.storage.retire(f.namespace,f.evidence){true})
            assertFalse(f.directory.exists());assertEquals("sibling",siblingFile.readText());assertEquals("operator",operatorFile.readText())
            assertTrue(f.storage.retire(f.namespace,f.evidence){true})
        }
    }
    @Test fun heldNativeOwnershipPreventsAllDeletionAndCancellationCannotBorrowIt() {
        Fixture().use{f->
            f.populate();val before=File(f.directory,"config.json").readText()
            RandomAccessFile(File(context.noBackupFilesDir,"engine-owner.lock"),"rw").use{file->file.channel.lock().use{
                assertFalse(f.storage.retire(f.namespace,f.evidence){true})
                assertFalse(NativeRetirement.withReleased(context){fail("owned cleanup callback ran");true})
            }}
            assertEquals(before,File(f.directory,"config.json").readText())
            assertFalse(f.storage.retire(f.namespace,f.evidence){false})
            assertEquals(before,File(f.directory,"config.json").readText())
            assertTrue(f.storage.retire(f.namespace,f.evidence){true})
        }
    }
    @Test fun wrongEvidenceUnclaimedSDKAndAmbiguousManifestNeverAuthorizeErasure() {
        Fixture().use{f->
            f.populate();val manifest=File(f.directory,"syn443-managed-identity.json");val original=manifest.readText()
            assertFalse(f.storage.retire(f.namespace,Identity.hash("wrong".toByteArray())){true})
            assertTrue(File(f.directory,"config.json").isFile)
            for(bad in listOf("null","{}",original.dropLast(1)+",\"extra\":true}",original.replace("\"schemaVersion\":1","\"schemaVersion\":1,\"schemaVersion\":1"),original.replace(f.namespace,"managed-netbird/other"),"x".repeat(1025))) {
                manifest.writeText(bad);assertFalse(f.storage.retire(f.namespace,f.evidence){true});assertTrue(File(f.directory,"config.json").isFile)
            }
            check(manifest.delete());assertFalse(f.storage.retire(f.namespace,null){true});assertTrue(File(f.directory,"config.json").isFile)
            manifest.writeText(original);assertTrue(f.storage.retire(f.namespace,f.evidence){true})
        }
    }
    @Test fun symlinkAndOversizedTreesFailBeforeDeletingAnyOwnedFile() {
        Fixture().use{f->
            f.populate();val foreign=File(f.root,"foreign").apply{writeText("unchanged")}
            val alias=File(f.directory,"alias");Files.createSymbolicLink(alias.toPath(),foreign.toPath())
            assertFalse(f.storage.retire(f.namespace,f.evidence){true});assertEquals("unchanged",foreign.readText());assertTrue(File(f.directory,"config.json").isFile)
            check(alias.delete())
            val huge=File(f.directory,"huge");RandomAccessFile(huge,"rw").use{it.setLength(64L*1024*1024+1)}
            assertFalse(f.storage.retire(f.namespace,f.evidence){true});assertTrue(File(f.directory,"config.json").isFile);check(huge.delete())
            val nested=File(f.directory,"too-many").apply{check(mkdir())};repeat(513){File(nested,"f$it").writeText("")}
            assertFalse(f.storage.retire(f.namespace,f.evidence){true});assertTrue(File(f.directory,"config.json").isFile)
        }
    }
    @Test fun interruptedDeletionKeepsOwnershipUntilTheSameRetirementCompletes() {
        Fixture().use{f->
            f.populate();var checks=0
            assertFalse(f.storage.retire(f.namespace,f.evidence){++checks<4})
            assertTrue(File(f.directory,"syn443-managed-identity.json").isFile)
            assertTrue(f.storage.retire(f.namespace,f.evidence){true});assertFalse(f.directory.exists())
            check(f.directory.mkdirs());File(f.directory,"identity.lock").writeText("");File(f.directory,"syn443-retry.json").writeText("{}")
            assertTrue(f.storage.retire(f.namespace,null){true})
        }
    }
    @Test fun nativeOwnershipIsHeldThroughoutCleanupAndMainThreadCannotErase() {
        Fixture().use{f->
            f.populate();var blocked=false
            assertTrue(NativeRetirement.withReleased(context) {
                RandomAccessFile(File(context.noBackupFilesDir,"engine-owner.lock"),"rw").use{file->
                    blocked=runCatching{file.channel.tryLock()?.use{false}?:true}.getOrDefault(true)
                };blocked
            });assertTrue(blocked)
            InstrumentationRegistry.getInstrumentation().runOnMainSync {
                val error=runCatching{f.storage.retire(f.namespace,f.evidence){true}}.exceptionOrNull()
                assertTrue(error is LoginStorageException && error.reason==LoginStorageFailure.WRONG_THREAD)
            }
            for(bad in listOf("netbird/operator",f.namespace+"=","managed-netbird/../escape"))
                assertTrue(runCatching{f.storage.directory(bad)}.isFailure)
            assertTrue(f.storage.retire(f.namespace,f.evidence){true})
        }
    }
}
