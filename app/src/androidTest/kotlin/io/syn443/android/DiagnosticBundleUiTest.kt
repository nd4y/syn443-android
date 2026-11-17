package io.syn443.android

import android.net.Uri
import androidx.activity.compose.LocalActivityResultRegistryOwner
import androidx.activity.result.ActivityResultRegistry
import androidx.activity.result.ActivityResultRegistryOwner
import androidx.activity.result.contract.ActivityResultContract
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.Modifier
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.junit4.StateRestorationTester
import androidx.core.app.ActivityOptionsCompat
import io.syn443.android.support.DiagnosticArchive
import io.syn443.android.support.DiagnosticBundleControls
import io.syn443.android.support.validBundlePreview
import io.syn443.android.support.DiagnosticsRoute
import kotlinx.coroutines.CompletableDeferred
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test

class DiagnosticBundleUiTest {
    @get:Rule val compose = createComposeRule()
    private fun ready(): JSONObject {
        val archive = DiagnosticArchive.create(emptyList())
        return JSONObject().put("state", "ready").put("id", "b".repeat(32)).put("bytes", archive.bytes.size)
            .put("sha256", "c".repeat(64)).put("manifest", archive.manifest)
    }

    @Test fun idlePresentationDoesNotCollectOrExportUntilAnExplicitClick() {
        var collects = 0; var exports = 0
        compose.setContent { MaterialTheme(colorScheme = darkColorScheme()) {
            DiagnosticBundleControls(JSONObject().put("state", "idle"), false, "", { collects++ }, {}, {}, { exports++ })
        } }
        compose.onNodeWithTag("bundle-export").assertIsNotEnabled()
        compose.onNodeWithTag("bundle-not-sent").assertTextEquals("В SYN443 не отправлен")
        compose.runOnIdle { assertEquals(0, collects); assertEquals(0, exports) }
        compose.onNodeWithTag("bundle-collect").performClick()
        compose.runOnIdle { assertEquals(1, collects); assertEquals(0, exports) }
    }

    @Test fun readyPartialArchiveShowsCompositionSizeAndSeparateExportAction() {
        var exports = 0
        val value = ready()
        assertTrue(validBundlePreview(value))
        compose.setContent { MaterialTheme(colorScheme = darkColorScheme()) {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                DiagnosticBundleControls(value, false, "", {}, {}, {}, { exports++ })
            }
        } }
        compose.onNodeWithTag("bundle-state").assertTextEquals("Архив готов")
        compose.onNodeWithTag("bundle-size").assertTextContains("байт")
        compose.onNodeWithTag("bundle-completeness").assertTextContains("Часть источников")
        compose.onNodeWithTag("bundle-component-8").assertExists()
        compose.runOnIdle { assertEquals(0, exports) }
        compose.onNodeWithTag("bundle-export").performScrollTo().assertIsEnabled().performClick()
        compose.runOnIdle { assertEquals(1, exports) }
        compose.onNodeWithTag("bundle-not-sent").assertTextEquals("В SYN443 не отправлен")
    }

    @Test fun busyCollectionCannotOverlapOrExportAndCancellationIsExplicit() {
        val working = mutableStateOf(true)
        var cancels = 0; var refreshes = 0
        compose.setContent { MaterialTheme(colorScheme = darkColorScheme()) {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                DiagnosticBundleControls(JSONObject().put("state", "collecting"), working.value, "", {}, { refreshes++ }, { cancels++ }, {})
            }
        } }
        compose.onNodeWithTag("bundle-collect").assertIsNotEnabled()
        compose.onNodeWithTag("bundle-export").assertIsNotEnabled()
        compose.onNodeWithTag("bundle-cancel").assertIsEnabled()
        compose.onNodeWithTag("bundle-cancel").performScrollTo().assertIsEnabled().performClick()
        compose.runOnIdle { assertEquals(1, cancels); assertEquals(0, refreshes) }
    }

    @Test fun routeCancellationRemainsResponsiveWhilePollingAndRejectsLateReadyReply() {
        val pending = CompletableDeferred<Unit>()
        val requested = AtomicBoolean()
        val cancels = AtomicInteger()
        val jobId = "b".repeat(32)
        compose.setContent { MaterialTheme(colorScheme = darkColorScheme()) {
            DiagnosticsRoute(rpc = { method, _ -> when (method) {
                "bundle-collect" -> JSONObject().put("state", "collecting").put("id", jobId)
                "bundle-status" -> { requested.set(true); pending.await(); ready() }
                "bundle-cancel" -> { cancels.incrementAndGet(); JSONObject().put("state", "cancelled").put("id", jobId) }
                else -> error("unexpected synthetic command")
            } })
        } }
        try {
            compose.onNodeWithTag("bundle-collect").performScrollTo().performClick()
            compose.waitUntil(5_000) { requested.get() }
            compose.onNodeWithTag("bundle-export").assertIsNotEnabled()
            compose.onNodeWithTag("bundle-cancel").performScrollTo().assertIsEnabled().performClick()
            compose.waitUntil(5_000) { cancels.get() == 1 }
            compose.onNodeWithTag("bundle-state").assertTextEquals("Сбор отменён")
            compose.runOnIdle { pending.complete(Unit) }
            compose.waitForIdle()
            compose.onNodeWithTag("bundle-state").assertTextEquals("Сбор отменён")
            compose.onNodeWithTag("bundle-export").assertIsNotEnabled()
        } finally { pending.complete(Unit) }
    }

    @Test fun malformedUnknownOrInconsistentManifestNeverEnablesExportOrEchoesValues() {
        val invalid = ready().also { it.getJSONObject("manifest").put("complete", true) }
        assertFalse(validBundlePreview(invalid))
        assertFalse(validBundlePreview(ready().put("bytes", "1024")))
        assertFalse(validBundlePreview(ready().put("sha256", "synthetic-private-value")))
        assertFalse(validBundlePreview(ready().also {
            val parts = it.getJSONObject("manifest").getJSONArray("components")
            parts.getJSONObject(0).put("name", "../../synthetic-private-value")
        }))
        compose.setContent { MaterialTheme(colorScheme = darkColorScheme()) {
            DiagnosticBundleControls(invalid, false, "", {}, {}, {}, {})
        } }
        compose.onNodeWithTag("bundle-export").assertIsNotEnabled()
        compose.onAllNodesWithText("synthetic-private-value", substring = true).assertCountEquals(0)
        compose.onNodeWithTag("bundle-state").assertTextEquals("Некорректные сведения об архиве")
    }

    @Test fun delayedDocumentResultAfterRestorationUsesReviewedArtifactAndCancelledPickerNeverReplaysCollection() {
        data class Export(val id: String, val uri: Uri, val sha256: String, val bytes: Int)
        val reviewed = ready()
        val reviewedId = reviewed.getString("id")
        val reviewedHash = reviewed.getString("sha256")
        val reviewedBytes = reviewed.getInt("bytes")
        var latest = reviewed
        val commands = mutableListOf<String>()
        val launches = mutableListOf<Int>()
        val exports = mutableListOf<Export>()
        val exportCount = AtomicInteger()
        val statusCount = AtomicInteger()
        val finishExport = CompletableDeferred<Unit>()
        val restoreStatus = CompletableDeferred<Unit>()
        val registry = object : ActivityResultRegistry() {
            override fun <I, O> onLaunch(requestCode: Int, contract: ActivityResultContract<I, O>,
                input: I, options: ActivityOptionsCompat?) {
                assertTrue(contract is ActivityResultContracts.CreateDocument)
                assertEquals("syn443-support.zip", input)
                launches += requestCode
                // Hold the actual registry result. No document picker, provider,
                // file descriptor or exporter is invoked from this fixture.
            }
        }
        val owner = object : ActivityResultRegistryOwner {
            override val activityResultRegistry = registry
        }
        val restoration = StateRestorationTester(compose)
        restoration.setContent {
            CompositionLocalProvider(LocalActivityResultRegistryOwner provides owner) {
                MaterialTheme(colorScheme = darkColorScheme()) {
                    DiagnosticsRoute(rpc = { method, argument ->
                        commands += method
                        when (method) {
                            "bundle-collect" -> { assertNull(argument); reviewed }
                            "bundle-status" -> {
                                assertEquals(reviewedId, argument)
                                if (statusCount.incrementAndGet() == 2) restoreStatus.await()
                                latest
                            }
                            else -> error("unexpected synthetic command")
                        }
                    }, exporter = { id, uri, hash, bytes ->
                        exports += Export(id, uri, hash, bytes)
                        exportCount.incrementAndGet()
                        finishExport.await()
                    })
                }
            }
        }
        try {
            compose.onNodeWithTag("bundle-collect").performScrollTo().performClick()
            compose.waitUntil(5_000) { statusCount.get() == 1 }
            compose.onNodeWithTag("bundle-state").assertTextEquals("Архив готов")
            compose.onNodeWithTag("bundle-export").performScrollTo().assertIsEnabled().performClick()
            compose.onNodeWithTag("bundle-collect").assertIsNotEnabled()
            compose.onNodeWithTag("bundle-export").assertIsNotEnabled()
            compose.onNodeWithTag("bundle-cancel").assertIsNotEnabled()
            var firstCode = 0
            compose.runOnIdle {
                assertEquals(listOf("bundle-collect", "bundle-status"), commands)
                assertEquals(1, launches.size); assertTrue(exports.isEmpty())
                firstCode = launches.single()
                // The recreated route obtains a newer, still-valid preview.
                // Its delayed result must retain the tuple reviewed at click.
                val replacement = DiagnosticArchive.create(listOf(DiagnosticArchive.Component(
                    DiagnosticArchive.Name.HEALTH, "{\"state\":\"unknown\"}".toByteArray(Charsets.UTF_8),
                    DiagnosticArchive.State.AVAILABLE, DiagnosticArchive.Reason.PROJECTION_ONLY)))
                latest = ready().put("sha256", "d".repeat(64)).put("bytes", replacement.bytes.size)
                    .put("manifest", replacement.manifest)
                assertNotEquals(reviewedBytes, latest.getInt("bytes"))
                assertTrue(validBundlePreview(latest))
            }
            restoration.emulateSavedInstanceStateRestore()
            compose.waitUntil(5_000) { statusCount.get() == 2 }
            compose.onNodeWithTag("bundle-collect").assertIsNotEnabled()
            compose.onNodeWithTag("bundle-export").assertIsNotEnabled()
            compose.onNodeWithTag("bundle-cancel").assertIsNotEnabled()
            val destination = Uri.parse("content://example.invalid/owned")
            compose.runOnIdle {
                assertEquals(1, launches.size) // Restoration never launches again.
                assertTrue(registry.dispatchResult<Uri?>(firstCode, destination))
                assertEquals(0, exportCount.get())
                // The result arrived while restored status still owns busy.
                // It must be queued, then consumed once after real admission.
                restoreStatus.complete(Unit)
            }
            compose.waitUntil(5_000) { exportCount.get() == 1 }
            compose.onNodeWithTag("bundle-collect").assertIsNotEnabled()
            compose.onNodeWithTag("bundle-export").assertIsNotEnabled()
            compose.onNodeWithTag("bundle-cancel").assertIsNotEnabled()
            compose.runOnIdle {
                assertEquals(listOf(Export(reviewedId, destination, reviewedHash, reviewedBytes)), exports)
                assertEquals(listOf("bundle-collect", "bundle-status", "bundle-status"), commands)
                finishExport.complete(Unit)
            }
            compose.waitForIdle()
            compose.onNodeWithTag("bundle-export").performScrollTo().assertIsEnabled().performClick()
            compose.onNodeWithTag("bundle-collect").assertIsNotEnabled()
            compose.onNodeWithTag("bundle-export").assertIsNotEnabled()
            compose.onNodeWithTag("bundle-cancel").assertIsNotEnabled()
            compose.runOnIdle {
                assertEquals(2, launches.size)
                assertTrue(registry.dispatchResult<Uri?>(launches.last(), null))
            }
            compose.waitForIdle()
            compose.onNodeWithTag("bundle-export").assertIsEnabled()
            compose.onNodeWithTag("bundle-collect").assertIsEnabled()
            compose.onNodeWithTag("bundle-cancel").assertIsEnabled()
            compose.runOnIdle {
                assertEquals(1, exports.size)
                assertEquals(1, exportCount.get())
                assertEquals(listOf("bundle-collect", "bundle-status", "bundle-status"), commands)
                assertEquals(2, launches.size)
            }
        } finally { restoreStatus.complete(Unit); finishExport.complete(Unit) }
    }
}
