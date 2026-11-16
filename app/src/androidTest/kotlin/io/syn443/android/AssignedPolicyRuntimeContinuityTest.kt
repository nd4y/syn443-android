package io.syn443.android

import io.syn443.android.vpn.AdaptivePolicyBinding
import io.syn443.android.vpn.AssignedPolicyRuntime
import io.syn443.android.vpn.BootstrapTrustStore
import androidx.test.platform.app.InstrumentationRegistry
import io.syn443.decision.NetworkMode
import io.syn443.identity.*
import io.syn443.identity.TrustedTime
import io.syn443.policy.*
import java.io.Closeable
import java.io.File
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import java.util.UUID
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test

/** Actual signed assignment/receipt/worker admission, with a virtual boot clock.
 * No network, native SDK, device credentials, wall-clock or packet evidence. */
internal class AssignedPolicyContinuityFixture(val raw: String) : Closeable {
    private val worker=Executors.newSingleThreadExecutor { job -> Thread(job, "synthetic-assignment-worker") }
    private fun key()=KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    private val roots=mapOf("fixture-root" to key(), "fixture-reserve" to key())
    private val device=key()
    private val utc=1_800_000_000_000L
    var elapsed=1000L
    var boot=1
    var anchor: String?=Policy.hash("synthetic-installation-anchor")
    var corruptAnchor=false
    var anchorReads=0
    val anchorThreads=mutableListOf<String>()
    var duringElapsed: (() -> Unit)?=null
    val bootstrap=Bootstrap("fixture", "https://identity.example.invalid/realms/fixture", "syn443-android", "https://api.example.invalid",
        roots.mapValues { Base64.getEncoder().encodeToString(it.value.public.encoded) })
    private val thumb=Identity.thumbprint(device.public as ECPublicKey)
    private val authority=Identity.bootstrapAuthority(bootstrap)
    private val session=SessionReply(DeviceSession(Identity.random(), Identity.random(), Identity.random(), utc+590_000,
        utc+86_400_000, 0, Identity.random()), time(), authority, thumb)
    var login=LoginIntent(generation=1, revision=5, phase=LoginPhase.PROVISIONING, authority=authority, serviceId=bootstrap.serviceId,
        keyAlias="syn443-dpop-"+Identity.random(), thumbprint=thumb, ownerTag=LoginRecovery.ownerTag(bootstrap, "fixture-user"),
        protectedHash=Identity.random(), maybeRegistered=true, deviceId=session.session.deviceId, sessionGeneration=0)
    val payload=LoginPayload(bootstrap, session=session,
        advertisedCapabilities=CapabilityNegotiation.canonical(IdentityOperation.supportedCapabilities))
    val runtime=AssignedPolicyRuntime({boot}, {
        duringElapsed?.let {duringElapsed=null; it()}
        elapsed
    }, {
        anchorReads++; anchorThreads+=Thread.currentThread().name
        if(corruptAnchor) error("synthetic_corrupt_anchor")
        anchor
    })
    var state=AssignmentState()
        private set
    var policy=Payload(2, 1, 0, 0, login.deviceId, "syn443-device", utc, utc, utc+300_000, utc+3_600_000,
        IdentityOperation.requiredCapabilities+listOf("route.health.v1", Policy.ROUTE_DECISION, Policy.ROUTE_ADAPTIVE_TCP),
        Policy.ADAPTIVE_ALGORITHM, Identity.encode(raw.toByteArray()), Policy.hash(raw),
        Gate(30, false, listOf(Check("internet", "https_204", "https://health.example.invalid/generate_204"))), keyThumbprint=thumb)
        private set
    init { receive(policy, "fixture-root"); activate(); publish() }
    private fun utcNow()=utc+elapsed-1000
    private fun time()=TrustedTime(boot, elapsed, utcNow(), utcNow()+1000)
    private fun signed(p: Payload, kid: String): String {
        val header="""{"alg":"ES256","kid":"$kid","typ":"syn443-policy+jws"}"""
        val body=Canonical.encode(Canonical.parse(Policy.json.encodeToString(p)))
        val input=Identity.encode(header.toByteArray())+"."+Identity.encode(body.toByteArray())
        val der=Signature.getInstance("SHA256withECDSA").run {initSign(roots.getValue(kid).private); update(input.toByteArray()); sign()}
        return input+"."+Identity.encode(Identity.derToRaw(der))
    }
    private fun receive(p: Payload, kid: String) {
        state=Assignments.receive(state, login, payload, PolicyReply(signed(p, kid), time()), boot, elapsed)
        login=LoginRecovery.policyCached(login, login.generation, Assignments.receipt(state, login, payload, boot, elapsed), login.protectedHash)
        policy=p
    }
    private fun activate() {
        state=Assignments.begin(state, login, payload, listOf(false), boot, elapsed)
        state=Assignments.finish(state, login, payload, listOf(true), true, boot, elapsed)
        check(state.journal.phase=="committed")
    }
    fun publish(): AssignedPolicyRuntime.Prepared {
        val prepared=worker.submit<AssignedPolicyRuntime.Prepared> { runtime.prepare(login, payload, state) }.get(30, TimeUnit.SECONDS)
        runtime.publish(prepared)
        return prepared
    }
    fun renew(at: Long, kid: String="fixture-root", change: (Payload)->Payload={it}) {
        stage(at, kid, change)
        if(state.journal.phase=="prepared") { activate(); publish() }
    }
    fun stage(at: Long, kid: String="fixture-root", change: (Payload)->Payload={it}) {
        elapsed=at
        val next=change(policy.copy(revision=policy.revision+1, issuedAtMs=utcNow(), notBeforeMs=utcNow(),
            refreshAfterMs=utcNow()+300_000, offlineUntilMs=utcNow()+3_600_000))
        receive(next, kid)
        publish()
    }
    fun beginActivation() {
        state=Assignments.begin(state, login, payload, listOf(false), boot, elapsed)
        publish()
    }
    fun binding()=checkNotNull(runtime.adaptiveBinding(login, state.journal.active, runtime.ticket(login)))
    fun read(raw: String?=state.journal.active, intent: LoginIntent=login, ticket: AssignedPolicyRuntime.Ticket=runtime.ticket(login))=
        runtime.adaptiveBinding(intent, raw, ticket)
    override fun close() {runtime.clear(); worker.shutdownNow(); check(worker.awaitTermination(5, TimeUnit.SECONDS))}
}

class AssignedPolicyRuntimeContinuityTest {
    private fun config(choices: Int=3)=ManagedAdaptiveRoutesFairnessTest().config(choices=choices)
    private fun replacement(b: AdaptivePolicyBinding, revision: Long=b.revision, authority: String=b.semanticAuthority,
        deadline: Long=b.leaseDeadlineElapsed, boot: Int=b.boot)=
        AdaptivePolicyBinding(revision, b.contentHash, authority, deadline, boot)

    @Test fun signedPureLeaseUsesWorkerAuthorityAndCurrentReceiptWithoutHandlerHashing() {
        AssignedPolicyContinuityFixture(config()).use { f ->
            val old=f.binding(); val oldTicket=f.runtime.ticket(f.login); val oldRaw=f.state.journal.active
            val activation=f.state.journal.activationGeneration
            f.renew(301_000)
            val next=f.binding()
            assertEquals(old.semanticAuthority, next.semanticAuthority)
            assertEquals(old.contentHash, next.contentHash)
            assertEquals(old.revision+1, next.revision)
            assertTrue(next.leaseDeadlineElapsed>old.leaseDeadlineElapsed)
            assertEquals(activation, f.state.journal.activationGeneration)
            assertNull(f.read(ticket=oldTicket)); assertNull(f.read(raw=oldRaw))
            val reads=f.anchorReads
            repeat(32) {assertSame(next, f.binding())}
            assertEquals("reader touched worker trust supplier", reads, f.anchorReads)
            assertTrue(f.anchorThreads.all {it=="synthetic-assignment-worker"})
            assertEquals("AdaptivePolicyBinding([redacted])", next.toString())
        }
    }

    @Test fun missingCorruptAndMalformedAnchorKeepStrictEnvelopeIdentityAndParentPermission() {
        AssignedPolicyContinuityFixture(config()).use { f ->
            val trusted=f.binding()
            f.anchor=null; f.publish(); val missing=f.binding()
            assertNotEquals(trusted.semanticAuthority, missing.semanticAuthority)
            f.renew(301_000); val next=f.binding()
            assertNotEquals(missing.semanticAuthority, next.semanticAuthority)
            f.corruptAnchor=true; f.publish()
            assertEquals(next.semanticAuthority, f.binding().semanticAuthority)
            f.corruptAnchor=false; f.anchor="invalid-anchor"; f.publish()
            assertEquals(next.semanticAuthority, f.binding().semanticAuthority)
            f.anchor="A".repeat(42)+"B"; f.publish() // alternate base64 pad bits are not a stable anchor.
            assertEquals(next.semanticAuthority, f.binding().semanticAuthority)
            assertNull(f.read(intent=f.login.copy(policyHash=Identity.random())))
            assertNull(f.read(intent=f.login.copy(generation=f.login.generation+1)))
            f.runtime.clear(); assertNull(f.runtime.adaptiveBinding(f.login, f.state.journal.active,
                AssignedPolicyRuntime.Ticket(f.login.generation, f.login.policyHash, f.state.journal.activationGeneration, f.login.reauthRevision)))
        }
    }

    @Test fun preparedBindingsFenceBootDeadlineClockRawLoginAndCurrentTicket() {
        AssignedPolicyContinuityFixture(config()).use { f ->
            val b=f.binding(); val ticket=f.runtime.ticket(f.login)
            assertNull(f.read(raw=f.state.journal.active+"x"))
            assertNull(f.read(intent=f.login.copy(authority=Identity.random())))
            assertNull(f.read(intent=f.login.copy(thumbprint=Identity.random())))
            assertNull(f.read(intent=f.login.copy(deviceId=Identity.random())))
            assertNull(f.read(intent=f.login.copy(reauthRevision=1)))
            assertNull(f.read(ticket=ticket.copy(activation=ticket.activation+1)))
            f.elapsed=999; assertNull(f.read()); f.elapsed=1000
            f.boot=2; assertNull(f.read()); f.boot=1
            f.elapsed=b.leaseDeadlineElapsed; assertNull(f.read())
            // Even a newly signed and parent-authorized lease after this
            // deadline does not revive the still-live old native owner below.
            f.renew(b.leaseDeadlineElapsed+1)
            assertNotNull(f.read())
            ManagedAdaptiveRoutesFairnessTest.Harness(f.raw, b).use { h ->
                h.ready(1000)
                h.bind(f.binding(), f.elapsed)
                assertTrue(h.controller.requiresRetirement())
            }
        }
    }

    @Test fun stagedCandidateCannotRunAndApplyingBindingUsesParentActivationDeadline() {
        AssignedPolicyContinuityFixture(config()).use { f ->
            f.stage(2000) {it.copy(activation=it.activation.copy(timeoutSeconds=31))}
            assertEquals("prepared", f.state.journal.phase)
            val candidate=checkNotNull(f.state.journal.candidate)
            assertNotNull(f.runtime.allowed(f.login, candidate)) // validation, not execution permission.
            assertNull(f.read(raw=candidate)); assertNotNull(f.read())
            f.beginActivation()
            val binding=checkNotNull(f.read(raw=candidate))
            assertEquals(f.state.applyDeadlineElapsed, binding.leaseDeadlineElapsed)
            assertTrue(binding.leaseDeadlineElapsed<checkNotNull(f.runtime.read(f.login).candidateBinding).leaseDeadlineElapsed)
            f.elapsed=binding.leaseDeadlineElapsed
            assertNotNull(f.runtime.allowed(f.login, candidate))
            assertNull(f.read(raw=candidate))
        }
    }

    @Test fun sameTicketPreparedReplacementCannotLeakStaleAnchorBinding() {
        AssignedPolicyContinuityFixture(config()).use { f ->
            val old=f.runtime.read(f.login); val ticket=f.runtime.ticket(f.login)
            val oldBinding=f.binding()
            f.anchor=Policy.hash("synthetic-replacement-anchor")
            val current=f.publish(); val currentBinding=f.binding()
            assertEquals(ticket, f.runtime.ticket(f.login)) // same envelope/journal, different trusted worker view.
            assertNotEquals(oldBinding.semanticAuthority, currentBinding.semanticAuthority)
            f.runtime.publish(old)
            f.duringElapsed={f.runtime.publish(current)}
            assertNull(f.read(ticket=ticket))
            assertSame(currentBinding, f.binding())
        }
    }

    @Test fun selectedAAndPendingBReceiptSurvivePureRenewalWithSingleNativeAcknowledgement() {
        AssignedPolicyContinuityFixture(config()).use { f ->
        ManagedAdaptiveRoutesFairnessTest.Harness(f.raw, f.binding()).use { h ->
            h.ready(1000)
            val a=checkNotNull(h.tick(1000)); h.selected(a, 1000)
            val scope=h.policyScope
            f.renew(301_000); h.bind(f.binding(), 301_000)
            assertEquals(scope, h.policyScope)
            val b=checkNotNull(h.tick(302_000)); assertEquals("hop-001", b.getJSONArray("hops").getString(0))
            val commit=h.verified(b, 302_000); assertEquals("commit", commit.getString("command"))
            assertEquals("hop-000", h.view().getJSONArray("routes").getJSONObject(0).getJSONArray("measuredPath").getString(0))
            f.renew(303_000); h.bind(f.binding(), 303_000)
            assertEquals(scope, h.policyScope)
            assertNull(h.tick(303_000)) // verified B remains pending its one native ACK.
            val ack=h.status().put("request", b.getString("request")).put("group", b.getString("group"))
                .put("hops", JSONArray(b.getJSONArray("hops").toString())).put("code", "selected").put("groupSelected", true)
                .put("receipt", commit.getString("receipt")).put("probeMs", 20)
            h.acknowledge(ack, 303_000)
            assertEquals("hop-001", h.view().getJSONArray("routes").getJSONObject(0).getJSONArray("measuredPath").getString(0))
            val count=h.commands.size
            h.acknowledge(ack, 303_000); assertNull(h.tick(304_000))
            assertEquals(count, h.commands.size); assertTrue(h.view().getBoolean("requiredReady"))
            assertFalse(h.controller.requiresRetirement())
        }
        }
    }

    @Test fun signerAnchorAndNonLeaseFieldsResetScopeAndDiscardOldPendingProof() {
        AssignedPolicyContinuityFixture(config()).use { f ->
        ManagedAdaptiveRoutesFairnessTest.Harness(f.raw, f.binding()).use { h ->
            h.ready(1000); val first=checkNotNull(h.tick(1000)); val old=h.policyScope
            val staleProof=h.status().put("request", first.getString("request")).put("group", first.getString("group"))
                .put("hops", first.getJSONArray("hops")).put("code", "verified")
                .put("receipt", Policy.hash(first.getString("request"))).put("probeMs", 20)
            val original=f.binding()
            // Both signers were pinned before activation. Content equality is
            // not sufficient for semantic authority across signing-key change.
            f.renew(2000, "fixture-reserve"); assertNotEquals(original.semanticAuthority, f.binding().semanticAuthority)
            h.bind(f.binding(), 2000); assertNotEquals(old, h.policyScope)
            val before=h.commands.size
            h.acknowledge(staleProof, 2000)
            val reconfigure=h.commands.drop(before).single()
            assertEquals(setOf("command","schemaVersion","nativeEpoch","scope","mode"),reconfigure.keys().asSequence().toSet())
            assertEquals("configure",reconfigure.getString("command"))
            assertEquals(1,reconfigure.getInt("schemaVersion"));assertEquals(h.epoch,reconfigure.getLong("nativeEpoch"))
            assertEquals(h.policyScope,reconfigure.getString("scope"));assertEquals("WIFI",reconfigure.getString("mode"))
            // The old proof may request configuration of the new scope, but
            // cannot dispatch a start, commit or discard of stale authority.
            val signerScope=h.policyScope
            f.anchor=Policy.hash("synthetic-new-anchor"); f.publish(); h.bind(f.binding(), 2000)
            assertNotEquals(signerScope, h.policyScope)
            val anchorScope=h.policyScope; val activation=f.state.journal.activationGeneration
            f.renew(3000, "fixture-reserve") {it.copy(activation=it.activation.copy(timeoutSeconds=31))}
            assertTrue(f.state.journal.activationGeneration>activation)
            h.scope=h.scope.copy(activation=f.state.journal.activationGeneration)
            h.bind(f.binding(), 3000); assertNotEquals(anchorScope, h.policyScope)
        }
        }
    }

    @Test fun downgradeScopeModeAndBootCannotBorrowStableExecutionOrReviveOwner() {
        AssignedPolicyContinuityFixture(config()).use { f ->
            val initial=f.binding(); f.renew(2000); val newer=f.binding()
            ManagedAdaptiveRoutesFairnessTest.Harness(f.raw, initial).use { h ->
                h.ready(1000); val first=checkNotNull(h.tick(1000)); h.failed(first, 1000)
                h.bind(newer, 2000); val stable=h.policyScope
                h.bind(initial, 3000); assertTrue(h.controller.requiresRetirement())
                assertEquals(stable,h.policyScope)
                val before=h.commands.size
                h.bind(replacement(newer, revision=3),4000)
                assertTrue(h.controller.requiresRetirement());h.ready(4000);assertNull(h.tick(5000))
                assertEquals(before,h.commands.size)
            }
            // Retirement is sticky for the old owner; use an independent
            // virtual owner to exercise mode, network and BOOT boundaries.
            ManagedAdaptiveRoutesFairnessTest.Harness(f.raw,newer).use { h ->
                h.ready(1000)
                h.bind(replacement(newer, revision=3), 4000); val revisionScope=h.policyScope
                h.controller.bind(h.scope, NetworkMode.CELLULAR, replacement(newer, revision=4), 5000)
                assertNotEquals(revisionScope, h.policyScope)
                val cellularScope=h.policyScope
                h.scope=h.scope.copy(network=h.scope.network+1)
                h.bind(replacement(newer, revision=5), 6000); assertNotEquals(cellularScope, h.policyScope)
                val sameEngine=h.scope
                h.bind(replacement(newer, revision=6, boot=2), 7000)
                assertTrue(h.controller.requiresRetirement())
                h.bind(replacement(newer, revision=7, boot=2), 8000)
                assertTrue(h.controller.requiresRetirement()) // same owner cannot clear retirement.
                h.scope=sameEngine.copy(engine="synthetic-new-native-owner")
                h.bind(replacement(newer, revision=8, boot=2), 9000)
                assertFalse(h.controller.requiresRetirement())
                assertNotEquals(sameEngine.engine, h.scope.engine)
            }
        }
    }

    @Test fun persistedAnchorFingerprintExcludesFloorsButRotatesAndCorruptionFailsClosed() {
        assumeTrue(android.os.Build.HARDWARE in setOf("ranchu", "goldfish"))
        val context=InstrumentationRegistry.getInstrumentation().targetContext
        val namespace="test-continuity-"+UUID.randomUUID().toString().replace("-", "").take(20)
        val file=File(context.noBackupFilesDir, "$namespace.bin")
        fun pair()=KeyPairGenerator.getInstance("EC").apply {initialize(ECGenParameterSpec("secp256r1"))}.generateKeyPair()
        fun spki(key: KeyPair)=Base64.getEncoder().encodeToString(key.public.encoded)
        val root=pair(); val next=pair(); val online=pair()
        val anchor=TrustAnchor("fixture-old", spki(root), 1)
        val nextAnchor=TrustAnchor("fixture-new", spki(next), 2)
        val now=System.currentTimeMillis()/1000
        fun signed(key: KeyPair, kid: String, body: JsonElement, type: String): String {
            val header=Canonical.encode(buildJsonObject {put("alg", "ES256"); put("kid", kid); put("typ", type)})
            val input=Identity.encode(header.toByteArray())+"."+Identity.encode(Canonical.encode(body).toByteArray())
            val der=Signature.getInstance("SHA256withECDSA").run {initSign(key.private); update(input.toByteArray()); sign()}
            return input+"."+Identity.encode(Identity.derToRaw(der))
        }
        fun manifest(revision: Long, issued: Long): String {
            val descriptor=ServiceDescriptor(1, "syn443-client-bootstrap", 1, revision, "fixture",
                "https://identity.example.invalid/realms/fixture", "syn443-android", "https://api.example.invalid",
                mapOf("online" to spki(online)), issued, issued, now+3600)
            return signed(root, anchor.id, Canonical.json.encodeToJsonElement(descriptor), "syn443-bootstrap+jws")
        }
        val worker=Executors.newSingleThreadExecutor()
        try {
            worker.submit {
                val store=BootstrapTrustStore(context, namespace, anchor)
                assertNull(store.adaptiveAuthorityFingerprint())
                store.acceptDefaultDescriptor(manifest(1, now-10))
                val first=checkNotNull(store.adaptiveAuthorityFingerprint())
                store.acceptDefaultDescriptor(manifest(2, now-1))
                assertEquals(first, store.adaptiveAuthorityFingerprint())
                assertEquals(first, BootstrapTrustStore(context, namespace, anchor).adaptiveAuthorityFingerprint())
                val transition=RootTransition(1, "syn443-root-transition", anchor.id, nextAnchor.id, nextAnchor.spki,
                    2, now, now, now+3600)
                val body=Canonical.json.encodeToJsonElement(transition)
                val rotation=RootRotation(signed(root, anchor.id, body, "syn443-root-transition+jws"),
                    signed(next, nextAnchor.id, body, "syn443-root-transition+jws"))
                store.rotate(Canonical.json.encodeToString(rotation))
                assertNotEquals(first, store.adaptiveAuthorityFingerprint())
                val bytes=file.readBytes()
                file.writeBytes(bytes.copyOf().apply {this[lastIndex]=(this[lastIndex].toInt() xor 1).toByte()})
                assertTrue(runCatching {store.adaptiveAuthorityFingerprint()}.isFailure)
            }.get(30, TimeUnit.SECONDS)
        } finally {
            worker.shutdownNow(); check(worker.awaitTermination(5, TimeUnit.SECONDS))
            for(suffix in listOf("", ".bak", ".new")) File(file.path+suffix).delete()
        }
    }
}
