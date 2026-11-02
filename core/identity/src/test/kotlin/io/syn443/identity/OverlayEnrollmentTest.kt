package io.syn443.identity

import io.syn443.policy.Canonical
import kotlinx.serialization.encodeToString
import org.junit.Assert.*
import org.junit.Test

class OverlayEnrollmentTest {
    private fun digest(s:String)=Identity.hash(s.toByteArray())
    private fun binding()=OverlayCredentialBinding(OverlayAddress("fixture",digest("owner"),"device-12345","home","netbird","resource","tenant",1,"https://overlay.example.invalid"),digest("key"),digest("ref"),1,0,1_800_000_060_000L)
    private fun invalid(block:()->Unit){assertThrows(IllegalArgumentException::class.java,block)}
    @Test fun durableFlowRetainsOperationAndErasesBeforeAcknowledgment() {
        val b=binding();val reserved=OverlayEnrollments.reserve(b,7)
        assertEquals(OverlayPhase.RESERVED,reserved.phase)
        val cached=OverlayEnrollments.cached(reserved,digest("protected"),1_800_000_030_000L)
        val starting=OverlayEnrollments.enrolling(cached)
        val retried=OverlayEnrollments.enrolling(starting)
        val registered=OverlayEnrollments.registered(retried,digest("native-durable-identity"))
        val erasing=OverlayEnrollments.erasing(registered)
        val erasingAgain=OverlayEnrollments.erasing(erasing)
        val erased=OverlayEnrollments.erased(erasingAgain)
        val ack=OverlayEnrollments.acknowledged(erased)
        val ackAgain=OverlayEnrollments.acknowledged(ack)
        for(s in listOf(reserved,cached,starting,retried,registered,erasing,erasingAgain,erased,ack,ackAgain)) {
            OverlayEnrollments.validate(s);OverlayEnrollments.requireAuthorized(s,b,7)
            assertEquals(reserved.operation,s.operation)
            assertEquals(s,Canonical.json.decodeFromString<OverlayEnrollment>(Canonical.json.encodeToString(s)))
            assertFalse(s.toString().contains(b.reference));assertFalse(s.operation.toString().contains(b.reference))
        }
        assertEquals("",erased.protectedHash);assertEquals(0L,erased.credentialUntilMs)
        assertTrue(ack.revision>reserved.revision)
        invalid{OverlayEnrollments.acknowledged(registered)}
        invalid{OverlayEnrollments.registered(cached,digest("fake-ack"))}
        invalid{OverlayEnrollments.erased(registered)}
        invalid{OverlayEnrollments.cached(cached,digest("another"),1)}
        invalid{OverlayEnrollments.registered(starting,"invalid")}
    }
    @Test fun cancellationWithdrawsEveryPhaseAndCannotBeReactivated() {
        val b=binding();val reserved=OverlayEnrollments.reserve(b,2)
        val cached=OverlayEnrollments.cached(reserved,digest("cipher"),100)
        val enrolling=OverlayEnrollments.enrolling(cached)
        val registered=OverlayEnrollments.registered(enrolling,digest("native"))
        val erasing=OverlayEnrollments.erasing(registered);val erased=OverlayEnrollments.erased(erasing)
        for(value in listOf(reserved,cached,enrolling,registered,erasing,erased,OverlayEnrollments.acknowledged(erased))) {
            val retiring=OverlayEnrollments.retiring(value);val retired=OverlayEnrollments.retired(retiring)
            assertEquals("",retiring.protectedHash);assertEquals(0L,retiring.credentialUntilMs)
            OverlayEnrollments.validate(retired)
            invalid{OverlayEnrollments.requireAuthorized(retiring,b,2)}
            invalid{OverlayEnrollments.requireAuthorized(retired,b,2)}
            invalid{OverlayEnrollments.retiring(retired)}
            invalid{OverlayEnrollments.retired(value)}
            invalid{OverlayEnrollments.enrolling(retired)}
        }
    }
    @Test fun pendingAuthorityCannotSwitchAccountKeyDeviceEpochReferenceOrGeneration() {
        val b=binding();val s=OverlayEnrollments.reserve(b,9)
        for(changed in listOf(b.copy(keyThumbprint=digest("other")),b.copy(reference=digest("other")),b.copy(version=2),b.copy(securityEpoch=1),b.copy(address=b.address.copy(deviceId="other-device")),b.copy(address=b.address.copy(resourceId="other")),b.copy(address=b.address.copy(identityEpoch=2)))) {
            invalid{OverlayEnrollments.requireAuthorized(s,changed,9)}
        }
        invalid{OverlayEnrollments.requireAuthorized(s,b,10)}
        val registered=OverlayEnrollments.registered(OverlayEnrollments.enrolling(OverlayEnrollments.cached(s,digest("cipher"),100)),digest("native"))
        OverlayEnrollments.requireAuthorized(registered,b.copy(reference=digest("refresh-ref"),version=3,securityEpoch=2,offlineUntilMs=200),9)
        // Transport and config revision are deliberately not part of the binding.
        OverlayEnrollments.requireAuthorized(s,b.copy(address=b.address.copy(managementURL="https://OVERLAY.EXAMPLE.INVALID:443/")),9)
    }
    @Test fun boundedOperationsAndCorruptJournalAreRejected() {
        val b=binding();val s=OverlayEnrollments.reserve(b,0);s.operation.requireBound(b)
        assertTrue(s.operation.body().contains("operationId"))
        invalid{OverlayOperation("short",s.operation.namespace,b.reference,1)}
        invalid{OverlayOperation(Identity.random(),"netbird/"+digest("unsafe"),b.reference,1)}
        invalid{OverlayOperation(Identity.random(),s.operation.namespace,"bad",1)}
        invalid{OverlayOperation(Identity.random(),s.operation.namespace,b.reference,0)}
        invalid{s.operation.requireBound(b.copy(version=2))}
        invalid{OverlayEnrollments.reserve(b,-1)}
        invalid{OverlayEnrollments.reserve(b.copy(keyThumbprint="bad"),0)}
        for(value in listOf(s.copy(revision=0),s.copy(identityTag="bad"),s.copy(bindingTag="bad"),s.copy(protectedHash="bad"),s.copy(identityEvidence="bad"),s.copy(credentialUntilMs=-1),s.copy(protectedHash=digest("unexpected")),s.copy(phase=OverlayPhase.CACHED),s.copy(phase=OverlayPhase.ERASING))) {
            invalid{OverlayEnrollments.validate(value)}
        }
        assertNull(runCatching {Canonical.json.decodeFromString<OverlayEnrollment>("{}")}.getOrNull())
    }
    @Test fun grantReplacementKeepsIdentityButRequiresErasureAndANewAddressedReference() {
        val b=binding();val initial=OverlayEnrollments.reserve(b,4)
        val cached=OverlayEnrollments.cached(initial,digest("cipher"),100)
        val refreshed=b.copy(reference=digest("fresh-ref"),version=2,securityEpoch=1)
        for(pending in listOf(initial,cached,OverlayEnrollments.enrolling(cached))) {
            invalid{OverlayEnrollments.requireAuthorized(pending,refreshed,4)}
            OverlayEnrollments.requireIdentity(pending,refreshed,4)
            val discarding=OverlayEnrollments.discarding(pending)
            val retry=OverlayEnrollments.discarding(discarding)
            val discarded=OverlayEnrollments.discarded(retry)
            for(s in listOf(discarding,retry,discarded)) {
                assertEquals(initial.operation,s.operation);OverlayEnrollments.requireAuthorized(s,refreshed,4)
                assertEquals("",s.protectedHash);assertEquals(0L,s.credentialUntilMs);assertEquals("",s.identityEvidence)
                assertEquals(s,Canonical.json.decodeFromString<OverlayEnrollment>(Canonical.json.encodeToString(s)))
            }
            val replaced=OverlayEnrollments.replaceDiscarded(discarded,refreshed,4)
            assertEquals(initial.identityTag,replaced.identityTag);assertEquals(OverlayPhase.RESERVED,replaced.phase)
            assertEquals(discarded.revision+1,replaced.revision);assertNotEquals(initial.operation,replaced.operation)
            OverlayEnrollments.requireAuthorized(replaced,refreshed,4)
            invalid{OverlayEnrollments.requireAuthorized(replaced,b,4)}
            invalid{OverlayEnrollments.replaceDiscarded(discarded,b,4)}
            invalid{OverlayEnrollments.replaceDiscarded(discarding,refreshed,4)}
            invalid{OverlayEnrollments.discarded(pending)}
            invalid{OverlayEnrollments.replaceDiscarded(discarded,refreshed,5)}
            invalid{OverlayEnrollments.replaceDiscarded(discarded,refreshed.copy(keyThumbprint=digest("other-key")),4)}
            invalid{OverlayEnrollments.replaceDiscarded(discarded,refreshed.copy(address=b.address.copy(identityEpoch=2)),4)}
        }
    }
    @Test fun confirmedIdentityCannotDiscardItsGrantToSilentlyRegisterAgain() {
        val b=binding();val s=OverlayEnrollments.reserve(b,2)
        val registered=OverlayEnrollments.registered(OverlayEnrollments.enrolling(OverlayEnrollments.cached(s,digest("cipher"),100)),digest("native"))
        val erasing=OverlayEnrollments.erasing(registered);val erased=OverlayEnrollments.erased(erasing)
        for(value in listOf(registered,erasing,erased,OverlayEnrollments.acknowledged(erased),OverlayEnrollments.retiring(s),OverlayEnrollments.retired(OverlayEnrollments.retiring(s)))) {
            invalid{OverlayEnrollments.discarding(value)}
            invalid{OverlayEnrollments.replaceDiscarded(value,b.copy(version=2),2)}
        }
        for(phase in listOf(OverlayPhase.DISCARDING,OverlayPhase.DISCARDED)) {
            invalid{OverlayEnrollments.validate(s.copy(phase=phase,identityEvidence=digest("native")))}
            invalid{OverlayEnrollments.validate(s.copy(phase=phase,protectedHash=digest("unexpected")))}
            val cleanup=s.copy(phase=phase)
            val retired=OverlayEnrollments.retired(OverlayEnrollments.retiring(cleanup));OverlayEnrollments.validate(retired)
            invalid{OverlayEnrollments.requireAuthorized(retired,b,2)}
        }
    }

    @Test fun newCapabilityAdvertisementPreservesExactLegacyEnrollmentAndInvitationRetries() {
        val key=java.security.KeyPairGenerator.getInstance("EC").apply{initialize(java.security.spec.ECGenParameterSpec("secp256r1"))}.generateKeyPair().public as java.security.interfaces.ECPublicKey
        val enroll=IdentityOperation.enroll(key);val claim=InvitationOperation.claim(Identity.random(),key)
        val expected=kotlinx.serialization.json.JsonArray(IdentityOperation.supportedCapabilities.map{ kotlinx.serialization.json.JsonPrimitive(it) })
        assertEquals(expected,Identity.objectJSON(enroll.body).getValue("capabilities"))
        assertEquals(expected,Identity.objectJSON(claim.body).getValue("capabilities"))
        assertTrue(IdentityOperation.supportedCapabilities.containsAll(IdentityOperation.requiredCapabilities))
        assertTrue("overlay.credentials.v1" in IdentityOperation.supportedCapabilities)
        val old=kotlinx.serialization.json.JsonArray(IdentityOperation.requiredCapabilities.map{ kotlinx.serialization.json.JsonPrimitive(it) })
        val oldEnrollBody=Canonical.encode(kotlinx.serialization.json.JsonObject(Identity.objectJSON(enroll.body)+("capabilities" to old)))
        val oldClaimBody=Canonical.encode(kotlinx.serialization.json.JsonObject(Identity.objectJSON(claim.body)+("capabilities" to old)))
        val oldEnroll=IdentityOperation(enroll.path,oldEnrollBody);val oldClaim=InvitationOperation(claim.path,oldClaimBody)
        assertEquals(oldEnroll,Canonical.json.decodeFromString<IdentityOperation>(Canonical.json.encodeToString(oldEnroll)))
        assertEquals(oldClaim,Canonical.json.decodeFromString<InvitationOperation>(Canonical.json.encodeToString(oldClaim)))
        assertEquals(oldEnrollBody,oldEnroll.body);assertEquals(oldClaimBody,oldClaim.body)
    }
}
