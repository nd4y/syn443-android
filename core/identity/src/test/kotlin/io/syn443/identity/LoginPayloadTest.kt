package io.syn443.identity

import io.syn443.policy.Canonical
import kotlinx.serialization.encodeToString
import org.junit.Assert.*
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.Base64

class LoginPayloadTest {
    private val key=KeyPairGenerator.getInstance("EC").apply {initialize(ECGenParameterSpec("secp256r1"))}.generateKeyPair()
    private val bootstrap=Bootstrap("test","https://id.example.invalid/realms/test","test","https://api.example.invalid",
        mapOf("root" to Base64.getEncoder().encodeToString(key.public.encoded)))
    private val thumb=Identity.thumbprint(key.public as ECPublicKey)
    private val reserved=LoginRecovery.reserve(LoginIntent(),0,bootstrap,"syn443-dpop-"+Identity.random())
    private val pending=Identity.newPending(reserved.generation,thumb,1,100)
    private val browser=LoginRecovery.prepared(reserved,reserved.generation,thumb,Identity.random())
    private val exchanging=LoginRecovery.consumeCallback(browser,browser.generation)
    private val time=TrustedTime(1,100,1_800_000_000_000,1_800_000_001_000)
    private val user=UserCredential(Identity.random(),"synthetic-subject",thumb,time,reserved.authority)
    private val authenticated=LoginRecovery.authenticated(exchanging,exchanging.generation,bootstrap,user,Identity.random())
    private val enrolling=LoginRecovery.beginEnrollment(authenticated,authenticated.generation,key.public as ECPublicKey,1,100)
    private val session=SessionReply(DeviceSession(Identity.random(),Identity.random(),Identity.random(),time.lowerMs+590_000,
        time.lowerMs+86_000_000,0,Identity.random()),time,reserved.authority,thumb)
    private val registered=LoginRecovery.enrolled(enrolling,enrolling.generation,session,Identity.random())
    private fun invalid(block:()->Unit) {assertThrows(IllegalArgumentException::class.java,block)}
    @Test fun eachProtectedPhaseRoundTripsWithItsOwnRecoveryIntent() {
        for((payload,intent) in listOf(LoginPayload(bootstrap,pending=pending) to browser,
            LoginPayload(bootstrap,user=user) to authenticated,LoginPayload(bootstrap,session=session) to registered)) {
            val encoded=payload.encode();assertEquals(encoded,LoginPayload.decode(encoded,intent).encode())
            assertEquals("LoginPayload([redacted])",payload.toString())
            assertEquals(encoded,LoginPayload.decode(encoded,LoginRecovery.needsReauthentication(intent,intent.generation)).encode())
        }
    }
    @Test fun cacheCannotCrossGenerationKeyOwnerDeviceOrSessionRevision() {
        val p=LoginPayload(bootstrap,pending=pending)
        invalid {p.requireBound(browser.copy(generation=2))};invalid {p.requireBound(browser.copy(thumbprint=Identity.random()))}
        invalid {LoginPayload(bootstrap,user=user).requireBound(authenticated.copy(ownerTag=Identity.random()))}
        val s=LoginPayload(bootstrap,session=session)
        invalid {s.requireBound(registered.copy(deviceId=Identity.random()))}
        invalid {s.requireBound(registered.copy(sessionGeneration=1))}
        invalid {s.requireBound(registered.copy(thumbprint=Identity.random()))}
        invalid {s.requireBound(LoginIntent())}
    }
    @Test fun oldKindAndChangedTrustCannotBeMisreadAsNextPhase() {
        invalid {LoginPayload(bootstrap,pending=pending).requireBound(authenticated)}
        invalid {LoginPayload(bootstrap,user=user).requireBound(enrolling.copy(phase=LoginPhase.NEEDS_REAUTH,operation=null,operationBoot= -1,operationElapsedMs= -1,ownerTag=Identity.random()))}
        invalid {LoginPayload(bootstrap,session=session).requireBound(browser)}
        invalid {LoginPayload(bootstrap.copy(serviceId="different"),pending=pending).requireBound(browser)}
        invalid {LoginPayload(bootstrap.copy(clientId="different"),user=user).encode()}
        invalid {LoginPayload(bootstrap.copy(apiOrigin="https://other.example.invalid"),session=session).encode()}
    }
    @Test fun emptyMixedOversizedAndMalformedPayloadsAreRejected() {
        invalid {LoginPayload(bootstrap).encode()}
        invalid {LoginPayload(bootstrap,pending=pending,user=user).encode()}
        invalid {LoginPayload(bootstrap,pending=pending.copy(verifier="not-a-verifier")).encode()}
        invalid {LoginPayload(bootstrap,pending=pending.copy(bootCount= -1)).encode()}
        invalid {LoginPayload(bootstrap,user=UserCredential("x".repeat(16_385),"test",thumb,time,reserved.authority)).encode()}
        invalid {LoginPayload(bootstrap,user=UserCredential(Identity.random(),"",thumb,time,reserved.authority)).encode()}
        invalid {LoginPayload(bootstrap,session=session.copy(session=session.session.copy(refreshToken=session.session.accessToken))).encode()}
        invalid {LoginPayload(bootstrap,session=session.copy(session=session.session.copy(refreshUntilMs=1))).encode()}
        invalid {LoginPayload(bootstrap,session=session.copy(session=session.session.copy(generation= -1))).encode()}
        invalid {LoginPayload.decode("{\"extra\":1,\"extra\":2}",browser)}
        invalid {LoginPayload.decode("x".repeat(65_537),browser)}
        val raw=Canonical.json.encodeToString(LoginPayload(bootstrap,pending=pending))
        invalid {LoginPayload.decode(raw.replace("\"generation\":1","\"generation\":\"1\""),browser)}
        invalid {LoginPayload.decode(raw.dropLast(1)+",\"extra\":1}",browser)}
    }
}
