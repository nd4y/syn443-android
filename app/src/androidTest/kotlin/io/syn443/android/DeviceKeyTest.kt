package io.syn443.android

import androidx.test.ext.junit.runners.AndroidJUnit4
import io.syn443.android.vpn.DeviceKey
import io.syn443.identity.Identity
import io.syn443.identity.ProofKey
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyStore
import java.security.Signature
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

@RunWith(AndroidJUnit4::class)
class DeviceKeyTest {
    @Test fun keystoreIdentityPersistsSignsAndCannotExportPrivateMaterial() {
        val key=DeviceKey.create()
        try {
            val public=key.publicKey();val reopened=DeviceKey.open(key.alias)
            assertArrayEquals(public.encoded,reopened.publicKey().encoded)
            val adapter:ProofKey=reopened;assertArrayEquals(public.encoded,adapter.publicKey.encoded)
            val bytes="synthetic request".toByteArray();val signature=adapter.sign(bytes)
            assertTrue(Signature.getInstance("SHA256withECDSA").run {initVerify(public);update(bytes);verify(signature)})
            assertEquals(64,Identity.derToRaw(signature).size)
            val store=KeyStore.getInstance("AndroidKeyStore").apply {load(null)}
            assertNull(store.getKey(key.alias,null).encoded)
            assertEquals(Identity.thumbprint(public),Identity.thumbprint(reopened.publicKey()))
        } finally {key.delete()}
        assertThrows(IllegalStateException::class.java) {DeviceKey.open(key.alias)}
    }
    @Test fun identityKeysAreIndependentAndCannotDeleteUnrelatedAliases() {
        val first=DeviceKey.create();val second=DeviceKey.create()
        try {
            assertNotEquals(first.alias,second.alias)
            assertNotEquals(Identity.thumbprint(first.publicKey()),Identity.thumbprint(second.publicKey()))
            first.delete();assertNotNull(DeviceKey.open(second.alias).publicKey())
            assertThrows(IllegalArgumentException::class.java) {DeviceKey.open("syn443-policy-v1")}
        } finally {first.delete();second.delete()}
    }
    @Test fun cancellationOrdersDeletionAfterInFlightCreationAndFencesQueuedCreation() {
        val alias=DeviceKey.newAlias();val pool=Executors.newFixedThreadPool(2)
        val entered=CountDownLatch(1);val release=CountDownLatch(1);val current=AtomicBoolean(true)
        try {
            assertNull(DeviceKey.createIfCurrent(alias) {false})
            assertThrows(IllegalStateException::class.java) {DeviceKey.open(alias)}
            val creating=pool.submit<DeviceKey?> {DeviceKey.createIfCurrent(alias) {
                val admitted=current.get();entered.countDown();check(release.await(10,TimeUnit.SECONDS));admitted
            }}
            assertTrue(entered.await(10,TimeUnit.SECONDS))
            current.set(false) // Public intent fence does not acquire the Keystore lock.
            val deleting=pool.submit {DeviceKey.deleteOwned(alias)}
            release.countDown();assertNotNull(creating.get(15,TimeUnit.SECONDS));deleting.get(15,TimeUnit.SECONDS)
            assertThrows(IllegalStateException::class.java) {DeviceKey.open(alias)}
            // Cleanup can finish before the queued creation starts. That creation must remain absent.
            assertNull(DeviceKey.createIfCurrent(alias) {current.get()})
            assertThrows(IllegalStateException::class.java) {DeviceKey.open(alias)}
            assertThrows(IllegalArgumentException::class.java) {DeviceKey.deleteOwned("syn443-policy-v1")}
        } finally {current.set(false);release.countDown();pool.shutdownNow();DeviceKey.deleteOwned(alias)}
    }
}
