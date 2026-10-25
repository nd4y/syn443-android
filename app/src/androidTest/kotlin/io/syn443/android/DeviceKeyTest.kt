package io.syn443.android

import androidx.test.ext.junit.runners.AndroidJUnit4
import io.syn443.android.vpn.DeviceKey
import io.syn443.identity.Identity
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyStore
import java.security.Signature

@RunWith(AndroidJUnit4::class)
class DeviceKeyTest {
    @Test fun keystoreIdentityPersistsSignsAndCannotExportPrivateMaterial() {
        val key=DeviceKey.create()
        try {
            val public=key.publicKey();val reopened=DeviceKey.open(key.alias)
            assertArrayEquals(public.encoded,reopened.publicKey().encoded)
            val bytes="synthetic request".toByteArray();val signature=reopened.sign(bytes)
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
}
