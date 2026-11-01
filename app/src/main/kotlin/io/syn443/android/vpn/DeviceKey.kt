package io.syn443.android.vpn

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import io.syn443.identity.Identity
import io.syn443.identity.ProofKey
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

/** No private bytes leave Keystore. Call on the bounded identity worker, never the UI thread. */
class DeviceKey private constructor(val alias: String):ProofKey {
    companion object {
        private val pattern=Regex("syn443-dpop-[A-Za-z0-9_-]{43}")
        private val lock=Any()
        private fun store()=KeyStore.getInstance("AndroidKeyStore").apply {load(null)}
        fun newAlias()="syn443-dpop-"+Identity.random()
        fun create(alias:String=newAlias()):DeviceKey = checkNotNull(createIfCurrent(alias) {true})
        /** The predicate takes only the short public-intent lock, never crypto/network locks. */
        fun createIfCurrent(alias:String,current:()->Boolean):DeviceKey? = synchronized(lock) {
            require(pattern.matches(alias))
            if(!current())return@synchronized null
            check(!store().containsAlias(alias))
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC,"AndroidKeyStore").apply {
                initialize(KeyGenParameterSpec.Builder(alias,KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256).setUserAuthenticationRequired(false).build())
            }.generateKeyPair()
            DeviceKey(alias)
        }
        fun open(alias:String):DeviceKey = synchronized(lock) {
            require(pattern.matches(alias));check(store().containsAlias(alias));DeviceKey(alias)
        }
        /** Also works when cancellation precedes creation. Never accepts another subsystem's alias. */
        fun deleteOwned(alias:String) = synchronized(lock) {
            require(pattern.matches(alias));store().deleteEntry(alias);check(!store().containsAlias(alias))
        }
    }
    fun publicKey():ECPublicKey = synchronized(lock) {
        val key=store().getCertificate(alias).publicKey as ECPublicKey
        check(key.params.order==Identity.ecParameters.order && key.params.cofactor==1);key
    }
    override val publicKey:ECPublicKey get()=publicKey()
    override fun sign(input:ByteArray):ByteArray = synchronized(lock) {
        require(input.size in 1..32_768)
        val key=store().getKey(alias,null) as PrivateKey
        check(key.encoded==null)
        Signature.getInstance("SHA256withECDSA").run {initSign(key);update(input);sign()}
    }
    fun delete() = deleteOwned(alias)
}
