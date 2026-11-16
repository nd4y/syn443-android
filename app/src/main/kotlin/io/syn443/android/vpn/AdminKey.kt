package io.syn443.android.vpn

import android.os.Looper
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

/** Administrative signing identity only. Private key bytes never leave Android Keystore. */
internal class AdminKey private constructor(val alias:String):ProofKey {
    companion object {
        private val pattern=Regex("syn443-admin-dpop-[A-Za-z0-9_-]{43}")
        private val lock=Any()
        fun newAlias()="syn443-admin-dpop-"+Identity.random()
        fun ownedAlias(alias:String)=pattern.matches(alias)
        private fun worker() {
            check(Looper.myLooper()!=Looper.getMainLooper() && !Thread.currentThread().name.startsWith("Binder:")) {
                "admin_key_worker_required"
            }
        }
        private fun store()=KeyStore.getInstance("AndroidKeyStore").apply {load(null)}
        private fun publicFrom(store:KeyStore,alias:String):ECPublicKey {
            val key=store.getCertificate(alias)?.publicKey as? ECPublicKey ?: error("admin_key_unavailable")
            val expected=Identity.ecParameters
            check(key.params.curve==expected.curve && key.params.generator==expected.generator &&
                key.params.order==expected.order && key.params.cofactor==expected.cofactor) {"admin_key_curve_invalid"}
            return key
        }
        /** Persist the owned reservation before calling this method. The predicate must remain short. */
        fun createIfCurrent(alias:String,current:()->Boolean):AdminKey? {
            worker();require(ownedAlias(alias)) {"admin_key_alias_invalid"}
            return synchronized(lock) {
                if(!current())return@synchronized null
                check(!store().containsAlias(alias)) {"admin_key_already_exists"}
                KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC,"AndroidKeyStore").apply {
                    initialize(KeyGenParameterSpec.Builder(alias,KeyProperties.PURPOSE_SIGN)
                        .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                        .setDigests(KeyProperties.DIGEST_SHA256).setUserAuthenticationRequired(false).build())
                }.generateKeyPair()
                publicFrom(store(),alias)
                AdminKey(alias)
            }
        }
        fun open(alias:String):AdminKey {
            worker();require(ownedAlias(alias)) {"admin_key_alias_invalid"}
            return synchronized(lock) {publicFrom(store(),alias);AdminKey(alias)}
        }
        /** Only a journal's already persisted RETIRING alias may be retired by its controller. */
        fun deleteOwned(alias:String) {
            worker();require(ownedAlias(alias)) {"admin_key_alias_invalid"}
            synchronized(lock) {val store=store();store.deleteEntry(alias);check(!store.containsAlias(alias))}
        }
    }
    override val publicKey:ECPublicKey get() {
        worker()
        return synchronized(lock) {publicFrom(store(),alias)}
    }
    override fun sign(input:ByteArray):ByteArray {
        worker();require(input.size in 1..32_768)
        return synchronized(lock) {
            val key=store().getKey(alias,null) as? PrivateKey ?: error("admin_key_unavailable")
            check(key.encoded==null) {"admin_key_exportable"}
            Signature.getInstance("SHA256withECDSA").run {initSign(key);update(input);sign()}
        }
    }
    override fun toString()="AdminKey([redacted])"
}
