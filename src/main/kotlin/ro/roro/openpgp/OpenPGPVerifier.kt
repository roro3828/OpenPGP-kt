package ro.roro.openpgp

import ro.roro.openpgp.packet.PublicKey
import java.security.Provider
import java.security.Security
import java.security.Signature

class OpenPGPVerifier {
    val provider: Provider?
    val publicKey: PublicKey

    constructor(publicKey: PublicKey){
        this.provider = null
        this.publicKey = publicKey
    }

    constructor(publicKey: PublicKey, provider: Provider){
        this.provider = provider
        this.publicKey = publicKey
    }

    constructor(publicKey: PublicKey, providerName: String){
        val provider = Security.getProvider(providerName)

        if(provider == null){
            throw IllegalArgumentException("Provider $providerName not found")
        }
        this.provider = provider
        this.publicKey = publicKey
    }

    fun verify(data: ByteArray, signature: ByteArray): Boolean {

        val algorithm = when(publicKey.keyAlgo){
            OpenPGPPublicKeyAlgorithms.Ed25519,
            OpenPGPPublicKeyAlgorithms.EDDSA_LEGACY -> "Ed25519"
            else -> throw Error("Unsupported algorithm: ${publicKey.keyAlgo}")
        }

        val verifier = if(provider == null){
            Signature.getInstance(algorithm)
        } else {
            Signature.getInstance(algorithm, provider)
        }

        verifier.initVerify(publicKey.key)

        return verifier.let {
            it.update(data)
            it.verify(signature)
        }
    }
}