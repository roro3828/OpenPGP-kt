package ro.roro.openpgp

import ro.roro.openpgp.packet.PublicKey
import java.io.ByteArrayInputStream
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
        val provider =
            Security.getProvider(providerName) ?: throw IllegalArgumentException("Provider $providerName not found")

        this.provider = provider
        this.publicKey = publicKey
    }

    /**
     * 署名を検証
     * @param digest 検証するダイジェスト
     * @param signature 検証する署名 RFC 9580に従った形式で
     */
    fun verify(digest: ByteArray, signature: ByteArray): Boolean {

        val algorithm = when(publicKey.keyAlgo){
            OpenPGPPublicKeyAlgorithms.Ed25519,
            OpenPGPPublicKeyAlgorithms.EDDSA_LEGACY -> "Ed25519"
            else -> throw Error("Unsupported algorithm: ${publicKey.keyAlgo}")
        }

        // RFC 9580に従い、署名値を抽出
        val signatureValue = when(publicKey.keyAlgo){
            OpenPGPPublicKeyAlgorithms.EDDSA_LEGACY -> {
                // Ed25519の署名は64バイトのRとSの連結
                val bytesInputStream = ByteArrayInputStream(signature)
                val rLen = OpenPGPUtil.readMPILen(bytesInputStream)
                val r = bytesInputStream.readNBytes(rLen)
                val sLen = OpenPGPUtil.readMPILen(bytesInputStream)
                val s = bytesInputStream.readNBytes(sLen)

                r + s
            }
            else -> throw Error("Unsupported algorithm: ${publicKey.keyAlgo}")
        }

        val verifier = if(provider == null){
            Signature.getInstance(algorithm)
        } else {
            Signature.getInstance(algorithm, provider)
        }

        verifier.initVerify(publicKey.key)

        verifier.update(digest)

        return verifier.verify(signatureValue)
    }
}