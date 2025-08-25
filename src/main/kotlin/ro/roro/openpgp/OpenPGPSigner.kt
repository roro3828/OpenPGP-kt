package ro.roro.openpgp

import ro.roro.openpgp.packet.SecretKey
import ro.roro.openpgp.packet.signature.SignatureSubPacket
import java.io.ByteArrayOutputStream
import java.security.Provider
import java.security.Security
import java.security.Signature

class OpenPGPSigner{

    val provider: Provider?
    val secretKey: SecretKey

    constructor(secretKey: SecretKey){
        this.provider = null
        this.secretKey = secretKey
    }

    constructor(secretKey: SecretKey, provider: Provider){
        this.provider = provider
        this.secretKey = secretKey
    }

    constructor(secretKey: SecretKey, providerName: String){
        val provider = Security.getProvider(providerName)

        if(provider == null){
            throw IllegalArgumentException("Provider $providerName not found")
        }
        this.provider = provider
        this.secretKey = secretKey
    }

    fun sign(digest: ByteArray, passPhrase: String): ByteArray {
        return sign(digest, passPhrase.toByteArray())
    }
    /**
     * digestに対して署名を生成する
     * @param digest 署名対象のダイジェスト値
     * @param passPhrase パスフレーズ
     * @return 署名値 署名値はRFC 9580の仕様に従った形式で返される
     */
    fun sign(digest: ByteArray, passPhrase: ByteArray? = null): ByteArray {
        if(secretKey.keyVertion != 4 && secretKey.keyVertion != 6){
            // このライブラリではv4とv6の署名生成のみサポート
            throw Error("This library only supports signature generation for v4 and v6 keys.")
        }

        val algorithm = when(secretKey.keyAlgo){
            OpenPGPPublicKeyAlgorithms.Ed25519,
            OpenPGPPublicKeyAlgorithms.EDDSA_LEGACY -> "Ed25519"
            else -> throw Error("Unsupported algorithm: ${secretKey.keyAlgo}")
        }

        val signer = if(provider == null){
            Signature.getInstance(algorithm)
        } else {
            Signature.getInstance(algorithm, provider)
        }

        signer.initSign(secretKey.getSecretKey(passPhrase))

        val signature = signer.let {
            it.update(digest)
            it.sign()
        }

        val signatureValue = when(secretKey.keyAlgo){
            OpenPGPPublicKeyAlgorithms.EDDSA_LEGACY -> {
                // Ed25519の署名は64バイトのRとSの連結
                // OpenPGPではMPIとして格納するため、先頭に2バイトの長さを付与する
                val r = signature.sliceArray(0 until 32)
                val s = signature.sliceArray(32 until 64)

                val rWithLength = OpenPGPUtil.toMPI(r)
                val sWithLength = OpenPGPUtil.toMPI(s)

                rWithLength + sWithLength
            }
            else -> throw Error("Unsupported algorithm: ${secretKey.keyAlgo}")
        }


        return signatureValue
    }
}