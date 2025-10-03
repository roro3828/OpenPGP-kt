package ro.roro.openpgp

import ro.roro.openpgp.OpenPGPSigner
import ro.roro.openpgp.packet.PublicKey
import ro.roro.openpgp.packet.SecretKey
import java.io.ByteArrayInputStream
import java.security.Provider
import java.security.Security
import java.security.Signature

open class OpenPGPVerifier(val publicKey: PublicKey, provider: Provider? = null) {
    protected val signer: Signature

    val provider: Provider
        get() = signer.provider

    val keyAlgo: Int
        get() = publicKey.keyAlgo

    init {
        val algorithm = when(publicKey.keyAlgo){
            PublicKey.Ed25519,
            PublicKey.EDDSA_LEGACY -> "Ed25519"
            else -> throw Error("Unsupported algorithm: ${publicKey.keyAlgo}")
        }

        this.signer = if(provider == null){
            Signature.getInstance(algorithm)
        } else {
            Signature.getInstance(algorithm, provider)
        }
    }

    constructor(publicKey: PublicKey): this(publicKey, null)

    /**
     * providerNameで指定されたセキュリティプロバイダを使用して署名オブジェクトを初期化するコンストラクタ
     * providerNameで指定された名前のプロバイダが見つからない場合、エラーがスローされる
     * @param publicKey 公開鍵
     * @param providerName セキュリティプロバイダの名前
     * @throws Error 指定された名前のプロバイダが見つからない場合にスローされる
     */
    @Throws(Error::class)
    constructor(publicKey: PublicKey, providerName: String): this(
        publicKey,
        Security.getProviders().firstOrNull { it.name == providerName }
            ?: throw Error("Provider not found: $providerName")
    )

    /**
     * 署名を検証
     * @param digest 検証するダイジェスト
     * @param signature 検証する署名 RFC 9580に従った形式で
     */
    fun verify(digest: ByteArray, signature: ByteArray): Boolean {

        // RFC 9580に従い、署名値を抽出
        val signatureValue = when(publicKey.keyAlgo){
            PublicKey.EDDSA_LEGACY -> {
                // Ed25519の署名は64バイトのRとSの連結
                val bytesInputStream = ByteArrayInputStream(signature)
                val rLen = OpenPGPUtil.readMPILen(bytesInputStream)
                val r = bytesInputStream.readNBytes(rLen)
                val sLen = OpenPGPUtil.readMPILen(bytesInputStream)
                val s = bytesInputStream.readNBytes(sLen)

                r + s
            }

            PublicKey.Ed25519 -> {
                // Ed25519の署名は64バイトのRとSの連結
                if(signature.size != 64){
                    throw Error("Invalid Ed25519 signature length: ${signature.size}")
                }
                signature
            }
            else -> throw Error("Unsupported algorithm: ${publicKey.keyAlgo}")
        }

        signer.let {
            it.initVerify(publicKey.key)
            it.update(digest)
        }

        return signer.verify(signatureValue)
    }
}