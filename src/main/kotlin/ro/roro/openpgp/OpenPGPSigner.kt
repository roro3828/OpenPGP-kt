package ro.roro.openpgp

import ro.roro.openpgp.packet.PublicKey
import ro.roro.openpgp.packet.SecretKey
import java.security.Provider
import java.security.Security

class OpenPGPSigner(val secretKey: SecretKey, provider: Provider? = null): OpenPGPVerifier(secretKey.publicKey, provider) {

    init {
        if(secretKey.keyVertion != 4 && secretKey.keyVertion != 6){
            // このライブラリではv4とv6の署名のみサポート
            throw Error("This library supports only v4 and v6 signatures.")
        }
    }

    constructor(secretKey: SecretKey): this(secretKey, null)

    /**
     * providerNameで指定されたセキュリティプロバイダを使用して署名オブジェクトを初期化するコンストラクタ
     * providerNameで指定された名前のプロバイダが見つからない場合、エラーがスローされる
     * @param secretKey 秘密鍵
     * @param providerName セキュリティプロバイダの名前
     * @throws Error 指定された名前のプロバイダが見つからない場合にスローされる
     */
    @Throws(Error::class)
    constructor(secretKey: SecretKey, providerName: String): this(
        secretKey,
        Security.getProviders().firstOrNull { it.name == providerName }
            ?: throw Error("Provider not found: $providerName")
    )

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

        signer.initSign(secretKey.getSecretKey(passPhrase))

        val signature = signer.let {
            it.update(digest)
            it.sign()
        }

        val signatureValue = when(secretKey.keyAlgo){
            PublicKey.EDDSA_LEGACY -> {
                // Ed25519の署名は64バイトのRとSの連結
                // OpenPGPではMPIとして格納するため、先頭に2バイトの長さを付与する
                val r = signature.sliceArray(0 until 32)
                val s = signature.sliceArray(32 until 64)

                val rWithLength = OpenPGPUtil.toMPI(r)
                val sWithLength = OpenPGPUtil.toMPI(s)

                rWithLength + sWithLength
            }

            PublicKey.Ed25519 -> {
                signature
            }
            else -> throw Error("Unsupported algorithm: ${secretKey.keyAlgo}")
        }


        return signatureValue
    }
}