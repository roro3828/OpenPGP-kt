package ro.roro.openpgp

import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Provider
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 *     +=========+==================+==============+====================+
 *     |      ID | Name             | Nonce Length | Authentication Tag |
 *     |         |                  | (Octets)     | Length (Octets)    |
 *     +=========+==================+==============+====================+
 *     |       0 | Reserved         |              |                    |
 *     +---------+------------------+--------------+--------------------+
 *     |       1 | EAX [EAX]        | 16           | 16                 |
 *     +---------+------------------+--------------+--------------------+
 *     |       2 | OCB [RFC7253]    | 15           | 16                 |
 *     +---------+------------------+--------------+--------------------+
 *     |       3 | GCM [SP800-38D]  | 12           | 16                 |
 *     +---------+------------------+--------------+--------------------+
 *     | 100-110 | Private or       |              |                    |
 *     |         | Experimental Use |              |                    |
 *     +---------+------------------+--------------+--------------------+
 */
class OpenPGPAEAD(val aeadAlgorithm: Int, provider: Provider? = BouncyCastleProvider()) {
    private val cipher: Cipher = if(provider == null){
        Cipher.getInstance(getTransformationString(aeadAlgorithm))
    }
    else {
        Cipher.getInstance(getTransformationString(aeadAlgorithm), provider)
    }

    val transformation: String = getTransformationString(aeadAlgorithm)
    val nonceLength: Int = getNonceLength(aeadAlgorithm)
    val tagLength: Int = getTagLength(aeadAlgorithm)

    companion object{
        const val EAX = 1
        const val OCB = 2
        const val GCM = 3

        const val EAX_NONCE_LENGTH = 16
        const val OCB_NONCE_LENGTH = 15
        const val GCM_NONCE_LENGTH = 12

        const val EAX_TAG_LENGTH = 16
        const val OCB_TAG_LENGTH = 16
        const val GCM_TAG_LENGTH = 16

        const val AES_EAX_TRANSFORMATION = "AES/EAX/NoPadding"
        const val AES_OCB_TRANSFORMATION = "AES/OCB/NoPadding"
        const val AES_GCM_TRANSFORMATION = "AES/GCM/NoPadding"

        /**
         * 指定されたAEADアルゴリズムに対応するノンスの長さを取得
         */
        fun getNonceLength(aeadAlgo: Int): Int {
            return when(aeadAlgo){
                EAX -> EAX_NONCE_LENGTH
                OCB -> OCB_NONCE_LENGTH
                GCM -> GCM_NONCE_LENGTH
                else -> throw Error("Unsupported AEAD algorithm: $aeadAlgo")
            }
        }

        /**
         * 指定されたAEADアルゴリズムに対応する認証タグの長さを取得
         */
        fun getTagLength(aeadAlgo: Int): Int {
            return when(aeadAlgo){
                EAX -> EAX_TAG_LENGTH
                OCB -> OCB_TAG_LENGTH
                GCM -> GCM_TAG_LENGTH
                else -> throw Error("Unsupported AEAD algorithm: $aeadAlgo")
            }
        }

        /**
         * 指定されたAEADアルゴリズムに対応するCipherのtransformation文字列を取得
         */
        fun getTransformationString(aeadAlgo: Int): String {
            return when(aeadAlgo){
                EAX -> AES_EAX_TRANSFORMATION
                OCB -> AES_OCB_TRANSFORMATION
                GCM -> AES_GCM_TRANSFORMATION
                else -> throw Error("Unsupported AEAD algorithm: $aeadAlgo")
            }
        }
    }

    /**
     * dataをAEADで暗号化
     * @param data 暗号化するデータ
     * @param key 鍵
     * @param nonce ノンス 長さはnonceLengthで指定された長さである必要がある
     * @param associatedData 認証に使用する追加データ 長さはtagLengthで指定された長さである必要がある
     * @return 暗号化されたデータ
     */
    fun encrypt(data: ByteArray, key: ByteArray, nonce: ByteArray, associatedData: ByteArray? = null): ByteArray {
        return encrypt(data, SecretKeySpec(key, OpenPGPSymmetricKeyAlgorithm.AES_STANDARD_NAME), nonce, associatedData)
    }

    /**
     * dataをAEADで暗号化
     * @param data 暗号化するデータ
     * @param key 鍵
     * @param nonce ノンス 長さはnonceLengthで指定された長さである必要がある
     * @param associatedData 認証に使用する追加データ 長さはtagLengthで指定された長さである必要がある
     * @return 暗号化されたデータ
     */
    fun encrypt(data: ByteArray, key: SecretKey, nonce: ByteArray, associatedData: ByteArray? = null): ByteArray {
        require(nonce.size == nonceLength) { "Invalid nonce length: ${nonce.size}, expected: $nonceLength" }

        val parameter = GCMParameterSpec(tagLength * 8, nonce)

        cipher.init(Cipher.ENCRYPT_MODE, key, parameter)

        if(associatedData != null){
            cipher.updateAAD(associatedData)
        }

        return cipher.doFinal(data)
    }

    /**
     * dataをAEADで復号
     * @param data 復号するデータ
     * @param key 鍵
     * @param nonce ノンス 長さはnonceLengthで指定された長さである必要がある
     * @param associatedData 認証に使用する追加データ 長さはtagLengthで指定された長さである必要がある
     * @return 復号されたデータ
     */
    fun decrypt(data: ByteArray, key: ByteArray, nonce: ByteArray, associatedData: ByteArray? = null): ByteArray {
        return decrypt(data, SecretKeySpec(key, OpenPGPSymmetricKeyAlgorithm.AES_STANDARD_NAME), nonce, associatedData)

    }
    /**
     * dataをAEADで復号
     * @param data 復号するデータ
     * @param key 鍵
     * @param nonce ノンス 長さはnonceLengthで指定された長さである必要がある
     * @param associatedData 認証に使用する追加データ 長さはtagLengthで指定された長さである必要がある
     * @return 復号されたデータ
     */
    fun decrypt(data: ByteArray, key: SecretKey, nonce: ByteArray, associatedData: ByteArray? = null): ByteArray {
        require(nonce.size == nonceLength) { "Invalid nonce length: ${nonce.size}, expected: $nonceLength" }

        val parameter = GCMParameterSpec(tagLength * 8, nonce)

        cipher.init(Cipher.DECRYPT_MODE, key, parameter)

        if(associatedData != null){
            cipher.updateAAD(associatedData)
        }

        return cipher.doFinal(data)
    }

    fun hkdfExpand(ikm: ByteArray, info: ByteArray, length: Int): ByteArray {
        val hkdfParam = HKDFParameters(ikm, null, info)
        val hkdfGenerator = HKDFBytesGenerator(SHA256Digest())
        hkdfGenerator.init(hkdfParam)

        val key = ByteArray(length)
        hkdfGenerator.generateBytes(key, 0, length)

        return key
    }
}