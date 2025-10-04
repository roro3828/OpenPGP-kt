package ro.roro.openpgp

import org.bouncycastle.jce.provider.BouncyCastleProvider
import ro.roro.openpgp.packet.PublicKey
import java.security.Provider
import java.security.Signature
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 *          +=========+============================================+
 *          |      ID | Algorithm                                  |
 *          +=========+============================================+
 *          |       0 | Plaintext or unencrypted data              |
 *          +---------+--------------------------------------------+
 *          |       1 | IDEA [IDEA]                                |
 *          +---------+--------------------------------------------+
 *          |       2 | TripleDES (or DES-EDE) [SP800-67] with     |
 *          |         | 168-bit key derived from 192               |
 *          +---------+--------------------------------------------+
 *          |       3 | CAST5 with 128-bit key [RFC2144]           |
 *          +---------+--------------------------------------------+
 *          |       4 | Blowfish with 128-bit key, 16 rounds       |
 *          |         | [BLOWFISH]                                 |
 *          +---------+--------------------------------------------+
 *          |       5 | Reserved                                   |
 *          +---------+--------------------------------------------+
 *          |       6 | Reserved                                   |
 *          +---------+--------------------------------------------+
 *          |       7 | AES with 128-bit key [AES]                 |
 *          +---------+--------------------------------------------+
 *          |       8 | AES with 192-bit key                       |
 *          +---------+--------------------------------------------+
 *          |       9 | AES with 256-bit key                       |
 *          +---------+--------------------------------------------+
 *          |      10 | Twofish with 256-bit key [TWOFISH]         |
 *          +---------+--------------------------------------------+
 *          |      11 | Camellia with 128-bit key [RFC3713]        |
 *          +---------+--------------------------------------------+
 *          |      12 | Camellia with 192-bit key                  |
 *          +---------+--------------------------------------------+
 *          |      13 | Camellia with 256-bit key                  |
 *          +---------+--------------------------------------------+
 *          | 100-110 | Private or Experimental Use                |
 *          +---------+--------------------------------------------+
 *          | 253-255 | Reserved to avoid collision with Secret    |
 *          |         | Key Encryption (Table 2 and Section 5.5.3) |
 *          +---------+--------------------------------------------+
 *
 */
class OpenPGPSymmetricKeyAlgorithm(val algorithm: Int, provider: Provider?) {
    private val cipher: Cipher = if(provider == null){
        Cipher.getInstance(getTransformationString(algorithm))
    }
    else {
        Cipher.getInstance(getTransformationString(algorithm), provider)
    }

    val transformation: String = getTransformationString(algorithm)
    val keySize: Int = getKeySize(algorithm)
    val blockSize: Int = getBlockSize(algorithm)
    val standardAlgorithmName: String = getStandardAlgorithmName(algorithm)



    companion object {
        const val PLAIN = 0
        const val IDEA = 1
        const val TRIPLE_DES = 2
        const val CAST5 = 3
        const val BLOWFISH = 4
        const val AES_128 = 7
        const val AES_192 = 8
        const val AES_256 = 9
        const val TWOFISH = 10
        const val CAMELLIA_128 = 11
        const val CAMELLIA_192 = 12
        const val CAMELLIA_256 = 13

        const val TRIPLE_DES_TRANSFORMATION = "DESede/CFB/NoPadding"
        const val AES_128_TRANSFORMATION = "AES/CFB/NoPadding"
        const val AES_192_TRANSFORMATION = "AES/CFB/NoPadding"
        const val AES_256_TRANSFORMATION = "AES/CFB/NoPadding"

        const val IDEA_KEY_SIZE = 128
        const val TRIPLE_DES_KEY_SIZE = 192
        const val CAST5_KEY_SIZE = 128
        const val BLOWFISH_KEY_SIZE = 128
        const val AES_128_KEY_SIZE = 128
        const val AES_192_KEY_SIZE = 192
        const val AES_256_KEY_SIZE = 256
        const val TWOFISH_KEY_SIZE = 256
        const val CAMELLIA_128_KEY_SIZE = 128
        const val CAMELLIA_192_KEY_SIZE = 192
        const val CAMELLIA_256_KEY_SIZE = 256

        const val IDEA_BLOCK_SIZE = 64
        const val TRIPLE_DES_BLOCK_SIZE = 64
        const val CAST5_BLOCK_SIZE = 64
        const val BLOWFISH_BLOCK_SIZE = 64
        const val AES_BLOCK_SIZE = 128
        const val TWOFISH_BLOCK_SIZE = 128
        const val CAMELLIA_BLOCK_SIZE = 128

        const val TRIPLE_DES_STANDARD_NAME = "DESede"
        const val AES_STANDARD_NAME = "AES"

        /**
         * Cipher.getInstance()で使用する変換文字列を取得する
         * @param algorithm 鍵アルゴリズムのタグ
         * @return 変換文字列
         */
        fun getTransformationString(algorithm: Int): String {
            when (algorithm) {
                //IDEA -> return ""
                TRIPLE_DES -> return TRIPLE_DES_TRANSFORMATION
                //CAST5 -> return ""
                //BLOWFISH -> return ""
                AES_128 -> return AES_128_TRANSFORMATION
                AES_192 -> return AES_192_TRANSFORMATION
                AES_256 -> return AES_256_TRANSFORMATION
                //TWOFISH -> return ""
                //CAMELLIA_128 -> return ""
                //CAMELLIA_192 -> return ""
                //CAMELLIA_256 -> return ""
                else -> throw IllegalArgumentException("Unsupported algorithm: $algorithm")
            }
        }

        /**
         * 鍵長をビット単位で取得する
         * @param algorithm 鍵アルゴリズムのタグ
         * @return 鍵長（ビット単位）
         */
        fun getKeySize(algorithm: Int): Int {
            return when (algorithm) {
                IDEA -> IDEA_KEY_SIZE
                TRIPLE_DES -> TRIPLE_DES_KEY_SIZE
                CAST5 -> CAST5_KEY_SIZE
                BLOWFISH -> BLOWFISH_KEY_SIZE
                AES_128 -> AES_128_KEY_SIZE
                AES_192 -> AES_192_KEY_SIZE
                AES_256 -> AES_256_KEY_SIZE
                TWOFISH -> TWOFISH_KEY_SIZE
                CAMELLIA_128 -> CAMELLIA_128_KEY_SIZE
                CAMELLIA_192 -> CAMELLIA_192_KEY_SIZE
                CAMELLIA_256 -> CAMELLIA_256_KEY_SIZE
                else -> throw IllegalArgumentException("Unsupported algorithm: $algorithm")
            }
        }

        /**
         * 暗号アルゴリズムのブロックサイズをビット単位で取得する
         * @param algorithm 鍵アルゴリズムのタグ
         * @return ブロックサイズ（ビット単位）
         */
        fun getBlockSize(algorithm: Int): Int {
            return when (algorithm) {
                IDEA -> IDEA_BLOCK_SIZE
                TRIPLE_DES -> TRIPLE_DES_BLOCK_SIZE
                CAST5 -> CAST5_BLOCK_SIZE
                BLOWFISH -> BLOWFISH_BLOCK_SIZE
                AES_128, AES_192, AES_256 -> AES_BLOCK_SIZE
                TWOFISH -> TWOFISH_BLOCK_SIZE
                CAMELLIA_128, CAMELLIA_192, CAMELLIA_256 -> CAMELLIA_BLOCK_SIZE
                else -> throw IllegalArgumentException("Unsupported algorithm: $algorithm")
            }
        }

        /**
         * SecretKeySpecで使用する標準アルゴリズム名を取得する
         * @param algorithm 鍵アルゴリズムのタグ
         * @return 標準アルゴリズム名
         */
        fun getStandardAlgorithmName(algorithm: Int): String {
            return when (algorithm) {
                TRIPLE_DES -> TRIPLE_DES_STANDARD_NAME
                AES_128, AES_192, AES_256 -> AES_STANDARD_NAME
                else -> throw IllegalArgumentException("Unsupported algorithm: $algorithm")
            }
        }
    }


    override fun toString(): String {
        val algorithmName = when (algorithm) {
            PLAIN -> "Plaintext"
            IDEA -> "IDEA"
            TRIPLE_DES -> "TripleDES"
            CAST5 -> "CAST5"
            BLOWFISH -> "Blowfish"
            AES_128 -> "AES-128"
            AES_192 -> "AES-192"
            AES_256 -> "AES-256"
            TWOFISH -> "Twofish"
            CAMELLIA_128 -> "Camellia-128"
            CAMELLIA_192 -> "Camellia-192"
            CAMELLIA_256 -> "Camellia-256"
            else -> "Unknown Algorithm"
        }
        return "OpenPGPSymmetricKeyAlgorithm(tag=$algorithm, keySize=$keySize, blockSize=$blockSize, AlgorithmName=$algorithmName)"
    }

    /**
     * CFBモードで暗号化する
     * @param data 暗号化するデータ
     * @param key 鍵
     * @param iv 初期化ベクトル
     * @return 暗号化されたデータ
     */
    fun encrypt(data: ByteArray, key: ByteArray, iv: ByteArray): ByteArray{
        val secretKey = SecretKeySpec(key, standardAlgorithmName)

        return encrypt(data, secretKey, iv)
    }

    /**
     * CFBモードで暗号化する
     * @param data 暗号化するデータ
     * @param key 鍵
     * @param iv 初期化ベクトル
     * @return 暗号化されたデータ
     */
    fun encrypt(data: ByteArray, key: SecretKey, iv: ByteArray): ByteArray{
        cipher.init(Cipher.ENCRYPT_MODE, key, IvParameterSpec(iv))

        return cipher.doFinal(data)
    }

    /**
     * CFBモードで復号化する
     * @param data 復号化するデータ
     * @param key 鍵
     * @param iv 初期化ベクトル
     * @return 復号化されたデータ
     */
    fun decrypt(data: ByteArray, key: ByteArray, iv: ByteArray): ByteArray{
        val secretKey = SecretKeySpec(key, standardAlgorithmName)

        return decrypt(data, secretKey, iv)
    }
    /**
     * CFBモードで復号化する
     * @param data 復号化するデータ
     * @param key 鍵
     * @param iv 初期化ベクトル
     * @return 復号化されたデータ
     */
    fun decrypt(data: ByteArray, key: SecretKey, iv: ByteArray): ByteArray{
        cipher.init(Cipher.DECRYPT_MODE, key, IvParameterSpec(iv))

        return cipher.doFinal(data)
    }
}