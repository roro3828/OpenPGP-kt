package ro.roro.openpgp

import org.bouncycastle.jce.provider.BouncyCastleProvider
import javax.crypto.Cipher
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
class OpenPGPSymmetricKeyAlgorithm {

    val algorithmTag: Int

    /**
     * 鍵のサイズ
     * 単位はビット
     */
    val keySize: Int
    /**
     * ブロックサイズ
     * 単位はビット
     */
    val blockSize: Int

    val transformation: String
    val standardAlgorithmName: String

    private constructor(algorithmTag: Int, keySize: Int, blockSize: Int, transformation: String, standardAlgorithmName: String) {
        this.algorithmTag = algorithmTag
        this.keySize = keySize
        this.blockSize = blockSize
        this.transformation = transformation
        this.standardAlgorithmName = standardAlgorithmName
    }

    companion object{
        val PLAIN = OpenPGPSymmetricKeyAlgorithm(0, 0, 0, "NONE", "NONE")
        //val IDEA = OpenPGPSymmetricKeyAlgorithm(1, 128, 64, "")
        val TRIPLE_DES = OpenPGPSymmetricKeyAlgorithm(2, 192, 64, "DESede/CFB/NoPadding", "DESede")
        //val CAST5 = OpenPGPSymmetricKeyAlgorithm(3, 128, 64, "")
        //val BLOWFISH = OpenPGPSymmetricKeyAlgorithm(4, 128, 64, "")
        val AES_128 = OpenPGPSymmetricKeyAlgorithm(7, 128, 128, "AES/CFB/NoPadding", "AES")
        val AES_192 = OpenPGPSymmetricKeyAlgorithm(8, 192, 128, "AES/CFB/NoPadding", "AES")
        val AES_256 = OpenPGPSymmetricKeyAlgorithm(9, 256, 128, "AES/CFB/NoPadding", "AES")
        //val TWOFISH = OpenPGPSymmetricKeyAlgorithm(10, 256, 128, "")
        //val CAMELLIA_128 = OpenPGPSymmetricKeyAlgorithm(11, 128, 128, "")
        //val CAMELLIA_192 = OpenPGPSymmetricKeyAlgorithm(12, 192, 128, "")
        //val CAMELLIA_256 = OpenPGPSymmetricKeyAlgorithm(13, 256, 128, "")

        /**
         * 指定されたタグに対応するOpenPGPSymmetricKeyAlgorithmを返す。
         * @param tag
         * @throws IllegalArgumentException
         */
        @Throws(IllegalArgumentException::class)
        fun getKeyAlgorithmByTag(tag: Int): OpenPGPSymmetricKeyAlgorithm {
            return when (tag) {
                0 -> PLAIN
                //1 -> IDEA
                2 -> TRIPLE_DES
                //3 -> CAST5
                //4 -> BLOWFISH
                7 -> AES_128
                8 -> AES_192
                9 -> AES_256
                //10 -> TWOFISH
                //11 -> CAMELLIA_128
                //12 -> CAMELLIA_192
                //13 -> CAMELLIA_256
                else -> throw IllegalArgumentException("Unknown symmetric key algorithm tag: $tag")
            }
        }
    }

    override fun toString(): String {
        val algorithmName = when (algorithmTag) {
            0 -> "Plaintext"
            1 -> "IDEA"
            2 -> "TripleDES"
            3 -> "CAST5"
            4 -> "Blowfish"
            7 -> "AES-128"
            8 -> "AES-192"
            9 -> "AES-256"
            10 -> "Twofish"
            11 -> "Camellia-128"
            12 -> "Camellia-192"
            13 -> "Camellia-256"
            else -> "Unknown Algorithm"
        }
        return "OpenPGPSymmetricKeyAlgorithm(tag=$algorithmTag, keySize=$keySize, blockSize=$blockSize, AlgorithmName=$algorithmName)"
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
        val cipher = Cipher.getInstance(transformation, BouncyCastleProvider())

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, IvParameterSpec(iv))

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
        val cipher = Cipher.getInstance(transformation, BouncyCastleProvider())

        cipher.init(Cipher.DECRYPT_MODE, secretKey, IvParameterSpec(iv))

        return cipher.doFinal(data)
    }
}