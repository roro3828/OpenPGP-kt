package ro.roro.openpgp

import java.security.MessageDigest


/**
 *    +=========+==================+=============+========================+
 *    |      ID | Algorithm        | Text Name   | V6 Signature           |
 *    |         |                  |             | Salt Size              |
 *    +=========+==================+=============+========================+
 *    |       0 | Reserved         |             |                        |
 *    +---------+------------------+-------------+------------------------+
 *    |       1 | MD5 [RFC1321]    | "MD5"       | N/A                    |
 *    +---------+------------------+-------------+------------------------+
 *    |       2 | SHA-1 [FIPS180]  | "SHA1"      | N/A                    |
 *    +---------+------------------+-------------+------------------------+
 *    |       3 | RIPEMD-160       | "RIPEMD160" | N/A                    |
 *    |         | [RIPEMD-160]     |             |                        |
 *    +---------+------------------+-------------+------------------------+
 *    |       4 | Reserved         |             |                        |
 *    +---------+------------------+-------------+------------------------+
 *    |       5 | Reserved         |             |                        |
 *    +---------+------------------+-------------+------------------------+
 *    |       6 | Reserved         |             |                        |
 *    +---------+------------------+-------------+------------------------+
 *    |       7 | Reserved         |             |                        |
 *    +---------+------------------+-------------+------------------------+
 *    |       8 | SHA2-256         | "SHA256"    | 16                     |
 *    |         | [FIPS180]        |             |                        |
 *    +---------+------------------+-------------+------------------------+
 *    |       9 | SHA2-384         | "SHA384"    | 24                     |
 *    |         | [FIPS180]        |             |                        |
 *    +---------+------------------+-------------+------------------------+
 *    |      10 | SHA2-512         | "SHA512"    | 32                     |
 *    |         | [FIPS180]        |             |                        |
 *    +---------+------------------+-------------+------------------------+
 *    |      11 | SHA2-224         | "SHA224"    | 16                     |
 *    |         | [FIPS180]        |             |                        |
 *    +---------+------------------+-------------+------------------------+
 *    |      12 | SHA3-256         | "SHA3-256"  | 16                     |
 *    |         | [FIPS202]        |             |                        |
 *    +---------+------------------+-------------+------------------------+
 *    |      13 | Reserved         |             |                        |
 *    +---------+------------------+-------------+------------------------+
 *    |      14 | SHA3-512         | "SHA3-512"  | 32                     |
 *    |         | [FIPS202]        |             |                        |
 *    +---------+------------------+-------------+------------------------+
 *    | 100-110 | Private or       |             |                        |
 *    |         | Experimental Use |             |                        |
 *    +---------+------------------+-------------+------------------------+
 */
class OpenPGPDigest {

    val algorithmTag: Int
    val algorithm: String
    val saltSize: Int
    private val delegate: MessageDigest

    private constructor(algorithmTag: Int, algorithm: String, saltSize: Int) {
        this.algorithmTag = algorithmTag
        this.algorithm = algorithm
        this.saltSize = saltSize
        this.delegate = MessageDigest.getInstance(algorithm)
    }

    fun write(input: ByteArray){
        this.update(input)
    }

    fun writeByte(input: Int){
        this.update(input.toByte())
    }
    fun writeShort(input: Int){
        this.update(
            byteArrayOf(
                (input ushr 8).toByte(),
                input.toByte()
            )
        )
    }
    fun writeInt(input: Int){
        this.update(
            byteArrayOf(
                (input ushr 24).toByte(),
                (input ushr 16).toByte(),
                (input ushr 8).toByte(),
                input.toByte()
            )
        )
    }
    fun writeLong(input: Long){
        this.update(
            byteArrayOf(
                (input ushr 56).toByte(),
                (input ushr 48).toByte(),
                (input ushr 40).toByte(),
                (input ushr 32).toByte(),
                (input ushr 24).toByte(),
                (input ushr 16).toByte(),
                (input ushr 8).toByte(),
                input.toByte()
            )
        )
    }

    fun update(input: Byte) {
        delegate.update(input)
    }

    fun update(input: ByteArray) {
        delegate.update(input)
    }

    fun update(input: ByteArray, offset: Int, len: Int) {
        delegate.update(input, offset, len)
    }

    fun digest(input: ByteArray): ByteArray {
        return delegate.digest(input)
    }

    fun digest(): ByteArray {
        return delegate.digest()
    }

    fun reset() {
        delegate.reset()
    }


    companion object{

        const val MD5 = 1
        const val SHA1 = 2
        //const val RIPEMD160 = 3
        const val SHA256 = 8
        const val SHA384 = 9
        const val SHA512 = 10
        const val SHA224 = 11
        const val SHA3_256 = 12
        const val SHA3_512 = 14

        const val SHA256_SALT_SIZE = 16
        const val SHA384_SALT_SIZE = 24
        const val SHA512_SALT_SIZE = 32
        const val SHA224_SALT_SIZE = 16
        const val SHA3_256_SALT_SIZE = 16
        const val SHA3_512_SALT_SIZE = 32

        fun getInstance(algorithm: Int): OpenPGPDigest {
            return when(algorithm){
                MD5 -> OpenPGPDigest(MD5, "MD5", 0)
                SHA1 -> OpenPGPDigest(SHA1, "SHA-1", 0)
                //RIPEMD160 -> OpenPGPDigest(RIPEMD160, "RIPEMD160", 0)
                SHA256 -> OpenPGPDigest(SHA256, "SHA-256", SHA256_SALT_SIZE)
                SHA384 -> OpenPGPDigest(SHA384, "SHA-384", SHA384_SALT_SIZE)
                SHA512 -> OpenPGPDigest(SHA512, "SHA-512", SHA512_SALT_SIZE)
                SHA224 -> OpenPGPDigest(SHA224, "SHA-224", SHA224_SALT_SIZE)
                SHA3_256 -> OpenPGPDigest(SHA3_256, "SHA3-256", SHA3_256_SALT_SIZE)
                SHA3_512 -> OpenPGPDigest(SHA3_512, "SHA3-512", SHA3_512_SALT_SIZE)
                else -> throw IllegalArgumentException("Unsupported digest algorithm: $algorithm")
            }
        }
    }
}