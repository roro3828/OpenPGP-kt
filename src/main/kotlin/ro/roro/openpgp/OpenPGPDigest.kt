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
class OpenPGPDigest(algorithm: String): MessageDigest( algorithm ) {
    companion object{
        const val MD5 = 1
        const val SHA1 = 2
        const val RIPEMD160 = 3
        const val SHA256 = 8
        const val SHA384 = 9
        const val SHA512 = 10
        const val SHA224 = 11
        const val SHA3_256 = 12
        const val SHA3_512 = 14

        fun getInstance(algorithm: Int): OpenPGPDigest {
            return when (algorithm) {
                MD5 -> OpenPGPDigest("MD5")
                SHA1 -> OpenPGPDigest("SHA-1")
                RIPEMD160 -> OpenPGPDigest("RIPEMD160")
                SHA256 -> OpenPGPDigest("SHA-256")
                SHA384 -> OpenPGPDigest("SHA-384")
                SHA512 -> OpenPGPDigest("SHA-512")
                SHA224 -> OpenPGPDigest("SHA-224")
                SHA3_256 -> OpenPGPDigest("SHA3-256")
                SHA3_512 -> OpenPGPDigest("SHA3-512")
                else -> throw IllegalArgumentException("Unsupported algorithm: $algorithm")
            }
        }
    }

    private val delegate: MessageDigest = getInstance(algorithm)

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

    override fun engineUpdate(input: Byte) {
        delegate.update(input)
    }

    override fun engineUpdate(input: ByteArray?, offset: Int, len: Int) {
        delegate.update(input, offset, len)
    }

    override fun engineDigest(): ByteArray {
        return delegate.digest()
    }

    override fun engineReset() {
        delegate.reset()
    }


}