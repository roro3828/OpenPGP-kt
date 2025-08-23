package ro.roro.openpgp.packet.signature

import ro.roro.openpgp.OpenPGPUtil
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream

/**
 *    +=========+===========================+==================+
 *    |      ID | Description               | Reference        |
 *    +=========+===========================+==================+
 *    |       0 | Reserved                  |                  |
 *    +---------+---------------------------+------------------+
 *    |       1 | Reserved                  |                  |
 *    +---------+---------------------------+------------------+
 *    |       2 | Signature Creation Time   | Section 5.2.3.11 |
 *    +---------+---------------------------+------------------+
 *    |       3 | Signature Expiration Time | Section 5.2.3.18 |
 *    +---------+---------------------------+------------------+
 *    |       4 | Exportable Certification  | Section 5.2.3.19 |
 *    +---------+---------------------------+------------------+
 *    |       5 | Trust Signature           | Section 5.2.3.21 |
 *    +---------+---------------------------+------------------+
 *    |       6 | Regular Expression        | Section 5.2.3.22 |
 *    +---------+---------------------------+------------------+
 *    |       7 | Revocable                 | Section 5.2.3.20 |
 *    +---------+---------------------------+------------------+
 *    |       8 | Reserved                  |                  |
 *    +---------+---------------------------+------------------+
 *    |       9 | Key Expiration Time       | Section 5.2.3.13 |
 *    +---------+---------------------------+------------------+
 *    |      10 | Placeholder for backward  |                  |
 *    |         | compatibility             |                  |
 *    +---------+---------------------------+------------------+
 *    |      11 | Preferred Symmetric       | Section 5.2.3.14 |
 *    |         | Ciphers for v1 SEIPD      |                  |
 *    +---------+---------------------------+------------------+
 *    |      12 | Revocation Key            | Section 5.2.3.23 |
 *    |         | (deprecated)              |                  |
 *    +---------+---------------------------+------------------+
 *    |   13-15 | Reserved                  |                  |
 *    +---------+---------------------------+------------------+
 *    |      16 | Issuer Key ID             | Section 5.2.3.12 |
 *    +---------+---------------------------+------------------+
 *    |   17-19 | Reserved                  |                  |
 *    +---------+---------------------------+------------------+
 *    |      20 | Notation Data             | Section 5.2.3.24 |
 *    +---------+---------------------------+------------------+
 *    |      21 | Preferred Hash Algorithms | Section 5.2.3.16 |
 *    +---------+---------------------------+------------------+
 *    |      22 | Preferred Compression     | Section 5.2.3.17 |
 *    |         | Algorithms                |                  |
 *    +---------+---------------------------+------------------+
 *    |      23 | Key Server Preferences    | Section 5.2.3.25 |
 *    +---------+---------------------------+------------------+
 *    |      24 | Preferred Key Server      | Section 5.2.3.26 |
 *    +---------+---------------------------+------------------+
 *    |      25 | Primary User ID           | Section 5.2.3.27 |
 *    +---------+---------------------------+------------------+
 *    |      26 | Policy URI                | Section 5.2.3.28 |
 *    +---------+---------------------------+------------------+
 *    |      27 | Key Flags                 | Section 5.2.3.29 |
 *    +---------+---------------------------+------------------+
 *    |      28 | Signer's User ID          | Section 5.2.3.30 |
 *    +---------+---------------------------+------------------+
 *    |      29 | Reason for Revocation     | Section 5.2.3.31 |
 *    +---------+---------------------------+------------------+
 *    |      30 | Features                  | Section 5.2.3.32 |
 *    +---------+---------------------------+------------------+
 *    |      31 | Signature Target          | Section 5.2.3.33 |
 *    +---------+---------------------------+------------------+
 *    |      32 | Embedded Signature        | Section 5.2.3.34 |
 *    +---------+---------------------------+------------------+
 *    |      33 | Issuer Fingerprint        | Section 5.2.3.35 |
 *    +---------+---------------------------+------------------+
 *    |      34 | Reserved                  |                  |
 *    +---------+---------------------------+------------------+
 *    |      35 | Intended Recipient        | Section 5.2.3.36 |
 *    |         | Fingerprint               |                  |
 *    +---------+---------------------------+------------------+
 *    |      37 | Reserved (Attested        |                  |
 *    |         | Certifications)           |                  |
 *    +---------+---------------------------+------------------+
 *    |      38 | Reserved (Key Block)      |                  |
 *    +---------+---------------------------+------------------+
 *    |      39 | Preferred AEAD            | Section 5.2.3.15 |
 *    |         | Ciphersuites              |                  |
 *    +---------+---------------------------+------------------+
 *    | 100-110 | Private or Experimental   |                  |
 *    |         | Use                       |                  |
 *    +---------+---------------------------+------------------+
 */

interface SignatureSubPacket {

    /**
     * サブパケットのタイプ
     */
    abstract val subPacketType: Int

    open val mustBeHashed: Boolean
        get() = false
    abstract val isCritical: Boolean

    /**
     * サブパケットのエンコードされたバイト列
     * ヘッダを含まない
     */
    abstract val encoded: ByteArray

    /**
     * サブパケットのエンコードされたバイト列
     * ヘッダを含む
     */
    val encodedWithHeader: ByteArray
        get() {
            val length = this.encoded.size + 1
            val packetLen = OpenPGPUtil.toPacketLen( length )
            val bytes = ByteArrayOutputStream()
            val dataOutputStream = DataOutputStream(bytes)

            dataOutputStream.write( packetLen )
            dataOutputStream.writeByte( this.subPacketType )
            dataOutputStream.write( this.encoded )

            return bytes.toByteArray()
        }

    companion object{
        const val SIGNATURE_CREATION_TIME = 2
        const val SIGNATURE_EXPIRATION_TIME = 3
        const val EXPORTABLE_CERTIFICATION = 4
        const val TRUST_SIGNATURE = 5
        const val REGULAR_EXPRESSION = 6
        const val REVOCABLE = 7
        const val KEY_EXPIRATION_TIME = 9
        const val PREFERRED_SYMMETRIC_CIPHERS = 11
        const val REVOCATION_KEY = 12
        const val ISSUER_KEY_ID = 16
        const val NOTATION_DATA = 20
        const val PREFERRED_HASH_ALGORITHMS = 21
        const val PREFERRED_COMPRESSION_ALGORITHMS = 22
        const val KEY_SERVER_PREFERENCES = 23
        const val PREFERRED_KEY_SERVER = 24
        const val PRIMARY_USER_ID = 25
        const val POLICY_URI = 26
        const val KEY_FLAGS = 27
        const val SIGNERS_USER_ID = 28
        const val REASON_FOR_REVOCATION = 29
        const val FEATURES = 30
        const val SIGNATURE_TARGET = 31
        const val EMBEDDED_SIGNATURE = 32
        const val ISSUER_FINGERPRINT = 33
        const val INTENDED_RECIPIENT_FINGERPRINT = 35
        const val PREFERRED_AEAD_CIPHERSUITES = 39
    }
}