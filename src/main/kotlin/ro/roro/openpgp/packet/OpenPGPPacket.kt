package ro.roro.openpgp.packet


/**
 *     +=======+==========+=====================+===========+===========+
 *     |    ID | Critical | Packet Type         | Shorthand | Reference |
 *     |       |          | Description         |           |           |
 *     +=======+==========+=====================+===========+===========+
 *     |     0 | Yes      | Reserved - this     |           |           |
 *     |       |          | Packet Type ID MUST |           |           |
 *     |       |          | NOT be used         |           |           |
 *     +-------+----------+---------------------+-----------+-----------+
 *     |     1 | Yes      | Public Key          | PKESK     | Section   |
 *     |       |          | Encrypted Session   |           | 5.1       |
 *     |       |          | Key Packet          |           |           |
 *     +-------+----------+---------------------+-----------+-----------+
 *     |     2 | Yes      | Signature Packet    | SIG       | Section   |
 *     |       |          |                     |           | 5.2       |
 *     +-------+----------+---------------------+-----------+-----------+
 *     |     3 | Yes      | Symmetric Key       | SKESK     | Section   |
 *     |       |          | Encrypted Session   |           | 5.3       |
 *     |       |          | Key Packet          |           |           |
 *     +-------+----------+---------------------+-----------+-----------+
 *     |     4 | Yes      | One-Pass Signature  | OPS       | Section   |
 *     |       |          | Packet              |           | 5.4       |
 *     +-------+----------+---------------------+-----------+-----------+
 *     |     5 | Yes      | Secret Key Packet   | SECKEY    | Section   |
 *     |       |          |                     |           | 5.5.1.3   |
 *     +-------+----------+---------------------+-----------+-----------+
 *     |     6 | Yes      | Public Key Packet   | PUBKEY    | Section   |
 *     |       |          |                     |           | 5.5.1.1   |
 *     +-------+----------+---------------------+-----------+-----------+
 *     |     7 | Yes      | Secret Subkey       | SECSUBKEY | Section   |
 *     |       |          | Packet              |           | 5.5.1.4   |
 *     +-------+----------+---------------------+-----------+-----------+
 *     |     8 | Yes      | Compressed Data     | COMP      | Section   |
 *     |       |          | Packet              |           | 5.6       |
 *     +-------+----------+---------------------+-----------+-----------+
 *     |     9 | Yes      | Symmetrically       | SED       | Section   |
 *     |       |          | Encrypted Data      |           | 5.7       |
 *     |       |          | Packet              |           |           |
 *     +-------+----------+---------------------+-----------+-----------+
 *     |    10 | Yes      | Marker Packet       | MARKER    | Section   |
 *     |       |          |                     |           | 5.8       |
 *     +-------+----------+---------------------+-----------+-----------+
 *     |    11 | Yes      | Literal Data Packet | LIT       | Section   |
 *     |       |          |                     |           | 5.9       |
 *     +-------+----------+---------------------+-----------+-----------+
 *     |    12 | Yes      | Trust Packet        | TRUST     | Section   |
 *     |       |          |                     |           | 5.10      |
 *     +-------+----------+---------------------+-----------+-----------+
 *     |    13 | Yes      | User ID Packet      | UID       | Section   |
 *     |       |          |                     |           | 5.11      |
 *     +-------+----------+---------------------+-----------+-----------+
 *     |    14 | Yes      | Public Subkey       | PUBSUBKEY | Section   |
 *     |       |          | Packet              |           | 5.5.1.2   |
 *     +-------+----------+---------------------+-----------+-----------+
 *     |    17 | Yes      | User Attribute      | UAT       | Section   |
 *     |       |          | Packet              |           | 5.12      |
 *     +-------+----------+---------------------+-----------+-----------+
 *     |    18 | Yes      | Symmetrically       | SEIPD     | Section   |
 *     |       |          | Encrypted and       |           | 5.13      |
 *     |       |          | Integrity Protected |           |           |
 *     |       |          | Data Packet         |           |           |
 *     +-------+----------+---------------------+-----------+-----------+
 *     |    19 | Yes      | Reserved (formerly  |           | Section   |
 *     |       |          | Modification        |           | 5.13.1    |
 *     |       |          | Detection Code      |           |           |
 *     |       |          | Packet)             |           |           |
 *     +-------+----------+---------------------+-----------+-----------+
 *     |    20 | Yes      | Reserved            |           |           |
 *     +-------+----------+---------------------+-----------+-----------+
 *     |    21 | Yes      | Padding Packet      | PADDING   | Section   |
 *     |       |          |                     |           | 5.14      |
 *     +-------+----------+---------------------+-----------+-----------+
 *     | 22-39 | Yes      | Unassigned Critical |           |           |
 *     |       |          | Packets             |           |           |
 *     +-------+----------+---------------------+-----------+-----------+
 *     | 40-59 | No       | Unassigned Non-     |           |           |
 *     |       |          | Critical Packets    |           |           |
 *     +-------+----------+---------------------+-----------+-----------+
 *     | 60-63 | No       | Private or          |           |           |
 *     |       |          | Experimental Use    |           |           |
 *     +-------+----------+---------------------+-----------+-----------+
 */

interface OpenPGPPacket {

    companion object{

        const val PUBLIC_KEY_ENCRYPTED_SESSION = 1
        const val SIGNATURE = 2
        const val SYMMETRIC_KEY_ENCRYPTED_SESSION = 3
        const val ONE_PASS_SIGNATURE = 4
        const val SECRET_KEY = 5
        const val PUBLIC_KEY = 6
        const val SECRET_SUBKEY = 7
        const val COMPRESSED_DATA = 8
        const val SYMMETRICALLY_ENCRYPTED_DATA = 9
        const val MARKER = 10
        const val LITERAL_DATA = 11
        const val TRUST = 12
        const val USER_ID = 13
        const val PUBLIC_SUBKEY = 14
        const val USER_ATTRIBUTE = 17
        const val SYMMETRICALLY_ENCRYPTED_AND_INTEGRITY_PROTECTED_DATA = 18
        const val MODIFICATION_DETECTION_CODE = 19
        const val PADDING = 21

        /**
         * バイト列からOpenPGPパケットに変換する
         * @param packetType パケットタイプ
         * @param body パケットヘッダーを含まないボディのみのデータ
         * @throws IllegalArgumentException パケットタイプが不正またはボディーデータが不正な時
         * @return OpenPGPPacket
         */
        @Throws(IllegalArgumentException::class)
        fun toOpenPGPPacket(packetType: Int, body: ByteArray):OpenPGPPacket{
            when (packetType) {
                PUBLIC_KEY_ENCRYPTED_SESSION -> {
                    TODO("Public Key Encrypted Session Packet is not implemented yet")
                }
                SIGNATURE -> {
                    TODO("Signature Packet is not implemented yet")
                }
                SYMMETRIC_KEY_ENCRYPTED_SESSION -> {
                    TODO("Symmetric Key Encrypted Session Packet is not implemented yet")
                }
                ONE_PASS_SIGNATURE -> {
                    TODO("One Pass Signature Packet is not implemented yet")
                }
                SECRET_KEY -> {
                    TODO("Secret Key Packet is not implemented yet")
                }
                PUBLIC_KEY -> {
                    TODO("Public Key Packet is not implemented yet")
                }
                SECRET_SUBKEY -> {
                    TODO("Secret Subkey Packet is not implemented yet")
                }
                COMPRESSED_DATA -> {
                    TODO("Compressed Data Packet is not implemented yet")
                }
                SYMMETRICALLY_ENCRYPTED_DATA -> {
                    TODO("Symmetrically Encrypted Data Packet is not implemented yet")
                }
                MARKER -> {
                    TODO("Marker Packet is not implemented yet")
                }
                LITERAL_DATA -> {
                    TODO("Literal Data Packet is not implemented yet")
                }
                TRUST -> {
                    TODO("Trust Packet is not implemented yet")
                }
                USER_ID -> {
                    return UserID.fromBytes(body)
                }
                PUBLIC_SUBKEY -> {
                    TODO("Public Subkey Packet is not implemented yet")
                }
                USER_ATTRIBUTE -> {
                    TODO("User Attribute Packet is not implemented yet")
                }
                SYMMETRICALLY_ENCRYPTED_AND_INTEGRITY_PROTECTED_DATA -> {
                    TODO("Symmetrically Encrypted and Integrity Protected Data Packet is not implemented yet")
                }
                MODIFICATION_DETECTION_CODE -> {
                    TODO("Modification Detection Code Packet is not implemented yet")
                }
                PADDING -> {
                    TODO("Padding Packet is not implemented yet")
                }
                else -> {
                    throw IllegalArgumentException("Unknown or unsupported packet type: $packetType")
                }
            }
        }

        /**
         * OpenPGPヘッダーを生成
         */
        fun buildOpenPGPPacketHeader(packetType:Int):Byte{
            return (0b11000000 or (packetType and 0b00111111)).toByte()
        }
    }

    /**
     * パケットタイプ
     */
    abstract val packetType:Int

    /**
     * パケットヘッダーを含まないボディーのみのバイト列を取得する
     */
    abstract val encoded: ByteArray
}