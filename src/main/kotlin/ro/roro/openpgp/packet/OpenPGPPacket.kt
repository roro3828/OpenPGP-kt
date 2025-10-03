package ro.roro.openpgp.packet

import ro.roro.openpgp.OpenPGPUtil
import ro.roro.openpgp.OpenPGPUtil.Companion.readPacketLen
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream


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

    /**
     * パケットタイプ
     */
    abstract val packetType:Int

    /**
     * パケットヘッダーを含まないボディーのみのバイト列を取得する
     */
    abstract val encoded: ByteArray

    /**
     * パケットヘッダーを含むバイト列を取得する
     */
    val encodedWithHeader: ByteArray
        get() {
            val encoded = this.encoded
            val header = createOpenPGPPacketHeader(packetType, encoded.size, true)
            return header + encoded
        }

    interface OpenPGPPacketCompanion<T> {
        fun fromBytes(body: ByteArray): T
    }

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
        fun createOpenPGPPacketHeader(packetType:Int, packetLen:Int, legacy: Boolean = false): ByteArray {
            val bytesOutputStream = ByteArrayOutputStream()
            val dataOutputStream = DataOutputStream(bytesOutputStream)
            if(legacy){
                val lenType = when{
                    packetLen < 0x0100 -> 0 // 1バイト長
                    packetLen < 0x010000 -> 1 // 2バイト長
                    else -> 2 // 4バイト長
                }
                dataOutputStream.writeByte((0b10000000 or ((packetType and 0b00001111) shl 2) or (lenType and 0b11)))

                when(lenType){
                    0 -> dataOutputStream.writeByte(packetLen)
                    1 -> dataOutputStream.writeShort(packetLen)
                    2 -> dataOutputStream.writeInt(packetLen)
                }
            }
            else{
                dataOutputStream.writeByte(0b11000000 or (packetType and 0b00111111))
                val lenBytes = OpenPGPUtil.toPacketLen(packetLen)
                dataOutputStream.write(lenBytes)
            }

            return bytesOutputStream.toByteArray()
        }

        fun readOpenPGPPacketHeader(bytes: DataInputStream): Pair<Int, Int>{
            val firstByte = bytes.readUnsignedByte()
            if((firstByte and 0b10000000) == 0){
                throw IllegalArgumentException("Not OpenPGP packet")
            }

            val legacy = (firstByte and 0b01000000) == 0
            val packetType = if(legacy){
                (firstByte ushr 2) and 0b00001111
            }
            else{
                firstByte and 0b00111111
            }

            val packetLen = if(legacy){
                // 旧形式
                val lenType = firstByte and 0b00000011
                when(lenType){
                    0 -> {
                        // 1バイト長
                        bytes.readUnsignedByte()
                    }
                    1 -> {
                        // 2バイト長
                        bytes.readUnsignedShort()
                    }
                    2 -> {
                        // 4バイト長
                        bytes.readInt()
                    }
                    3 -> {
                        // 不定長
                        bytes.available()
                    }
                    else -> {
                        throw IllegalArgumentException("Invalid length type")
                    }
                }
            }
            else{
                // 新形式
                readPacketLen(bytes)
            }

            return Pair(packetType, packetLen)
        }
    }

}