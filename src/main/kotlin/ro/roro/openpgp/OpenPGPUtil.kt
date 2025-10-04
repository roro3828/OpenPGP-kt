package ro.roro.openpgp

import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.jce.provider.BouncyCastleProvider
import ro.roro.openpgp.packet.OpenPGPPacket
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPair
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import kotlin.io.encoding.Base64

class OpenPGPUtil {
    companion object{
        const val CRC24_INIT= 0xB704CE
        const val CRC24_GENERATOR=0x864CFB
        private const val TAG = "OpenPGPUtil"

        class OpenPGPPacketIdAndLength(val id: Int, val length: Int)

        fun getHexString(bytes: ByteArray, limitLen: Int = 100): String {
            val dbg = StringBuilder(String.format("len:[%5d] ", bytes.size))

            if (limitLen < bytes.size) {
                for(i in 0..<(limitLen / 2)){
                    dbg.append(String.format("%02X ",bytes[i]))
                }
                dbg.append("...")
                for(i in bytes.size-5..<bytes.size){
                    dbg.append(String.format("%02X ",bytes[i]))
                }
            } else {
                for (element in bytes) {
                    dbg.append(String.format("%02X ", element))
                }
            }

            return dbg.toString()
        }
        /**
         * MPIのバイト列の長さ
         */
        fun readMPILen(bytes: ByteArrayInputStream): Int {
            return readMPILen(DataInputStream(bytes))
        }
        /**
         * MPIのバイト列の長さ
         */
        fun readMPILen(dataInputStream: DataInputStream): Int {
            // MPIの長さは最初の2バイトで表される
            val mpiLen = dataInputStream.readShort().toInt()
            // MPIの長さは8の倍数に切り上げられる
            return (mpiLen + 7) / 8
        }
        /**
         * MPI (Multi-Precision Integer) を読み取る
         * @return 読み取ったMPIのBigInteger
         */
        fun readMPI(bytes: ByteArrayInputStream): BigInteger {
            return readMPI(DataInputStream(bytes))
        }
        /**
         * MPI (Multi-Precision Integer) を読み取る
         * @return 読み取ったMPIのBigInteger
         */
        fun readMPI(dataInputStream: DataInputStream): BigInteger {
            val mpiLen = (dataInputStream.readShort().toInt() + 7)/8
            val bigInt = BigInteger(1, dataInputStream.readNBytes((mpiLen)))

            return bigInt
        }

        /**
         * MPI (Multi-Precision Integer) をBigIntegerからバイト配列に変換する
         */
        fun toMPI(bigInteger: BigInteger): ByteArray {
            val byteArray = bigInteger.toByteArray()
            return toMPI(byteArray)
        }
        fun toMPI(byteArray: ByteArray): ByteArray{
            var zeroCount = 0
            for(i in 7 downTo 0){
                if(((byteArray[0].toInt() ushr i) and 0b1) == 0b0){
                    zeroCount++;
                }
                else{
                    break
                }
            }
            val mpiLen = byteArray.size * 8 - zeroCount

            return byteArrayOf(
                (mpiLen ushr 8).toByte(),
                mpiLen.toByte(),
                *(byteArray.sliceArray(byteArray.size-(mpiLen+7)/8 until byteArray.size)),
            )
        }

        /**
         * OpenPGPのパケット長を取得する
         * @param bytes パケットのバイト列
         * @return パケットの長さ
         */
        fun readPacketLen(bytes: ByteArrayInputStream): Int{
            return readPacketLen(DataInputStream(bytes))
        }
        /**
         * OpenPGPのパケット長を取得する
         * @param dataInputStream パケットのDataInputStream
         * @return パケットの長さ
         */
        fun readPacketLen(dataInputStream: DataInputStream): Int {
            val firstByte = dataInputStream.readUnsignedByte()

            if(firstByte < 192){
                return firstByte
            }
            else if(firstByte < 0xFF){
                val secondByte = dataInputStream.readUnsignedByte()
                return ((firstByte - 192) shl 8 ) + secondByte + 192
            }

            else{
                val len = dataInputStream.readInt()
                return len
            }
        }

        /**
         * レガシーパケットのパケット長を取得する
         * @param bytes パケットのバイト列
         * @param lengthType 長さのタイプ (0,1,2,3)
         * @return パケットの長さ
         * -1の場合、無限長
         */
        fun readLegacyPacketLen(bytes: ByteArrayInputStream, lengthType: Int): Int {
            return readLegacyPacketLen(DataInputStream(bytes), lengthType)
        }
        /**
         * レガシーパケットのパケット長を取得する
         * @param dataInputStream パケットのDataInputStream
         * @param lengthType 長さのタイプ (0,1,2,3)
         * @return パケットの長さ
         * -1の場合、無限長
         */
        fun readLegacyPacketLen(dataInputStream: DataInputStream, lengthType: Int): Int {
            return when(lengthType and 0b11){
                0 -> {
                    dataInputStream.readUnsignedByte()
                }
                1 -> {
                    dataInputStream.readUnsignedShort()
                }
                2 -> {
                    dataInputStream.readInt()
                }
                3 -> {
                    // indeterminate length
                    -1
                }
                else -> {
                    throw IllegalArgumentException("Invalid length type: $lengthType")
                }
            }
        }

        /**
         * OpenPGPのパケット長をバイト列に変換する
         */
        fun toPacketLen(len: Int): ByteArray{
            val bytesOutputStream = ByteArrayOutputStream()
            val dataOutputStream = DataOutputStream(bytesOutputStream)

            if(len < 192){
                // 0-191の範囲
                dataOutputStream.writeByte(len)
            }
            else if(len <= 16319){
                // 192-7936
                val fixed = len - 192
                dataOutputStream.writeByte(( fixed ushr 8 ) + 192 )
                dataOutputStream.writeByte(fixed % 0x0100 )
            }
            else{
                dataOutputStream.writeByte(0xFF)
                dataOutputStream.writeInt(len)
            }

            return bytesOutputStream.toByteArray()
        }

        /**
         * CRCを計算する
         * @param data CRCを計算するデータ
         * @return CRCのバイト列 (3バイト)
         */
        fun calcCRC(data: ByteArray): ByteArray{
            var crc = CRC24_INIT
            for(byte in data){
                crc = (crc xor ((byte.toInt() and 0xFF) shl 16)) and 0xFFFFFF

                for(j in 0 until 8){
                    crc = (crc shl 1)
                    if((crc and 0x1000000) != 0){
                        crc = (crc xor CRC24_GENERATOR) and 0xFFFFFF
                    }
                }
            }

            return byteArrayOf(
                ((crc ushr 16) and 0xFF).toByte(),
                ((crc ushr 8) and 0xFF).toByte(),
                (crc and 0xFF).toByte(),
            )
        }

        fun toBase64(data: ByteArray): String{
            return Base64.encode(data)
        }

        fun fromBase64(data: String): ByteArray{
            return Base64.decode(data)
        }

        /**
         * dataが RFC 9580 で定義されるOpenPGPのフォーマットかどうかを判定する
         * @param data 判定するデータ
         * @return true OpenPGPFormat
         * @return false LegacyFormat
         */
        fun isOpenPGPFormat(data: ByteArray): Boolean{
            return isOpenPGPFormat(data[0].toInt())
        }
        /**
         * dataが RFC 9580 で定義されるOpenPGPのフォーマットかどうかを判定する
         * @param data 判定するデータ
         * @return true OpenPGPFormat
         * @return false LegacyFormat
         */
        fun isOpenPGPFormat(data: Int): Boolean{
            val type = data and 0b11000000

            return when (type) {
                0b11000000 -> {
                    true
                }

                0b10000000 -> {
                    false
                }

                else -> {
                    throw IllegalArgumentException("Invalid format")
                }
            }
        }

        /**
         * OpenPGPのパケットIDとパケット長を取得する
         * @param data パケットのバイト列
         * @return Pair<パケットID, パケット長>
         */
        fun getOpenPGPPacketIdAndLength(data: ByteArrayInputStream): OpenPGPPacketIdAndLength{
            return getOpenPGPPacketIdAndLength(DataInputStream(data))
        }
        /**
         * OpenPGPのパケットIDとパケット長を取得する
         * @param data パケットのDataInputStream
         * @return Pair<パケットID, パケット長>
         */
        fun getOpenPGPPacketIdAndLength(data: DataInputStream): OpenPGPPacketIdAndLength {
            val firstByte = data.readUnsignedByte()
            val format = isOpenPGPFormat(firstByte)

            val packetId = if(format){
                firstByte and 0b00111111
            }
            else{
                (firstByte ushr 2) and 0b00001111
            }

            val packetLen = if(format){
                readPacketLen(data)
            }
            else{
                val lengthType = firstByte and 0b00000011
                readLegacyPacketLen(data, lengthType)
            }

            return OpenPGPPacketIdAndLength(packetId, packetLen)
        }
    }
}