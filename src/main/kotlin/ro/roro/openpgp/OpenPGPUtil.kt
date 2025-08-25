package ro.roro.openpgp

import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPair
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

class OpenPGPUtil {
    companion object{
        private const val TAG = "OpenPGPUtil"

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
         * OpenPGPのパケット長を取得する
         * @param bytes パケットのバイト列
         * @return パケットの長さ
         */
        fun getPacketLen(bytes: ByteArrayInputStream): Int{
            return getPacketLen(DataInputStream(bytes))
        }
        /**
         * OpenPGPのパケット長を取得する
         * @param dataInputStream パケットのDataInputStream
         * @return パケットの長さ
         */
        fun getPacketLen(dataInputStream: DataInputStream): Int {
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
         * SPKI (Subject Public Key Info) からEd25519の公開鍵を取得する
         * @param spkiBytes SPKIのバイト配列
         * @throws IllegalArgumentException
         */
        @Throws(IllegalArgumentException::class)
        fun getRawEd25519PublicKey(spkiBytes: ByteArray): ByteArray{
            val spki = SubjectPublicKeyInfo.getInstance(spkiBytes)

            val algoId = spki.algorithm

            if(EdECObjectIdentifiers.id_Ed25519 != algoId.algorithm){
                throw IllegalArgumentException("Unsupported public key algorithm: ${algoId.algorithm.id}")
            }

            val subjectPublicKeyBitString = spki.publicKeyData
            val rawPublicKey = subjectPublicKeyBitString.bytes

            if(rawPublicKey.size != 32){
                throw IllegalArgumentException("Invalid Ed25519 public key length: ${rawPublicKey.size}")
            }

            return rawPublicKey
        }

        /**
         * 32ByteのEd25519秘密鍵からKeyPairを生成
         */
        fun getKeyPairFromEd25519Secret(seed: ByteArray): KeyPair {
            if (seed.size != 32) {
                throw IllegalArgumentException("Seed must be 32 bytes long for Ed25519. Provided length: ${seed.size}")
            }

            // 1. BouncyCastleの低レベルAPIを使用して秘密鍵パラメータと公開鍵パラメータを取得
            val privateKeyParams = Ed25519PrivateKeyParameters(seed, 0)
            val publicKeyParams = privateKeyParams.generatePublicKey() // シードから公開鍵を導出

            // 2. KeyFactoryをBouncyCastleプロバイダで取得
            // "Ed25519" または "EdDSA" がアルゴリズム名として利用可能
            val keyFactory = KeyFactory.getInstance("Ed25519", BouncyCastleProvider())

            // 3. PrivateKeyオブジェクトを生成
            // RFC 8410 によると、Ed25519のPrivateKeyInfoでは、privateKeyオクテット文字列が直接シードを格納します。
            val privateKeyAlgorithmIdentifier =
                AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519)
            val pkInfo = PrivateKeyInfo(privateKeyAlgorithmIdentifier, DEROctetString(seed))
            val pkcs8Spec = PKCS8EncodedKeySpec(pkInfo.encoded) // PKCS#8形式にエンコード
            val privateKey = keyFactory.generatePrivate(pkcs8Spec)

            // 4. PublicKeyオブジェクトを生成
            // Ed25519の公開鍵(32バイト)をX.509 SubjectPublicKeyInfo形式にエンコード
            val publicKeyAlgorithmIdentifier = AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519)
            // publicKeyParams.encoded は生の32バイト公開鍵を返します
            val spki = SubjectPublicKeyInfo(publicKeyAlgorithmIdentifier, publicKeyParams.encoded)
            val x509Spec = X509EncodedKeySpec(spki.encoded) // X.509形式にエンコード
            val publicKey = keyFactory.generatePublic(x509Spec)


            // 5. KeyPairオブジェクトを作成して返す
            val keyPair = KeyPair(publicKey, privateKey)
            return keyPair
        }

        const val ED25519_PUBLIC_KEY_LENGTH = 32
        const val ED25519_LEGACY_PUBLIC_KEY_PREFIX = 0x40
    }
}