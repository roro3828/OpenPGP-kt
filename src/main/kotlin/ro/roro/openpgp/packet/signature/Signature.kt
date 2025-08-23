package ro.roro.openpgp.packet.signature

import ro.roro.openpgp.OpenPGPUtil
import ro.roro.openpgp.packet.OpenPGPPacket
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream

/**
 *      +======+====================================+==================+
 *      | ID   | Name                               | Reference        |
 *      +======+====================================+==================+
 *      | 0x00 | Binary Signature                   | Section 5.2.1.1  |
 *      +------+------------------------------------+------------------+
 *      | 0x01 | Text Signature                     | Section 5.2.1.2  |
 *      +------+------------------------------------+------------------+
 *      | 0x02 | Standalone Signature               | Section 5.2.1.3  |
 *      +------+------------------------------------+------------------+
 *      | 0x10 | Generic Certification Signature    | Section 5.2.1.4  |
 *      +------+------------------------------------+------------------+
 *      | 0x11 | Persona Certification Signature    | Section 5.2.1.5  |
 *      +------+------------------------------------+------------------+
 *      | 0x12 | Casual Certification Signature     | Section 5.2.1.6  |
 *      +------+------------------------------------+------------------+
 *      | 0x13 | Positive Certification Signature   | Section 5.2.1.7  |
 *      +------+------------------------------------+------------------+
 *      | 0x18 | Subkey Binding Signature           | Section 5.2.1.8  |
 *      +------+------------------------------------+------------------+
 *      | 0x19 | Primary Key Binding Signature      | Section 5.2.1.9  |
 *      +------+------------------------------------+------------------+
 *      | 0x1F | Direct Key Signature               | Section 5.2.1.10 |
 *      +------+------------------------------------+------------------+
 *      | 0x20 | Key Revocation Signature           | Section 5.2.1.11 |
 *      +------+------------------------------------+------------------+
 *      | 0x28 | Subkey Revocation Signature        | Section 5.2.1.12 |
 *      +------+------------------------------------+------------------+
 *      | 0x30 | Certification Revocation Signature | Section 5.2.1.13 |
 *      +------+------------------------------------+------------------+
 *      | 0x40 | Timestamp Signature                | Section 5.2.1.14 |
 *      +------+------------------------------------+------------------+
 *      | 0x50 | Third-Party Confirmation Signature | Section 5.2.1.15 |
 *      +------+------------------------------------+------------------+
 *      | 0xFF | Reserved                           | Section 5.2.1.16 |
 *      +------+------------------------------------+------------------+
 */

class Signature: OpenPGPPacket {

    override val packetType = OpenPGPPacket.Companion.SIGNATURE

    /**
     * 署名のバージョン
     * 3 or 4 or 6
     * 3は非推奨
     */
    val signatureVersion: Int

    /**
     * 署名タイプ
     */
    val signatureTypeId: Int

    /**
     * 署名が作成された時間
     * バージョン3でのみ使用される
     */
    val creationTime: Int

    /**
     * 署名した鍵のID
     * 8Byte
     * バージョン3でのみ使用される
     */
    val signerKeyId: ByteArray

    /**
     * 署名の鍵アルゴリズムID
     */
    val keyAlgorithmId: Int

    /**
     * 署名のハッシュアルゴリズムID
     */
    val hashAlgorithmId: Int

    /**
     * ハッシュ値の左側2Byte
     */
    val hashLeft2Bytes: Int

    /**
     * 署名の値
     */
    private val signatureValue: ByteArray?

    /**
     * ハッシュに使用したソルト
     * バージョン6でのみ使用される
     */
    val salt: ByteArray

    /**
     * ハッシュされたサブパケットのリスト
     * バージョン4, 6で使用される
     */
    val hashedSubPackets: List<SignatureSubPacket>

    /**
     * ハッシュされていないサブパケットのリスト
     * バージョン4, 6で使用される
     */
    val unhashedSubPackets: List<SignatureSubPacket>

    companion object{
        const val BINARY_SIGNATURE = 0x00
        const val TEXT_SIGNATURE = 0x01
        const val STANDALONE_SIGNATURE = 0x02
        const val GENERIC_CERTIFICATION_SIGNATURE = 0x10
        const val PERSONA_CERTIFICATION_SIGNATURE = 0x11
        const val CASUAL_CERTIFICATION_SIGNATURE = 0x12
        const val POSITIVE_CERTIFICATION_SIGNATURE = 0x13
        const val SUBKEY_BINDING_SIGNATURE = 0x18
        const val PRIMARY_KEY_BINDING_SIGNATURE = 0x19
        const val DIRECT_KEY_SIGNATURE = 0x1F
        const val KEY_REVOCATION_SIGNATURE = 0x20
        const val SUBKEY_REVOCATION_SIGNATURE = 0x28
        const val CERTIFICATION_REVOCATION_SIGNATURE = 0x30
        const val TIMESTAMP_SIGNATURE = 0x40
        const val THIRD_PARTY_CONFIRMATION_SIGNATURE = 0x50

        /**
         * バイト列からSignatureパケットへ変換する
         * @param body パケットヘッダーを含まないボディのみのデータ
         * @return Signature
         */
        fun fromBytes( body: ByteArrayInputStream):Signature{
            return fromBytes(DataInputStream(body))
        }
        fun fromBytes( dataInputStream: DataInputStream):Signature{
            val version = dataInputStream.readByte().toInt()

            return when(version){
                3 -> {
                    parseVersion3( dataInputStream )
                }

                4, 6 -> {
                    parseVersion4or6(version, dataInputStream )
                }

                else -> {
                    throw IllegalArgumentException("Unsupported signature version: $version")
                }
            }
        }

        /**
         * バージョン3の署名パケットをバイト列から変換する
         */
        private fun parseVersion3( dataInputStream: DataInputStream): Signature{
            val typeAndCreationTimeLen = dataInputStream.readByte().toInt()

            if( typeAndCreationTimeLen != 5 ){
                throw IllegalArgumentException("Invalid length for signature type and creation time: $typeAndCreationTimeLen")
            }

            val signatureType = dataInputStream.readByte().toInt()
            val creationTime = dataInputStream.readInt()
            val signerKeyId = dataInputStream.readNBytes(8) // 8バイトの鍵ID
            val pubKeyAlgorithm = dataInputStream.readByte().toInt()
            val hashAlgorithm = dataInputStream.readByte().toInt()
            val hashLeft2Bytes = dataInputStream.readShort().toInt()
            val signatureValue = dataInputStream.readAllBytes() // 残りのデータは署名値

            return Signature(3,
                signatureType,
                creationTime,
                signerKeyId,
                pubKeyAlgorithm,
                hashAlgorithm,
                hashLeft2Bytes,
                signatureValue,
                null, // バージョン3ではsaltは使用されない
                null, // バージョン3ではハッシュされたサブパケットは使用されない
                null  // バージョン3ではハッシュされていないサブパケットは使用されない
            )
        }

        /**
         * バージョン4の署名パケットをバイト列から変換する
         */
        private fun parseVersion4or6( version: Int, dataInputStream: DataInputStream): Signature{
            val signatureType = dataInputStream.readByte().toInt()
            val pubKeyAlgorithm = dataInputStream.readByte().toInt()
            val hashAlgorithm = dataInputStream.readByte().toInt()

            val hashedSubPacketsLength = if( version == 4 ) {
                dataInputStream.readShort().toInt()
            } else {
                dataInputStream.readInt()
            }

            val hashedSubPackets = parseSubPackets(
                ByteArrayInputStream(
                    dataInputStream.readNBytes(
                        hashedSubPacketsLength
                    )
                )
            )

            val unhashedSubPacketsLength = if( version == 4 ) {
                dataInputStream.readShort().toInt()
            } else {
                dataInputStream.readInt()
            }
            val unhashedSubPackets = parseSubPackets(
                ByteArrayInputStream(
                    dataInputStream.readNBytes(
                        unhashedSubPacketsLength
                    )
                )
            )

            val hashLeft2Bytes = dataInputStream.readShort().toInt()

            val salt: ByteArray? = if( version == 6 ) {
                val saltLength = dataInputStream.readByte().toInt()

                dataInputStream.readNBytes(saltLength)
            } else {
                null // バージョン4ではsaltは使用されない
            }

            return Signature(version,
                signatureType,
                0, // バージョン4, 6では作成時間は使用されない
                null, // バージョン4, 6では署名者の鍵IDは使用されない
                pubKeyAlgorithm,
                hashAlgorithm,
                hashLeft2Bytes,
                dataInputStream.readAllBytes(), // 残りのデータは署名値
                salt,
                hashedSubPackets,
                unhashedSubPackets
            )
        }

        /**
         * 署名パケットのサブパケットをパースする
         * @param byteArrayInputStream サブパケットのデータを含むByteArrayInputStream
         * @return パースされたSignatureSubPacketのリスト
         * @throws IllegalArgumentException 不明なサブパケットタイプの場合
         */
        @Throws(IllegalArgumentException::class)
        private fun parseSubPackets( byteArrayInputStream: ByteArrayInputStream): List<SignatureSubPacket> {
            return parseSubPackets(DataInputStream(byteArrayInputStream))
        }
        /**
         * 署名パケットのサブパケットをパースする
         * @param dataInputStream サブパケットのデータを含むDataInputStream
         * @return パースされたSignatureSubPacketのリスト
         * @throws IllegalArgumentException 不明なサブパケットタイプの場合
         */
        @Throws(IllegalArgumentException::class)
        private fun parseSubPackets( dataInputStream: DataInputStream): List<SignatureSubPacket> {
            val subPackets = mutableListOf<SignatureSubPacket>()
            while (0 < dataInputStream.available()) {

                val length = OpenPGPUtil.getPacketLen(dataInputStream)

                val subPacketTypeId = dataInputStream.readByte().toInt()
                val subPacketType = subPacketTypeId and 0b01111111 // タイプの下位7ビットを取得
                val isCritical = (subPacketTypeId and 0b10000000) != 0 // タイプの最上位ビットが1ならクリティカル
                // タイプ分減らす
                val packetBytes = dataInputStream.readNBytes(length - 1)

                val subPacket: SignatureSubPacket = runCatching {

                    when (subPacketType) {
                        SignatureSubPacket.SIGNATURE_CREATION_TIME -> {
                            SignatureCreationTime(packetBytes)
                        }

                        SignatureSubPacket.SIGNATURE_EXPIRATION_TIME -> {
                            SignatureExpirationTime(packetBytes)
                        }

                        SignatureSubPacket.EXPORTABLE_CERTIFICATION -> {
                            TODO("EXPORTABLE_CERTIFICATION is not implemented yet")
                        }

                        SignatureSubPacket.TRUST_SIGNATURE -> {
                            TODO("TRUST_SIGNATURE is not implemented yet")
                        }

                        SignatureSubPacket.REGULAR_EXPRESSION -> {
                            TODO("REGULAR_EXPRESSION is not implemented yet")
                        }

                        SignatureSubPacket.REVOCABLE -> {
                            TODO("REVOCABLE is not implemented yet")
                        }

                        SignatureSubPacket.KEY_EXPIRATION_TIME -> {
                            KeyExpirationTime(packetBytes)
                        }

                        SignatureSubPacket.PREFERRED_SYMMETRIC_CIPHERS -> {
                            PreferredSymmetricCiphersV1(packetBytes)
                        }

                        SignatureSubPacket.ISSUER_KEY_ID -> {
                            IssuerKeyID(packetBytes)
                        }

                        SignatureSubPacket.NOTATION_DATA -> {
                            TODO("NOTATION_DATA is not implemented yet")
                        }

                        SignatureSubPacket.PREFERRED_HASH_ALGORITHMS -> {
                            PreferredHashAlgorithms(packetBytes)
                        }

                        SignatureSubPacket.PREFERRED_COMPRESSION_ALGORITHMS -> {
                            PreferredCompressionAlgorithms(packetBytes)
                        }

                        SignatureSubPacket.KEY_SERVER_PREFERENCES -> {
                            KeyServerPreferences(packetBytes)
                        }

                        SignatureSubPacket.PREFERRED_KEY_SERVER -> {
                            TODO("PREFERRED_KEY_SERVER is not implemented yet")
                        }

                        SignatureSubPacket.PRIMARY_USER_ID -> {
                            PrimaryUserID(packetBytes)
                        }

                        SignatureSubPacket.POLICY_URI -> {
                            TODO("POLICY_URI is not implemented yet")
                        }

                        SignatureSubPacket.KEY_FLAGS -> {
                            KeyFlags(packetBytes)
                        }

                        SignatureSubPacket.SIGNER_USER_ID -> {
                            TODO("SIGNER_USER_ID is not implemented yet")
                        }

                        SignatureSubPacket.REASON_FOR_REVOCATION -> {
                            TODO("REASON_FOR_REVOCATION is not implemented yet")
                        }

                        SignatureSubPacket.FEATURES -> {
                            Features(packetBytes)
                        }

                        SignatureSubPacket.SIGNATURE_TARGET -> {
                            TODO("SIGNATURE_TARGET is not implemented yet")
                        }

                        SignatureSubPacket.EMBEDDED_SIGNATURE -> {
                            TODO("EMBEDDED_SIGNATURE is not implemented yet")
                        }

                        SignatureSubPacket.ISSUER_FINGERPRINT -> {
                            IssuerFingerprint(packetBytes)
                        }

                        SignatureSubPacket.INTENDED_RECIPIENT_FINGERPRINT -> {
                            TODO("INTENDED_RECIPIENT_FINGERPRINT is not implemented yet")
                        }

                        SignatureSubPacket.ATTESTED_CERTIFICATIONS -> {
                            TODO("ATTESTED_CERTIFICATIONS is not implemented yet")
                        }

                        SignatureSubPacket.KEY_BLOCK -> {
                            TODO("KEY_BLOCK is not implemented yet")
                        }

                        SignatureSubPacket.PREFERRED_AEAD_CIPHERSUITES -> {
                            TODO("PREFERRED_AEAD_CIPHERSUITES is not implemented yet")
                        }

                        else -> {
                            UnKnownSubPacket(packetBytes)
                        }
                    }
                }.fold(
                    onSuccess = {
                        return@fold it
                    },
                    onFailure = { e ->
                        throw IllegalArgumentException("Failed to parse subpacket type $subPacketTypeId: ${e.message}", e)
                    }
                )

                if(isCritical && subPacket.subPacketType == SignatureSubPacket.UNKNOWN_SUBPACKET){
                    throw IllegalArgumentException("Unknown subpacket type $subPacketTypeId is critical")
                }

                subPackets.add(subPacket)
            }
            return subPackets
        }
    }

    private constructor(
        signatureVersion: Int,
        signatureTypeId: Int,
        creationTime: Int,
        signerKeyId: ByteArray?,
        keyAlgorithmId: Int,
        hashAlgorithmId: Int,
        hashLeft2Bytes: Int,
        signatureValue: ByteArray?,
        salt: ByteArray?,
        hashedSubPackets: List<SignatureSubPacket>?,
        unhashedSubPackets: List<SignatureSubPacket>?
    ) {
        if(!( signatureVersion==3 || signatureVersion==4 || signatureVersion==6 )) {
            throw IllegalArgumentException("Invalid signature version: $signatureVersion")
        }
        this.signatureVersion = signatureVersion
        this.signatureTypeId = signatureTypeId

        if( this.signatureVersion == 3 ){
            if( signerKeyId == null ){
                throw IllegalArgumentException("signerKeyId must not be null for signature version 3")
            }
            this.creationTime = creationTime
            this.signerKeyId = signerKeyId
        }
        else{
            this.creationTime = 0 // バージョン3以外では使用されない
            this.signerKeyId = ByteArray(0) // バージョン3以外では使用されない
        }
        this.keyAlgorithmId = keyAlgorithmId
        this.hashAlgorithmId = hashAlgorithmId
        this.hashLeft2Bytes = hashLeft2Bytes
        this.signatureValue = signatureValue

        if( this.signatureVersion == 6 ){
            if( salt == null ){
                throw IllegalArgumentException("salt must not be null for signature version 6")
            }
            this.salt = salt
        }
        else{
            this.salt = ByteArray(0) // バージョン6以外では使用されない
        }

        if( this.signatureVersion != 3){
            if( hashedSubPackets == null ){
                this.hashedSubPackets = emptyList()
            }
            else{
                this.hashedSubPackets = hashedSubPackets
            }
            if( unhashedSubPackets == null ){
                this.unhashedSubPackets = emptyList()
            }
            else {
                this.unhashedSubPackets = unhashedSubPackets
            }
        }
        else{
            this.hashedSubPackets = emptyList() // バージョン3では使用されない
            this.unhashedSubPackets = emptyList() // バージョン3では使用されない
        }
    }

    override val encoded: ByteArray
        get(){
            val bytesStream = ByteArrayOutputStream()
            val dataStream = DataOutputStream(bytesStream)
            dataStream.writeByte(this.signatureVersion)
            when( this.signatureVersion ){
                3->{
                    //署名タイプと作成時間のデータサイズ
                    dataStream.writeByte( 5 )
                    dataStream.writeByte( this.signatureTypeId )
                    dataStream.writeInt(this.creationTime)

                    dataStream.write( this.signerKeyId)
                    dataStream.writeByte( this.keyAlgorithmId )
                    dataStream.writeByte( this.hashAlgorithmId )
                    dataStream.writeShort(this.hashLeft2Bytes)

                    dataStream.write( this.signatureValue )
                }
                4, 6->{
                    dataStream.writeByte(this.signatureTypeId)
                    dataStream.writeByte(this.keyAlgorithmId)
                    dataStream.writeByte(this.hashAlgorithmId)

                    val hashedSubPacketsBytes = this.encodedHashedPackets
                    val unhashedSubPacketsBytes = this.encodedUnhashedPackets

                    if(this.signatureVersion == 4){
                        dataStream.writeShort( hashedSubPacketsBytes.size )
                    }
                    else{
                        dataStream.writeInt( hashedSubPacketsBytes.size )
                    }
                    dataStream.write( hashedSubPacketsBytes )

                    if( this.signatureVersion == 4 ){
                        dataStream.writeShort( unhashedSubPacketsBytes.size )
                    }
                    else{
                        dataStream.writeInt( unhashedSubPacketsBytes.size )
                    }
                    dataStream.write( unhashedSubPacketsBytes )

                    dataStream.writeShort( this.hashLeft2Bytes )

                    if( this.signatureVersion == 6 ){
                        dataStream.writeByte( this.salt.size )
                        dataStream.write( this.salt )
                    }

                    dataStream.write( this.signatureValue )
                }
            }

            return bytesStream.toByteArray()
        }

    /**
     * ハッシュされたサブパケットのエンコードされたバイト列
     */
    val encodedHashedPackets: ByteArray
        get() {
            val bytesStream = ByteArrayOutputStream()

            // ハッシュされたサブパケットのエンコード
            for (subPacket in hashedSubPackets) {
                bytesStream.write(subPacket.encodedWithHeader)
            }

            return bytesStream.toByteArray()
        }

    /**
     * ハッシュされていないサブパケットのエンコードされたバイト列
     */
    val encodedUnhashedPackets: ByteArray
        get() {
            val bytesStream = ByteArrayOutputStream()

            // ハッシュされていないサブパケットのエンコード
            for (subPacket in unhashedSubPackets) {
                bytesStream.write(subPacket.encodedWithHeader)
            }

            return bytesStream.toByteArray()
        }
}