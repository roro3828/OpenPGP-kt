package ro.roro.openpgp.packet.signature

import ro.roro.openpgp.OpenPGPDigest
import ro.roro.openpgp.OpenPGPSigner
import ro.roro.openpgp.OpenPGPUtil
import ro.roro.openpgp.OpenPGPVerifier
import ro.roro.openpgp.packet.OpenPGPPacket
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.security.SecureRandom

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

    override val packetType = OpenPGPPacket.SIGNATURE

    private val trailer: SignatureTrailer
    /**
     * 署名のバージョン
     * 3 or 4 or 6
     * 3は非推奨
     */
    val signatureVersion: Int
        get() {
            return trailer.signatureVersion
        }

    /**
     * 署名タイプ
     */
    val signatureTypeId: Int
        get() {
            return trailer.signatureTypeId
        }

    /**
     * 署名が作成された時間
     * バージョン3でのみ使用される
     */
    val creationTime: Int
        get() {
            return trailer.creationTime
        }

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
        get() {
            return trailer.keyAlgorithmId
        }

    /**
     * 署名のハッシュアルゴリズムID
     */
    val hashAlgorithmId: Int
        get() {
            return trailer.hashAlgorithmId
        }

    /**
     * ハッシュ値の左側2Byte
     */
    val hashLeft2Bytes: Short

    /**
     * 署名の値
     */
    val signatureValue: ByteArray

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
        get() {
            return trailer.subPackets
        }

    /**
     * ハッシュされないサブパケットのリスト
     * バージョン4, 6で使用される
     */
    val unhashedSubPackets: List<SignatureSubPacket>

    /**
     * バージョン3の署名パケット
     */
    constructor(
        trailer: SignatureTrailer,
        signerKeyId: ByteArray,
        hashLeft2Bytes: Short,
        signatureValue: ByteArray
    ) {
        require(trailer.signatureVersion == 3) { "Signature version must be 3 for this constructor." }
        require(signerKeyId.size == 8) { "signerKeyId must be 8 bytes long." }
        this.trailer = trailer
        this.signerKeyId = signerKeyId
        this.hashLeft2Bytes = hashLeft2Bytes
        this.signatureValue = signatureValue
        this.unhashedSubPackets = emptyList()
        this.salt = ByteArray(0) // バージョン6以外では使用されない
    }

    /**
     * バージョン4の署名パケット
     */
    constructor(
        trailer: SignatureTrailer,
        hashLeft2Bytes: Short,
        signatureValue: ByteArray,
        unhashedSubPackets: List<SignatureSubPacket>?
    ) {
        require(trailer.signatureVersion == 4) { "Signature version must be 4 for this constructor." }
        this.trailer = trailer
        this.signerKeyId = ByteArray(0) // バージョン3以外では使用されない
        this.hashLeft2Bytes = hashLeft2Bytes
        this.signatureValue = signatureValue
        if(unhashedSubPackets == null){
            this.unhashedSubPackets = emptyList()
        }
        else {
            this.unhashedSubPackets = unhashedSubPackets
        }

        this.salt = ByteArray(0) // バージョン6以外では使用されない
    }
    /**
     * バージョン6の署名パケット
     */
    constructor(
        trailer: SignatureTrailer,
        hashLeft2Bytes: Short,
        signatureValue: ByteArray,
        salt: ByteArray,
        unhashedSubPackets: List<SignatureSubPacket>?
    ) {
        require(trailer.signatureVersion == 6) { "Signature version must be 6 for this constructor." }
        this.trailer = trailer
        this.signerKeyId = ByteArray(0) // バージョン3以外では使用されない
        this.hashLeft2Bytes = hashLeft2Bytes
        this.signatureValue = signatureValue

        val saltSize = OpenPGPDigest.getInstance(this.trailer.keyAlgorithmId).saltSize
        require(saltSize == salt.size) { "salt must be $saltSize bytes long for key algorithm ${this.trailer.keyAlgorithmId}." }
        this.salt = salt

        if(unhashedSubPackets == null){
            this.unhashedSubPackets = emptyList()
        }
        else {
            this.unhashedSubPackets = unhashedSubPackets
        }
    }

    fun verify(data: ByteArray, verifier: OpenPGPVerifier): Boolean{

        val hash = OpenPGPDigest.getInstance(hashAlgorithmId)
        if(this.signatureVersion == 6){
            hash.write(salt) // バージョン6ではソルトを入れる
        }

        hash.write(data)
        hash.write(trailer.encoded)

        val digest = hash.digest()

        val left2Bytes = ((digest[0].toInt() and 0xFF shl 8) or (digest[1].toInt() and 0xFF)).toShort()
        if( left2Bytes != this.hashLeft2Bytes ){
            return false
        }

        return verifier.verify(digest, this.signatureValue)
    }

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


        fun getV4Signature(
            data: ByteArray,
            signer: OpenPGPSigner,
            signatureTypeId: Int,
            keyAlgorithmId: Int,
            hashAlgorithmId: Int,
            hashedSubPackets: List<SignatureSubPacket>?,
            unhashedSubPackets: List<SignatureSubPacket>?,
            passPhrase: ByteArray? = null
        ): Signature{

            val trailer = SignatureTrailer(
                4,
                signatureTypeId,
                keyAlgorithmId,
                hashAlgorithmId,
                hashedSubPackets
            )

            val hash = OpenPGPDigest.getInstance(hashAlgorithmId)
            hash.write(data)
            hash.write(trailer.encoded)

            val digest = hash.digest()
            val left2Bytes = ((digest[0].toInt() and 0xFF shl 8) or (digest[1].toInt() and 0xFF)).toShort()

            val signatureValue = signer.sign(digest, passPhrase)

            return Signature(
                trailer,
                left2Bytes,
                signatureValue,
                unhashedSubPackets
            )

        }

        /**
         * バージョン6の署名を生成する
         * @param data 署名対象のデータ
         * @param signer 署名を行うOpenPGPSigner
         * @param signatureTypeId 署名タイプID
         * @param keyAlgorithmId 鍵アルゴリズムID
         * @param hashAlgorithmId ハッシュアルゴリズムID
         * @param hashedSubPackets ハッシュされたサブパケットのリスト
         * @param unhashedSubPackets ハッシュされていないサブパケットのリスト
         * @param salt ソルト値 鍵アルゴリズムに応じた長さのバイト配列を指定すること nullの場合はランダムに生成される
         * @param passPhrase パスフレーズ
         * @return 生成されたSignatureオブジェクト
         */
        fun getV6Signature(
            data: ByteArray,
            signer: OpenPGPSigner,
            signatureTypeId: Int,
            keyAlgorithmId: Int,
            hashAlgorithmId: Int,
            hashedSubPackets: List<SignatureSubPacket>?,
            unhashedSubPackets: List<SignatureSubPacket>?,
            salt: ByteArray? = null,
            passPhrase: ByteArray? = null
        ): Signature{

            val saltSize = OpenPGPDigest.getInstance(keyAlgorithmId).saltSize
            val saltValue = ByteArray(saltSize)
            if(salt == null){
                SecureRandom().nextBytes(saltValue)
            }
            else{
                require(salt.size == saltSize) { "salt must be $saltSize bytes long for key algorithm $keyAlgorithmId." }
                System.arraycopy(salt, 0, saltValue, 0, saltSize)
            }

            val trailer = SignatureTrailer(
                6,
                signatureTypeId,
                keyAlgorithmId,
                hashAlgorithmId,
                hashedSubPackets
            )

            val hash = OpenPGPDigest.getInstance(hashAlgorithmId)
            hash.write(saltValue) // バージョン6ではソルトを入れる
            hash.write(data)
            hash.write(trailer.encoded)

            val digest = hash.digest()
            val left2Bytes = ((digest[0].toInt() and 0xFF shl 8) or (digest[1].toInt() and 0xFF)).toShort()

            val signatureValue = signer.sign(digest, passPhrase)

            return Signature(
                trailer,
                left2Bytes,
                signatureValue,
                saltValue,
                unhashedSubPackets
            )

        }
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
            val hashLeft2Bytes = dataInputStream.readShort()
            val signatureValue = dataInputStream.readAllBytes() // 残りのデータは署名値

            val trailer = SignatureTrailer(
                signatureType,
                creationTime,
                pubKeyAlgorithm,
                hashAlgorithm
            )

            return Signature(
                trailer,
                signerKeyId,
                hashLeft2Bytes,
                signatureValue
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

            val hashLeft2Bytes = dataInputStream.readShort()

            val trailer = SignatureTrailer(
                version,
                signatureType,
                pubKeyAlgorithm,
                hashAlgorithm,
                hashedSubPackets
            )

            if(version == 4){
                return Signature(
                    trailer,
                    hashLeft2Bytes,
                    dataInputStream.readAllBytes(),
                    unhashedSubPackets
                )
            }
            else{
                val saltLength = dataInputStream.readByte().toInt()
                val salt = dataInputStream.readNBytes(saltLength)

                return Signature(
                    trailer,
                    hashLeft2Bytes,
                    dataInputStream.readAllBytes(),
                    salt,
                    unhashedSubPackets
                )
            }
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
                            SignatureCreationTime(packetBytes, isCritical)
                        }

                        SignatureSubPacket.SIGNATURE_EXPIRATION_TIME -> {
                            SignatureExpirationTime(packetBytes, isCritical)
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
                            KeyExpirationTime(packetBytes, isCritical)
                        }

                        SignatureSubPacket.PREFERRED_SYMMETRIC_CIPHERS -> {
                            PreferredSymmetricCiphersV1(packetBytes, isCritical)
                        }

                        SignatureSubPacket.ISSUER_KEY_ID -> {
                            IssuerKeyID(packetBytes, isCritical)
                        }

                        SignatureSubPacket.NOTATION_DATA -> {
                            TODO("NOTATION_DATA is not implemented yet")
                        }

                        SignatureSubPacket.PREFERRED_HASH_ALGORITHMS -> {
                            PreferredHashAlgorithms(packetBytes, isCritical)
                        }

                        SignatureSubPacket.PREFERRED_COMPRESSION_ALGORITHMS -> {
                            PreferredCompressionAlgorithms(packetBytes, isCritical)
                        }

                        SignatureSubPacket.KEY_SERVER_PREFERENCES -> {
                            KeyServerPreferences(packetBytes, isCritical)
                        }

                        SignatureSubPacket.PREFERRED_KEY_SERVER -> {
                            TODO("PREFERRED_KEY_SERVER is not implemented yet")
                        }

                        SignatureSubPacket.PRIMARY_USER_ID -> {
                            PrimaryUserID(packetBytes, isCritical)
                        }

                        SignatureSubPacket.POLICY_URI -> {
                            TODO("POLICY_URI is not implemented yet")
                        }

                        SignatureSubPacket.KEY_FLAGS -> {
                            KeyFlags(packetBytes, isCritical)
                        }

                        SignatureSubPacket.SIGNER_USER_ID -> {
                            TODO("SIGNER_USER_ID is not implemented yet")
                        }

                        SignatureSubPacket.REASON_FOR_REVOCATION -> {
                            TODO("REASON_FOR_REVOCATION is not implemented yet")
                        }

                        SignatureSubPacket.FEATURES -> {
                            Features(packetBytes, isCritical)
                        }

                        SignatureSubPacket.SIGNATURE_TARGET -> {
                            TODO("SIGNATURE_TARGET is not implemented yet")
                        }

                        SignatureSubPacket.EMBEDDED_SIGNATURE -> {
                            TODO("EMBEDDED_SIGNATURE is not implemented yet")
                        }

                        SignatureSubPacket.ISSUER_FINGERPRINT -> {
                            IssuerFingerprint(packetBytes, isCritical)
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
                            UnKnownSubPacket(subPacketType, packetBytes, isCritical)
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

                if(isCritical && subPacket.unKnown){
                    throw IllegalArgumentException("Unknown subpacket type $subPacketTypeId is critical")
                }

                subPackets.add(subPacket)
            }
            return subPackets
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
                    dataStream.writeShort(this.hashLeft2Bytes.toInt())

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

                    dataStream.writeShort( this.hashLeft2Bytes.toInt() )

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