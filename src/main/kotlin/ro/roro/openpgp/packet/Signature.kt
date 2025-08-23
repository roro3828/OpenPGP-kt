package ro.roro.openpgp.packet

import ro.roro.openpgp.packet.OpenPGPPacket
import ro.roro.openpgp.packet.signature.SignatureSubPacket
import java.io.ByteArrayOutputStream
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

class Signature:OpenPGPPacket {

    override val packetType = OpenPGPPacket.SIGNATURE

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

    constructor(
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
            val dataStream = DataOutputStream( bytesStream )
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