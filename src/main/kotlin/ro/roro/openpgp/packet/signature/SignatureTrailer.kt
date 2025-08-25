package ro.roro.openpgp.packet.signature

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream

class SignatureTrailer {
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
     * 署名の鍵アルゴリズムID
     */
    val keyAlgorithmId: Int

    /**
     * 署名のハッシュアルゴリズムID
     */
    val hashAlgorithmId: Int
    /**
     * サブパケットのリスト
     * バージョン4, 6で使用される
     */
    val subPackets: List<SignatureSubPacket>

    /**
     * バージョン3の署名生成
     */
    constructor(signatureType: Int, creationTime: Int, keyAlgorithmId: Int, hashAlgorithmId: Int) {
        this.signatureVersion = 3
        this.signatureTypeId = signatureType
        this.creationTime = creationTime
        this.keyAlgorithmId = keyAlgorithmId
        this.hashAlgorithmId = hashAlgorithmId
        this.subPackets = emptyList()
    }

    /**
     * バージョン4, 6の署名生成
     */
    constructor(signatureVersion: Int, signatureTypeId: Int, keyAlgorithmId: Int, hashAlgorithmId: Int, subPackets: List<SignatureSubPacket>?) {
        require(signatureVersion == 4 || signatureVersion == 6) { "Signature version must be 4 or 6" }
        this.signatureVersion = signatureVersion
        this.signatureTypeId = signatureTypeId
        this.creationTime = 0
        this.keyAlgorithmId = keyAlgorithmId
        this.hashAlgorithmId = hashAlgorithmId
        if (subPackets == null) {
            this.subPackets = emptyList()
        }
        else {
            this.subPackets = subPackets
        }
    }

    val encoded: ByteArray
        get() {
            val bytesStream = ByteArrayOutputStream()
            val dataStream = DataOutputStream(bytesStream)
            dataStream.writeByte(this.signatureVersion)
            when( this.signatureVersion ){
                3->{
                    dataStream.writeByte( this.signatureTypeId )
                    dataStream.writeInt(this.creationTime)
                }
                4, 6->{
                    dataStream.writeByte(this.signatureTypeId)
                    dataStream.writeByte(this.keyAlgorithmId)
                    dataStream.writeByte(this.hashAlgorithmId)

                    val hashedSubPacketsBytes = this.encodedSubPackets

                    if(this.signatureVersion == 4){
                        dataStream.writeShort( hashedSubPacketsBytes.size )
                    }
                    else{
                        dataStream.writeInt( hashedSubPacketsBytes.size )
                    }
                    dataStream.write( hashedSubPacketsBytes )

                    val hashDataLength = dataStream.size()

                    dataStream.writeByte(this.signatureVersion)
                    dataStream.writeByte(0xFF)
                    dataStream.writeInt(hashDataLength)

                }
            }

            return bytesStream.toByteArray()
        }

    /**
     * ハッシュされたサブパケットのエンコードされたバイト列
     */
    val encodedSubPackets: ByteArray
        get() {
            val bytesStream = ByteArrayOutputStream()

            // ハッシュされたサブパケットのエンコード
            for (subPacket in subPackets) {
                bytesStream.write(subPacket.encodedWithHeader)
            }

            return bytesStream.toByteArray()
        }
}