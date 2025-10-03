package ro.roro.openpgp.packet

import java.io.ByteArrayInputStream
import java.io.DataInputStream
import java.util.Calendar

/**
 * パケットタグ以外はPublicKeyと同じ
 */
class PublicSubkey: PublicKey{
    override val packetType = OpenPGPPacket.PUBLIC_SUBKEY
    /**
     * 鍵バージョン3のコンストラクタ
     * @param creationTime 鍵が作成された時間
     * @param validDays 鍵の有効期限 (単位は日)
     * @param keyAlgo 鍵のアルゴリズム
     * @param key 公開鍵
     */
    protected constructor(
        creationTime: Calendar,
        validDays: Short,
        keyAlgo: Int,
        key: java.security.PublicKey
    ): super(creationTime, validDays, keyAlgo, key)
    /**
     * 鍵バージョン3のコンストラクタ
     * @param creationTime 鍵が作成された時間
     * @param validDays 鍵の有効期限 (単位は日)
     * @param keyAlgo 鍵のアルゴリズム
     * @param key 公開鍵
     */
    protected constructor(
        creationTime: Int,
        validDays: Short,
        keyAlgo: Int,
        key: java.security.PublicKey
    ): super(creationTime, validDays, keyAlgo, key)

    /**
     * 鍵バージョン4か6のコンストラクタ
     * @param version 鍵バージョン (4か6)
     * @param creationTime 鍵が作成された時間
     * @param keyAlgo 鍵のアルゴリズム
     * @param key 公開鍵
     */
    constructor(
        version: Int,
        creationTime: Calendar,
        keyAlgo: Int,
        key: java.security.PublicKey
    ): super(version, creationTime, keyAlgo, key)
    /**
     * 鍵バージョン4か6のコンストラクタ
     * @param version 鍵バージョン (4か6)
     * @param creationTime 鍵が作成された時間
     * @param keyAlgo 鍵のアルゴリズム
     * @param key 公開鍵
     */
    constructor(
        version: Int,
        creationTime: Int,
        keyAlgo: Int,
        key: java.security.PublicKey
    ): super(version, creationTime, keyAlgo, key)

    companion object: OpenPGPPacket.OpenPGPPacketCompanion<PublicSubkey> {
        /**
         * バイト列からPublicKeyパケットへ変換する
         * @param body パケットヘッダーを含まないボディのみのデータ
         * @return PublicKey
         * @throws IllegalArgumentException versionが3,4,6以外の場合
         */
        @Throws(IllegalArgumentException::class)
        override fun fromBytes( body: ByteArray ): PublicSubkey{
            return fromBytes(ByteArrayInputStream(body) )
        }
        /**
         * バイト列からPublicKeyパケットへ変換する
         * @param body パケットヘッダーを含まないボディのみのデータ
         * @return PublicKey
         */
        @Throws(IllegalArgumentException::class)
        fun fromBytes( body: ByteArrayInputStream ): PublicSubkey{
            return fromBytes(DataInputStream(body) )
        }

        /**
         * バイト列からPublicKeyパケットへ変換する
         * @param body パケットヘッダーを含まないボディのみのデータ
         * @return PublicKey
         * @throws IllegalArgumentException versionが3,4,6以外の場合
         */
        @Throws(IllegalArgumentException::class)
        fun fromBytes( body: DataInputStream ): PublicSubkey{
            val version = body.readUnsignedByte()
            val creationTime = body.readInt()

            if( version == 3 ){
                val validDays = body.readUnsignedShort()
                val keyAlgo = body.readUnsignedByte()

                val key = PublicKey.bytesToPublicKey(keyAlgo, body )

                return PublicSubkey(creationTime, validDays.toShort(), keyAlgo, key)
            }
            else if( version == 4 ){
                val keyAlgo = body.readUnsignedByte()
                val key = bytesToPublicKey(keyAlgo, body )

                return PublicSubkey(4, creationTime, keyAlgo, key)
            }
            else if( version == 6 ){
                val keyAlgo = body.readUnsignedByte()
                val keyLen = body.readInt()
                //鍵の長さが合わないときエラー
                if( body.available() < keyLen ){
                    throw IllegalArgumentException("keyLen is not valid")
                }
                val key = bytesToPublicKey(keyAlgo, body )

                return PublicSubkey(6, creationTime, keyAlgo, key)
            }
            else{
                throw IllegalArgumentException("version must be 3,4 or 6")
            }
        }
    }
}