package ro.roro.openpgp.packet

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
}