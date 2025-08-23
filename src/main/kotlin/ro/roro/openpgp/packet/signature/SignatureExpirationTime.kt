package ro.roro.openpgp.packet.signature

class SignatureExpirationTime: SignatureSubPacket {
    override val subPacketType: Int = SignatureSubPacket.SIGNATURE_EXPIRATION_TIME

    override val mustBeHashed: Boolean = false
    override val shouldBeCritical: Boolean = true

    /**
     * 署名の有効期限
     * 作成時からの秒数
     */
    val expirationTime: Int

    constructor(creationTime: Int) {
        this.expirationTime = creationTime
    }

    /**
     * SignatureExpirationTimeのコンストラクタ
     * @param bytes 4バイトの配列でなければならない。
     * @throws IllegalArgumentException もしbytesが4バイトでない場合にスローされる
     */
    @Throws(IllegalArgumentException::class)
    constructor(bytes: ByteArray) {
        if (bytes.size != 4) {
            throw IllegalArgumentException("SignatureExpirationTime must be 4 bytes long, but was ${bytes.size} bytes.")
        }
        this.expirationTime = ((bytes[0].toInt() and 0xFF) shl 24) or
                              ((bytes[1].toInt() and 0xFF) shl 16) or
                              ((bytes[2].toInt() and 0xFF) shl 8) or
                              (bytes[3].toInt() and 0xFF)
    }

    override val encoded: ByteArray
        get() = byteArrayOf(
            (expirationTime ushr 24).toByte(),
            (expirationTime ushr 16).toByte(),
            (expirationTime ushr 8).toByte(),
            (expirationTime and 0xFF).toByte()
        )
}