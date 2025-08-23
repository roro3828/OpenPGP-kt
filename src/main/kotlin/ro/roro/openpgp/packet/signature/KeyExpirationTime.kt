package ro.roro.openpgp.packet.signature

class KeyExpirationTime: SignatureSubPacket {
    override val subPacketType: Int = SignatureSubPacket.KEY_EXPIRATION_TIME

    override val mustBeHashed: Boolean = false
    override val shouldBeCritical: Boolean = true

    /**
     * 署名の有効期限
     * Unix時間で表現される
     */
    val expirationTime: Int

    constructor(expirationTime: Int) {
        this.expirationTime = expirationTime
    }

    /**
     * KeyExpirationTimeのコンストラクタ
     * @param bytes 4バイトの配列でなければならない。
     * @throws IllegalArgumentException もしbytesが4バイトでない場合にスローされる
     */
    @Throws(IllegalArgumentException::class)
    constructor(bytes: ByteArray) {
        if (bytes.size != 4) {
            throw IllegalArgumentException("KeyExpirationTime must be 4 bytes long, but was ${bytes.size} bytes.")
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