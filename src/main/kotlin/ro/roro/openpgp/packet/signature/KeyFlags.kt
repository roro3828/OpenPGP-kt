package ro.roro.openpgp.packet.signature

class KeyFlags: SignatureSubPacket {
    override val subPacketType: Int = SignatureSubPacket.KEY_FLAGS

    override val critical: Boolean

    /**
     * キーフラグ
     * 1バイトの値
     */
    val keyFlags: ByteArray

    constructor(keyFlags: Byte, critical: Boolean = false) {
        this.keyFlags = byteArrayOf(keyFlags)
        this.critical = critical
    }
    constructor(keyFlags: ByteArray, critical: Boolean = false) {
        this.keyFlags = keyFlags
        this.critical = critical
    }

    override val encoded: ByteArray
        get() = keyFlags

    companion object{
        const val CERTIFY = 0x01.toByte()
        const val SIGN = 0x02.toByte()
        const val ENCRYPT_COMMUNICATIONS = 0x04.toByte()
        const val ENCRYPT_STORAGE = 0x08.toByte()
        const val SPLIT_KEY = 0x10.toByte()
        const val AUTHENTICATION = 0x20.toByte()
        const val SHARED_PRIVATE_KEY = 0x80.toByte()
    }
}