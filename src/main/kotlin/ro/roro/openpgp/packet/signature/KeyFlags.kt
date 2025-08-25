package ro.roro.openpgp.packet.signature

class KeyFlags: SignatureSubPacket {
    override val subPacketType: Int = SignatureSubPacket.KEY_FLAGS

    override val critical: Boolean

    /**
     * キーフラグ
     * 1バイトの値
     */
    val keyFlags: ByteArray

    constructor(keyFlags: Byte, critical: Boolean = SignatureSubPacket.KEY_FLAGS_SHOULD_BE_CRITICAL) {
        this.keyFlags = byteArrayOf(keyFlags)
        this.critical = critical
    }
    constructor(keyFlags: ByteArray, critical: Boolean = SignatureSubPacket.KEY_FLAGS_SHOULD_BE_CRITICAL) {
        this.keyFlags = keyFlags
        this.critical = critical
    }

    override val encoded: ByteArray
        get() = keyFlags
}