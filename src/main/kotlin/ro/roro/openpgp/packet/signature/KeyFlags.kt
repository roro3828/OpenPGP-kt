package ro.roro.openpgp.packet.signature

class KeyFlags: SignatureSubPacket {
    override val subPacketType: Int = SignatureSubPacket.KEY_FLAGS

    override val mustBeHashed: Boolean = false
    override val shouldBeCritical: Boolean = true

    /**
     * キーフラグ
     * 1バイトの値
     */
    val keyFlags: ByteArray

    constructor(keyFlags: Byte){
        this.keyFlags = byteArrayOf(keyFlags)
    }
    constructor(keyFlags: ByteArray) {
        this.keyFlags = keyFlags
    }

    override val encoded: ByteArray
        get() = keyFlags
}