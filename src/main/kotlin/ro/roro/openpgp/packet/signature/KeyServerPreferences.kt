package ro.roro.openpgp.packet.signature

class KeyServerPreferences: SignatureSubPacket {
    override val subPacketType: Int = SignatureSubPacket.KEY_SERVER_PREFERENCES

    override val critical: Boolean

    val serverPreferences: ByteArray

    constructor( serverPreferences: Byte = 0x80.toByte(), critical: Boolean = SignatureSubPacket.KEY_SERVER_PREFERENCES_SHOULD_BE_CRITICAL){
        this.serverPreferences = byteArrayOf(serverPreferences)
        this.critical = critical
    }
    constructor( serverPreferences: ByteArray, critical: Boolean = SignatureSubPacket.KEY_SERVER_PREFERENCES_SHOULD_BE_CRITICAL){
        this.critical = critical
        this.serverPreferences = serverPreferences
    }

    override val encoded: ByteArray
        get() = this.serverPreferences
}