package ro.roro.openpgp.packet.signature

class KeyServerPreferences: SignatureSubPacket {
    override val subPacketType: Int = SignatureSubPacket.KEY_SERVER_PREFERENCES

    override val critical: Boolean

    val serverPreferences: ByteArray

    constructor( serverPreferences: Byte = NO_MODIFY, critical: Boolean = false){
        this.serverPreferences = byteArrayOf(serverPreferences)
        this.critical = critical
    }
    constructor( serverPreferences: ByteArray, critical: Boolean = false){
        this.critical = critical
        this.serverPreferences = serverPreferences
    }

    override val encoded: ByteArray
        get() = this.serverPreferences

    companion object{
        const val NO_MODIFY = 0x80.toByte()
    }
}