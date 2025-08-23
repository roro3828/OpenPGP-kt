package ro.roro.openpgp.packet.signature

class KeyServerPreferences: SignatureSubPacket {
    override val subPacketType: Int = SignatureSubPacket.KEY_SERVER_PREFERENCES

    override val mustBeHashed: Boolean = false
    override val shouldBeCritical: Boolean = false

    val serverPreferences: ByteArray

    constructor( serverPreferences: Byte = 0x80.toByte() ){
        this.serverPreferences = byteArrayOf(serverPreferences)
    }
    constructor( serverPreferences: ByteArray){
        this.serverPreferences = serverPreferences
    }

    override val encoded: ByteArray
        get() = this.serverPreferences
}