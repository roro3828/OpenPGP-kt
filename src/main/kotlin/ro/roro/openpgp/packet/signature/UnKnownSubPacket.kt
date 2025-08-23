package ro.roro.openpgp.packet.signature

/**
 * 署名サブパケットのうち、定義されていないもの
 */
class UnKnownSubPacket: SignatureSubPacket {
    override val subPacketType: Int = SignatureSubPacket.UNKNOWN_SUBPACKET

    override val mustBeHashed: Boolean = false
    override val shouldBeCritical: Boolean = false

    override val encoded: ByteArray
        get() = this.data

    val data: ByteArray

    constructor( data: ByteArray ){
        this.data = data
    }
}