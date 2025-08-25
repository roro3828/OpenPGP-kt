package ro.roro.openpgp.packet.signature

/**
 * 署名サブパケットのうち、定義されていないもの
 */
class UnKnownSubPacket: SignatureSubPacket {
    override val subPacketType: Int

    override val critical: Boolean

    override val encoded: ByteArray
        get() = this.data

    override val unKnown: Boolean = true

    val data: ByteArray

    constructor(subPacketType: Int, data: ByteArray, critical: Boolean = false ){
        this.subPacketType = subPacketType
        this.critical = critical
        this.data = data
    }
}