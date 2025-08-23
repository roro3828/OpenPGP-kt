package ro.roro.openpgp.packet.signature


class Features: SignatureSubPacket {
    override val subPacketType: Int = SignatureSubPacket.FEATURES

    override val mustBeHashed: Boolean = false
    override val shouldBeCritical: Boolean = false

    override val encoded: ByteArray
        get() = this.features

    val features: ByteArray

    constructor( features: ByteArray ){
        this.features = features
    }
    constructor( features: Byte ){
        this.features = byteArrayOf(features)
    }
}