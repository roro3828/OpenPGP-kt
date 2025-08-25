package ro.roro.openpgp.packet.signature


class Features: SignatureSubPacket {
    override val subPacketType: Int = SignatureSubPacket.FEATURES

    override val critical: Boolean

    override val encoded: ByteArray
        get() = this.features

    val features: ByteArray

    constructor( features: ByteArray, critical: Boolean = SignatureSubPacket.FEATURES_SHOULD_BE_CRITICAL){
        this.features = features
        this.critical = critical
    }
    constructor( features: Byte, critical: Boolean = SignatureSubPacket.FEATURES_SHOULD_BE_CRITICAL ){
        this.features = byteArrayOf(features)
        this.critical = critical
    }
}