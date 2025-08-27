package ro.roro.openpgp.packet.signature

/**
 *        +=========+=====================================+===========+
 *        | Feature | Definition                          | Reference |
 *        +=========+=====================================+===========+
 *        | 0x01... | Version 1 Symmetrically Encrypted   | Section   |
 *        |         | and Integrity Protected Data packet | 5.13.1    |
 *        +---------+-------------------------------------+-----------+
 *        | 0x02... | Reserved                            |           |
 *        +---------+-------------------------------------+-----------+
 *        | 0x04... | Reserved                            |           |
 *        +---------+-------------------------------------+-----------+
 *        | 0x08... | Version 2 Symmetrically Encrypted   | Section   |
 *        |         | and Integrity Protected Data packet | 5.13.2    |
 *        +---------+-------------------------------------+-----------+
 */
class Features: SignatureSubPacket {
    override val subPacketType: Int = SignatureSubPacket.FEATURES

    override val critical: Boolean

    override val encoded: ByteArray
        get() = this.features

    val features: ByteArray

    constructor( features: ByteArray, critical: Boolean = false){
        this.features = features
        this.critical = critical
    }
    constructor( features: Byte, critical: Boolean = false){
        this.features = byteArrayOf(features)
        this.critical = critical
    }

    companion object {
        const val SYMMETRIC_ENCRYPTION_V1 = 0x01.toByte()
        const val SYMMETRIC_ENCRYPTION_V2 = 0x08.toByte()
    }
}