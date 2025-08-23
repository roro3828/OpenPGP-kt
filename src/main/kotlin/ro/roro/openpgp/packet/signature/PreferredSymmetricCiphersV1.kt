package ro.roro.openpgp.packet.signature

class PreferredSymmetricCiphersV1: SignatureSubPacket {
    override val subPacketType: Int = SignatureSubPacket.PREFERRED_SYMMETRIC_CIPHERS

    override val mustBeHashed: Boolean = false
    override val shouldBeCritical: Boolean = false

    override val encoded: ByteArray
        get() = this.algorithms

    val algorithms: ByteArray

    constructor( algorithm: Int ){
        this.algorithms = byteArrayOf(algorithm.toByte())
    }
    constructor( algorithm: Byte ){
        this.algorithms = byteArrayOf(algorithm)
    }
    constructor( algorithms: ByteArray ){
        this.algorithms = algorithms
    }
    /*
    constructor( vararg algorithm: Byte ){
        this.algorithms = algorithm
    }

     */
}