package ro.roro.openpgp.packet.signature

class PreferredCompressionAlgorithms: SignatureSubPacket {
    override val subPacketType: Int = SignatureSubPacket.PREFERRED_COMPRESSION_ALGORITHMS

    override val critical: Boolean

    override val encoded: ByteArray
        get() = this.algorithms

    val algorithms: ByteArray

    constructor( algorithm: Int, critical: Boolean = SignatureSubPacket.PREFERRED_COMPRESSION_ALGORITHMS_SHOULD_BE_CRITICAL ){
        this.algorithms = byteArrayOf(algorithm.toByte())
        this.critical = critical
    }
    constructor( algorithm: Byte, critical: Boolean = SignatureSubPacket.PREFERRED_COMPRESSION_ALGORITHMS_SHOULD_BE_CRITICAL ){
        this.critical = critical
        this.algorithms = byteArrayOf(algorithm)
    }
    constructor( algorithms: ByteArray, critical: Boolean = SignatureSubPacket.PREFERRED_COMPRESSION_ALGORITHMS_SHOULD_BE_CRITICAL ){
        this.critical = critical
        this.algorithms = algorithms
    }
    /*
    constructor( vararg algorithm: Byte ){
        this.algorithms = algorithm
    }

     */
}