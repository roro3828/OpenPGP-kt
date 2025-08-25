package ro.roro.openpgp.packet.signature

class PreferredHashAlgorithms: SignatureSubPacket {
    override val subPacketType: Int = SignatureSubPacket.PREFERRED_HASH_ALGORITHMS

    override val critical: Boolean

    override val encoded: ByteArray
        get() = this.algorithms

    val algorithms: ByteArray

    constructor( algorithm: Int, critical: Boolean = SignatureSubPacket.PREFERRED_HASH_ALGORITHMS_SHOULD_BE_CRITICAL ){
        this.critical = critical
        this.algorithms = byteArrayOf(algorithm.toByte())
    }
    constructor( algorithm: Byte, critical: Boolean = SignatureSubPacket.PREFERRED_HASH_ALGORITHMS_SHOULD_BE_CRITICAL ){
        this.critical = critical
        this.algorithms = byteArrayOf(algorithm)
    }
    constructor( algorithms: ByteArray, critical: Boolean = SignatureSubPacket.PREFERRED_HASH_ALGORITHMS_SHOULD_BE_CRITICAL ){
        this.critical = critical
        this.algorithms = algorithms
    }
    /*
    constructor( vararg algorithm: Byte ){
        this.algorithms = algorithm
    }

     */
}