package ro.roro.openpgp.packet.signature

class PreferredSymmetricCiphersV1: SignatureSubPacket {
    override val subPacketType: Int = SignatureSubPacket.PREFERRED_SYMMETRIC_CIPHERS

    override val critical: Boolean

    override val encoded: ByteArray
        get() = this.algorithms

    val algorithms: ByteArray

    constructor( algorithm: Int, critical: Boolean = false){
        this.critical = critical
        this.algorithms = byteArrayOf(algorithm.toByte())
    }
    constructor( algorithm: Byte, critical: Boolean = false){
        this.critical = critical
        this.algorithms = byteArrayOf(algorithm)
    }
    constructor( algorithms: ByteArray, critical: Boolean = false){
        this.critical = critical
        this.algorithms = algorithms
    }
    /*
    constructor( vararg algorithm: Byte ){
        this.algorithms = algorithm
    }

     */
}