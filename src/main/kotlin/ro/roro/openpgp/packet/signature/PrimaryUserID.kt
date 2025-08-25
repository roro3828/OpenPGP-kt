package ro.roro.openpgp.packet.signature

class PrimaryUserID: SignatureSubPacket {
    override val subPacketType: Int = SignatureSubPacket.PRIMARY_USER_ID

    override val critical: Boolean

    val isPrimary: Boolean

    constructor( isPrimary: Boolean, critical: Boolean = SignatureSubPacket.PRIMARY_USER_ID_SHOULD_BE_CRITICAL ){
        this.critical = critical
        this.isPrimary = isPrimary
    }

    /**
     * PrimaryUserIDのコンストラクタ
     * @param byte 1バイトの配列でなければならない。
     * @throws IllegalArgumentException もしbyteが1バイトでない場合にスローされる
     */
    @Throws(IllegalArgumentException::class)
    constructor( byte: ByteArray, critical: Boolean = SignatureSubPacket.PRIMARY_USER_ID_SHOULD_BE_CRITICAL ){
        this.critical = critical
        require(byte.size == 1){ "PrimaryUserID must be 1 byte long, but was ${byte.size} bytes." }
        this.isPrimary = (byte[0] == 0x01.toByte())
    }

    override val encoded: ByteArray
        get(){
            if( this.isPrimary ){
                return byteArrayOf(0x01)
            }
            else{
                return byteArrayOf(0x00)
            }
        }
}