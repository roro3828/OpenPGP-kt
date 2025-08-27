package ro.roro.openpgp.packet.signature

class IssuerKeyID: SignatureSubPacket {
    override val subPacketType: Int = SignatureSubPacket.ISSUER_KEY_ID

    override val critical: Boolean

    /**
     * 署名の公開鍵のID
     * 8バイトの値
     */
    val issuerKeyId: ByteArray

    override val encoded: ByteArray
        get() = issuerKeyId
    /**
     * IssuerKeyIDのコンストラクタ
     * @param issuerKeyId 署名の公開鍵のID。8バイトの配列でなければならない。
     * @throws IllegalArgumentException もしissuerKeyIdが8バイトでない場合にスローされる
     */
    @Throws(IllegalArgumentException::class)
    constructor(issuerKeyId: ByteArray, critical: Boolean = false) {
        require(issuerKeyId.size == 8) { "IssuerKeyID must be 8 bytes long, but was ${issuerKeyId.size} bytes." }

        this.issuerKeyId = issuerKeyId
        this.critical = critical
    }
}