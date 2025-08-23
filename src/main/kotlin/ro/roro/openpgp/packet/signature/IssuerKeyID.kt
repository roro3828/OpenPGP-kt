package ro.roro.openpgp.packet.signature

class IssuerKeyID: SignatureSubPacket {
    override val subPacketType: Int = SignatureSubPacket.ISSUER_KEY_ID

    override val mustBeHashed: Boolean = false
    override val shouldBeCritical: Boolean = false

    /**
     * 署名の公開鍵のID
     * 8バイトの値
     */
    val issuerKeyId: ByteArray

    /**
     * IssuerKeyIDのコンストラクタ
     * @param issuerKeyId 署名の公開鍵のID。8バイトの配列でなければならない。
     * @throws IllegalArgumentException もしissuerKeyIdが8バイトでない場合にスローされる
     */
    @Throws(IllegalArgumentException::class)
    constructor(issuerKeyId: ByteArray) {
        if(issuerKeyId.size != 8){
            throw IllegalArgumentException("IssuerKeyID must be 8 bytes long, but was ${issuerKeyId.size} bytes.")
        }
        this.issuerKeyId = issuerKeyId
    }

    override val encoded: ByteArray
        get() = issuerKeyId
}