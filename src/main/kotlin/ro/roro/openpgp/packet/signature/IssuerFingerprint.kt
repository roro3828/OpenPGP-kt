package ro.roro.openpgp.packet.signature

import ro.roro.openpgp.packet.PublicKey
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream

class IssuerFingerprint: SignatureSubPacket {
    override val subPacketType: Int = SignatureSubPacket.ISSUER_FINGERPRINT

    override val mustBeHashed: Boolean = false
    override val shouldBeCritical: Boolean = false

    /**
     * 鍵のバージョン
     */
    val keyVersion: Int

    /**
     * 署名鍵のフィンガープリント
     */
    val issuerFingerprint: ByteArray

    constructor( keyVersion: Int, issuerFingerprint: ByteArray ){
        if( !( keyVersion == 3 || keyVersion == 4 || keyVersion == 6 ) ){
            throw IllegalArgumentException("Invalid key version: $keyVersion. Must be 3, 4, or 6.")
        }
        this.keyVersion = keyVersion
        this.issuerFingerprint = issuerFingerprint
    }
    constructor( publicKeyPacket: PublicKey ){
        this.keyVersion = publicKeyPacket.keyVertion
        this.issuerFingerprint = publicKeyPacket.fingerprint
    }

    /**
     * IssuerFingerprintのコンストラクタ
     * @param bytes 署名鍵のフィンガープリントのバイト配列
     * @throws IllegalArgumentException bytesの長さが不正な場合
     */
    @Throws(IllegalArgumentException::class)
    constructor(bytes: ByteArray){
        try {
            this.keyVersion = PublicKey.getFingerprintVersion(bytes)
            this.issuerFingerprint = bytes
        }
        catch (e: IllegalArgumentException) {
            throw IllegalArgumentException("Invalid bytes for IssuerFingerprint: ${e.message}")
        }
    }

    override val encoded: ByteArray
        get(){
            val bytes = ByteArrayOutputStream()
            val dataOutputStream = DataOutputStream(bytes)
            dataOutputStream.writeByte( this.keyVersion )
            dataOutputStream.write( issuerFingerprint )
            return bytes.toByteArray()
        }
}