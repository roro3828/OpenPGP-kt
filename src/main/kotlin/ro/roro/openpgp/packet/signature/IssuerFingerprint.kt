package ro.roro.openpgp.packet.signature

import ro.roro.openpgp.packet.PublicKey
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream

class IssuerFingerprint: SignatureSubPacket {
    override val subPacketType: Int = SignatureSubPacket.ISSUER_FINGERPRINT

    override val critical: Boolean

    /**
     * 鍵のバージョン
     */
    val keyVersion: Int

    /**
     * 署名鍵のフィンガープリント
     */
    val issuerFingerprint: ByteArray

    constructor( keyVersion: Int, issuerFingerprint: ByteArray, critical: Boolean = SignatureSubPacket.ISSUER_FINGERPRINT_SHOULD_BE_CRITICAL ){
        require(keyVersion == 3 || keyVersion == 4 || keyVersion == 6) {
            "Invalid key version: $keyVersion. Must be 3, 4, or 6."
        }
        this.keyVersion = keyVersion
        require(PublicKey.getFingerprintSize(keyVersion) == issuerFingerprint.size) {
            "Invalid fingerprint size: ${issuerFingerprint.size}. Must be ${PublicKey.getFingerprintSize(keyVersion)} bytes."
        }
        this.issuerFingerprint = issuerFingerprint
        this.critical = critical
    }
    constructor( publicKeyPacket: PublicKey, critical: Boolean = SignatureSubPacket.ISSUER_FINGERPRINT_SHOULD_BE_CRITICAL ){
        this.keyVersion = publicKeyPacket.keyVertion
        this.issuerFingerprint = publicKeyPacket.fingerprint
        this.critical = critical
    }

    /**
     * IssuerFingerprintのコンストラクタ
     * @param bytes 署名鍵のフィンガープリントのバイト配列
     * @throws IllegalArgumentException bytesの長さが不正な場合
     */
    @Throws(IllegalArgumentException::class)
    constructor(bytes: ByteArray, critical: Boolean = SignatureSubPacket.ISSUER_FINGERPRINT_SHOULD_BE_CRITICAL){
        try {
            this.keyVersion = PublicKey.getFingerprintVersion(bytes)
            this.issuerFingerprint = bytes
        }
        catch (e: IllegalArgumentException) {
            throw IllegalArgumentException("Invalid bytes for IssuerFingerprint: ${e.message}")
        }

        this.critical = critical
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