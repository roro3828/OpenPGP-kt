package ro.roro.openpgp.packet.signature

import java.util.Calendar

class SignatureCreationTime:SignatureSubPacket {
    override val subPacketType: Int = SignatureSubPacket.SIGNATURE_CREATION_TIME

    override val mustBeHashed: Boolean = true
    override val shouldBeCritical: Boolean = false

    /**
     * 署名が作成された時間
     * Unix時間で表現される
     */
    val creationTime: Int

    constructor(creationTime: Int) {
        this.creationTime = creationTime
    }

    constructor(creationTime: Calendar){
        val time = creationTime.timeInMillis / 1000

        this.creationTime = time.toInt()
    }

    /**
     * SignatureCreationTimeのコンストラクタ
     * @param bytes 4バイトの配列でなければならない。
     * @throws IllegalArgumentException もしbytesが4バイトでない場合にスローされる
     */
    @Throws(IllegalArgumentException::class)
    constructor(bytes: ByteArray){
        if (bytes.size != 4) {
            throw IllegalArgumentException("SignatureCreationTime must be 4 bytes long, but was ${bytes.size} bytes.")
        }
        this.creationTime = ((bytes[0].toInt() and 0xFF) shl 24) or
                            ((bytes[1].toInt() and 0xFF) shl 16) or
                            ((bytes[2].toInt() and 0xFF) shl 8) or
                            (bytes[3].toInt() and 0xFF)
    }

    override val encoded: ByteArray
        get() = byteArrayOf(
            (creationTime ushr 24).toByte(),
            (creationTime ushr 16).toByte(),
            (creationTime ushr 8).toByte(),
            (creationTime and 0xFF).toByte()
        )
}