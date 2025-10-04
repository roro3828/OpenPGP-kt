package ro.roro.openpgp.packet

import java.io.ByteArrayInputStream
import java.io.DataInputStream
import java.security.PrivateKey

/**
 * パケットタグ以外はSecretKeyと同じ
 */
class SecretSubkey: SecretKey {
    override val packetType = OpenPGPPacket.SECRET_SUBKEY

    constructor(
        publicKey: PublicKey,
        secretKeyData: ByteArray
    ): super(publicKey, secretKeyData)

    constructor(
        publicKey: PublicKey,
        secretKey: PrivateKey
    ): super(publicKey, secretKey)

    companion object: OpenPGPPacket.OpenPGPPacketCompanion<SecretSubkey>{
        override fun fromBytes( body: ByteArray): SecretSubkey{
            val dataInputStream = DataInputStream(ByteArrayInputStream(body))

            val publicKey = PublicKey.fromBytes(dataInputStream)
            val secretKeyData = dataInputStream.readAllBytes()

            return SecretSubkey(publicKey, secretKeyData)
        }
    }
}