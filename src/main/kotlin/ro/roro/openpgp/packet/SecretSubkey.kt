package ro.roro.openpgp.packet

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
}