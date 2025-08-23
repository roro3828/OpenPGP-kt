package ro.roro.openpgp.packet

/**
 * パケットタグ以外はPublicKeyと同じ
 */
class PublicSubkey(
    creationTime: Int,
    keyAlgo: Int,
    key: java.security.PublicKey,
    version: Int,
    validDays: Int
) : PublicKey(creationTime, keyAlgo, key, version, validDays) {
    override val packetType = OpenPGPPacket.PUBLIC_SUBKEY

}