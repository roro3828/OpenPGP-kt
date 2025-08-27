package ro.roro

import org.bouncycastle.jce.provider.BouncyCastleProvider
import ro.roro.openpgp.OpenPGPDigest
import ro.roro.openpgp.OpenPGPSigner
import ro.roro.openpgp.OpenPGPSymmetricKeyAlgorithm
import ro.roro.openpgp.OpenPGPUtil
import ro.roro.openpgp.OpenPGPVerifier
import ro.roro.openpgp.packet.PublicKey
import ro.roro.openpgp.packet.SecretKey
import ro.roro.openpgp.packet.UserID
import ro.roro.openpgp.packet.signature.Features
import ro.roro.openpgp.packet.signature.IssuerFingerprint
import ro.roro.openpgp.packet.signature.IssuerKeyID
import ro.roro.openpgp.packet.signature.KeyExpirationTime
import ro.roro.openpgp.packet.signature.KeyFlags
import ro.roro.openpgp.packet.signature.KeyServerPreferences
import ro.roro.openpgp.packet.signature.PreferredCompressionAlgorithms
import ro.roro.openpgp.packet.signature.PreferredHashAlgorithms
import ro.roro.openpgp.packet.signature.PreferredSymmetricCiphersV1
import ro.roro.openpgp.packet.signature.PrimaryUserID
import ro.roro.openpgp.packet.signature.Signature
import ro.roro.openpgp.packet.signature.SignatureCreationTime
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.util.Calendar
import java.util.TimeZone
import kotlin.experimental.or

fun main(){
    val rsaPublicKeyData = byteArrayOf(0x04.toByte(),0x68.toByte(),0x1d.toByte(),0xb6.toByte(),0x96.toByte(),0x01.toByte(),0x0c.toByte(),0x00.toByte(),0xd1.toByte(),0x5a.toByte(),0xc0.toByte(),0xc8.toByte(),0xe3.toByte(),0x2c.toByte(),0x35.toByte(),0x8b.toByte(),0x9d.toByte(),0x0a.toByte(),0xf6.toByte(),0xbe.toByte(),0x3e.toByte(),0x43.toByte(),0x69.toByte(),0x56.toByte(),0x29.toByte(),0x42.toByte(),0xaf.toByte(),0x97.toByte(),0xea.toByte(),0xcc.toByte(),0x06.toByte(),0x71.toByte(),0x56.toByte(),0x6e.toByte(),0x26.toByte(),0xe9.toByte(),0x8b.toByte(),0x0b.toByte(),0xbc.toByte(),0x87.toByte(),0xd3.toByte(),0x35.toByte(),0x3c.toByte(),0x4c.toByte(),0x10.toByte(),0x78.toByte(),0x8e.toByte(),0x1b.toByte(),0x47.toByte(),0x17.toByte(),0x6f.toByte(),0x31.toByte(),0xd0.toByte(),0xfc.toByte(),0xbd.toByte(),0xfa.toByte(),0x6b.toByte(),0xbe.toByte(),0xbf.toByte(),0x61.toByte(),0x80.toByte(),0x53.toByte(),0x81.toByte(),0x65.toByte(),0xba.toByte(),0x2e.toByte(),0xc5.toByte(),0x45.toByte(),0xec.toByte(),0x46.toByte(),0x85.toByte(),0x86.toByte(),0x39.toByte(),0x19.toByte(),0xc7.toByte(),0xf6.toByte(),0x93.toByte(),0x72.toByte(),0x06.toByte(),0x37.toByte(),0xa3.toByte(),0xa7.toByte(),0x0e.toByte(),0xa3.toByte(),0x95.toByte(),0x6f.toByte(),0x5a.toByte(),0x73.toByte(),0xae.toByte(),0xc9.toByte(),0x16.toByte(),0x4d.toByte(),0x7f.toByte(),0x50.toByte(),0xa5.toByte(),0xe4.toByte(),0xed.toByte(),0xe6.toByte(),0x2e.toByte(),0x88.toByte(),0x85.toByte(),0xa0.toByte(),0xa3.toByte(),0xa7.toByte(),0x34.toByte(),0x69.toByte(),0x41.toByte(),0xc5.toByte(),0xbd.toByte(),0xad.toByte(),0x69.toByte(),0xf1.toByte(),0x93.toByte(),0x69.toByte(),0x60.toByte(),0x39.toByte(),0x30.toByte(),0xd1.toByte(),0x5b.toByte(),0x4b.toByte(),0x4f.toByte(),0xb2.toByte(),0xe9.toByte(),0x1a.toByte(),0x71.toByte(),0x2e.toByte(),0x59.toByte(),0x85.toByte(),0x59.toByte(),0x8e.toByte(),0xbc.toByte(),0xb4.toByte(),0xd0.toByte(),0xb3.toByte(),0x85.toByte(),0x28.toByte(),0x5a.toByte(),0x02.toByte(),0x78.toByte(),0xad.toByte(),0x6b.toByte(),0xb4.toByte(),0x4c.toByte(),0x14.toByte(),0x50.toByte(),0x77.toByte(),0x09.toByte(),0x79.toByte(),0x9c.toByte(),0xb6.toByte(),0xb2.toByte(),0x6c.toByte(),0x67.toByte(),0x1b.toByte(),0x77.toByte(),0xb8.toByte(),0x3e.toByte(),0x03.toByte(),0x5b.toByte(),0xe3.toByte(),0x70.toByte(),0x82.toByte(),0x28.toByte(),0x74.toByte(),0x1b.toByte(),0x64.toByte(),0x14.toByte(),0x83.toByte(),0x8c.toByte(),0x53.toByte(),0x99.toByte(),0xc2.toByte(),0xed.toByte(),0x1c.toByte(),0xe8.toByte(),0x69.toByte(),0x36.toByte(),0x11.toByte(),0xa9.toByte(),0xd7.toByte(),0xdf.toByte(),0xc6.toByte(),0xfd.toByte(),0x02.toByte(),0x90.toByte(),0xa4.toByte(),0x7b.toByte(),0x17.toByte(),0x7d.toByte(),0xaa.toByte(),0x1e.toByte(),0x77.toByte(),0xbb.toByte(),0x10.toByte(),0x08.toByte(),0xba.toByte(),0x1f.toByte(),0xf4.toByte(),0x40.toByte(),0x52.toByte(),0xff.toByte(),0x60.toByte(),0xcc.toByte(),0xb0.toByte(),0x09.toByte(),0x92.toByte(),0x13.toByte(),0x77.toByte(),0x6b.toByte(),0x48.toByte(),0xa3.toByte(),0xe3.toByte(),0x1a.toByte(),0x2b.toByte(),0x04.toByte(),0x36.toByte(),0x70.toByte(),0xfa.toByte(),0x61.toByte(),0x42.toByte(),0x1c.toByte(),0xe4.toByte(),0x04.toByte(),0xf7.toByte(),0x35.toByte(),0x59.toByte(),0xd9.toByte(),0x54.toByte(),0x0a.toByte(),0xa3.toByte(),0x90.toByte(),0xa5.toByte(),0xbb.toByte(),0x01.toByte(),0x78.toByte(),0xd4.toByte(),0xaa.toByte(),0xd0.toByte(),0x70.toByte(),0xaf.toByte(),0x1f.toByte(),0x0c.toByte(),0xd0.toByte(),0xbb.toByte(),0x80.toByte(),0x42.toByte(),0x7d.toByte(),0xcd.toByte(),0x0f.toByte(),0x14.toByte(),0x88.toByte(),0xf8.toByte(),0x2a.toByte(),0xb9.toByte(),0xdb.toByte(),0xe8.toByte(),0xe7.toByte(),0x98.toByte(),0x9b.toByte(),0x7d.toByte(),0x3d.toByte(),0x69.toByte(),0xcd.toByte(),0x59.toByte(),0xd3.toByte(),0x92.toByte(),0xee.toByte(),0x45.toByte(),0x4a.toByte(),0x37.toByte(),0x02.toByte(),0x50.toByte(),0xd5.toByte(),0x16.toByte(),0xf9.toByte(),0xb5.toByte(),0xff.toByte(),0x0b.toByte(),0x30.toByte(),0xb7.toByte(),0x88.toByte(),0xa8.toByte(),0xbb.toByte(),0xcd.toByte(),0x48.toByte(),0xb6.toByte(),0x8f.toByte(),0xb4.toByte(),0x63.toByte(),0xca.toByte(),0x65.toByte(),0x98.toByte(),0x1c.toByte(),0xb6.toByte(),0xda.toByte(),0x4c.toByte(),0x1c.toByte(),0xc1.toByte(),0x73.toByte(),0x29.toByte(),0x31.toByte(),0x14.toByte(),0xfe.toByte(),0x96.toByte(),0x11.toByte(),0xe9.toByte(),0x16.toByte(),0x57.toByte(),0x78.toByte(),0xdb.toByte(),0x28.toByte(),0xc3.toByte(),0x0f.toByte(),0x1f.toByte(),0xd0.toByte(),0x42.toByte(),0xc3.toByte(),0xe1.toByte(),0x11.toByte(),0xfe.toByte(),0x48.toByte(),0xfe.toByte(),0x6c.toByte(),0x88.toByte(),0x2f.toByte(),0xac.toByte(),0x31.toByte(),0xe1.toByte(),0x6b.toByte(),0xb0.toByte(),0x6f.toByte(),0xca.toByte(),0x6e.toByte(),0x49.toByte(),0xdb.toByte(),0xb7.toByte(),0x72.toByte(),0xc0.toByte(),0xfa.toByte(),0xb2.toByte(),0x44.toByte(),0x9c.toByte(),0x7b.toByte(),0x89.toByte(),0xe6.toByte(),0x25.toByte(),0x5b.toByte(),0x44.toByte(),0x2b.toByte(),0x54.toByte(),0x38.toByte(),0xec.toByte(),0x26.toByte(),0x24.toByte(),0x43.toByte(),0xa5.toByte(),0xf7.toByte(),0x2c.toByte(),0xdf.toByte(),0xf4.toByte(),0x55.toByte(),0x06.toByte(),0xdb.toByte(),0x4b.toByte(),0x09.toByte(),0x4f.toByte(),0xd0.toByte(),0x75.toByte(),0x35.toByte(),0xe8.toByte(),0x1e.toByte(),0x47.toByte(),0x1b.toByte(),0xf3.toByte(),0xed.toByte(),0x58.toByte(),0xf7.toByte(),0x2e.toByte(),0x13.toByte(),0x8a.toByte(),0xf7.toByte(),0x5a.toByte(),0xf7.toByte(),0xe8.toByte(),0x0c.toByte(),0xaf.toByte(),0xc8.toByte(),0x9b.toByte(),0x86.toByte(),0xb8.toByte(),0x2f.toByte(),0xcd.toByte(),0x00.toByte(),0x11.toByte(),0x01.toByte(),0x00.toByte(),0x01.toByte())
    val ed25519LegacyPublicKeyData = byteArrayOf(0x04.toByte(),0x67.toByte(),0xe6.toByte(),0x9a.toByte(),0x00.toByte(),0x16.toByte(),0x09.toByte(),0x2b.toByte(),0x06.toByte(),0x01.toByte(),0x04.toByte(),0x01.toByte(),0xda.toByte(),0x47.toByte(),0x0f.toByte(),0x01.toByte(),0x01.toByte(),0x07.toByte(),0x40.toByte(),0x02.toByte(),0xfa.toByte(),0xe9.toByte(),0x31.toByte(),0x63.toByte(),0x2a.toByte(),0x09.toByte(),0xa4.toByte(),0x32.toByte(),0xa5.toByte(),0x0f.toByte(),0x11.toByte(),0x84.toByte(),0xf7.toByte(),0x82.toByte(),0x57.toByte(),0x20.toByte(),0xd7.toByte(),0x9a.toByte(),0x81.toByte(),0x97.toByte(),0xb7.toByte(),0x8a.toByte(),0x2a.toByte(),0xfc.toByte(),0x78.toByte(),0xea.toByte(),0xa5.toByte(),0xd9.toByte(),0xd0.toByte(),0x1c.toByte(),0x50.toByte())
    val ed25519PublicKeyData = byteArrayOf(0x06.toByte(),0x63.toByte(),0x87.toByte(),0x7f.toByte(),0xe3.toByte(),0x1b.toByte(),0x00.toByte(),0x00.toByte(),0x00.toByte(),0x20.toByte(),0xf9.toByte(),0x4d.toByte(),0xa7.toByte(),0xbb.toByte(),0x48.toByte(),0xd6.toByte(),0x0a.toByte(),0x61.toByte(),0xe5.toByte(),0x67.toByte(),0x70.toByte(),0x6a.toByte(),0x65.toByte(),0x87.toByte(),0xd0.toByte(),0x33.toByte(),0x19.toByte(),0x99.toByte(),0xbb.toByte(),0x9d.toByte(),0x89.toByte(),0x1a.toByte(),0x08.toByte(),0x24.toByte(),0x2e.toByte(),0xad.toByte(),0x84.toByte(),0x54.toByte(),0x3d.toByte(),0xf8.toByte(),0x95.toByte(),0xa3.toByte())
    val secretkeyData = byteArrayOf(0x04.toByte(),0x67.toByte(),0xe6.toByte(),0x9a.toByte(),0x00.toByte(),0x16.toByte(),0x09.toByte(),0x2b.toByte(),0x06.toByte(),0x01.toByte(),0x04.toByte(),0x01.toByte(),0xda.toByte(),0x47.toByte(),0x0f.toByte(),0x01.toByte(),0x01.toByte(),0x07.toByte(),0x40.toByte(),0x02.toByte(),0xfa.toByte(),0xe9.toByte(),0x31.toByte(),0x63.toByte(),0x2a.toByte(),0x09.toByte(),0xa4.toByte(),0x32.toByte(),0xa5.toByte(),0x0f.toByte(),0x11.toByte(),0x84.toByte(),0xf7.toByte(),0x82.toByte(),0x57.toByte(),0x20.toByte(),0xd7.toByte(),0x9a.toByte(),0x81.toByte(),0x97.toByte(),0xb7.toByte(),0x8a.toByte(),0x2a.toByte(),0xfc.toByte(),0x78.toByte(),0xea.toByte(),0xa5.toByte(),0xd9.toByte(),0xd0.toByte(),0x1c.toByte(),0x50.toByte(),0xfe.toByte(),0x07.toByte(),0x03.toByte(),0x02.toByte(),0x4a.toByte(),0x0f.toByte(),0xc1.toByte(),0xff.toByte(),0xba.toByte(),0x33.toByte(),0xf0.toByte(),0x6e.toByte(),0xfa.toByte(),0x51.toByte(),0xe6.toByte(),0xdf.toByte(),0x40.toByte(),0xbd.toByte(),0xf3.toByte(),0x67.toByte(),0x77.toByte(),0x65.toByte(),0xbb.toByte(),0x44.toByte(),0x2d.toByte(),0x46.toByte(),0xc8.toByte(),0xa6.toByte(),0xfc.toByte(),0xc6.toByte(),0xe6.toByte(),0xfe.toByte(),0x09.toByte(),0x78.toByte(),0x42.toByte(),0x3a.toByte(),0x48.toByte(),0xf0.toByte(),0xb1.toByte(),0xdd.toByte(),0xf8.toByte(),0x7d.toByte(),0x8c.toByte(),0xbb.toByte(),0x25.toByte(),0x4b.toByte(),0x4e.toByte(),0x1a.toByte(),0x96.toByte(),0x5e.toByte(),0xba.toByte(),0xef.toByte(),0xa3.toByte(),0x23.toByte(),0x1f.toByte(),0x0e.toByte(),0x24.toByte(),0x40.toByte(),0xe4.toByte(),0x40.toByte(),0xcf.toByte(),0x6f.toByte(),0xe8.toByte(),0xba.toByte(),0x07.toByte(),0x29.toByte(),0xc2.toByte(),0x7b.toByte(),0x5f.toByte(),0x9e.toByte(),0x7c.toByte(),0x40.toByte(),0x91.toByte(),0x18.toByte(),0xd0.toByte(),0xb7.toByte(),0x0d.toByte(),0x8a.toByte(),0xdf.toByte(),0x5a.toByte(),0x5a.toByte(),0x43.toByte(),0x9e.toByte())

    /**
     * From RFC 9580 - Test Vector 1 (Ed25519)
     * https://www.rfc-editor.org/rfc/rfc9580.html#name-sample-version-4-ed25519leg
     */
    val rfc9580SampleEd25519PublicKeyPacket = byteArrayOf(0x04.toByte(), 0x53.toByte(), 0xf3.toByte(), 0x5f.toByte(), 0x0b.toByte(), 0x16.toByte(), 0x09.toByte(), 0x2b.toByte(), 0x06.toByte(), 0x01.toByte(), 0x04.toByte(), 0x01.toByte(), 0xda.toByte(), 0x47.toByte(), 0x0f.toByte(), 0x01.toByte(), 0x01.toByte(), 0x07.toByte(), 0x40.toByte(), 0x3f.toByte(), 0x09.toByte(), 0x89.toByte(), 0x94.toByte(), 0xbd.toByte(), 0xd9.toByte(), 0x16.toByte(), 0xed.toByte(), 0x40.toByte(), 0x53.toByte(), 0x19.toByte(), 0x79.toByte(), 0x34.toByte(), 0xe4.toByte(), 0xa8.toByte(), 0x7c.toByte(), 0x80.toByte(), 0x73.toByte(), 0x3a.toByte(), 0x12.toByte(), 0x80.toByte(), 0xd6.toByte(), 0x2f.toByte(), 0x80.toByte(), 0x10.toByte(), 0x99.toByte(), 0x2e.toByte(), 0x43.toByte(), 0xee.toByte(), 0x3b.toByte(), 0x24.toByte(), 0x06.toByte())
    val rfc9580SampleEd25519SecretKeyRaw = byteArrayOf(0x1a.toByte(), 0x8b.toByte(), 0x1f.toByte(), 0xf0.toByte(), 0x5d.toByte(), 0xed.toByte(), 0x48.toByte(), 0xe1.toByte(), 0x8b.toByte(), 0xf5.toByte(), 0x01.toByte(), 0x66.toByte(), 0xc6.toByte(), 0x64.toByte(), 0xab.toByte(), 0x02.toByte(), 0x3e.toByte(), 0xa7.toByte(), 0x00.toByte(), 0x03.toByte(), 0xd7.toByte(), 0x8d.toByte(), 0x9e.toByte(), 0x41.toByte(), 0xf5.toByte(), 0x75.toByte(), 0x8a.toByte(), 0x91.toByte(), 0xd8.toByte(), 0x50.toByte(), 0xf8.toByte(), 0xd2.toByte())
    val rfc9580SampleEd25519Key = OpenPGPUtil.getKeyPairFromEd25519Secret(rfc9580SampleEd25519SecretKeyRaw)

    val publicKeyPacket = PublicKey.fromBytes(rfc9580SampleEd25519PublicKeyPacket)
    val secretKeyPacket = SecretKey(publicKeyPacket, rfc9580SampleEd25519Key.private)

    val signer = OpenPGPSigner(secretKeyPacket, BouncyCastleProvider())

    val cal = Calendar.getInstance(TimeZone.getTimeZone("UTC"))
    cal.set(2015, 8, 16, 12, 24, 53)
    val creationtime = SignatureCreationTime(cal, false)

    val issuer = IssuerKeyID(secretKeyPacket.keyId)

    val signature = Signature.getV4Signature(
        "OpenPGP".toByteArray(),
        signer,
        Signature.BINARY_SIGNATURE,
        PublicKey.EDDSA_LEGACY,
        OpenPGPDigest.SHA256,
        listOf(creationtime),
        listOf(issuer)
    )

    val e = signature.encoded
    println("Encoded signature: " + OpenPGPUtil.getHexString(e))
    //e[e.size - 1] = 0x05.toByte() // Corrupt the signature for testing

    val copyedSignature = Signature.fromBytes(ByteArrayInputStream(e))


    val verifier = OpenPGPVerifier(secretKeyPacket.publicKey, BouncyCastleProvider())
    println("Verify result: " + copyedSignature.verify("OpenPGP".toByteArray(), verifier).toString() )

    println(OpenPGPUtil.getHexString(OpenPGPUtil.calcCRC(byteArrayOf(0x01, 0x02, 0x03, 0x04))))
    println(OpenPGPUtil.toBase64(signature.encodedWithHeader))
    println(OpenPGPUtil.toBase64(OpenPGPUtil.calcCRC(signature.encodedWithHeader)))

    generatePublicKeyPacketWithSign()
}

fun generatePublicKeyPacketWithSign() {
    println("Generate PublicKey Packet with Sign")
    val secretKeySeed = byteArrayOf(0x2B.toByte(),0xD5.toByte(),0xD3.toByte(),0x22.toByte(),0xEA.toByte(),0x88.toByte(),0x40.toByte(),0x9B.toByte(),0xEB.toByte(),0x66.toByte(),0x07.toByte(),0x0B.toByte(),0x9A.toByte(),0xBC.toByte(),0xD4.toByte(),0x95.toByte(),0xA5.toByte(),0x23.toByte(),0x5A.toByte(),0xE8.toByte(),0xBD.toByte(),0x13.toByte(),0xEC.toByte(),0x0C.toByte(),0x36.toByte(),0x4E.toByte(),0x55.toByte(),0x39.toByte(),0x38.toByte(),0xA8.toByte(),0xE7.toByte(),0xC6.toByte())
    val keyPair = OpenPGPUtil.getKeyPairFromEd25519Secret(secretKeySeed)
    val creationTime = Calendar.getInstance(TimeZone.getTimeZone("JST"))
    creationTime.set(2025, 2, 28, 21, 45, 52)
    val secretKeyPacket = SecretKey(creationTime, PublicKey.EDDSA_LEGACY, keyPair, 4)

    val signatureCreationTime = Calendar.getInstance(TimeZone.getTimeZone("JST"))
    signatureCreationTime.set(2025, 4, 9, 16, 47, 50)

    val userIDPacket = UserID("test", "test@roro.ro")

    val hashedSubpackets = listOf(
        KeyFlags((KeyFlags.CERTIFY or KeyFlags.SIGN), false),
        KeyExpirationTime(94659248, false),
        KeyServerPreferences(critical = false),
        PrimaryUserID(true, false),
        IssuerFingerprint(secretKeyPacket.publicKey, false),
        SignatureCreationTime(signatureCreationTime, false),
        PreferredSymmetricCiphersV1(
            byteArrayOf(OpenPGPSymmetricKeyAlgorithm.AES_256.algorithmTag.toByte(),
                    OpenPGPSymmetricKeyAlgorithm.AES_192.algorithmTag.toByte(),
                    OpenPGPSymmetricKeyAlgorithm.AES_128.algorithmTag.toByte(),
                    OpenPGPSymmetricKeyAlgorithm.TRIPLE_DES.algorithmTag.toByte()
                ), false),
        PreferredHashAlgorithms(
            byteArrayOf(OpenPGPDigest.SHA512.toByte(),
                    OpenPGPDigest.SHA384.toByte(),
                    OpenPGPDigest.SHA256.toByte(),
                    OpenPGPDigest.SHA224.toByte(),
                    OpenPGPDigest.SHA1.toByte()
                    ), false),
        PreferredCompressionAlgorithms(
            byteArrayOf(
                2,
                3,
                1
            ), false
        ),
        Features((Features.SYMMETRIC_ENCRYPTION_V1 or 0x04), false)
    )

    val data = ByteArrayOutputStream()
    val dataOutputStream = DataOutputStream(data)
    dataOutputStream.writeByte(Signature.PUBLICKEY_V4_SIGNATURE_PREFIX)
    dataOutputStream.writeShort(secretKeyPacket.publicKey.encoded.size)
    dataOutputStream.write(secretKeyPacket.publicKey.encoded)
    dataOutputStream.writeByte(Signature.USER_ID_CERTIFICATION_PREFIX)
    dataOutputStream.writeInt(userIDPacket.encoded.size)
    dataOutputStream.write(userIDPacket.encoded)

    val signer = OpenPGPSigner(secretKeyPacket)

    val signature = Signature.getV4Signature(
        data.toByteArray(),
        signer,
        Signature.POSITIVE_CERTIFICATION_SIGNATURE,
        PublicKey.EDDSA_LEGACY,
        OpenPGPDigest.SHA512,
        hashedSubpackets,
        listOf(IssuerKeyID(secretKeyPacket.keyId, false))
    )

    val outputData = ByteArrayOutputStream()

    outputData.write(secretKeyPacket.publicKey.encodedWithHeader)
    outputData.write(userIDPacket.encodedWithHeader)
    outputData.write(signature.encodedWithHeader)

    println(OpenPGPUtil.toBase64(outputData.toByteArray()))
    println(OpenPGPUtil.toBase64(OpenPGPUtil.calcCRC(outputData.toByteArray())))

    val verifier = OpenPGPVerifier(secretKeyPacket.publicKey)

    println("Verify result:" + signature.verify(data.toByteArray(), verifier))

}