package ro.roro.openpgp.packet

import ro.roro.openpgp.OpenPGPDigest
import ro.roro.openpgp.OpenPGPPublicKeyAlgorithms
import ro.roro.openpgp.OpenPGPS2K
import ro.roro.openpgp.OpenPGPSymmetricKeyAlgorithm
import ro.roro.openpgp.OpenPGPUtil
import java.io.ByteArrayInputStream
import java.io.DataInputStream
import java.security.KeyPair
import java.security.PrivateKey

open class SecretKey:OpenPGPPacket {
    override val packetType = OpenPGPPacket.SECRET_KEY

    /**
     * この秘密鍵の公開鍵
     */
    val publicKey: PublicKey

    /**
     * 鍵バージョン
     * 推奨 : 6
     */
    val keyVertion: Int
        get() {
            return publicKey.keyVertion
        }

    /**
     * 鍵が作成された時間
     */
    val creationTime: Int
        get() {
            return publicKey.creationTime
        }

    /**
     * 鍵のアルゴリズム
     */
    val keyAlgo: Int
        get() {
            return publicKey.keyAlgo
        }

    /**
     *    鍵のID
     *    +=======+=============+=========+
     *    |Key    | Key ID      |Reference|
     *    |Version|             |         |
     *    |       |             |         |
     *    +=======+=============+=========+
     *    |3      | low 64 bits |Section  |
     *    |       | of RSA      |5.5.4.1  |
     *    |       | modulus     |         |
     *    +-------+-------------+---------+
     *    |4      | last 64     |Section  |
     *    |       | bits of     |5.5.4.2  |
     *    |       | fingerprint |         |
     *    +-------+-------------+---------+
     *    |6      | first 64    |Section  |
     *    |       | bits of     |5.5.4.3  |
     *    |       | fingerprint |         |
     *    +-------+-------------+---------+
     */
    val keyId: ByteArray
        get() {
            return publicKey.keyId
        }

    /**
     *    鍵のフィンガープリント
     *    +=======+===================+===============+
     *    |Key    | Fingerprint       | Fingerprint   |
     *    |Version|                   | Length        |
     *    |       |                   | (Bits)        |
     *    +=======+===================+===============+
     *    |3      | MD5(MPIs without  | 128           |
     *    |       | length octets)    |               |
     *    |       |                   |               |
     *    +-------+-------------------+---------------+
     *    |4      | SHA1(normalized   | 160           |
     *    |       | pubkey packet)    |               |
     *    |       |                   |               |
     *    +-------+-------------------+---------------+
     *    |6      | SHA256(normalized | 256           |
     *    |       | pubkey packet)    |               |
     *    |       |                   |               |
     *    +-------+-------------------+---------------+
     */
    val fingerprint: ByteArray
        get() {
            return publicKey.fingerprint
        }

    /**
     * 秘密鍵
     */
    private val secretKeyData: ByteArray?
    private val secretKey: PrivateKey?

    constructor(
        publicKey: PublicKey,
        secretKeyData: ByteArray
    ){
        this.publicKey = publicKey

        this.secretKeyData = secretKeyData
        this.secretKey = null
    }
    constructor(
        publicKey: PublicKey,
        secretKey: PrivateKey
    ){
        this.publicKey = publicKey

        this.secretKeyData = null
        this.secretKey = secretKey
    }

    /**
     * 秘密鍵を作成する
     * @param creationTime 鍵の作成時間 (Unix time)
     * @param keyAlgo 鍵のアルゴリズム (OpenPGPPublicKeyAlgorithms)
     * @param keyPair 鍵ペア
     * @param version 鍵のバージョン (デフォルト: 6)
     */
    constructor(
        creationTime: Int,
        keyAlgo: Int,
        keyPair: KeyPair,
        version: Int = 6
    ){
        if( version != 6 && version != 4){
            throw IllegalArgumentException("This library only supports generating version 4 or 6 keys")
        }

        this.publicKey = PublicKey(creationTime, keyAlgo, keyPair.public, version)

        this.secretKeyData = null
        this.secretKey = keyPair.private
    }

    override val encoded: ByteArray
        get() {
            if( this.secretKeyData == null ){
                // 暗号化されていないシークレットキーパケットを作成

                val keyData = this.getKeyData()

                var checkSum = 0

                for( i in keyData.indices) {
                    checkSum = (keyData[i].toUByte().toInt() + checkSum) % 65536
                }

                return byteArrayOf(
                    *this.publicKey.encoded,
                    OpenPGPS2K.S2KUSAGE_UNPROTECTED.toByte(),
                    *keyData,
                    (checkSum ushr 8).toByte(),
                    (checkSum and 0xFF).toByte()
                )
            }
            else{
                return byteArrayOf(
                    *this.publicKey.encoded,
                    *this.secretKeyData
                )
            }
        }



    /**
     * 秘密鍵を取得する
     * @param passPhrase パスフレーズ
     * @return 秘密鍵
     * @throws Error 秘密鍵データがnullの場合
     * @throws IllegalArgumentException パスフレーズが間違っている場合
     */
    @Throws(Error::class, IllegalArgumentException::class)
    fun getSecretKey(passPhrase: ByteArray? = null): PrivateKey{
        if(this.secretKey != null){
            return this.secretKey
        }

        if(this.secretKeyData == null){
            throw Error("Secret key data is null, cannot get secret key")
        }

        val byteStream = ByteArrayInputStream(this.secretKeyData)
        val dataInputStream = DataInputStream(byteStream)

        val s2kUsage = dataInputStream.readUnsignedByte()

        if(s2kUsage == OpenPGPS2K.S2KUSAGE_UNPROTECTED){
            // 暗号化されていない鍵

            val keyData = ByteArray(dataInputStream.available() - 2) // 最後の2バイトはチェックサム
            dataInputStream.readFully(keyData)
            val checkSum = dataInputStream.readUnsignedShort()

            var tmp: Int = 0
            for( i in keyData.indices) {
                tmp = (keyData[i].toUByte().toInt() + tmp) % 65536
            }

            if( tmp != checkSum ){
                throw IllegalArgumentException("Checksum mismatch: expected $checkSum, got $tmp")
            }

            return bytesToPrivateKey(this.keyAlgo, ByteArrayInputStream(keyData))
        }

        if(passPhrase == null){
            throw IllegalArgumentException("Passphrase is required")
        }


        val length = if(this.publicKey.keyVertion == 6 ){
            dataInputStream.readUnsignedByte()
        }
        else{
            0
        }

        val encryptionAlgo =
            if( s2kUsage == OpenPGPS2K.S2KUSAGE_AEAD || s2kUsage == OpenPGPS2K.S2KUSAGE_CFB || s2kUsage == OpenPGPS2K.S2KUSAGE_MALLEABLE_CFB ){
                val tag = dataInputStream.readUnsignedByte()
                OpenPGPSymmetricKeyAlgorithm.getKeyAlgorithmByTag(tag)
            }
            else{
                OpenPGPSymmetricKeyAlgorithm.getKeyAlgorithmByTag(s2kUsage)
            }

        if( s2kUsage == OpenPGPS2K.S2KUSAGE_AEAD ){
            TODO("AEAD encryption is not yet implemented")
        }

        if( publicKey.keyVertion == 6 && (s2kUsage == OpenPGPS2K.S2KUSAGE_AEAD || s2kUsage == OpenPGPS2K.S2KUSAGE_CFB) ){
            val feldSize = dataInputStream.readUnsignedByte()
        }

        val key =
            if( s2kUsage == OpenPGPS2K.S2KUSAGE_AEAD || s2kUsage == OpenPGPS2K.S2KUSAGE_CFB || s2kUsage == OpenPGPS2K.S2KUSAGE_MALLEABLE_CFB ){
                val s2k = OpenPGPS2K.fromBytes(dataInputStream)
                s2k.getKey(passPhrase, encryptionAlgo)
            }
            else{
                passPhrase
            }

        if( s2kUsage == OpenPGPS2K.S2KUSAGE_AEAD ){
            TODO("AEAD encryption is not yet implemented")
        }

        val iv = if(s2kUsage != OpenPGPS2K.S2KUSAGE_AEAD){
            val blockSize = (encryptionAlgo.blockSize + 7) / 8
            dataInputStream.readNBytes(blockSize)
        } else {
            ByteArray(0) // AEAD does not use IV in the same way
        }

        val keyData = dataInputStream.readAllBytes()

        val decryptedKey = encryptionAlgo.decrypt(
            keyData,
            key,
            iv
        )

        val rawKeyMaterial = decryptedKey.sliceArray(0 until decryptedKey.size - 20) // 最後の20バイトはハッシュ値(SHA-1)
        val keyDigest = decryptedKey.sliceArray(decryptedKey.size - 20 until decryptedKey.size)

        // 与えられたハッシュ値と計算したハッシュ値が異なるときは、パスフレーズが間違っているか、鍵が破損している
        val rawKeyDigest = OpenPGPDigest.getInstance(OpenPGPDigest.SHA1).digest(rawKeyMaterial)
        if(!keyDigest.contentEquals(rawKeyDigest)){
            throw IllegalArgumentException("Key or passphrase is incorrect")
        }

        return bytesToPrivateKey(this.keyAlgo, ByteArrayInputStream(rawKeyMaterial))
    }

    private fun getKeyData(): ByteArray{
        if(this.secretKey == null){
            throw Error("Secret key data is null, cannot get key data")
        }

        when(this.keyAlgo){
            OpenPGPPublicKeyAlgorithms.RSA_GENERAL -> {
                TODO("RSA is not supported yet")
            }
            OpenPGPPublicKeyAlgorithms.DSA -> {
                TODO("DSA is not supported yet")
            }
            OpenPGPPublicKeyAlgorithms.ELGAMAL_ENCRYPT -> {
                TODO("ELGAMAL_ENCRYPT is not supported yet")
            }
            OpenPGPPublicKeyAlgorithms.ECDSA -> {
                TODO("ECDSA is not supported yet")
            }
            OpenPGPPublicKeyAlgorithms.ECDH -> {
                TODO("ECDH is not supported yet")
            }
            OpenPGPPublicKeyAlgorithms.EDDSA_LEGACY -> {
                val rawKeyData = this.secretKey.encoded.sliceArray((this.secretKey.encoded.size) - 32 until this.secretKey.encoded.size)
                return OpenPGPUtil.toMPI(rawKeyData)
            }
            OpenPGPPublicKeyAlgorithms.X25519 -> {
                TODO("X25519 is not supported yet")
            }
            OpenPGPPublicKeyAlgorithms.X448 -> {
                TODO("X448 is not supported yet")
            }
            OpenPGPPublicKeyAlgorithms.Ed25519 -> {
                TODO("Ed25519 is not supported yet")
            }
            OpenPGPPublicKeyAlgorithms.Ed448 -> {
                TODO("Ed448 is not supported yet")
            }
            else -> {
                throw IllegalArgumentException("Unsupported algorithm: $keyAlgo")
            }
        }
    }

    companion object{
        fun fromBytes( body: ByteArray):SecretKey{
            val dataInputStream = DataInputStream(ByteArrayInputStream(body))

            val publicKey = PublicKey.fromBytes(dataInputStream)
            val secretKeyData = dataInputStream.readAllBytes()

            return SecretKey(publicKey, secretKeyData)
        }

        fun bytesToPrivateKey(algorithm: Int, bytes: ByteArrayInputStream): PrivateKey {
            return this.bytesToPrivateKey(algorithm, DataInputStream(bytes))
        }

        fun bytesToPrivateKey(algorithm: Int, dataInputStream: DataInputStream): PrivateKey {
            when(algorithm){
                OpenPGPPublicKeyAlgorithms.RSA_GENERAL -> {
                    TODO("RSA_GENERAL is not supported yet")
                }
                OpenPGPPublicKeyAlgorithms.DSA -> {
                    TODO("DSA is not supported yet")
                }
                OpenPGPPublicKeyAlgorithms.ELGAMAL_ENCRYPT -> {
                    TODO("ELGAMAL_ENCRYPT is not supported yet")
                }
                OpenPGPPublicKeyAlgorithms.ECDSA -> {
                    TODO("ECDSA is not supported yet")
                }
                OpenPGPPublicKeyAlgorithms.ECDH -> {
                    TODO("ECDH is not supported yet")
                }
                OpenPGPPublicKeyAlgorithms.EDDSA_LEGACY -> {
                    val mpi = OpenPGPUtil.readMPI(dataInputStream)
                    val ed25519Seed = mpi.toByteArray()

                    val keyPair = OpenPGPUtil.getKeyPairFromEd25519Secret(ed25519Seed)

                    return keyPair.private
                }
                OpenPGPPublicKeyAlgorithms.X25519 -> {
                    TODO("X25519 is not supported yet")
                }
                OpenPGPPublicKeyAlgorithms.X448 -> {
                    TODO("X448 is not supported yet")
                }
                OpenPGPPublicKeyAlgorithms.Ed25519 -> {
                    TODO("Ed25519 is not supported yet")
                }
                OpenPGPPublicKeyAlgorithms.Ed448 -> {
                    TODO("Ed448 is not supported yet")
                }
                else -> {
                    throw IllegalArgumentException("Unsupported algorithm: $algorithm")
                }
            }
        }
    }
}