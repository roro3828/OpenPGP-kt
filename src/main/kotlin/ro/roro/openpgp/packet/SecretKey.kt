package ro.roro.openpgp.packet

import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.crypto.hpke.AEAD
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.jce.provider.BouncyCastleProvider
import ro.roro.openpgp.OpenPGPAEAD
import ro.roro.openpgp.OpenPGPDigest
import ro.roro.openpgp.OpenPGPS2K
import ro.roro.openpgp.OpenPGPSymmetricKeyAlgorithm
import ro.roro.openpgp.OpenPGPUtil
import java.io.ByteArrayInputStream
import java.io.DataInputStream
import java.security.KeyFactory
import java.security.KeyPair
import java.security.PrivateKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Calendar

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
        require(version == 4 || version == 6){ "This library only supports generating version 4 or 6 keys"}


        this.publicKey = PublicKey(
            version,
            creationTime,
            keyAlgo,
            keyPair.public
        )

        this.secretKeyData = null
        this.secretKey = keyPair.private
    }
    /**
     * 秘密鍵を作成する
     * @param creationTime 鍵の作成時間
     * @param keyAlgo 鍵のアルゴリズム (OpenPGPPublicKeyAlgorithms)
     * @param keyPair 鍵ペア
     * @param version 鍵のバージョン (デフォルト: 6)
     */
    constructor(
        creationTime: Calendar,
        keyAlgo: Int,
        keyPair: KeyPair,
        version: Int = 6
    ){
        require(version == 4 || version == 6){ "This library only supports generating version 4 or 6 keys"}


        this.publicKey = PublicKey(
            version,
            creationTime,
            keyAlgo,
            keyPair.public
        )

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

        val rawKeyMaterial = this.getKeyData(passPhrase)

        return bytesToPrivateKey(this.keyAlgo, ByteArrayInputStream(rawKeyMaterial))
    }

    /**
     * 暗号化されていない秘密鍵の生データを取得する
     */
    fun getKeyData(passPhrase: ByteArray? = null): ByteArray{
        if(this.secretKey != null) {
            when (this.keyAlgo) {
                PublicKey.RSA_GENERAL -> {
                    TODO("RSA is not supported yet")
                }

                PublicKey.DSA -> {
                    TODO("DSA is not supported yet")
                }

                PublicKey.ELGAMAL_ENCRYPT -> {
                    TODO("ELGAMAL_ENCRYPT is not supported yet")
                }

                PublicKey.ECDSA -> {
                    TODO("ECDSA is not supported yet")
                }

                PublicKey.ECDH -> {
                    TODO("ECDH is not supported yet")
                }

                PublicKey.EDDSA_LEGACY -> {
                    val encodedSize = this.secretKey.encoded.size
                    val rawKeyData =
                        this.secretKey.encoded.sliceArray((encodedSize - ED25519_PRIVATE_KEY_LENGTH) until encodedSize)
                    return OpenPGPUtil.toMPI(rawKeyData)
                }

                PublicKey.X25519 -> {
                    val encodedSize = this.secretKey.encoded.size
                    return this.secretKey.encoded.sliceArray((encodedSize - X25519_PRIVATE_KEY_LENGTH) until encodedSize)
                }

                PublicKey.X448 -> {
                    TODO("X448 is not supported yet")
                }

                PublicKey.Ed25519 -> {
                    val encodedSize = this.secretKey.encoded.size
                    return this.secretKey.encoded.sliceArray((encodedSize - ED25519_PRIVATE_KEY_LENGTH) until encodedSize)
                }

                PublicKey.Ed448 -> {
                    TODO("Ed448 is not supported yet")
                }

                else -> {
                    throw IllegalArgumentException("Unsupported algorithm: $keyAlgo")
                }
            }
        }
        if(this.secretKeyData == null){
            throw Error("Secret key data is null, cannot get secret key")
        }

        val byteStream = ByteArrayInputStream(this.secretKeyData)
        val dataInputStream = DataInputStream(byteStream)

        val s2kUsage = dataInputStream.readUnsignedByte()

        if(s2kUsage == OpenPGPS2K.S2KUSAGE_UNPROTECTED){
            // 暗号化されていない鍵

            val keyData = when(this.keyVertion){
                //3 4の場合、最後の2バイトがチェックサム
                3, 4 -> {
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

                    keyData
                }
                6 -> {
                    dataInputStream.readAllBytes()
                }
                else -> {
                    throw IllegalArgumentException("Unsupported key version: $keyVertion")
                }
            }

            return keyData
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
                OpenPGPSymmetricKeyAlgorithm(tag, BouncyCastleProvider())
            }
            else{
                OpenPGPSymmetricKeyAlgorithm(s2kUsage, BouncyCastleProvider())
            }

        val aeadAlgo = if( s2kUsage == OpenPGPS2K.S2KUSAGE_AEAD ){
            dataInputStream.readUnsignedByte()
        }
        else{
            -1
        }

        val fieldSize = if( publicKey.keyVertion == 6 && (s2kUsage == OpenPGPS2K.S2KUSAGE_AEAD || s2kUsage == OpenPGPS2K.S2KUSAGE_CFB) ){
            val size = dataInputStream.readUnsignedByte()

            size
        }
        else{
            -1
        }

        val key =
            if( s2kUsage == OpenPGPS2K.S2KUSAGE_AEAD || s2kUsage == OpenPGPS2K.S2KUSAGE_CFB || s2kUsage == OpenPGPS2K.S2KUSAGE_MALLEABLE_CFB ){
                val s2k = OpenPGPS2K.fromBytes(dataInputStream)
                s2k.getKey(passPhrase, encryptionAlgo)
            }
            else{
                passPhrase
            }

        val iv = when(s2kUsage){
            OpenPGPS2K.S2KUSAGE_AEAD -> {
                val nonceLength = OpenPGPAEAD.getNonceLength(aeadAlgo)
                dataInputStream.readNBytes(nonceLength)
            }
            else -> {
                val blockSize = (encryptionAlgo.blockSize + 7) / 8
                dataInputStream.readNBytes(blockSize)
            }
        }

        val keyData = dataInputStream.readAllBytes()

        return if( s2kUsage == OpenPGPS2K.S2KUSAGE_AEAD ) {
            require(encryptionAlgo.standardAlgorithmName == OpenPGPSymmetricKeyAlgorithm.AES_STANDARD_NAME) { "AEAD is only supported with AES" }


            val aeadCipher = OpenPGPAEAD(aeadAlgo)

            val packetHeader = byteArrayOf((0b11000000 or this.packetType).toByte())

            val hkdf = aeadCipher.hkdfExpand(key, packetHeader + byteArrayOf(this.keyVertion.toByte(), encryptionAlgo.algorithm.toByte(), aeadAlgo.toByte()), 32)

            val associatedData = packetHeader + this.publicKey.encoded

            aeadCipher.decrypt(
                keyData,
                hkdf,
                iv,
                associatedData
            )

        }
        else{
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

            rawKeyMaterial
        }
    }

    companion object{
        const val ED25519_PRIVATE_KEY_LENGTH = 32
        const val ED448_PRIVATE_KEY_LENGTH = 57
        const val X25519_PRIVATE_KEY_LENGTH = 32
        const val X448_PRIVATE_KEY_LENGTH = 56



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
                PublicKey.RSA_GENERAL -> {
                    TODO("RSA_GENERAL is not supported yet")
                }
                PublicKey.DSA -> {
                    TODO("DSA is not supported yet")
                }
                PublicKey.ELGAMAL_ENCRYPT -> {
                    TODO("ELGAMAL_ENCRYPT is not supported yet")
                }
                PublicKey.ECDSA -> {
                    TODO("ECDSA is not supported yet")
                }
                PublicKey.ECDH -> {
                    TODO("ECDH is not supported yet")
                }
                PublicKey.EDDSA_LEGACY -> {
                    val mpi = OpenPGPUtil.readMPI(dataInputStream)
                    val ed25519Seed = mpi.toByteArray()

                    val keyPair = getEd25519KeyPair(ed25519Seed)

                    return keyPair.private
                }
                PublicKey.X25519 -> {
                    val x25519Seed = dataInputStream.readNBytes(X25519_PRIVATE_KEY_LENGTH)
                    val keyPair = getX25519KeyPair(x25519Seed)
                    return keyPair.private
                }
                PublicKey.X448 -> {
                    TODO("X448 is not supported yet")
                }
                PublicKey.Ed25519 -> {
                    val ed25519Seed = dataInputStream.readNBytes(ED25519_PRIVATE_KEY_LENGTH)

                    val keyPair = getEd25519KeyPair(ed25519Seed)
                    return keyPair.private
                }
                PublicKey.Ed448 -> {
                    TODO("Ed448 is not supported yet")
                }
                else -> {
                    throw IllegalArgumentException("Unsupported algorithm: $algorithm")
                }
            }
        }

        /**
         * 32ByteのEd25519秘密鍵からKeyPairを生成
         */
        fun getEd25519KeyPair(bytes: ByteArray): KeyPair {
            require(bytes.size == ED25519_PRIVATE_KEY_LENGTH) { "Ed25519 private key must be $ED25519_PRIVATE_KEY_LENGTH bytes long" }

            // 1. BouncyCastleの低レベルAPIを使用して秘密鍵パラメータと公開鍵パラメータを取得
            val privateKeyParams = Ed25519PrivateKeyParameters(bytes, 0)
            val publicKeyParams = privateKeyParams.generatePublicKey()

            // 2. KeyFactoryをBouncyCastleプロバイダで取得
            // "Ed25519" または "EdDSA" がアルゴリズム名として利用可能
            val keyFactory = KeyFactory.getInstance("Ed25519", BouncyCastleProvider())

            // 3. PrivateKeyオブジェクトを生成
            // RFC 8410 によると、Ed25519のPrivateKeyInfoでは、privateKeyオクテット文字列が直接シードを格納します。
            val privateKeyAlgorithmIdentifier =
                AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519)
            val pkInfo = PrivateKeyInfo(privateKeyAlgorithmIdentifier, DEROctetString(bytes))
            val pkcs8Spec = PKCS8EncodedKeySpec(pkInfo.encoded) // PKCS#8形式にエンコード
            val privateKey = keyFactory.generatePrivate(pkcs8Spec)

            // 4. PublicKeyオブジェクトを生成
            // Ed25519の公開鍵(32バイト)をX.509 SubjectPublicKeyInfo形式にエンコード
            val publicKeyAlgorithmIdentifier = AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519)
            // publicKeyParams.encoded は生の32バイト公開鍵を返します
            val spki = SubjectPublicKeyInfo(publicKeyAlgorithmIdentifier, publicKeyParams.encoded)
            val x509Spec = X509EncodedKeySpec(spki.encoded) // X.509形式にエンコード
            val publicKey = keyFactory.generatePublic(x509Spec)


            // 5. KeyPairオブジェクトを作成して返す
            val keyPair = KeyPair(publicKey, privateKey)
            return keyPair
        }

        /**
         * 32ByteのX25519秘密鍵からKeyPairを生成
         */
        fun getX25519KeyPair(bytes: ByteArray): KeyPair {
            require(bytes.size == X25519_PRIVATE_KEY_LENGTH) {"X25519 private} key must be $X25519_PRIVATE_KEY_LENGTH bytes long" }

            // 1. BouncyCastleの低レベルAPIを使用して秘密鍵パラメータと公開鍵パラメータを取得
            val privateKeyParams = X25519PrivateKeyParameters(bytes, 0)
            val publicKeyParams = privateKeyParams.generatePublicKey()

            // 2. KeyFactoryをBouncyCastleプロバイダで取得
            val keyFactory = KeyFactory.getInstance("X25519", BouncyCastleProvider())

            // 3. PrivateKeyオブジェクトを生成
            val privateKeyAlgorithmIdentifier =
                AlgorithmIdentifier(EdECObjectIdentifiers.id_X25519)
            val pkInfo = PrivateKeyInfo(privateKeyAlgorithmIdentifier, DEROctetString(bytes))
            val pkcs8Spec = PKCS8EncodedKeySpec(pkInfo.encoded) // PKCS#8形式にエンコード
            val privateKey = keyFactory.generatePrivate(pkcs8Spec)

            // 4. PublicKeyオブジェクトを生成
            val publicKeyAlgorithmIdentifier = AlgorithmIdentifier(EdECObjectIdentifiers.id_X25519)
            // publicKeyParams.encoded は生の32バイト公開鍵を返します
            val spki = SubjectPublicKeyInfo(publicKeyAlgorithmIdentifier, publicKeyParams.encoded)
            val x509Spec = X509EncodedKeySpec(spki.encoded) // X.509形式にエンコード
            val publicKey = keyFactory.generatePublic(x509Spec)


            // 5. KeyPairオブジェクトを作成して返す
            val keyPair = KeyPair(publicKey, privateKey)
            return keyPair
        }
    }
}