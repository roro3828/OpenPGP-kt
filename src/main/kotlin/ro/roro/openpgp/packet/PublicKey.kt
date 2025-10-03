package ro.roro.openpgp.packet

import org.bouncycastle.asn1.edec.EdECObjectIdentifiers
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.jce.provider.BouncyCastleProvider
import ro.roro.openpgp.OpenPGPDigest
import ro.roro.openpgp.OpenPGPECCCurveOIDs
import ro.roro.openpgp.OpenPGPUtil
import ro.roro.openpgp.packet.signature.Signature
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.security.InvalidKeyException
import java.security.KeyFactory
import java.security.interfaces.RSAPublicKey
import java.security.spec.RSAPublicKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Calendar

/**
 *    +===+==============+=========+============+===========+=============+
 *    | ID| Algorithm    |Public   | Secret Key | Signature | PKESK       |
 *    |   |              |Key      | Format     | Format    | Format      |
 *    |   |              |Format   |            |           |             |
 *    +===+==============+=========+============+===========+=============+
 *    |  0| Reserved     |         |            |           |             |
 *    +---+--------------+---------+------------+-----------+-------------+
 *    |  1| RSA (Encrypt |MPI(n),  | MPI(d),    | MPI(m^d   | MPI(m^e     |
 *    |   | or Sign)     |MPI(e)   | MPI(p),    | mod n)    | mod n)      |
 *    |   | [FIPS186]    |[Section | MPI(q),    | [Section  | [Section    |
 *    |   |              |5.5.5.1] | MPI(u)     | 5.2.3.1]  | 5.1.3]      |
 *    +---+--------------+---------+------------+-----------+-------------+
 *    |  2| RSA Encrypt- |MPI(n),  | MPI(d),    | N/A       | MPI(m^e     |
 *    |   | Only         |MPI(e)   | MPI(p),    |           | mod n)      |
 *    |   | [FIPS186]    |[Section | MPI(q),    |           | [Section    |
 *    |   |              |5.5.5.1] | MPI(u)     |           | 5.1.3]      |
 *    +---+--------------+---------+------------+-----------+-------------+
 *    |  3| RSA Sign-    |MPI(n),  | MPI(d),    | MPI(m^d   | N/A         |
 *    |   | Only         |MPI(e)   | MPI(p),    | mod n)    |             |
 *    |   | [FIPS186]    |[Section | MPI(q),    | [Section  |             |
 *    |   |              |5.5.5.1] | MPI(u)     | 5.2.3.1]  |             |
 *    +---+--------------+---------+------------+-----------+-------------+
 *    | 16| Elgamal      |MPI(p),  | MPI(x)     | N/A       | MPI(g^k     |
 *    |   | (Encrypt-    |MPI(g),  |            |           | mod p),     |
 *    |   | Only)        |MPI(y)   |            |           | MPI(m *     |
 *    |   | [ELGAMAL]    |[Section |            |           | y^k mod     |
 *    |   |              |5.5.5.3] |            |           | p)          |
 *    |   |              |         |            |           | [Section    |
 *    |   |              |         |            |           | 5.1.4]      |
 *    +---+--------------+---------+------------+-----------+-------------+
 *    | 17| DSA (Digital |MPI(p),  | MPI(x)     | MPI(r),   | N/A         |
 *    |   | Signature    |MPI(q),  |            | MPI(s)    |             |
 *    |   | Algorithm)   |MPI(g),  |            | [Section  |             |
 *    |   | [FIPS186]    |MPI(y)   |            | 5.2.3.2]  |             |
 *    |   |              |[Section |            |           |             |
 *    |   |              |5.5.5.2] |            |           |             |
 *    +---+--------------+---------+------------+-----------+-------------+
 *    | 18| ECDH public  |OID,     | MPI(value  | N/A       | MPI(point   |
 *    |   | key          |MPI(point| in curve-  |           | in curve-   |
 *    |   | algorithm    |in curve-| specific   |           | specific    |
 *    |   |              |specific | format)    |           | point       |
 *    |   |              |point    | [Section   |           | format),    |
 *    |   |              |format), | 9.2.1]     |           | size        |
 *    |   |              |KDFParams|            |           | octet,      |
 *    |   |              |[Sections|            |           | encoded     |
 *    |   |              |9.2.1 and|            |           | key         |
 *    |   |              |5.5.5.6] |            |           | [Sections   |
 *    |   |              |         |            |           | 9.2.1,      |
 *    |   |              |         |            |           | 5.1.5,      |
 *    |   |              |         |            |           | and 11.5]   |
 *    +---+--------------+---------+------------+-----------+-------------+
 *    | 19| ECDSA public |OID,     | MPI(value) | MPI(r),   | N/A         |
 *    |   | key          |MPI(point|            | MPI(s)    |             |
 *    |   | algorithm    |in SEC1  |            | [Section  |             |
 *    |   | [FIPS186]    |format)  |            | 5.2.3.2]  |             |
 *    |   |              |[Section |            |           |             |
 *    |   |              |5.5.5.4] |            |           |             |
 *    +---+--------------+---------+------------+-----------+-------------+
 *    | 20| Reserved     |         |            |           |             |
 *    |   | (formerly    |         |            |           |             |
 *    |   | Elgamal      |         |            |           |             |
 *    |   | Encrypt or   |         |            |           |             |
 *    |   | Sign)        |         |            |           |             |
 *    +---+--------------+---------+------------+-----------+-------------+
 *    | 21| Reserved for |         |            |           |             |
 *    |   | Diffie-      |         |            |           |             |
 *    |   | Hellman      |         |            |           |             |
 *    |   | (X9.42, as   |         |            |           |             |
 *    |   | defined for  |         |            |           |             |
 *    |   | IETF-S/MIME) |         |            |           |             |
 *    +---+--------------+---------+------------+-----------+-------------+
 *    | 22| EdDSALegacy  |OID,     | MPI(value  | MPI, MPI  | N/A         |
 *    |   | (deprecated) |MPI(point| in curve-  | [Sections |             |
 *    |   |              |in       | specific   | 9.2.1 and |             |
 *    |   |              |prefixed | format)    | 5.2.3.3]  |             |
 *    |   |              |native   | [Section   |           |             |
 *    |   |              |format)  | 9.2.1]     |           |             |
 *    |   |              |[Sections|            |           |             |
 *    |   |              |11.2.2   |            |           |             |
 *    |   |              |and      |            |           |             |
 *    |   |              |5.5.5.5] |            |           |             |
 *    +---+--------------+---------+------------+-----------+-------------+
 *    | 23| Reserved     |         |            |           |             |
 *    |   | (AEDH)       |         |            |           |             |
 *    +---+--------------+---------+------------+-----------+-------------+
 *    | 24| Reserved     |         |            |           |             |
 *    |   | (AEDSA)      |         |            |           |             |
 *    +---+--------------+---------+------------+-----------+-------------+
 *    | 25| X25519       |32 octets| 32 octets  | N/A       | 32          |
 *    |   |              |[Section |            |           | octets,     |
 *    |   |              |5.5.5.7] |            |           | size        |
 *    |   |              |         |            |           | octet,      |
 *    |   |              |         |            |           | encoded     |
 *    |   |              |         |            |           | key         |
 *    |   |              |         |            |           | [Section    |
 *    |   |              |         |            |           | 5.1.6]      |
 *    +---+--------------+---------+------------+-----------+-------------+
 *    | 26| X448         |56 octets| 56 octets  | N/A       | 56          |
 *    |   |              |[Section |            |           | octets,     |
 *    |   |              |5.5.5.8] |            |           | size        |
 *    |   |              |         |            |           | octet,      |
 *    |   |              |         |            |           | encoded     |
 *    |   |              |         |            |           | key         |
 *    |   |              |         |            |           | [Section    |
 *    |   |              |         |            |           | 5.1.7]      |
 *    +---+--------------+---------+------------+-----------+-------------+
 *    | 27| Ed25519      |32 octets| 32 octets  | 64 octets |             |
 *    |   |              |[Section |            | [Section  |             |
 *    |   |              |5.5.5.9] |            | 5.2.3.4]  |             |
 *    +---+--------------+---------+------------+-----------+-------------+
 *    | 28| Ed448        |57 octets| 57 octets  | 114       |             |
 *    |   |              |[Section |            | octets    |             |
 *    |   |              |5.5.5.10]|            | [Section  |             |
 *    |   |              |         |            | 5.2.3.5]  |             |
 *    +---+--------------+---------+------------+-----------+-------------+
 *    |100| Private or   |         |            |           |             |
 *    | to| Experimental |         |            |           |             |
 *    |110| Use          |         |            |           |             |
 *    +---+--------------+---------+------------+-----------+-------------+
 */

open class PublicKey:OpenPGPPacket {
    override val packetType = OpenPGPPacket.PUBLIC_KEY

    /**
     * 鍵バージョン
     * 3か4か6
     * 推奨 : 6
     */
    val keyVertion: Int

    /**
     * 鍵が作成された時間
     */
    val creationTime: Int

    /**
     * 鍵の有効期限
     * 単位は日
     * 0の場合は無期限
     * バージョン2か3でのみ使われる
     */
    val validDays: Short

    /**
     * 鍵のアルゴリズム
     */
    val keyAlgo: Int

    /**
     * 公開鍵
     */
    val key:java.security.PublicKey

    /**
     * 鍵バージョン3のコンストラクタ
     * @param creationTime 鍵が作成された時間
     * @param validDays 鍵の有効期限 (単位は日)
     * @param keyAlgo 鍵のアルゴリズム
     * @param key 公開鍵
     */
    protected constructor(
        creationTime: Calendar,
        validDays: Short,
        keyAlgo: Int,
        key: java.security.PublicKey
    ){
        this.keyVertion = 3
        this.creationTime = (creationTime.timeInMillis / 1000).toInt()
        this.validDays = validDays
        this.keyAlgo = keyAlgo
        this.key = key
        require(isAlgorithmMatch(this.keyAlgo, this.key.algorithm)) {
            "keyAlgo ${this.keyAlgo} does not match key algorithm ${this.key.algorithm}"
        }

        require(keyAlgo == RSA_GENERAL || keyAlgo == RSA_SIGN_ONLY || keyAlgo == RSA_ENCRYPT_ONLY) {
            "For key version 3, only RSA algorithms (1, 2, 3) are supported. Provided: $keyAlgo"
        }
    }
    /**
     * 鍵バージョン3のコンストラクタ
     * @param creationTime 鍵が作成された時間
     * @param validDays 鍵の有効期限 (単位は日)
     * @param keyAlgo 鍵のアルゴリズム
     * @param key 公開鍵
     */
    protected constructor(
        creationTime: Int,
        validDays: Short,
        keyAlgo: Int,
        key: java.security.PublicKey
    ){
        this.keyVertion = 3
        this.creationTime = creationTime
        this.validDays = validDays
        this.keyAlgo = keyAlgo
        this.key = key
        require(isAlgorithmMatch(this.keyAlgo, this.key.algorithm)) {
            "keyAlgo ${this.keyAlgo} does not match key algorithm ${this.key.algorithm}"
        }

        require(keyAlgo == RSA_GENERAL || keyAlgo == RSA_SIGN_ONLY || keyAlgo == RSA_ENCRYPT_ONLY) {
            "For key version 3, only RSA algorithms (1, 2, 3) are supported. Provided: $keyAlgo"
        }
    }

    /**
     * 鍵バージョン4か6のコンストラクタ
     * @param version 鍵バージョン (4か6)
     * @param creationTime 鍵が作成された時間
     * @param keyAlgo 鍵のアルゴリズム
     * @param key 公開鍵
     */
    constructor(
        version: Int,
        creationTime: Calendar,
        keyAlgo: Int,
        key: java.security.PublicKey
    ){
        this.keyVertion = version
        this.creationTime = (creationTime.timeInMillis / 1000).toInt()
        this.keyAlgo = keyAlgo
        this.key = key
        this.validDays = 0
        require(isAlgorithmMatch(this.keyAlgo, this.key.algorithm)) {
            "keyAlgo ${this.keyAlgo} does not match key algorithm ${this.key.algorithm}"
        }
        require(this.keyVertion == 4 || this.keyVertion == 6) {
            "Only key versions 4 and 6 are supported in this constructor. Provided: $version"
        }
    }
    /**
     * 鍵バージョン4か6のコンストラクタ
     * @param version 鍵バージョン (4か6)
     * @param creationTime 鍵が作成された時間
     * @param keyAlgo 鍵のアルゴリズム
     * @param key 公開鍵
     */
    constructor(
        version: Int,
        creationTime: Int,
        keyAlgo: Int,
        key: java.security.PublicKey
    ){
        this.keyVertion = version
        this.creationTime = creationTime
        this.keyAlgo = keyAlgo
        this.key = key
        this.validDays = 0
        require(isAlgorithmMatch(this.keyAlgo, this.key.algorithm)) {
            "keyAlgo ${this.keyAlgo} does not match key algorithm ${this.key.algorithm}"
        }
        require(this.keyVertion == 4 || this.keyVertion == 6) {
            "Only key versions 4 and 6 are supported in this constructor. Provided: $version"
        }
    }


    override val encoded: ByteArray
        get(){
            val bytes = ByteArrayOutputStream()
            val dataOutput = DataOutputStream(bytes)
            when(this.keyVertion){
                3->{
                    dataOutput.writeByte(this.keyVertion)
                    dataOutput.writeInt(this.creationTime)
                    dataOutput.writeShort(this.validDays.toInt())
                    dataOutput.writeByte(this.keyAlgo)
                    dataOutput.write( getKeyMaterial() )
                }
                4->{
                    dataOutput.writeByte(this.keyVertion)
                    dataOutput.writeInt(this.creationTime)
                    dataOutput.writeByte(this.keyAlgo)
                    dataOutput.write( getKeyMaterial() )
                }
                6->{
                    val keyMaterial = getKeyMaterial()
                    val keyMaterialLen = keyMaterial.size
                    dataOutput.writeByte(this.keyVertion)
                    dataOutput.writeInt(this.creationTime)
                    dataOutput.writeByte(this.keyAlgo)
                    dataOutput.writeInt(keyMaterialLen)
                    dataOutput.write( keyMaterial )
                }
                else -> {
                    throw IllegalArgumentException("version must be 3,4 or 6")
                }
            }

            return bytes.toByteArray()
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
        get(){
            when(this.keyVertion){
                3 -> {
                    val rsaKey = this.key as RSAPublicKey
                    val md5 = OpenPGPDigest.getInstance(OpenPGPDigest.MD5)

                    md5.write(rsaKey.modulus.toByteArray())
                    md5.write(rsaKey.publicExponent.toByteArray())

                    val hashedData = md5.digest()

                    return hashedData
                }
                4 -> {
                    val sha1 = OpenPGPDigest.getInstance(OpenPGPDigest.SHA1)
                    sha1.write(Signature.createKeySignatureData(this))

                    val hashedData = sha1.digest()

                    return hashedData
                }
                6 -> {
                    val sha256 = OpenPGPDigest.getInstance(OpenPGPDigest.SHA256)
                    sha256.write(Signature.createKeySignatureData(this))

                    val hashedData = sha256.digest()

                    return hashedData
                }
                else -> {
                    throw IllegalArgumentException("version must be 3,4 or 6")
                }
            }
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
        get(){
            when(this.keyVertion){
                3 -> {
                    val rsaKey = this.key as RSAPublicKey
                    // modulusの下位64bitをkeyIDとする
                    val keyID = rsaKey.modulus.toByteArray()

                    return keyID.sliceArray(keyID.size-8 until keyID.size)
                }
                4 -> {
                    val fingerprint = this.fingerprint
                    // fingerPrintの下位64bitをkeyIDとする
                    return fingerprint.sliceArray(fingerprint.size-8 until fingerprint.size)
                }
                6 -> {
                    val fingerprint = this.fingerprint
                    // fingerPrintの上位64bitをkeyIDとする
                    return fingerprint.sliceArray(0 until 8)
                }
                else -> {
                    throw IllegalArgumentException("version must be 3,4 or 6")
                }
            }
        }

    /**
     * 鍵データのデータを取得
     * @throws IllegalArgumentException 鍵のアルゴリズムがサポートされていない場合
     */
    @Throws(IllegalArgumentException::class)
    private fun getKeyMaterial(): ByteArray{
        when(this.keyAlgo){
            RSA_GENERAL -> {
                val rsaKey = this.key as RSAPublicKey
                val modulus = rsaKey.modulus
                val exponent = rsaKey.publicExponent


                return byteArrayOf(
                    *OpenPGPUtil.toMPI( modulus ),
                    *OpenPGPUtil.toMPI( exponent )
                )
            }
            DSA -> {
                TODO("DSA is not supported yet")
            }
            ELGAMAL_ENCRYPT -> {
                TODO("ELGAMAL_ENCRYPT is not supported yet")
            }
            ECDSA -> {
                TODO("ECDSA is not supported yet")
            }
            ECDH -> {
                TODO("ECDH is not supported yet")
            }
            EDDSA_LEGACY -> {
                val outputStream = ByteArrayOutputStream()
                val dataOutputStream = DataOutputStream(outputStream)

                dataOutputStream.writeByte(OpenPGPECCCurveOIDs.ED25519_LEGACY.size)
                dataOutputStream.write(OpenPGPECCCurveOIDs.ED25519_LEGACY)

                // Ed25519の公開鍵は33バイトで、最初の1バイトは0x40
                val rawPublicKey = getRawEd25519PublicKey(this.key)
                val mpiBytes = byteArrayOf( ED25519_LEGACY_PUBLIC_KEY_PREFIX.toByte(), *rawPublicKey )
                val mpi = OpenPGPUtil.toMPI(mpiBytes)
                dataOutputStream.write( mpi )

                return outputStream.toByteArray()
            }
            X25519 -> {
                val x25519Key = this.key

                if( x25519Key.format != "X.509" ){
                    throw InvalidKeyException("X25519 key must be in X.509 format")
                }
                // X.509形式の公開鍵からrawな公開鍵を取り出す
                val spki = SubjectPublicKeyInfo.getInstance(x25519Key.encoded)

                val algoId = spki.algorithm

                if(EdECObjectIdentifiers.id_X25519 != algoId.algorithm){
                    throw InvalidKeyException("Not X25519 public key")
                }

                val subjectPublicKeyBitString = spki.publicKeyData
                val rawPublicKey = subjectPublicKeyBitString.bytes

                if(rawPublicKey.size != X25519_PUBLIC_KEY_LENGTH){
                    throw IllegalArgumentException("Invalid X25519 public key length: ${rawPublicKey.size}")
                }

                return rawPublicKey
            }
            X448 -> {
                TODO("X448 is not supported yet")
            }
            Ed25519 -> {
                return getRawEd25519PublicKey( this.key )
            }
            Ed448 -> {
                TODO("Ed448 is not supported yet")
            }
            else -> {
                throw IllegalArgumentException("Unsupported algorithm: $keyAlgo")
            }
        }
    }

    companion object: OpenPGPPacket.OpenPGPPacketCompanion<PublicKey>{

        const val RSA_GENERAL = 1
        const val RSA_ENCRYPT_ONLY = 2
        const val RSA_SIGN_ONLY = 3
        const val ELGAMAL_ENCRYPT = 16
        const val DSA = 17
        const val ECDH = 18
        const val ECDSA = 19
        const val EDDSA_LEGACY = 22
        const val X25519 = 25
        const val X448 = 26
        const val Ed25519 = 27
        const val Ed448 = 28

        const val ED25519_PUBLIC_KEY_LENGTH = 32
        const val ED25519_LEGACY_PUBLIC_KEY_PREFIX = 0x40
        const val ED448_PUBLIC_KEY_LENGTH = 57

        const val X25519_PUBLIC_KEY_LENGTH = 32
        const val X448_PUBLIC_KEY_LENGTH = 56


        /**
         * PublikKey Algorithm Tag とPublicKeyのアルゴリズム名が一致しているかどうか
         */
        fun isAlgorithmMatch(algorithmTag: Int, algorithmName: String): Boolean{
            return when(algorithmTag){
                RSA_GENERAL, RSA_ENCRYPT_ONLY, RSA_SIGN_ONLY -> algorithmName == "RSA"
                ELGAMAL_ENCRYPT -> algorithmName == "ElGamal"
                DSA -> algorithmName == "DSA"
                ECDH -> algorithmName == "ECDH"
                ECDSA -> algorithmName == "ECDSA"
                EDDSA_LEGACY, Ed25519 -> algorithmName == "Ed25519"
                X25519 -> algorithmName == "X25519"
                X448 -> algorithmName == "X448"
                Ed448 -> algorithmName == "Ed448"
                else -> false
            }
        }

        /**
         * バイト列からPublicKeyパケットへ変換する
         * @param body パケットヘッダーを含まないボディのみのデータ
         * @return PublicKey
         * @throws IllegalArgumentException versionが3,4,6以外の場合
         */
        @Throws(IllegalArgumentException::class)
        override fun fromBytes( body: ByteArray ):PublicKey{
            return fromBytes(ByteArrayInputStream(body) )
        }
        /**
         * バイト列からPublicKeyパケットへ変換する
         * @param body パケットヘッダーを含まないボディのみのデータ
         * @return PublicKey
         */
        @Throws(IllegalArgumentException::class)
        fun fromBytes( body: ByteArrayInputStream ):PublicKey{
            return fromBytes(DataInputStream(body) )
        }

        /**
         * バイト列からPublicKeyパケットへ変換する
         * @param body パケットヘッダーを含まないボディのみのデータ
         * @return PublicKey
         * @throws IllegalArgumentException versionが3,4,6以外の場合
         */
        @Throws(IllegalArgumentException::class)
        fun fromBytes( body: DataInputStream ):PublicKey{
            val version = body.readUnsignedByte()
            val creationTime = body.readInt()

            if( version == 3 ){
                val validDays = body.readUnsignedShort()
                val keyAlgo = body.readUnsignedByte()

                val key = bytesToPublicKey(keyAlgo, body )

                return PublicKey(creationTime, validDays.toShort(), keyAlgo, key)
            }
            else if( version == 4 ){
                val keyAlgo = body.readUnsignedByte()
                val key = bytesToPublicKey(keyAlgo, body )

                return PublicKey(4, creationTime, keyAlgo, key)
            }
            else if( version == 6 ){
                val keyAlgo = body.readUnsignedByte()
                val keyLen = body.readInt()
                //鍵の長さが合わないときエラー
                if( body.available() < keyLen ){
                    throw IllegalArgumentException("keyLen is not valid")
                }
                val key = bytesToPublicKey(keyAlgo, body )

                return PublicKey(6, creationTime, keyAlgo, key)
            }
            else{
                throw IllegalArgumentException("version must be 3,4 or 6")
            }
        }

        /**
         * フィンガープリントのサイズを取得する
         * @param version フィンガープリントのバージョン
         * @return フィンガープリントのサイズ（バイト単位）
         * @throws IllegalArgumentException versionが3,4,6以外の場合
         */
        @Throws(IllegalArgumentException::class)
        fun getFingerprintSize(version: Int): Int {
            return when (version) {
                3 -> 16 // MD5 fingerprint size
                4 -> 20 // SHA1 fingerprint size
                6 -> 32 // SHA256 fingerprint size
                else -> throw IllegalArgumentException("version must be 3,4 or 6")
            }
        }

        /**
         * フィンガープリントのバージョンを取得する
         * @param fingerprint フィンガープリントのバイト配列
         * @return フィンガープリントのバージョン
         * @throws IllegalArgumentException fingerprintのサイズが16,20,32以外の場合
         */
        @Throws(IllegalArgumentException::class)
        fun getFingerprintVersion(fingerprint: ByteArray): Int {
            return when (fingerprint.size) {
                16 -> 3 // MD5 fingerprint
                20 -> 4 // SHA1 fingerprint
                32 -> 6 // SHA256 fingerprint
                else -> throw IllegalArgumentException("Invalid fingerprint size: ${fingerprint.size}")
            }
        }

        /**
         * バイト列から公開鍵へ変換する
         */
        private fun bytesToPublicKey(algorithm: Int, bytes: ByteArrayInputStream): java.security.PublicKey {
            return bytesToPublicKey( algorithm, DataInputStream(bytes) )
        }

        @JvmStatic
        protected fun bytesToPublicKey(algorithm: Int, dataInputStream: DataInputStream): java.security.PublicKey {
            when(algorithm){
                RSA_GENERAL -> {
                    val modulus = OpenPGPUtil.readMPI(dataInputStream)

                    val exponent = OpenPGPUtil.readMPI(dataInputStream)

                    val keyFactory = KeyFactory.getInstance("RSA")
                    val publicKeySpec = RSAPublicKeySpec(modulus, exponent)

                    val rsaPublicKey = keyFactory.generatePublic(publicKeySpec) as RSAPublicKey

                    return rsaPublicKey
                }
                DSA -> {
                    TODO("DSA is not supported yet")
                }
                ELGAMAL_ENCRYPT -> {
                    TODO("ELGAMAL_ENCRYPT is not supported yet")
                }
                ECDSA -> {
                    TODO("ECDSA is not supported yet")
                }
                ECDH -> {
                    TODO("ECDH is not supported yet")
                }
                EDDSA_LEGACY -> {
                    val oidLen = dataInputStream.readUnsignedByte()
                    val oid = dataInputStream.readNBytes(oidLen)

                    if( !oid.contentEquals(OpenPGPECCCurveOIDs.ED25519_LEGACY) ){
                        throw IllegalArgumentException("Unsupported EDDSA_LEGACY OID: ${oid.joinToString(",")}")
                    }

                    val mpiLen = OpenPGPUtil.readMPILen(dataInputStream)

                    if( mpiLen != (ED25519_PUBLIC_KEY_LENGTH + 1) ){
                        throw IllegalArgumentException("EDDSA_LEGACY MPI length must be 33, but was $mpiLen")
                    }

                    val prefix = dataInputStream.readUnsignedByte()

                    if( prefix != ED25519_LEGACY_PUBLIC_KEY_PREFIX ){
                        throw IllegalArgumentException("EDDSA_LEGACY prefix must be 0x40, but was $prefix")
                    }

                    val rawPublicKey = dataInputStream.readNBytes(ED25519_PUBLIC_KEY_LENGTH)

                    val keyFactory = KeyFactory.getInstance("Ed25519", BouncyCastleProvider())

                    val publicKeyAlgorithmIdentifier = AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519)

                    val spki = SubjectPublicKeyInfo(publicKeyAlgorithmIdentifier, rawPublicKey)
                    val x509Spec = X509EncodedKeySpec(spki.encoded) // X.509形式にエンコード
                    val publicKey = keyFactory.generatePublic(x509Spec)

                    return publicKey
                }
                X25519 -> {
                    val rawPublicKey = dataInputStream.readNBytes(X25519_PUBLIC_KEY_LENGTH)

                    val keyFactory = KeyFactory.getInstance("X25519", BouncyCastleProvider())

                    val publicKeyAlgorithmIdentifier = AlgorithmIdentifier(EdECObjectIdentifiers.id_X25519)

                    val spki = SubjectPublicKeyInfo(publicKeyAlgorithmIdentifier, rawPublicKey)
                    val x509Spec = X509EncodedKeySpec(spki.encoded)
                    val publicKey = keyFactory.generatePublic(x509Spec)

                    return  publicKey
                }
                X448 -> {
                    val rawPublicKey = dataInputStream.readNBytes(X448_PUBLIC_KEY_LENGTH)
                    val keyFactory = KeyFactory.getInstance("X448", BouncyCastleProvider())

                    val publicKeyAlgorithmIdentifier = AlgorithmIdentifier(EdECObjectIdentifiers.id_X448)
                    val spki = SubjectPublicKeyInfo(publicKeyAlgorithmIdentifier, rawPublicKey)
                    val x509Spec = X509EncodedKeySpec(spki.encoded)
                    val publicKey = keyFactory.generatePublic(x509Spec)
                    return  publicKey
                }
                Ed25519 -> {
                    // Ed25519の生の32バイトの公開鍵を読み取る
                    val rawPublicKey = dataInputStream.readNBytes(ED25519_PUBLIC_KEY_LENGTH)

                    val keyFactory = KeyFactory.getInstance("Ed25519", BouncyCastleProvider())

                    val publicKeyAlgorithmIdentifier = AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519)

                    val spki = SubjectPublicKeyInfo(publicKeyAlgorithmIdentifier, rawPublicKey)
                    val x509Spec = X509EncodedKeySpec(spki.encoded) // X.509形式にエンコード
                    val publicKey = keyFactory.generatePublic(x509Spec)

                    return publicKey
                }
                Ed448 -> {
                    // Ed448の生の57バイトの公開鍵を読み取る
                    val rawPublicKey = dataInputStream.readNBytes(ED448_PUBLIC_KEY_LENGTH)

                    val keyFactory = KeyFactory.getInstance("Ed448", BouncyCastleProvider())

                    val publicKeyAlgorithmIdentifier = AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed448)

                    val spki = SubjectPublicKeyInfo(publicKeyAlgorithmIdentifier, rawPublicKey)
                    val x509Spec = X509EncodedKeySpec(spki.encoded) // X.509形式にエンコード
                    val publicKey = keyFactory.generatePublic(x509Spec)

                    return publicKey
                }
                else -> {
                    throw IllegalArgumentException("Unsupported algorithm: $algorithm")
                }
            }
        }

        fun getRawEd25519PublicKey(publicKey: java.security.PublicKey): ByteArray{
            val spki = SubjectPublicKeyInfo.getInstance(publicKey.encoded)

            val algoId = spki.algorithm

            require(EdECObjectIdentifiers.id_Ed25519 == algoId.algorithm) {
                "Not Ed25519 public key"
            }

            val subjectPublicKeyBitString = spki.publicKeyData
            val rawPublicKey = subjectPublicKeyBitString.bytes

            if(rawPublicKey.size != 32){
                throw IllegalArgumentException("Invalid Ed25519 public key length: ${rawPublicKey.size}")
            }

            return rawPublicKey
        }
    }
}