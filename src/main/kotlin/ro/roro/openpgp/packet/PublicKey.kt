package ro.roro.openpgp.packet

import ro.roro.openpgp.OpenPGPPublicKeyAlgorithms
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.jce.provider.BouncyCastleProvider
import ro.roro.openpgp.OpenPGPDigest
import ro.roro.openpgp.OpenPGPECCCurveOIDs
import ro.roro.openpgp.OpenPGPUtil
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.security.InvalidKeyException
import java.security.KeyFactory
import java.security.interfaces.RSAPublicKey
import java.security.spec.RSAPublicKeySpec
import java.security.spec.X509EncodedKeySpec

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
    val validDays: Int

    /**
     * 鍵のアルゴリズム
     */
    val keyAlgo: Int

    /**
     * 公開鍵
     */
    val key:java.security.PublicKey


    /**
     * 鍵のバージョン
     * @param version 鍵のバージョン
     * @param creationTime 鍵が作成された時間
     * @param keyAlgo 鍵のアルゴリズム
     * @param validDays 鍵の有効期限 (単位は日) バージョン3でのみ使われる
     * @param key 公開鍵
     * @throws IllegalArgumentException versionが3,4,6以外の場合
     */
    @Throws(IllegalArgumentException::class)
    constructor(creationTime: Int,
                keyAlgo: Int,
                key: java.security.PublicKey,
                version: Int = 6,
                validDays: Int = 0){
        this.keyVertion = version
        if(version != 3 && version != 4 && version != 6){
            throw IllegalArgumentException("version must be 3,4 or 6")
        }

        // 鍵のバージョンが3以外の時はvalidDaysは使わない
        if(version == 3){
            this.validDays = validDays

            if(key.algorithm!="RSA" || keyAlgo != OpenPGPPublicKeyAlgorithms.RSA_GENERAL){
                throw IllegalArgumentException("Algorithm must be RSA and keyAlgo must be 1")
            }
        }
        else{
            this.validDays = 0
        }

        this.keyAlgo = keyAlgo

        this.creationTime = creationTime
        this.key = key
    }

    override val encoded: ByteArray
        get(){
            when(this.keyVertion){
                3->{
                    return byteArrayOf(
                        this.keyVertion.toByte(),
                        (this.creationTime shr 24).toByte(),
                        (this.creationTime shr 16).toByte(),
                        (this.creationTime shr 8).toByte(),
                        this.creationTime.toByte(),
                        (this.validDays shr 8).toByte(),
                        this.validDays.toByte(),
                        this.keyAlgo.toByte(),
                        *getKeyMaterial()
                    )
                }
                4->{
                    return byteArrayOf(
                        this.keyVertion.toByte(),
                        (this.creationTime shr 24).toByte(),
                        (this.creationTime shr 16).toByte(),
                        (this.creationTime shr 8).toByte(),
                        this.creationTime.toByte(),
                        this.keyAlgo.toByte(),
                        *getKeyMaterial()
                    )
                }
                6->{
                    val keyMaterial = getKeyMaterial()
                    val keyMaterialLen = keyMaterial.size
                    return byteArrayOf(
                        this.keyVertion.toByte(),
                        (this.creationTime shr 24).toByte(),
                        (this.creationTime shr 16).toByte(),
                        (this.creationTime shr 8).toByte(),
                        this.creationTime.toByte(),
                        this.keyAlgo.toByte(),
                        (keyMaterialLen shr 24).toByte(),
                        (keyMaterialLen shr 16).toByte(),
                        (keyMaterialLen shr 8).toByte(),
                        keyMaterialLen.toByte(),
                        *keyMaterial
                    )
                }
                else -> {
                    throw IllegalArgumentException("version must be 3,4 or 6")
                }
            }
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
                    val packetBytes = this.encoded
                    val packetLen = packetBytes.size
                    val sha1 = OpenPGPDigest.getInstance(OpenPGPDigest.SHA1)

                    sha1.writeByte(0x99)
                    sha1.writeShort(packetLen)
                    sha1.write(packetBytes)

                    val hashedData = sha1.digest()

                    return hashedData
                }
                6 -> {
                    val packetBytes = this.encoded
                    val packetLen = packetBytes.size
                    val sha256 = OpenPGPDigest.getInstance(OpenPGPDigest.SHA256)

                    sha256.writeByte(0x9b)
                    sha256.writeInt(packetLen)
                    sha256.write(packetBytes)

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
            OpenPGPPublicKeyAlgorithms.RSA_GENERAL -> {
                val rsaKey = this.key as RSAPublicKey
                val modulus = rsaKey.modulus
                val exponent = rsaKey.publicExponent


                return byteArrayOf(
                    *OpenPGPUtil.toMPI( modulus ),
                    *OpenPGPUtil.toMPI( exponent )
                )
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
                val outputStream = ByteArrayOutputStream()
                val dataOutputStream = DataOutputStream(outputStream)

                dataOutputStream.writeByte(OpenPGPECCCurveOIDs.ED25519_LEGACY.size)
                dataOutputStream.write(OpenPGPECCCurveOIDs.ED25519_LEGACY)

                // Ed25519の公開鍵は33バイトで、最初の1バイトは0x40
                val rawPublicKey = OpenPGPUtil.getRawEd25519PublicKey(this.key.encoded)
                val mpiBytes = byteArrayOf( OpenPGPUtil.ED25519_LEGACY_PUBLIC_KEY_PREFIX.toByte(), *rawPublicKey )
                val mpi = OpenPGPUtil.toMPI(mpiBytes)
                dataOutputStream.write( mpi )

                return outputStream.toByteArray()
            }
            OpenPGPPublicKeyAlgorithms.X25519 -> {
                TODO("X25519 is not supported yet")
            }
            OpenPGPPublicKeyAlgorithms.X448 -> {
                TODO("X448 is not supported yet")
            }
            OpenPGPPublicKeyAlgorithms.Ed25519 -> {
                val ed25519Key = this.key

                if( ed25519Key.format != "X.509" ){
                    throw InvalidKeyException("Ed25519 key must be in X.509 format")
                }
                val encodedKey = ed25519Key.encoded

                return OpenPGPUtil.getRawEd25519PublicKey( encodedKey )
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

        /**
         * バイト列からPublicKeyパケットへ変換する
         * @param body パケットヘッダーを含まないボディのみのデータ
         * @return PublicKey
         * @throws IllegalArgumentException versionが3,4,6以外の場合
         */
        @Throws(IllegalArgumentException::class)
        fun fromBytes( body: ByteArray ):PublicKey{
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

                return PublicKey(creationTime, keyAlgo, key, version, validDays)
            }
            else if( version == 4 ){
                val keyAlgo = body.readUnsignedByte()
                val key = bytesToPublicKey(keyAlgo, body )

                return PublicKey(creationTime, keyAlgo, key, version)
            }
            else if( version == 6 ){
                val keyAlgo = body.readUnsignedByte()
                val keyLen = body.readInt()
                //鍵の長さが合わないときエラー
                if( body.available() < keyLen ){
                    throw IllegalArgumentException("keyLen is not valid")
                }
                val key = bytesToPublicKey(keyAlgo, body )

                return PublicKey(creationTime, keyAlgo, key, version)
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
        private fun bytesToPublicKey(algorithm: Int, dataInputStream: DataInputStream): java.security.PublicKey {
            when(algorithm){
                OpenPGPPublicKeyAlgorithms.RSA_GENERAL -> {
                    val modulus = OpenPGPUtil.readMPI(dataInputStream)

                    val exponent = OpenPGPUtil.readMPI(dataInputStream)

                    val keyFactory = KeyFactory.getInstance("RSA")
                    val publicKeySpec = RSAPublicKeySpec(modulus, exponent)

                    val rsaPublicKey = keyFactory.generatePublic(publicKeySpec) as RSAPublicKey

                    return rsaPublicKey
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
                    val oidLen = dataInputStream.readUnsignedByte()
                    val oid = dataInputStream.readNBytes(oidLen)

                    if( !oid.contentEquals(OpenPGPECCCurveOIDs.ED25519_LEGACY) ){
                        throw IllegalArgumentException("Unsupported EDDSA_LEGACY OID: ${oid.joinToString(",")}")
                    }

                    val mpiLen = OpenPGPUtil.readMPILen(dataInputStream)

                    if( mpiLen != (OpenPGPUtil.ED25519_PUBLIC_KEY_LENGTH + 1) ){
                        throw IllegalArgumentException("EDDSA_LEGACY MPI length must be 33, but was $mpiLen")
                    }

                    val prefix = dataInputStream.readUnsignedByte()

                    if( prefix != OpenPGPUtil.ED25519_LEGACY_PUBLIC_KEY_PREFIX ){
                        throw IllegalArgumentException("EDDSA_LEGACY prefix must be 0x40, but was $prefix")
                    }

                    val rawPublicKey = dataInputStream.readNBytes(32)

                    val keyFactory = KeyFactory.getInstance("Ed25519", BouncyCastleProvider())

                    val publicKeyAlgorithmIdentifier = AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519)

                    val spki = SubjectPublicKeyInfo(publicKeyAlgorithmIdentifier, rawPublicKey)
                    val x509Spec = X509EncodedKeySpec(spki.encoded) // X.509形式にエンコード
                    val publicKey = keyFactory.generatePublic(x509Spec)

                    return publicKey
                }
                OpenPGPPublicKeyAlgorithms.X25519 -> {
                    TODO("X25519 is not supported yet")
                }
                OpenPGPPublicKeyAlgorithms.X448 -> {
                    TODO("X448 is not supported yet")
                }
                OpenPGPPublicKeyAlgorithms.Ed25519 -> {
                    // Ed25519の生の32バイトの公開鍵を読み取る
                    val rawPublicKey = dataInputStream.readNBytes(32)

                    val keyFactory = KeyFactory.getInstance("Ed25519", BouncyCastleProvider())

                    val publicKeyAlgorithmIdentifier = AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519)

                    val spki = SubjectPublicKeyInfo(publicKeyAlgorithmIdentifier, rawPublicKey)
                    val x509Spec = X509EncodedKeySpec(spki.encoded) // X.509形式にエンコード
                    val publicKey = keyFactory.generatePublic(x509Spec)

                    return publicKey
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