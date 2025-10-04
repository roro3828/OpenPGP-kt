package ro.roro.openpgp

import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import org.bouncycastle.util.Strings
import java.io.DataInputStream
import java.io.IOException

/**
 *    String to Key
 *    +=========+==============+===============+==============+===========+
 *    |      ID | S2K Type     | S2K Field     | Generate?    | Reference |
 *    |         |              | Size          |              |           |
 *    |         |              | (Octets)      |              |           |
 *    +=========+==============+===============+==============+===========+
 *    |       0 | Simple S2K   | 2             | No           | Section   |
 *    |         |              |               |              | 3.7.1.1   |
 *    +---------+--------------+---------------+--------------+-----------+
 *    |       1 | Salted S2K   | 10            | Only when    | Section   |
 *    |         |              |               | string is    | 3.7.1.2   |
 *    |         |              |               | high entropy |           |
 *    +---------+--------------+---------------+--------------+-----------+
 *    |       2 | Reserved     | -             | No           |           |
 *    |         | value        |               |              |           |
 *    +---------+--------------+---------------+--------------+-----------+
 *    |       3 | Iterated and | 11            | Yes          | Section   |
 *    |         | Salted S2K   |               |              | 3.7.1.3   |
 *    +---------+--------------+---------------+--------------+-----------+
 *    |       4 | Argon2       | 20            | Yes          | Section   |
 *    |         |              |               |              | 3.7.1.4   |
 *    +---------+--------------+---------------+--------------+-----------+
 *    | 100-110 | Private or   | -             | As           |           |
 *    |         | Experimental |               | appropriate  |           |
 *    |         | Use          |               |              |           |
 *    +---------+--------------+---------------+--------------+-----------+
 *
 *    +=========+============+============+==========================+====+
 *    |S2K Usage|Shorthand   |Encryption  |Encryption                |Gen?|
 *    |Octet    |            |Parameter   |                          |    |
 *    |         |            |Fields      |                          |    |
 *    +=========+============+============+==========================+====+
 *    |0        |Unprotected |-           |*v3 or v4 keys:*          |Yes |
 *    |         |            |            |[cleartext secrets ||     |    |
 *    |         |            |            |check(secrets)]           |    |
 *    |         |            |            |*v6 keys:* [cleartext     |    |
 *    |         |            |            |secrets]                  |    |
 *    +---------+------------+------------+--------------------------+----+
 *    |Known    |LegacyCFB   |IV          |CFB(MD5(passphrase),      |No  |
 *    |symmetric|            |            |secrets || check(secrets))|    |
 *    |cipher   |            |            |                          |    |
 *    |algo ID  |            |            |                          |    |
 *    |(see     |            |            |                          |    |
 *    |Section  |            |            |                          |    |
 *    |9.3)     |            |            |                          |    |
 *    +---------+------------+------------+--------------------------+----+
 *    |253      |AEAD        |params-     |AEAD(HKDF(S2K(passphrase),|Yes |
 *    |         |            |length      |info), secrets,           |    |
 *    |         |            |(*v6-only*),|packetprefix)             |    |
 *    |         |            |cipher-algo,|                          |    |
 *    |         |            |AEAD-mode,  |                          |    |
 *    |         |            |S2K-        |                          |    |
 *    |         |            |specifier-  |                          |    |
 *    |         |            |length      |                          |    |
 *    |         |            |(*v6-only*),|                          |    |
 *    |         |            |S2K-        |                          |    |
 *    |         |            |specifier,  |                          |    |
 *    |         |            |nonce       |                          |    |
 *    +---------+------------+------------+--------------------------+----+
 *    |254      |CFB         |params-     |CFB(S2K(passphrase),      |Yes |
 *    |         |            |length      |secrets || SHA1(secrets)) |    |
 *    |         |            |(*v6-only*),|                          |    |
 *    |         |            |cipher-algo,|                          |    |
 *    |         |            |S2K-        |                          |    |
 *    |         |            |specifier-  |                          |    |
 *    |         |            |length      |                          |    |
 *    |         |            |(*v6-only*),|                          |    |
 *    |         |            |S2K-        |                          |    |
 *    |         |            |specifier,  |                          |    |
 *    |         |            |IV          |                          |    |
 *    +---------+------------+------------+--------------------------+----+
 *    |255      |MalleableCFB|cipher-algo,|CFB(S2K(passphrase),      |No  |
 *    |         |            |S2K-        |secrets || check(secrets))|    |
 *    |         |            |specifier,  |                          |    |
 *    |         |            |IV          |                          |    |
 *    +---------+------------+------------+--------------------------+----+
 */
class OpenPGPS2K {
    companion object{
        const val SIMPLE_S2K = 0
        const val SALTED_S2K = 1
        const val ITERATED_AND_SALTED_S2K = 3
        const val ARGON2_S2K = 4

        const val S2KUSAGE_UNPROTECTED = 0
        const val S2KUSAGE_LEGACY_CFB = 1
        const val S2KUSAGE_AEAD = 253
        const val S2KUSAGE_CFB = 254
        const val S2KUSAGE_MALLEABLE_CFB = 255

        private const val EXPBIAS = 6

        fun fromBytes(data: DataInputStream): OpenPGPS2K{
            val s2kType = data.readUnsignedByte()

            when(s2kType){
                SIMPLE_S2K -> {
                    val hashAlgo = data.readUnsignedByte()
                    return OpenPGPS2K(SIMPLE_S2K, hashAlgo)
                }
                SALTED_S2K -> {
                    val hashAlgo = data.readUnsignedByte()
                    val salt = ByteArray(8)
                    data.readFully(salt)
                    return OpenPGPS2K(SALTED_S2K, hashAlgo, salt)
                }
                ITERATED_AND_SALTED_S2K -> {
                    val hashAlgo = data.readUnsignedByte()
                    val salt = ByteArray(8)
                    data.readFully(salt)
                    val count = data.readUnsignedByte()

                    val decodedCount = (16L + (count and 0x0F)) shl ((count ushr 4) + EXPBIAS)

                    return OpenPGPS2K(ITERATED_AND_SALTED_S2K, hashAlgo, salt, decodedCount)
                }
                ARGON2_S2K -> {
                    val salt = data.readNBytes(16)
                    val argon2T = data.readUnsignedByte()
                    val argon2P = data.readUnsignedByte()
                    val argon2M = data.readUnsignedByte()
                    return OpenPGPS2K(ARGON2_S2K, null, salt, null, argon2T, argon2P, argon2M)
                }
                else -> throw IllegalArgumentException("Unknown S2K type: $s2kType")
            }
        }
    }

    /**
     * S2Kのタイプ
     * 0: Simple S2K
     * 1: Salted S2K
     * 3: Iterated and Salted S2K
     * 4: Argon2 S2K
     */
    val s2kType: Int

    /**
     * S2Kのハッシュアルゴリズム
     */
    val hashAlgo: Int

    val salt: ByteArray

    val count: Long

    val argon2T: Int
    val argon2P: Int
    val argon2M: Int

    constructor(s2kType: Int, hashAlgo: Int?, salt: ByteArray? = null, count: Long? = null, argon2T: Int? = null, argon2P: Int? = null, argon2M: Int? = null) {

        if(salt != null){
            when( s2kType ){
                SALTED_S2K, ITERATED_AND_SALTED_S2K->{
                    if( salt.size != 8){
                        throw IllegalArgumentException("Salt must be 8 bytes for S2K type $s2kType")
                    }
                    this.salt = salt
                }
                ARGON2_S2K ->{
                    if( salt.size != 16 ){
                        throw IllegalArgumentException("Salt must be 16 bytes for S2K type $s2kType")
                    }
                    this.salt = salt
                }
                SIMPLE_S2K ->{
                    this.salt = ByteArray(0)
                }
                else ->{
                    throw IllegalArgumentException("Unknown S2K type: $s2kType")
                }
            }
        }
        else{
            if( s2kType != SIMPLE_S2K ){
                throw IllegalArgumentException("Salt must not be null for S2K type $s2kType")
            }
            this.salt = ByteArray(0)
        }

        this.s2kType = s2kType

        if( s2kType != ARGON2_S2K ){
            if( hashAlgo == null ){
                throw IllegalArgumentException("Hash algorithm must not be null for S2K type $s2kType")
            }
            this.hashAlgo = hashAlgo
        }
        else{
            this.hashAlgo = -1 // Argon2 S2K does not usea hash algorithm
        }

        if( s2kType == ITERATED_AND_SALTED_S2K ){
            if(count == null || count < 0){
                throw IllegalArgumentException("Count must not be null or negative for S2K type $s2kType")
            }

            this.count = count
        }
        else{
            this.count = 1
        }

        if( s2kType == ARGON2_S2K ){
            if( argon2T == null || argon2P == null || argon2M == null ){
                throw IllegalArgumentException("Argon2 parameters must not be null for S2K type $s2kType")
            }

            this.argon2T = argon2T
            this.argon2P = argon2P
            this.argon2M = argon2M
        }
        else{
            this.argon2T = 0
            this.argon2P = 0
            this.argon2M = 0
        }
    }

    /**
     * パスフレーズから鍵を生成する
     * @param passPhrase パスフレーズ
     * @param keyAlgorithm 鍵アルゴリズム
     * @return 生成された鍵
     */
    fun getKey(passPhrase: String, keyAlgorithm: OpenPGPSymmetricKeyAlgorithm): ByteArray {
        return getKey(Strings.toUTF8ByteArray(passPhrase), keyAlgorithm.keySize)
    }

    /**
     * パスフレーズから鍵を生成する
     * @param passPhrase パスフレーズ
     * @param keyAlgorithm 鍵アルゴリズム
     * @return 生成された鍵
     */
    fun getKey(passPhrase: ByteArray, keyAlgorithm: OpenPGPSymmetricKeyAlgorithm): ByteArray {
        if (keyAlgorithm.algorithm == OpenPGPSymmetricKeyAlgorithm.PLAIN) {
            // PLAIN
            return passPhrase.copyOf((keyAlgorithm.keySize + 7) / 8)
        }

        if (this.s2kType == ARGON2_S2K && keyAlgorithm.algorithm != OpenPGPSymmetricKeyAlgorithm.AES_256) {
            throw IllegalArgumentException("Argon2 S2K can only be used with AES-256")
        }

        return getKey(passPhrase, keyAlgorithm.keySize)
    }

    /**
     * パスフレーズから鍵を生成する
     * @param passPhrase パスフレーズ
     * @param keySize 鍵のサイズ（ビット）
     * @return 生成された鍵
     */
    fun getKey(passPhrase : ByteArray, keySize: Int ): ByteArray {

        val keyBytes = ByteArray((keySize + 7) / 8)

        var generatedBytes = 0
        var loopCount = 0

        if(this.s2kType == ARGON2_S2K ){
            val builder = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withSalt(this.salt)
                .withIterations(this.argon2T)
                .withParallelism(this.argon2P)
                .withMemoryPowOfTwo(this.argon2M)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)

            val argon2 = Argon2BytesGenerator()
            argon2.init(builder.build())
            argon2.generateBytes(passPhrase, keyBytes)

            return keyBytes
        }

        val digest = OpenPGPDigest.getInstance(this.hashAlgo)

        try{
            val iv: ByteArray = this.salt

            while( generatedBytes < keyBytes.size ){
                for(i in 0..<loopCount){
                    digest.update(0)
                }

                when(s2kType){
                    SIMPLE_S2K -> digest.update(passPhrase)

                    SALTED_S2K -> {
                        digest.update(iv)
                        digest.update(passPhrase)
                    }

                    ITERATED_AND_SALTED_S2K -> {
                        var count = this.count
                        digest.update(iv)
                        digest.update(passPhrase)

                        count -= (iv.size + passPhrase.size).toLong()

                        while(0 < count){
                            if(count < iv.size){
                                digest.update(iv, 0, count.toInt())
                                count = 0
                            }
                            else{
                                digest.update(iv)
                                count -= iv.size.toLong()
                            }

                            if(count < passPhrase.size){
                                digest.update(passPhrase, 0, count.toInt())
                                count = 0
                            }
                            else{
                                digest.update(passPhrase)
                                count -= passPhrase.size.toLong()
                            }
                        }
                    }

                }

                val dig: ByteArray = digest.digest()

                if((keyBytes.size - generatedBytes) < dig.size){
                    System.arraycopy(
                        dig,
                        0,
                        keyBytes,
                        generatedBytes,
                        keyBytes.size - generatedBytes
                    )
                }
                else {
                    System.arraycopy(dig, 0, keyBytes, generatedBytes, dig.size)
                }

                generatedBytes += dig.size

                loopCount++
            }
        }
        catch (e: IOException) {
            throw Exception("exception calculating digest: " + e.message, e)
        }

        return keyBytes
    }

    override fun toString(): String {
        return "OpenPGPS2K(s2kType=$s2kType, hashAlgo=$hashAlgo, salt=${OpenPGPUtil.getHexString(salt)}, count=$count, argon2T=$argon2T, argon2P=$argon2P, argon2M=$argon2M)"
    }

}