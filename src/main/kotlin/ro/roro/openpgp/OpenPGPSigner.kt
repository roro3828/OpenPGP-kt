package ro.roro.openpgp

import ro.roro.openpgp.packet.SecretKey
import ro.roro.openpgp.packet.signature.SignatureSubPacket
import java.io.ByteArrayOutputStream
import java.security.Provider
import java.security.Security
import java.security.Signature

class OpenPGPSigner{

    val provider: Provider?
    val secretKey: SecretKey

    constructor(secretKey: SecretKey){
        this.provider = null
        this.secretKey = secretKey
    }

    constructor(secretKey: SecretKey, provider: Provider){
        this.provider = provider
        this.secretKey = secretKey
    }

    constructor(secretKey: SecretKey, providerName: String){
        val provider = Security.getProvider(providerName)

        if(provider == null){
            throw IllegalArgumentException("Provider $providerName not found")
        }
        this.provider = provider
        this.secretKey = secretKey
    }

    fun sign(digest: ByteArray, passPhrase: String): ByteArray {
        return sign(digest, passPhrase.toByteArray())
    }
    fun sign(digest: ByteArray, passPhrase: ByteArray? = null): ByteArray {
        if(secretKey.keyVertion != 4 && secretKey.keyVertion != 6){
            // このライブラリではv4とv6の署名生成のみサポート
            throw Error("This library only supports signature generation for v4 and v6 keys.")
        }

        val algorithm = when(secretKey.keyAlgo){
            OpenPGPPublicKeyAlgorithms.Ed25519,
            OpenPGPPublicKeyAlgorithms.EDDSA_LEGACY -> "Ed25519"
            else -> throw Error("Unsupported algorithm: ${secretKey.keyAlgo}")
        }

        val signer = if(provider == null){
            Signature.getInstance(algorithm)
        } else {
            Signature.getInstance(algorithm, provider)
        }

        signer.initSign(secretKey.getSecretKey(passPhrase))

        val signature = signer.let {
            it.update(digest)
            it.sign()
        }

        return signature
    }

    fun generateSignature(signatureType: Int, data: ByteArray, hashedSubPackets: List<SignatureSubPacket>? = null, unhashedSubPackets: List<SignatureSubPacket>? = null, passPhrase: ByteArray? = null, hashAlgorithm: Int = OpenPGPDigest.SHA256): ro.roro.openpgp.packet.signature.Signature {
        val signaturePacket = ro.roro.openpgp.packet.signature.Signature.getV4Instance(
            signatureType,
            secretKey.keyAlgo,
            hashAlgorithm,
            hashedSubPackets,
            unhashedSubPackets
        )

        val toBeHashed = ByteArrayOutputStream()
        toBeHashed.write(data)
        toBeHashed.write(signaturePacket.trailer)

        val digest = OpenPGPDigest.getInstance(hashAlgorithm).digest(toBeHashed.toByteArray())
        val signature = sign(digest, passPhrase)

        signaturePacket.hashLeft2Bytes = ((digest[0].toInt() and 0xFF shl 8) or (digest[1].toInt() and 0xFF)).toShort()

        signaturePacket.signatureValue =  when(secretKey.keyAlgo){
            OpenPGPPublicKeyAlgorithms.Ed25519,
            OpenPGPPublicKeyAlgorithms.EDDSA_LEGACY -> {
                // EdDSAの署名はRとSの連結で表現される
                // RとSはそれぞれ32バイト
                if(signature.size != 64){
                    throw Error("EdDSA signature must be 64 bytes long, but was ${signature.size} bytes.")
                }
                val r = signature.copyOfRange(0, 32)
                val s = signature.copyOfRange(32, 64)

                val mpiR = OpenPGPUtil.toMPI(r)
                val mpiS = OpenPGPUtil.toMPI(s)

                val sigOut = ByteArrayOutputStream()
                sigOut.write(mpiR)
                sigOut.write(mpiS)

                sigOut.toByteArray()
            }
            else -> throw Error("Unsupported algorithm: ${secretKey.keyAlgo}")
        }

        signaturePacket.hashLeft2Bytes = ((digest[0].toInt() and 0xFF shl 8) or (digest[1].toInt() and 0xFF)).toShort()

        return signaturePacket
    }
}