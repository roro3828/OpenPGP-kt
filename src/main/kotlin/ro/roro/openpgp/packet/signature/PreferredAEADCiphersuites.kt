package ro.roro.openpgp.packet.signature

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream

/**
 *     +=========+==================+==============+====================+
 *     |      ID | Name             | Nonce Length | Authentication Tag |
 *     |         |                  | (Octets)     | Length (Octets)    |
 *     +=========+==================+==============+====================+
 *     |       0 | Reserved         |              |                    |
 *     +---------+------------------+--------------+--------------------+
 *     |       1 | EAX [EAX]        | 16           | 16                 |
 *     +---------+------------------+--------------+--------------------+
 *     |       2 | OCB [RFC7253]    | 15           | 16                 |
 *     +---------+------------------+--------------+--------------------+
 *     |       3 | GCM [SP800-38D]  | 12           | 16                 |
 *     +---------+------------------+--------------+--------------------+
 *     | 100-110 | Private or       |              |                    |
 *     |         | Experimental Use |              |                    |
 *     +---------+------------------+--------------+--------------------+
 */

class PreferredAEADCiphersuites: SignatureSubPacket {
    override val subPacketType: Int = SignatureSubPacket.PREFERRED_AEAD_CIPHERSUITES

    override val critical: Boolean

    val aeadSuites: List<AEADSuite>

    override val encoded: ByteArray
        get() {
            val byteStream = ByteArrayOutputStream()
            val dataStream = DataOutputStream(byteStream)
            for(suite in aeadSuites){
                dataStream.writeByte(suite.symmetricAlgorithm)
                dataStream.writeByte(suite.aeadAlgorithm)
            }
            return byteStream.toByteArray()
        }

    companion object{
        class AEADSuite(val symmetricAlgorithm: Int, val aeadAlgorithm: Int){
            override fun toString(): String {
                return "AEADSuite(symmetricAlgorithm=$symmetricAlgorithm, AEADAlgorithm=$aeadAlgorithm)"
            }
        }
    }

    constructor(data: ByteArray, critical: Boolean = false){
        this.critical = critical
        if(data.size % 2 != 0){
            throw IllegalArgumentException("Invalid data length for PreferredAEADCiphersuites: ${data.size}. Must be even.")
        }
        val suites = mutableListOf<AEADSuite>()
        for(i in data.indices step 2) {
            val symAlgo = data[i].toInt() and 0xFF
            val aeadAlgo = data[i + 1].toInt() and 0xFF
            suites.add(AEADSuite(symAlgo, aeadAlgo))
        }

        this.aeadSuites = suites
    }


}