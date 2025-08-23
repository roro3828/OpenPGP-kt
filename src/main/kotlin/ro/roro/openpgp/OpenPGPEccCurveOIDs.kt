package ro.roro.openpgp

/**
 *    +======================+===+========+================+======+=======+
 *    |ASN.1 Object          |OID| Curve  |Curve Name      |Usage |Field  |
 *    |Identifier            |Len| OID    |                |      |Size   |
 *    |                      |   | Octets |                |      |(fsize)|
 *    +======================+===+========+================+======+=======+
 *    |1.2.840.10045.3.1.7   |8  | 2A 86  |NIST P-256      |ECDSA,|32     |
 *    |                      |   | 48 CE  |                |ECDH  |       |
 *    |                      |   | 3D 03  |                |      |       |
 *    |                      |   | 01 07  |                |      |       |
 *    +----------------------+---+--------+----------------+------+-------+
 *    |1.3.132.0.34          |5  | 2B 81  |NIST P-384      |ECDSA,|48     |
 *    |                      |   | 04 00  |                |ECDH  |       |
 *    |                      |   | 22     |                |      |       |
 *    +----------------------+---+--------+----------------+------+-------+
 *    |1.3.132.0.35          |5  | 2B 81  |NIST P-521      |ECDSA,|66     |
 *    |                      |   | 04 00  |                |ECDH  |       |
 *    |                      |   | 23     |                |      |       |
 *    +----------------------+---+--------+----------------+------+-------+
 *    |1.3.36.3.3.2.8.1.1.7  |9  | 2B 24  |brainpoolP256r1 |ECDSA,|32     |
 *    |                      |   | 03 03  |                |ECDH  |       |
 *    |                      |   | 02 08  |                |      |       |
 *    |                      |   | 01 01  |                |      |       |
 *    |                      |   | 07     |                |      |       |
 *    +----------------------+---+--------+----------------+------+-------+
 *    |1.3.36.3.3.2.8.1.1.11 |9  | 2B 24  |brainpoolP384r1 |ECDSA,|48     |
 *    |                      |   | 03 03  |                |ECDH  |       |
 *    |                      |   | 02 08  |                |      |       |
 *    |                      |   | 01 01  |                |      |       |
 *    |                      |   | 0B     |                |      |       |
 *    +----------------------+---+--------+----------------+------+-------+
 *    |1.3.36.3.3.2.8.1.1.13 |9  | 2B 24  |brainpoolP512r1 |ECDSA,|64     |
 *    |                      |   | 03 03  |                |ECDH  |       |
 *    |                      |   | 02 08  |                |      |       |
 *    |                      |   | 01 01  |                |      |       |
 *    |                      |   | 0D     |                |      |       |
 *    +----------------------+---+--------+----------------+------+-------+
 *    |1.3.6.1.4.1.11591.15.1|9  | 2B 06  |Ed25519Legacy   |EdDSA |32     |
 *    |                      |   | 01 04  |                |Legacy|       |
 *    |                      |   | 01 DA  |                |      |       |
 *    |                      |   | 47 0F  |                |      |       |
 *    |                      |   | 01     |                |      |       |
 *    +----------------------+---+--------+----------------+------+-------+
 *    |1.3.6.1.4.1.3029.1.5.1|10 | 2B 06  |Curve25519Legacy|ECDH  |32     |
 *    |                      |   | 01 04  |                |      |       |
 *    |                      |   | 01 97  |                |      |       |
 *    |                      |   | 55 01  |                |      |       |
 *    |                      |   | 05 01  |                |      |       |
 *    +----------------------+---+--------+----------------+------+-------+
 */

interface OpenPGPECCCurveOIDs {

    companion object {
        /**
         * OID for NIST P-256 curve.
         * 1.2.840.10045.3.1.7
         */
        val NIST_P256 = byteArrayOf(
            0x2A.toByte(), 0x86.toByte(), 0x48.toByte(), 0xCE.toByte(), 0x3D.toByte(), 0x03.toByte(), 0x01.toByte(), 0x07.toByte()
        )
        /**
         * OID for NIST P-384 curve.
         * 1.3.132.0.34
         */
        val NIST_P384 = byteArrayOf(
            0x2B.toByte(), 0x81.toByte(), 0x04.toByte(), 0x00.toByte(), 0x22.toByte()
        )
        /**
         * OID for NIST P-521 curve.
         * 1.3.132.0.35
         */
        val NIST_P521 = byteArrayOf(
            0x2B.toByte(), 0x81.toByte(), 0x04.toByte(), 0x00.toByte(), 0x23.toByte()
        )
        /**
         * OID for brainpoolP256r1 curve.
         * 1.3.36.3.3.2.8.1.1.7
         */
        val BRAINPOOL_P256R1 = byteArrayOf(
            0x2B.toByte(), 0x24.toByte(), 0x03.toByte(), 0x03.toByte(), 0x02.toByte(), 0x08.toByte(), 0x01.toByte(), 0x01.toByte(), 0x07.toByte()
        )
        /**
         * OID for brainpoolP384r1 curve.
         * 1.3.36.3.3.2.8.1.1.11
         */
        val BRAINPOOL_P384R1 = byteArrayOf(
            0x2B.toByte(), 0x24.toByte(), 0x03.toByte(), 0x03.toByte(), 0x02.toByte(), 0x08.toByte(), 0x01.toByte(), 0x01.toByte(), 0x0B.toByte()
        )
        /**
         * OID for brainpoolP512r1 curve.
         * 1.3.36.3.3.2.8.1.1.13
         */
        val BRAINPOOL_P512R1 = byteArrayOf(
            0x2B.toByte(), 0x24.toByte(), 0x03.toByte(), 0x03.toByte(), 0x02.toByte(), 0x08.toByte(), 0x01.toByte(), 0x01.toByte(), 0x0D.toByte()
        )
        /**
         * OID for Ed25519Legacy curve.
         * 1.3.6.1.4.1.11591.15.1
         */
        val ED25519_LEGACY = byteArrayOf(
            0x2B.toByte(), 0x06.toByte(), 0x01.toByte(), 0x04.toByte(), 0x01.toByte(), 0xDA.toByte(), 0x47.toByte(), 0x0F.toByte(), 0x01.toByte()
        )
        /**
         * OID for Curve25519Legacy curve.
         * 1.3.6.1.4.1.3029.1.5.1
         */
        val CURVE25519_LEGACY = byteArrayOf(
            0x2B.toByte(), 0x06.toByte(), 0x01.toByte(), 0x04.toByte(), 0x01.toByte(), 0x97.toByte(), 0x55.toByte(), 0x01.toByte(), 0x05.toByte(), 0x01.toByte()
        )
    }
}