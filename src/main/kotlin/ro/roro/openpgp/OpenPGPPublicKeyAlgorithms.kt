package ro.roro.openpgp

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
interface OpenPGPPublicKeyAlgorithms {
    companion object{
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
    }
}