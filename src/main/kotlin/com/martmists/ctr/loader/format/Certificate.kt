package com.martmists.ctr.loader.format

import com.martmists.ctr.reader.Reader

interface PublicKey

data class RSAPublicKey(
    val modulus: ByteArray,
    val exponent: Int,
) : PublicKey

data class ECCPublicKey(
    val key: ByteArray,
) : PublicKey

data class Certificate(
    val signatureType: Int,
    val signature: ByteArray,
    val issuer: ByteArray,
    val keyType: Int,
    val name: ByteArray,
    val expirationTime: Int,
    val pubKey: PublicKey,
) {
    companion object {
        fun parse(reader: Reader): Certificate {
            return reader.withEndian(false) {
                val signatureType = read<Int>()
                val signature = when (signatureType) {
                    0x010000, 0x010003 -> readBytes(0x200).also { skip(0x3c) }
                    0x010001, 0x010004 -> readBytes(0x100).also { skip(0x3c) }
                    0x010002, 0x010005 -> readBytes(0x3c).also { skip(0x40) }
                    else -> throw Exception("Unknown signature type: $signatureType")
                }
                val issuer = readBytes(0x40)
                val keyType = read<Int>()
                val name = readBytes(0x40)
                val expirationTime = read<Int>()
                val pubkey = when (keyType) {
                    0 -> RSAPublicKey(
                        modulus = readBytes(0x200),
                        exponent = read<Int>(),
                    ).also { skip(0x34) }

                    1 -> RSAPublicKey(
                        modulus = readBytes(0x100),
                        exponent = read<Int>(),
                    ).also { skip(0x34) }

                    2 -> ECCPublicKey(
                        key = readBytes(0x3c),
                    ).also { skip(0x3c) }

                    else -> throw Exception("Unknown key type: $keyType")
                }
                Certificate(
                    signatureType,
                    signature,
                    issuer,
                    keyType,
                    name,
                    expirationTime,
                    pubkey,
                )
            }
        }
    }
}
