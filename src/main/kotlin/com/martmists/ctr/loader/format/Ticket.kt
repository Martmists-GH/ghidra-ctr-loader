package com.martmists.ctr.loader.format

import com.martmists.ctr.reader.Reader

data class Ticket(
    val signatureType: Int,
    val signature: ByteArray,
    val issuer: ByteArray,
    val pubkey: ECCPublicKey,
    val version: Byte,
    val caCrlVersion: Byte,
    val signerCrlVersion: Byte,
    val titleKey: ByteArray,
    val ticketId: Long,
    val consoleId: Int,
    val titleId: Long,
    val ticketVersion: Short,
    val licenseType: Byte,
    val keyYIndex: Byte,
    val eshopId: Int,
    val audit: Byte,
    val limits: ByteArray,
    val contentIndex: ByteArray,
) {
    companion object {
        fun parse(reader: Reader): Ticket {
            return reader.withEndian(false) {
                val signatureType = read<Int>()
                val signature = when (signatureType) {
                    0x010000, 0x010003 -> readBytes(0x200).also { skip(0x3c) }
                    0x010001, 0x010004 -> readBytes(0x100).also { skip(0x3c) }
                    0x010002, 0x010005 -> readBytes(0x3c).also { skip(0x40) }
                    else -> throw Exception("Unknown signature type: $signatureType")
                }
                val issuer = readBytes(64)
                val pubkey = ECCPublicKey(
                    key = readBytes(60),
                )
                val version = read<Byte>()
                val caCrlVersion = read<Byte>()
                val signerCrlVersion = read<Byte>()
                val titleKey = readBytes(16)
                skip(1)
                val ticketId = read<Long>()
                val consoleId = read<Int>()
                val titleId = read<Long>()
                skip(2)
                val ticketVersion = read<Short>()
                skip(8)
                val licenseType = read<Byte>()
                val keyYIndex = read<Byte>()
                skip(42)
                val eshopId = read<Int>()
                skip(1)
                val audit = read<Byte>()
                skip(66)
                val limits = readBytes(64)
                val pos = tell()
                skip(4)
                val size = read<Int>()
                seek(pos)
                val contentIndex = readBytes(size)
                Ticket(
                    signatureType,
                    signature,
                    issuer,
                    pubkey,
                    version,
                    caCrlVersion,
                    signerCrlVersion,
                    titleKey,
                    ticketId,
                    consoleId,
                    titleId,
                    ticketVersion,
                    licenseType,
                    keyYIndex,
                    eshopId,
                    audit,
                    limits,
                    contentIndex,
                )
            }
        }
    }
}
