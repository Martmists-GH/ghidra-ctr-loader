package com.martmists.ctr.loader.format

data class NCCHHeader(
    val signature_256: ByteArray,  // Size: 0x100
    val id: Int,
    val contentSize: Int,
    val partitionId: Long,
    val makerCode: Short,
    val version: Short,
    val hash_maybe: Int,
    val programId: Long,
    val reserved1_16: ByteArray,
    val logoRegionHash_32: ByteArray,
    val productCode_16: String,
    val extendedHeaderHash_32: ByteArray,
    val extendedHeaderSize: Int,
    val reserved2: Int,
    val flags: Long,
    val plainRegionOffset: Int,
    val plainRegionSize: Int,
    val logoRegionOffset: Int,
    val logoRegionSize: Int,
    val exefsOffset: Int,
    val exefsSize: Int,
    val exefsHashSize: Int,
    val reserved3: Int,
    val romfsOffset: Int,
    val romfsSize: Int,
    val romfsHashSize: Int,
    val reserved4: Int,
    val exefsHash_32: ByteArray,  // Size: 0x20
    val romfsHash_32: ByteArray,  // Size: 0x20
)
