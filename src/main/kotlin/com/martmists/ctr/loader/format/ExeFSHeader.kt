package com.martmists.ctr.loader.format

data class ExeFSHeader(
    val fileHeaders_10: List<ExeFSFileHeader>,
    val reserved_32: ByteArray,
    val fileHashes_320: ByteArray
) {
    data class ExeFSFileHeader(
        val filename_8: String,
        val offset: Int,
        val size: Int
    )
}
