package com.martmists.ctr.loader.format

data class IVFCHeader(
    val magic_IVFC: String,
    val mgcNumber: Int,
    val masterHashSize: Int,
    val level1LogicalOffset: Long,
    val level1HashDataSize: Long,
    val level1BlockSize: Int,
    val reserved1: Int,
    val level2LogicalOffset: Long,
    val level2HashDataSize: Long,
    val level2BlockSize: Int,
    val reserved2: Int,
    val level3LogicalOffset: Long,
    val level3HashDataSize: Long,
    val level3BlockSize: Int,
    val reserved3: Long,
    val infoSize: Int,
) {
    data class Level3Header(
        val length: Int,
        val directoryHashTableOffset: Int,
        val directoryHashTableSize: Int,
        val directoryMetaTableOffset: Int,
        val directoryMetaTableSize: Int,
        val fileHashTableOffset: Int,
        val fileHashTableSize: Int,
        val fileMetaTableOffset: Int,
        val fileMetaTableSize: Int,
        val fileDataOffset: Int,
    ) {
        data class DirectoryMetadata(
            val parentOffset: Int,
            val siblingOffset: Int,
            val childDirectoryOffset: Int,
            val childFileOffset: Int,
            val nextDirectoryInBucketOffset: Int,
            val name_size: Int,
            val name: String,
            val align_4: Int,
        )

        data class FileMetadata(
            val directoryOffset: Int,
            val siblingOffset: Int,
            val dataOffset: Long,
            val dataSize: Long,
            val nextFileInBucketOffset: Int,
            val name_size: Int,
            val name: String,
            val align_4: Int,
        )
    }
}
