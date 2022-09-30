package com.martmists.ctr.loader.format

data class CRO0Header(
    val hashTable_128: ByteArray,
    val magic_CRO0: String,
    val nameOffset: Int,
    val nextLoadedCRO: Int,
    val previousLoadedCRO: Int,
    val fileSize: Int,
    val bssSize: Int,
    val unknown1: Long,  // Two ints, but keeping it short here
    val nnroControlObjectOffset: Int,
    val onLoadOffset: Int,
    val onExitOffset: Int,
    val onUnresolvedOffset: Int,
    val codeOffset: Int,
    val codeSize: Int,
    val dataOffset: Int,
    val dataSize: Int,
    val moduleNameOffset: Int,
    val moduleNameSize: Int,
    val segmentTableOffset: Int,
    val segmentTableNum: Int,
    val namedExportTableOffset: Int,
    val namedExportTableNum: Int,
    val indexedExportTableOffset: Int,
    val indexedExportTableNum: Int,
    val exportStringsOffset: Int,
    val exportStringsSize: Int,
    val exportTreeOffset: Int,
    val exportTreeNum: Int,
    val importModuleTableOffset: Int,
    val importModuleTableNum: Int,
    val importPatchesOffset: Int,
    val importPatchesNum: Int,
    val namedImportTableOffset: Int,
    val namedImportTableNum: Int,
    val indexedImportTableOffset: Int,
    val indexedImportTableNum: Int,
    val anonymousImportTableOffset: Int,
    val anonymousImportTableNum: Int,
    val importStringsOffset: Int,
    val importStringsSize: Int,
    val unknown2: Long,  // also two ints
    val relocationPatchesOffset: Int,
    val relocationPatchesNum: Int,
    val unknown3: Long,  // also two ints
) {
    data class SegmentTableEntry(
        val offset: Int,
        val size: Int,
        val id: Int,
    )

    data class NamedExportTableEntry(
        val nameOffset: Int,
        val segmentOffset: Int,
    )

    data class IndexedExportTableEntry(
        val segmentOffset: Int,
    )

    data class NamedImportTableEntry(
        val nameOffset: Int,
        val listOffset: Int,
    )

    data class IndexedImportTableEntry(
        val indexOffset: Int,
        val listOffset: Int,
    )

    data class AnonymousImportTableEntry(
        val segmentOffset: Int,
        val listOffset: Int,
    )

    data class ImportModuleTableEntry(
        val nameOffset: Int,
        val indexedHeadOffset: Int,
        val indexedImportNum: Int,
        val anonymousHeadOffset: Int,
        val anonymousImportNum: Int,
    )

    data class PatchEntry(
        val segmentOffset: Int,
        val patchType: UByte,
        val segmentIndex: Byte,
        val unknown1: Byte,
        val unknown2: Byte,
        val addend: Int,
    )
}
