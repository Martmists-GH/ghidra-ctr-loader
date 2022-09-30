package com.martmists.ctr.loader.struct

// struct SegmentOffset
// bits 0-3: segment ID
// bits 4-31: offset
val SegmentOffsetStruct = """struct SegmentOffset {
    int segment: 4;
    int offset: 28;
};"""

val PatchEntryStruct = """struct PatchEntry {
    struct SegmentOffset offset;
    byte type;
    byte segment;
    undefined unknown[2];
    int addend;
};"""

val SegmentTableEntryStruct = """struct SegmentTableEntry {
    void* offset;
    int size;
    int id;
};"""

val NamedExportTableEntryStruct = """struct NamedExportTableEntry {
    char* nameOffset;
    struct SegmentOffset segmentOffset;
};"""

val IndexedExportTableEntryStruct = """struct IndexedExportTableEntry {
    struct SegmentOffset segmentOffset;
};"""

val NamedImportTableEntryStruct = """struct NamedImportTableEntry {
    char* nameOffset;
    struct SegmentOffset segmentOffset;
};"""

val IndexedImportTableEntryStruct = """struct IndexedImportTableEntry {
    struct SegmentOffset segmentOffset;
};"""

val AnonymousImportTableEntryStruct = """struct AnonymousImportTableEntry {
    struct SegmentOffset segmentOffset;
    struct PatchEntry* patches;
};"""

val ImportModuleTableEntryStruct = """struct ImportModuleTableEntry {
    char* nameOffset;
    struct IndexedImportTableEntry* indexedHeadOffset;
    int indexedImportNum;
    struct AnonymousImportTableEntry* anonymousHeadOffset;
    int anonymousImportNum;
};"""

val CROHeaderStruct = """struct CRO0Header {
    byte hashTable_128[0x80];
    char magic_CRO0[4];
    int nameOffset;
    int nextLoadedCRO;
    int previousLoadedCRO;
    int fileSize;
    int bssSize;
    int unknown1[2];
    struct SegmentOffset nnroControlObjectOffset;
    struct SegmentOffset onLoadOffset;
    struct SegmentOffset onExitOffset;
    struct SegmentOffset onUnresolvedOffset;
    void* codeOffset;
    int codeSize;
    void* dataOffset;
    int dataSize;
    char* moduleNameOffset;
    int moduleNameSize;
    struct SegmentTableEntry* segmentTableOffset;
    int segmentTableNum;
    struct NamedExportTableEntry* namedExportTableOffset;
    int namedExportTableNum;
    struct IndexedExportTableEntry* indexedExportTableOffset;
    int indexedExportTableNum;
    char* exportStringsOffset;
    int exportStringsSize;
    void* exportTreeOffset;
    int exportTreeNum;
    struct ImportModuleTableEntry* importModuleTableOffset;
    int importModuleTableNum;
    struct PatchEntry* importPatchesOffset;
    int importPatchesNum;
    struct NamedImportTableEntry* namedImportTableOffset;
    int namedImportTableNum;
    struct IndexedImportTableEntry* indexedImportTableOffset;
    int indexedImportTableNum;
    struct AnonymousImportTableEntry* anonymousImportTableOffset;
    int anonymousImportTableNum;
    char* importStringsOffset;
    int importStringsSize;
    int unknown2[2];
    int relocationPatchesOffset;
    struct PatchEntry* relocationPatchesNum;
    int unknown3[2];
};"""
