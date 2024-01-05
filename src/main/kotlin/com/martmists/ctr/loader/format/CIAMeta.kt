package com.martmists.ctr.loader.format

data class CIAMeta(
    val dependencyModuleList_384: ByteArray,
    val reserved1_384: ByteArray,
    val coreVersion: Int,
    val reserved2_252: ByteArray,
    val iconData_14016: ByteArray,
)
