package com.martmists.ctr.loader.format

data class CIAHeader(
    val archiveHeaderSize: Int,
    val type: Short,
    val version: Short,
    val certificateChainSize: Int,
    val ticketSize: Int,
    val tmdSize: Int,
    val metaSize: Int,
    val contentSize: Long,
    val contentIndex_8192: ByteArray,
)
