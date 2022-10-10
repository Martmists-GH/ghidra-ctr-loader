package com.martmists.ctr.script

import com.martmists.ctr.ext.reader
import com.martmists.ctr.loader.format.CRO0Header
import ghidra.app.script.GhidraScript
import ghidra.app.util.bin.MemoryByteProvider
import ghidra.program.model.address.Address
import ghidra.program.model.data.DataType

open class CROStructPlacementImpl : GhidraScript() {
    private fun createDataOverride(address: Address, datatype: DataType) {
        clearListing(address, address.add(datatype.length - 1L))
        createData(address, datatype)
    }
    
    override fun run() {
        val headerBlock = currentProgram.memory.getBlock("header")
        val headerProvider = MemoryByteProvider.createMemoryBlockByteProvider(currentProgram.memory, headerBlock)

        val header = headerProvider.getInputStream(0).reader {
            read<CRO0Header>()
        }

        createDataOverride(headerBlock.start, currentProgram.dataTypeManager.getDataType("/CRO0Header"))

        for (i in 0 until header.segmentTableNum) {
            val dt = currentProgram.dataTypeManager.getDataType("/SegmentTableEntry")
            createDataOverride(headerBlock.start.add(header.segmentTableOffset.toLong() + i * dt.length), dt)
        }

        for (i in 0 until header.namedExportTableNum) {
            val dt = currentProgram.dataTypeManager.getDataType("/NamedExportTableEntry")
            createDataOverride(headerBlock.start.add(header.namedExportTableOffset.toLong() + i * dt.length), dt)
        }
        for (i in 0 until header.indexedExportTableNum) {
            val dt = currentProgram.dataTypeManager.getDataType("/IndexedExportTableEntry")
            createDataOverride(headerBlock.start.add(header.indexedExportTableOffset.toLong() + i * dt.length), dt)
        }

        for (i in 0 until header.importModuleTableNum) {
            val dt = currentProgram.dataTypeManager.getDataType("/ImportModuleTableEntry")
            createDataOverride(headerBlock.start.add(header.importModuleTableOffset.toLong() + i * dt.length), dt)
        }

        for (i in 0 until header.namedImportTableNum) {
            val dt = currentProgram.dataTypeManager.getDataType("/NamedImportTableEntry")
            createDataOverride(headerBlock.start.add(header.namedImportTableOffset.toLong() + i * dt.length), dt)
        }

        for (i in 0 until header.indexedImportTableNum) {
            val dt = currentProgram.dataTypeManager.getDataType("/IndexedImportTableEntry")
            createDataOverride(headerBlock.start.add(header.indexedImportTableOffset.toLong() + i * dt.length), dt)
        }

        for (i in 0 until header.anonymousImportTableNum) {
            val dt = currentProgram.dataTypeManager.getDataType("/AnonymousImportTableEntry")
            createDataOverride(headerBlock.start.add(header.anonymousImportTableOffset.toLong() + i * dt.length), dt)
        }

        for (i in 0 until header.relocationPatchesNum) {
            val dt = currentProgram.dataTypeManager.getDataType("/PatchEntry")
            createDataOverride(headerBlock.start.add(header.relocationPatchesOffset.toLong() + i * dt.length), dt)
        }
    }
}
