package com.martmists.ctr.script

import com.martmists.ctr.ext.reader
import com.martmists.ctr.loader.format.CRO0Header
import ghidra.app.script.GhidraScript
import ghidra.app.util.bin.MemoryByteProvider
import ghidra.program.flatapi.FlatProgramAPI
import ghidra.program.model.listing.Library
import ghidra.program.model.symbol.SourceType

open class CROStructPlacementImpl : GhidraScript() {
    override fun run() {
        val api = FlatProgramAPI(currentProgram, monitor)
        val headerBlock = currentProgram.memory.getBlock("header")
        val headerProvider = MemoryByteProvider.createMemoryBlockByteProvider(currentProgram.memory, headerBlock)

        val header = headerProvider.getInputStream(0).reader {
            read<CRO0Header>()
        }

        api.createData(headerBlock.start, currentProgram.dataTypeManager.getDataType("/CRO0Header"))

        for (i in 0 until header.segmentTableNum) {
            val dt = currentProgram.dataTypeManager.getDataType("/SegmentTableEntry")
            api.createData(headerBlock.start.add(header.segmentTableOffset.toLong() + i * dt.length), dt)
        }

        for (i in 0 until header.namedExportTableNum) {
            val dt = currentProgram.dataTypeManager.getDataType("/NamedExportTableEntry")
            api.createData(headerBlock.start.add(header.namedExportTableOffset.toLong() + i * dt.length), dt)
        }
        for (i in 0 until header.indexedExportTableNum) {
            val dt = currentProgram.dataTypeManager.getDataType("/IndexedExportTableEntry")
            api.createData(headerBlock.start.add(header.indexedExportTableOffset.toLong() + i * dt.length), dt)
        }

        for (i in 0 until header.importModuleTableNum) {
            val dt = currentProgram.dataTypeManager.getDataType("/ImportModuleTableEntry")
            api.createData(headerBlock.start.add(header.importModuleTableOffset.toLong() + i * dt.length), dt)
        }

        for (i in 0 until header.namedImportTableNum) {
            val dt = currentProgram.dataTypeManager.getDataType("/NamedImportTableEntry")
            api.createData(headerBlock.start.add(header.namedImportTableOffset.toLong() + i * dt.length), dt)
        }

        for (i in 0 until header.indexedImportTableNum) {
            val dt = currentProgram.dataTypeManager.getDataType("/IndexedImportTableEntry")
            api.createData(headerBlock.start.add(header.indexedImportTableOffset.toLong() + i * dt.length), dt)
        }

        for (i in 0 until header.anonymousImportTableNum) {
            val dt = currentProgram.dataTypeManager.getDataType("/AnonymousImportTableEntry")
            api.createData(headerBlock.start.add(header.anonymousImportTableOffset.toLong() + i * dt.length), dt)
        }

        for (i in 0 until header.relocationPatchesNum) {
            val dt = currentProgram.dataTypeManager.getDataType("/PatchEntry")
            api.createData(headerBlock.start.add(header.relocationPatchesOffset.toLong() + i * dt.length), dt)
        }
    }
}
