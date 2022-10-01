package com.martmists.ctr.analysis

import com.martmists.ctr.ext.reader
import com.martmists.ctr.loader.format.CRO0Header
import ghidra.app.services.AbstractAnalyzer
import ghidra.app.services.AnalysisPriority
import ghidra.app.services.AnalyzerType
import ghidra.app.util.bin.BinaryReader
import ghidra.app.util.bin.MemoryByteProvider
import ghidra.app.util.importer.MessageLog
import ghidra.program.flatapi.FlatProgramAPI
import ghidra.program.model.address.AddressSetView
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor

class CROAnalyzer : AbstractAnalyzer("CRO Analyzer", "Analyzes CRO files", AnalyzerType.BYTE_ANALYZER) {
    // TODO: Fix this

    init {
        priority = AnalysisPriority.FORMAT_ANALYSIS.before()
        setDefaultEnablement(false)
        setSupportsOneTimeAnalysis()
    }

    override fun canAnalyze(program: Program): Boolean {
        if (program.memory.blocks.isEmpty()) {
            return false
        }
        val provider = MemoryByteProvider.createMemoryBlockByteProvider(program.memory, program.memory.getBlock("header") ?: return false)
        val reader = BinaryReader(provider, true)
        return reader.readAsciiString(0x80, 4) == "CRO0"
    }

    private fun getSegmentName(segment: Int) = when (segment) {
        0 -> ".text"
        1 -> ".rodata"
        2 -> ".data"
        else -> throw IllegalArgumentException("Invalid segment $segment")
    }

    override fun added(program: Program, set: AddressSetView, monitor: TaskMonitor, log: MessageLog): Boolean {
        if (!resolveImports(program, monitor)) {
            return false
        }

        applyStructs(program, monitor)

        return true
    }

    private fun resolveImports(program: Program, monitor: TaskMonitor): Boolean {
        val provider = MemoryByteProvider.createMemoryBlockByteProvider(program.memory, program.memory.getBlock("header") ?: return false)
        val tableProvider = MemoryByteProvider.createMemoryBlockByteProvider(program.memory, program.memory.getBlock("tables") ?: return false)

        val header = provider.getInputStream(0).reader {
            read<CRO0Header>()
        }

        tableProvider.getInputStream(0).reader {
            seek(header.importModuleTableOffset - header.segmentTableOffset)
            val modules = readList<CRO0Header.ImportModuleTableEntry>(header.importModuleTableNum)

            for (mod in modules) {
                seek(mod.nameOffset - header.segmentTableOffset)
                val moduleName = readNullTerminatedString()

                val library = program.externalManager.getExternalLibrary(moduleName) ?: throw IllegalStateException("Library $moduleName not assigned!")
                val libraryProgram = library.symbol.program
                val api = FlatProgramAPI(libraryProgram, monitor)

                seek(mod.anonymousHeadOffset - header.segmentTableOffset)
                val anonymousImports = readList<CRO0Header.AnonymousImportTableEntry>(mod.anonymousImportNum)

                for (import in anonymousImports) {
                    seek(import.segmentOffset - header.segmentTableOffset)
                    val importSegment = import.segmentOffset and 0xF
                    val importOffset = import.segmentOffset shr 4

                    val block = libraryProgram.memory.getBlock(getSegmentName(importSegment))
                    val addr = block.start.add(importOffset.toLong() - block.start.offset)

                    api.createFunction(addr, "${moduleName}_anonymous_${importSegment}_${importOffset.toString(16)}")
                }
            }
            // Get all imports
        }

        return true
    }

    private fun applyStructs(program: Program, monitor: TaskMonitor) {
        val api = FlatProgramAPI(program, monitor)
        val headerBlock = program.memory.getBlock("header")
        val headerProvider = MemoryByteProvider.createMemoryBlockByteProvider(program.memory, headerBlock)

        val header = headerProvider.getInputStream(0).reader {
            read<CRO0Header>()
        }

        api.createData(headerBlock.start, program.dataTypeManager.getDataType("/CRO0Header"))

        for (i in 0 until header.segmentTableNum) {
            val dt = program.dataTypeManager.getDataType("/SegmentTableEntry")
            api.createData(headerBlock.start.add(header.segmentTableOffset.toLong() + i * dt.length), dt)
        }

        for (i in 0 until header.namedExportTableNum) {
            val dt = program.dataTypeManager.getDataType("/NamedExportTableEntry")
            api.createData(headerBlock.start.add(header.namedExportTableOffset.toLong() + i * dt.length), dt)
        }

        for (i in 0 until header.indexedExportTableNum) {
            val dt = program.dataTypeManager.getDataType("/IndexedExportTableEntry")
            api.createData(headerBlock.start.add(header.indexedExportTableOffset.toLong() + i * dt.length), dt)
        }

        for (i in 0 until header.importModuleTableNum) {
            val dt = program.dataTypeManager.getDataType("/ImportModuleTableEntry")
            api.createData(headerBlock.start.add(header.importModuleTableOffset.toLong() + i * dt.length), dt)
        }

        for (i in 0 until header.namedImportTableNum) {
            val dt = program.dataTypeManager.getDataType("/NamedImportTableEntry")
            api.createData(headerBlock.start.add(header.namedImportTableOffset.toLong() + i * dt.length), dt)
        }

        for (i in 0 until header.indexedImportTableNum) {
            val dt = program.dataTypeManager.getDataType("/IndexedImportTableEntry")
            api.createData(headerBlock.start.add(header.indexedImportTableOffset.toLong() + i * dt.length), dt)
        }
    }
}
