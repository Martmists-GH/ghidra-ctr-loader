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
    init {
        priority = AnalysisPriority.FORMAT_ANALYSIS.before()
        setDefaultEnablement(true)
        setSupportsOneTimeAnalysis()
    }

    override fun canAnalyze(program: Program): Boolean {
        if (program.memory.blocks.isEmpty()) {
            return false
        }
        val provider = MemoryByteProvider.createMemoryBlockByteProvider(program.memory, program.memory.getBlock("ram"))
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
        val provider = MemoryByteProvider.createMemoryBlockByteProvider(program.memory, program.memory.blocks.maxBy { it.size })
        provider.getInputStream(0).reader {
            val header = read<CRO0Header>()
            seek(header.importModuleTableOffset)
            val modules = readList<CRO0Header.ImportModuleTableEntry>(header.importModuleTableNum)

            for (mod in modules) {
                seek(mod.nameOffset)
                val moduleName = readNullTerminatedString()

                val library = program.externalManager.getExternalLibrary(moduleName) ?: throw IllegalStateException("Library $moduleName not assigned!")
                val libraryProgram = library.symbol.program
                val api = FlatProgramAPI(libraryProgram, monitor)

                seek(mod.anonymousHeadOffset)
                val anonymousImports = readList<CRO0Header.AnonymousImportTableEntry>(mod.anonymousImportNum)

                for (import in anonymousImports) {
                    seek(import.segmentOffset)
                    val importSegment = import.segmentOffset and 0xF
                    val importOffset = import.segmentOffset shr 4

                    val block = libraryProgram.memory.getBlock(getSegmentName(importSegment))
                    val addr = block.start.add(importOffset.toLong())

                    api.createFunction(addr, "${moduleName}_anonymous_${importSegment}_${importOffset.toString(16)}")
                }
            }
            // Get all imports
        }

        return true
    }
}
