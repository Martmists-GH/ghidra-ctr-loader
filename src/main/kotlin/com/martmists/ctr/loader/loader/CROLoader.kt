package com.martmists.ctr.loader.loader

import com.martmists.ctr.ext.reader
import com.martmists.ctr.loader.format.CRO0Header
import com.martmists.ctr.loader.struct.*
import ghidra.app.util.MemoryBlockUtils
import ghidra.app.util.Option
import ghidra.app.util.bin.BinaryReader
import ghidra.app.util.bin.ByteProvider
import ghidra.app.util.cparser.C.CParser
import ghidra.app.util.importer.MessageLog
import ghidra.app.util.opinion.AbstractLibrarySupportLoader
import ghidra.app.util.opinion.LoadSpec
import ghidra.program.flatapi.FlatProgramAPI
import ghidra.program.model.address.Address
import ghidra.program.model.data.DataTypeConflictHandler
import ghidra.program.model.lang.LanguageCompilerSpecPair
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.ExternalLocation
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor
import java.nio.ByteBuffer
import java.nio.ByteOrder


open class CROLoader : AbstractLibrarySupportLoader() {
    override fun getName() = "CRO Loader"

    override fun findSupportedLoadSpecs(provider: ByteProvider): MutableCollection<LoadSpec> {
        val loadSpecs = mutableListOf<LoadSpec>()
        val reader = BinaryReader(provider, true)

        if (reader.readAsciiString(0x80, 4) == "CRO0" && !provider.name.endsWith(".crs")) {
            // TODO: Consider other ARM versions
            loadSpecs.add(LoadSpec(this, 0, LanguageCompilerSpecPair("ARM:LE:32:v6", "default"), true))
        }

        return loadSpecs
    }

    override fun load(
        provider: ByteProvider,
        loadSpec: LoadSpec,
        options: MutableList<Option>,
        program: Program,
        monitor: TaskMonitor,
        log: MessageLog,
    ) {
        createDataTypes(program)
        createSegments(provider, program, monitor, log)
        declareImportsAndExports(program, provider, monitor, log)
    }

    protected open fun createDataTypes(program: Program) {
        for (struct in listOf(
            SegmentOffsetStruct,
            PatchEntryStruct,
            SegmentTableEntryStruct,
            NamedExportTableEntryStruct,
            IndexedExportTableEntryStruct,
            NamedImportTableEntryStruct,
            IndexedImportTableEntryStruct,
            AnonymousImportTableEntryStruct,
            ImportModuleTableEntryStruct,
            CROHeaderStruct,
        )) {
            val manager = program.dataTypeManager
            val parser = CParser(manager)
            val dt = parser.parse(struct)
            manager.addDataType(dt, DataTypeConflictHandler.REPLACE_HANDLER)
        }
    }

    private fun getSegmentName(segment: Int) = when (segment) {
        0 -> ".text"
        1 -> ".rodata"
        2 -> ".data"
        else -> throw IllegalArgumentException("Invalid segment $segment")
    }

    protected open fun createSegments(provider: ByteProvider, program: Program, monitor: TaskMonitor, log: MessageLog) {
        provider.getInputStream(0).reader {
            val header = read<CRO0Header>()

            seek(header.segmentTableOffset)
            val segments = readList<CRO0Header.SegmentTableEntry>(header.segmentTableNum)

            val headerBytes = MemoryBlockUtils.createFileBytes(program, provider, 0, 0x312, monitor)
            MemoryBlockUtils.createInitializedBlock(program, false, "header", program.imageBase.add(0x600000), headerBytes, 0, 0x312, "", null, true, false, false, log)

            val tablesBytes = MemoryBlockUtils.createFileBytes(program, provider, header.segmentTableOffset.toLong(), (header.dataOffset - header.segmentTableOffset).toLong(), monitor)
            MemoryBlockUtils.createInitializedBlock(program, false, "tables", program.imageBase.add(0x600000L + header.segmentTableOffset.toLong()), tablesBytes, 0, (header.dataOffset - header.segmentTableOffset).toLong(), "", null, true, true, false, log)

            for (segment in segments) {
                if (segment.size == 0) {
                    continue
                }

                val fileBytes = MemoryBlockUtils.createFileBytes(program, provider, segment.offset.toLong(), segment.size.toLong(), monitor)

                when (segment.id) {
                    0 -> {
                        MemoryBlockUtils.createInitializedBlock(program, false, ".text", program.addressFactory.defaultAddressSpace.getAddress(segment.offset.toLong()), fileBytes, 0, segment.size.toLong(), "", null, true, false, true, log)
                    }
                    1 -> {
                        MemoryBlockUtils.createInitializedBlock(program, false, ".rodata", program.addressFactory.defaultAddressSpace.getAddress(segment.offset.toLong()), fileBytes, 0, segment.size.toLong(), "", null, true, false, false, log)
                    }
                    2 -> {
                        MemoryBlockUtils.createInitializedBlock(program, false, ".data", program.addressFactory.defaultAddressSpace.getAddress(segment.offset.toLong()), fileBytes, 0, segment.size.toLong(), "", null, true, true, false, log)
                    }
                    3 -> {
                        continue
                    }
                    else -> throw IllegalStateException("Unknown segment ID ${segment.id}")
                }
            }
        }
    }

    protected open fun declareImportsAndExports(program: Program, provider: ByteProvider, monitor: TaskMonitor, log: MessageLog) {
        val api = FlatProgramAPI(program, monitor)
        provider.getInputStream(0).reader {
            val header = read<CRO0Header>()

            val numExternals = header.namedImportTableNum + header.indexedImportTableNum + header.anonymousImportTableNum

            var externalsStart = program.addressFactory.defaultAddressSpace.getAddress(0x100000000 - (numExternals + 1) * 4L)
            fun externalAddr(): Address {
                val addr = externalsStart
                externalsStart = externalsStart.add(4)
                return addr
            }

            if (numExternals > 0) {
                MemoryBlockUtils.createUninitializedBlock(program, false, "imports", externalsStart, numExternals * 4L, "", null, true, false, false, log)
            }

            seek(header.importModuleTableOffset)
            val importModules = readList<CRO0Header.ImportModuleTableEntry>(header.importModuleTableNum)

            program.externalManager.addExternalLibraryName("|named_exports|", SourceType.IMPORTED)
            for (module in importModules) {
                seek(module.nameOffset)
                val name = readNullTerminatedString()
                program.externalManager.addExternalLibraryName(name, SourceType.IMPORTED)
            }

            // Add symbols for exports
            seek(header.moduleNameOffset)
            val moduleName = readString(header.moduleNameSize)

            seek(header.namedExportTableOffset)
            val namedExports = readList<CRO0Header.NamedExportTableEntry>(header.namedExportTableNum)
            for (export in namedExports) {
                seek(export.nameOffset)
                val name = readNullTerminatedString()
                val segment = export.segmentOffset and 0xF
                val offset = export.segmentOffset shr 4
                val block = program.memory.getBlock(getSegmentName(segment))
                program.symbolTable.createLabel(block.start.add(offset.toLong()), name, SourceType.IMPORTED)
                api.addEntryPoint(block.start.add(offset.toLong()))
            }

            seek(header.indexedExportTableOffset)
            val indexedExports = readList<CRO0Header.IndexedExportTableEntry>(header.indexedExportTableNum)
            for ((index, export) in indexedExports.withIndex()) {
                val segment = export.segmentOffset and 0xF
                val offset = export.segmentOffset shr 4
                val block = program.memory.getBlock(getSegmentName(segment))
                program.symbolTable.createLabel(block.start.add(offset.toLong()), "${moduleName}_indexed_${index}", SourceType.IMPORTED)
                api.addEntryPoint(block.start.add(offset.toLong()))
            }

            fun readPatches(offset: Int): List<CRO0Header.PatchEntry> {
                seek(offset)
                val patches = mutableListOf<CRO0Header.PatchEntry>()
                do {
                    val patch = read<CRO0Header.PatchEntry>()
                    patches.add(patch)
                } while (patch.segmentIndex == 0.toByte())
                return patches
            }

            fun insertPatch(patch: CRO0Header.PatchEntry, function: ExternalLocation, name: String) {
                val segment = patch.segmentOffset and 0xF
                val offset = patch.segmentOffset shr 4
                val block = program.memory.getBlock(getSegmentName(segment))
                val addr = block.start.add(offset.toLong())
                // Create jump to func

                val arr = ByteArray(4)
                when (patch.patchType) {
                    2.toUByte() -> {
                        // Absolute jump
                        ByteBuffer.wrap(arr).order(ByteOrder.LITTLE_ENDIAN).putInt(function.address.offset.toInt())
                    }
                    3.toUByte() -> {
                        // Relative jump
                        ByteBuffer.wrap(arr).order(ByteOrder.LITTLE_ENDIAN).putInt(function.address.offset.toInt() - addr.offset.toInt())
                    }
                    else -> {
                        throw IllegalStateException("Unknown patch type ${patch.patchType}")
                    }
                }
                program.memory.setBytes(addr, arr)
            }

            // Imports
            seek(header.namedImportTableOffset)
            val namedImports = readList<CRO0Header.NamedImportTableEntry>(header.namedImportTableNum)
            for (import in namedImports) {
                seek(import.nameOffset)
                val name = readNullTerminatedString()
                val patches = readPatches(import.listOffset)

                val addr = externalAddr()
                val func = program.externalManager.addExtFunction("|named_exports|", name, addr, SourceType.IMPORTED)
                api.createFunction(addr, name)
                for (patch in patches) {
                    insertPatch(patch, func, name)
                }
            }

            for (module in importModules) {
                seek(module.nameOffset)
                val name = readNullTerminatedString()

                seek(module.indexedHeadOffset)
                val indexedImports = readList<CRO0Header.IndexedImportTableEntry>(module.indexedImportNum)

                for (import in indexedImports) {
                    val addr = externalAddr()
                    val func = program.externalManager.addExtFunction(name, "${name}_indexed_${import.indexOffset}", addr, SourceType.IMPORTED)
                    api.createFunction(addr, "${name}_indexed_${import.indexOffset}")
                    val patches = readPatches(import.listOffset)
                    for (patch in patches) {
                        insertPatch(patch, func, "${name}_indexed_${import.indexOffset}")
                    }
                }

                seek(module.anonymousHeadOffset)
                val anonymousImports = readList<CRO0Header.AnonymousImportTableEntry>(module.anonymousImportNum)

                for (import in anonymousImports) {
                    val importSegment = import.segmentOffset and 0xF
                    val importOffset = import.segmentOffset shr 4

                    val addr = externalAddr()
                    val func = program.externalManager.addExtFunction(name, "${name}_anonymous_${importSegment}_${importOffset.toString(16)}", addr, SourceType.IMPORTED)
                    api.createFunction(addr, "${name}_anonymous_${importSegment}_${importOffset.toString(16)}")
                    val patches = readPatches(import.listOffset)
                    for (patch in patches) {
                        insertPatch(patch, func, "${name}_anonymous_${importSegment}_${importOffset.toString(16)}")
                    }
                }
            }
        }
    }

}
