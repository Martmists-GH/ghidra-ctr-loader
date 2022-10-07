package com.martmists.ctr.common

import com.martmists.ctr.ext.reader
import com.martmists.ctr.ext.segOff
import com.martmists.ctr.ext.stripNulls
import com.martmists.ctr.loader.format.CRO0Header
import com.martmists.ctr.reader.Reader
import ghidra.app.util.bin.MemoryByteProvider
import ghidra.program.flatapi.FlatProgramAPI
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSet
import ghidra.program.model.listing.CodeUnit
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor
import java.nio.ByteBuffer
import java.nio.ByteOrder

interface CROUtilities {
    fun getSegmentPermissions(segment: Int) = when (segment) {
        0 -> Triple(true, false, true)
        1 -> Triple(true, false, false)
        2 -> Triple(true, true, false)
        3 -> Triple(true, true, false)
        else -> throw IllegalArgumentException("Invalid segment $segment")
    }

    fun getSegmentName(segment: Int) = when (segment) {
        0 -> ".text"
        1 -> ".rodata"
        2 -> ".data"
        3 -> ".bss"
        else -> throw IllegalArgumentException("Invalid segment $segment")
    }

    data class ModuleData(
        val name: String,
        val header: CRO0Header,
        val namedExports: Map<String, CRO0Header.NamedExportTableEntry>,
        val indexedExports: List<CRO0Header.IndexedExportTableEntry>,
        val namedImports: Map<String, CRO0Header.NamedImportTableEntry>,
        val importedModules: Map<String, ImportModuleData>,
    )
    data class ImportModuleData(
        val name: String,
        val indexed: List<CRO0Header.IndexedImportTableEntry>,
        val anonymous: List<CRO0Header.AnonymousImportTableEntry>,
    )

    fun Program.getModuleData(): ModuleData {
        val headerBlock = memory.getBlock("header") ?: throw IllegalStateException("No header block found")
        val tablesBlock = memory.getBlock("tables") ?: throw IllegalStateException("No tables block found")
        val nameBlock = memory.getBlock("name") ?: throw IllegalStateException("No name block found")
        val headerProvider = MemoryByteProvider.createMemoryBlockByteProvider(memory, headerBlock)
        val tableProvider = MemoryByteProvider.createMemoryBlockByteProvider(memory, tablesBlock)
        val nameProvider = MemoryByteProvider.createMemoryBlockByteProvider(memory, nameBlock)
        val relativeOffset = tablesBlock.start.offset - headerBlock.start.offset

        val header = headerProvider.getInputStream(0).reader {
            read<CRO0Header>()
        }

        return tableProvider.getInputStream(0).reader {
            val name = nameProvider.getInputStream(0).reader {
                readString(header.moduleNameSize).stripNulls()
            }

            seek(header.namedExportTableOffset - relativeOffset)
            val namedExports = readList<CRO0Header.NamedExportTableEntry>(header.namedExportTableNum).associateBy {
                seek(it.nameOffset - relativeOffset)
                val exportName = readNullTerminatedString()
                exportName
            }

            seek(header.indexedExportTableOffset - relativeOffset)
            val indexedExports = readList<CRO0Header.IndexedExportTableEntry>(header.indexedExportTableNum)

            seek(header.namedImportTableOffset - relativeOffset)
            val namedImports = readList<CRO0Header.NamedImportTableEntry>(header.namedImportTableNum).associateBy {
                seek(it.nameOffset - relativeOffset)
                val importName = readNullTerminatedString()
                importName
            }

            seek(header.importModuleTableOffset - relativeOffset)
            val importedModules = readList<CRO0Header.ImportModuleTableEntry>(header.importModuleTableNum).associate {
                seek(it.nameOffset - relativeOffset)
                val moduleName = readNullTerminatedString()

                seek(it.indexedHeadOffset - relativeOffset)
                val indexed = readList<CRO0Header.IndexedImportTableEntry>(it.indexedImportNum)

                seek(it.anonymousHeadOffset - relativeOffset)
                val anonymous = readList<CRO0Header.AnonymousImportTableEntry>(it.anonymousImportNum)

                moduleName to ImportModuleData(
                    moduleName,
                    indexed,
                    anonymous,
                )
            }

            ModuleData(
                name,
                header,
                namedExports,
                indexedExports,
                namedImports,
                importedModules,
            )
        }
    }

    fun Program.createFromReference(segment: Int, offset: Int, symName: String) {
        println("Creating $symName at $segment:$offset in $name")

        val segmentName = getSegmentName(segment)
        val block = memory.getBlock(segmentName) ?: throw IllegalStateException("No $segmentName block found")
        val address = block.start.add(offset.toLong())
        if (symbolTable.hasSymbol(address)) {
            // Already created or known
            return
        }

        if (segmentName == ".text") {
            // Create function
            symbolTable.createLabel(address, symName, SourceType.ANALYSIS)
            listing.createFunction(symName, address, AddressSet(address), SourceType.ANALYSIS)
        } else {
            // Create data
            symbolTable.createLabel(address, symName, SourceType.ANALYSIS)
        }
    }

    fun nextExportIndex(): Long

    fun Program.createReferenceTo(module: Program, segment: Int, offset: Int, symName: String, monitor: TaskMonitor): Address {
        val api = FlatProgramAPI(this, monitor)

        println("Creating reference to $symName in ${module.name} at ${getSegmentName(segment)}:${offset.toString(16)} in $name")
        monitor.message = "Creating reference to $symName in ${module.name} at ${getSegmentName(segment)}:${offset.toString(16)} in $name"

        val moduleNameBlock = module.memory.getBlock("name") ?: throw IllegalStateException("No name block found")
        val moduleName = MemoryByteProvider.createMemoryBlockByteProvider(module.memory, moduleNameBlock).getInputStream(0).reader {
            readString(moduleNameBlock.size.toInt()).stripNulls()
        }
        val segmentName = getSegmentName(segment)
        val moduleBlock = module.memory.getBlock(segmentName) ?: throw IllegalStateException("No $segmentName block found")
        val moduleAddress = moduleBlock.start.add(offset.toLong())
        val externalBlock = memory.getBlock("EXTERNALS") ?: throw IllegalStateException("No EXTERNALS block found")
        val externalAddress = externalBlock.start.add(nextExportIndex() * 4L)

        val sym = module.symbolTable.getSymbols(moduleAddress).firstOrNull()?.name ?: symName

        if (segmentName == ".text") {
            // Create function reference
            val loc = externalManager.addExtFunction(moduleName, sym, moduleAddress, SourceType.ANALYSIS)
            val func = api.createFunction(externalAddress, sym)
            func.setThunkedFunction(loc.function)
        } else {
            // Create data reference
            symbolTable.createLabel(externalAddress, symName, SourceType.ANALYSIS)
            listing.setComment(externalAddress, CodeUnit.REPEATABLE_COMMENT, "${sym}:{@program \"${module.domainFile.pathname}@${moduleAddress}\"}")
        }

        return externalAddress
    }

    fun Reader.readPatches(offset: Long): List<CRO0Header.PatchEntry> {
        seek(offset)
        val patches = mutableListOf<CRO0Header.PatchEntry>()
        do {
            val patch = read<CRO0Header.PatchEntry>()
            patches.add(patch)
        } while (patch.segmentIndex == 0.toByte())
        return patches
    }

    fun Program.applyPatches(offset: Int, address: Address) {
        val headerBlock = memory.getBlock("header") ?: throw IllegalStateException("No header block found")
        val tablesBlock = memory.getBlock("tables") ?: throw IllegalStateException("No tables block found")
        val tablesProvider = MemoryByteProvider.createMemoryBlockByteProvider(memory, tablesBlock)
        val relativeOffset = tablesBlock.start.offset - headerBlock.start.offset

        tablesProvider.getInputStream(0).reader {
            val patches = readPatches(offset - relativeOffset)
            for (patch in patches) {
                val (segment, segOffset) = patch.segmentOffset.segOff
                val block = memory.getBlock(getSegmentName(segment))
                val patchAddress = block.start.add(segOffset.toLong())

                val arr = ByteArray(4)
                when (patch.patchType) {
                    2.toUByte() -> {
                        // Absolute jump
                        ByteBuffer.wrap(arr).order(ByteOrder.LITTLE_ENDIAN).putInt(address.offset.toInt())
                    }
                    3.toUByte() -> {
                        // Relative jump
                        ByteBuffer.wrap(arr).order(ByteOrder.LITTLE_ENDIAN).putInt(address.offset.toInt() - patchAddress.offset.toInt())
                    }
                    else -> {
                        throw IllegalStateException("Unknown patch type ${patch.patchType}")
                    }
                }

                memory.setBytes(patchAddress, arr)
            }
        }
    }
}
