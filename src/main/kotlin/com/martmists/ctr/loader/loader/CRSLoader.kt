package com.martmists.ctr.loader.loader

import com.martmists.ctr.ext.reader
import com.martmists.ctr.loader.format.CRO0Header
import com.martmists.ctr.loader.format.NCCHExHeader
import com.martmists.ctr.loader.format.NCCHHeader
import ghidra.app.util.MemoryBlockUtils
import ghidra.app.util.bin.BinaryReader
import ghidra.app.util.bin.ByteProvider
import ghidra.app.util.importer.MessageLog
import ghidra.app.util.opinion.LoadSpec
import ghidra.formats.gfilesystem.FileSystemService
import ghidra.program.flatapi.FlatProgramAPI
import ghidra.program.model.lang.LanguageCompilerSpecPair
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor


class CRSLoader : CROLoader() {
    override fun getName() = "CRS Loader"

    override fun findSupportedLoadSpecs(provider: ByteProvider): MutableCollection<LoadSpec> {
        val loadSpecs = mutableListOf<LoadSpec>()
        val reader = BinaryReader(provider, true)

        if (reader.readAsciiString(0x80, 4) == "CRO0" && provider.name.endsWith(".crs")) {
            // TODO: Consider other ARM versions
            loadSpecs.add(LoadSpec(this, 0, LanguageCompilerSpecPair("ARM:LE:32:v6", "default"), true))
        }

        return loadSpecs
    }

    override fun createSegments(provider: ByteProvider, program: Program, monitor: TaskMonitor, log: MessageLog) {
        val cxiProvider = FileSystemService.getInstance().getByteProvider(provider.fsrl.fs.container, true, monitor)
        val codeBinProvider = FileSystemService.getInstance().getByteProvider(provider.fsrl.fs.withPath("/exefs/.code"), true, monitor)

        provider.getInputStream(0).reader {
            val header = read<CRO0Header>()

            val headerBytes = MemoryBlockUtils.createFileBytes(program, provider, 0, 0x312, monitor)
            MemoryBlockUtils.createInitializedBlock(program, false, "header", program.imageBase.add(0x600000), headerBytes, 0, 0x312, "", null, true, false, false, log)

            val tablesBytes = MemoryBlockUtils.createFileBytes(program, provider, header.segmentTableOffset.toLong(), (header.dataOffset - header.segmentTableOffset).toLong(), monitor)
            MemoryBlockUtils.createInitializedBlock(program, false, "tables", program.imageBase.add(0x600000L + header.segmentTableOffset), tablesBytes, 0, (header.dataOffset - header.segmentTableOffset).toLong(), "", null, true, true, false, log)

            cxiProvider.getInputStream(0).reader {
                seek(0x200)
                val ncchEx = read<NCCHExHeader>()

                val codeSetMap = mapOf(
                   ".text" to ncchEx.sci.textCodeSetInfo,
                   ".rodata" to ncchEx.sci.readOnlyCodeSetInfo,
                   ".data" to ncchEx.sci.dataCodeSetInfo,
                )

                val aligned = codeSetMap.values.sumOf { it.size } < codeBinProvider.length()

                var codeOffset = 0L
                for ((segmentName, codeSet) in codeSetMap) {
                    val regionSize = if (aligned) codeSet.physRegionSize * 0x1000L else codeSet.size.toLong()
                    val segmentBytes = MemoryBlockUtils.createFileBytes(program, codeBinProvider, codeOffset, regionSize, monitor)

                    when (segmentName) {
                        ".text" -> {
                            MemoryBlockUtils.createInitializedBlock(program, false, ".text", program.imageBase.add(codeSet.address.toLong()), segmentBytes, 0, regionSize, "", null, true, false, true, log)
                        }
                        ".rodata" -> {
                             MemoryBlockUtils.createInitializedBlock(program, false, ".rodata", program.imageBase.add(codeSet.address.toLong()), segmentBytes, 0, regionSize, "", null, true, false, false, log)
                        }
                        ".data" -> {
                            MemoryBlockUtils.createInitializedBlock(program, false, ".data", program.imageBase.add(codeSet.address.toLong()), segmentBytes, 0, regionSize, "", null, true, true, false, log)
                        }
                    }
                    codeOffset += regionSize
                }
            }
        }
    }
}
