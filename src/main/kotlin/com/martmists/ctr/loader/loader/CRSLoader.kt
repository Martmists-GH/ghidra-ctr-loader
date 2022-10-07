package com.martmists.ctr.loader.loader

import com.martmists.ctr.ext.reader
import com.martmists.ctr.loader.format.CRO0Header
import com.martmists.ctr.loader.format.NCCHExHeader
import ghidra.app.util.MemoryBlockUtils
import ghidra.app.util.bin.BinaryReader
import ghidra.app.util.bin.ByteProvider
import ghidra.app.util.importer.MessageLog
import ghidra.formats.gfilesystem.FileSystemService
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor


class CRSLoader : CROLoader() {
    override fun getName() = "CRS Loader"

    override fun isValid(provider: ByteProvider): Boolean {
        val reader = BinaryReader(provider, true)
        return reader.readAsciiString(0x80, 4) == "CRO0" && provider.name.endsWith(".crs")
    }

    override fun createSegmentsFromFile(provider: ByteProvider, program: Program, monitor: TaskMonitor, log: MessageLog) {
        TODO()
    }

    override fun createSegmentsFromCXI(provider: ByteProvider, program: Program, monitor: TaskMonitor, log: MessageLog) {
        val cxiProvider = FileSystemService.getInstance().getByteProvider(provider.fsrl.fs.container, true, monitor)
        val codeBinProvider = FileSystemService.getInstance().getByteProvider(provider.fsrl.fs.withPath("/exefs/.code"), true, monitor)

        provider.getInputStream(0).reader {
            val header = read<CRO0Header>()

            val headerBytes = MemoryBlockUtils.createFileBytes(program, provider, 0, 0x312, monitor)
            MemoryBlockUtils.createInitializedBlock(program, false, "header", program.imageBase, headerBytes, 0, 0x312, "", null, true, false, false, log)

            val tablesBytes = MemoryBlockUtils.createFileBytes(program, provider, header.segmentTableOffset.toLong(), (header.dataOffset - header.segmentTableOffset).toLong(), monitor)
            MemoryBlockUtils.createInitializedBlock(program, false, "tables", program.imageBase.add(header.segmentTableOffset.toLong()), tablesBytes, 0, (header.dataOffset - header.segmentTableOffset).toLong(), "", null, true, true, false, log)

            val nameBytes = MemoryBlockUtils.createFileBytes(program, provider, header.moduleNameOffset.toLong(), header.moduleNameSize.toLong(), monitor)
            MemoryBlockUtils.createInitializedBlock(program, false, "name", program.imageBase.add(header.moduleNameOffset.toLong()), nameBytes, 0, header.moduleNameSize.toLong(), "", null, true, true, false, log)

            cxiProvider.getInputStream(0).reader {
                seek(0x200)
                val ncchEx = read<NCCHExHeader>()

                var codeOffset = 0L
                val codeSetMap = mapOf(
                    ".text" to ncchEx.sci.textCodeSetInfo,
                    ".rodata" to ncchEx.sci.readOnlyCodeSetInfo,
                    ".data" to ncchEx.sci.dataCodeSetInfo,
                )

                val aligned = codeSetMap.values.sumOf { it.size } < codeBinProvider.length()

                seek(header.segmentTableOffset)
                val segments = readList<CRO0Header.SegmentTableEntry>(header.segmentTableNum)
                for (segment in segments) {
                    if (segment.size == 0 || program.memory.getBlock(getSegmentName(segment.id)) != null) {
                        continue
                    }

                    val segmentName = getSegmentName(segment.id)
                    val (r, w, x) = getSegmentPermissions(segment.id)

                    when (segment.id) {
                        0, 1, 2 -> {
                            val codeSet = codeSetMap[segmentName]!!
                            val regionSize = if (aligned) codeSet.physRegionSize * 0x1000L else codeSet.size.toLong()
                            val segmentBytes = MemoryBlockUtils.createFileBytes(program, codeBinProvider, codeOffset, regionSize, monitor)

                            MemoryBlockUtils.createInitializedBlock(program, false, segmentName, program.imageBase.add(codeSet.address.toLong()), segmentBytes, 0, regionSize, "", null, r, w, x, log)
                            codeOffset += regionSize
                        }
                        3 -> {
                            var offset = segment.offset
                            if (offset == 0) {
                                offset = 0x00800000
                            }
                            MemoryBlockUtils.createUninitializedBlock(program, false, segmentName, program.imageBase.add(offset.toLong()), segment.size.toLong(), "", null, r, w, x, log)
                        }
                        else -> throw IllegalStateException("Unknown segment ID ${segment.id}")
                    }
                }
            }
        }
    }
}
