package com.martmists.ctr.loader.loader

import com.martmists.ctr.common.CROUtilities
import com.martmists.ctr.ext.hex
import com.martmists.ctr.ext.reader
import com.martmists.ctr.ext.segOff
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
import ghidra.program.model.data.DataTypeConflictHandler
import ghidra.program.model.data.FileDataTypeManager
import ghidra.program.model.lang.LanguageCompilerSpecPair
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.SourceType
import ghidra.util.task.TaskMonitor
import java.io.File
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.ByteOrder


open class CROLoader : AbstractLibrarySupportLoader(), CROUtilities {
    override fun getName() = "CRO Loader"

    private var exportIndex = 0L
    override fun nextExportIndex(): Long {
        return exportIndex++
    }

    open fun isValid(provider: ByteProvider): Boolean {
        val reader = BinaryReader(provider, true)
        return reader.readAsciiString(0x80, 4) == "CRO0" && !provider.name.endsWith(".crs")
    }

    override fun findSupportedLoadSpecs(provider: ByteProvider): MutableCollection<LoadSpec> {
        val loadSpecs = mutableListOf<LoadSpec>()

        if (isValid(provider)) {
            loadSpecs.add(LoadSpec(this, 0, LanguageCompilerSpecPair("ARM:LE:32:v7", "default"), true))
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
        createSegments(program, provider, monitor, log)
        declareImportsAndExports(program, provider, monitor, log)
        setLabels(program, provider, monitor)
        applyPatches(program, provider)
    }

    protected open fun createDataTypes(program: Program) {
        try {
//            val manager = FileDataTypeManager.createFileArchive(File("/ProjectStructs${FileDataTypeManager.SUFFIX}"));
            val manager = program.dataTypeManager

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
                val parser = CParser(manager)
                val dt = parser.parse(struct)
                manager.addDataType(dt, DataTypeConflictHandler.REPLACE_HANDLER)
            }
        } catch (e: IOException) {
            // ignore
        }
    }

    private fun createSegments(program: Program, provider: ByteProvider, monitor: TaskMonitor, log: MessageLog) {
        if (provider.fsrl.fs.container != null) {
            val parent = provider.fsrl.fs.container
            when {
                parent.path.endsWith(".cxi") -> {
                    createSegmentsFromCXI(provider, program, monitor, log)
                }
            }
        } else {
            createSegmentsFromFile(provider, program, monitor, log)
        }
    }

    protected open fun createSegmentsFromCXI(provider: ByteProvider, program: Program, monitor: TaskMonitor, log: MessageLog) {
        return createSegmentsFromFile(provider, program, monitor, log)
    }

    protected open fun createSegmentsFromFile(provider: ByteProvider, program: Program, monitor: TaskMonitor, log: MessageLog) {
        provider.getInputStream(0).reader {
            val header = read<CRO0Header>()

            seek(header.segmentTableOffset)
            val segments = readList<CRO0Header.SegmentTableEntry>(header.segmentTableNum)

            val headerBytes = MemoryBlockUtils.createFileBytes(program, provider, 0, 0x138, monitor)
            MemoryBlockUtils.createInitializedBlock(program, false, "header", program.imageBase, headerBytes, 0, 0x138, "", null, true, false, false, log)

            val tablesBytes = MemoryBlockUtils.createFileBytes(program, provider, header.segmentTableOffset.toLong(), (header.dataOffset - header.segmentTableOffset).toLong(), monitor)
            MemoryBlockUtils.createInitializedBlock(program, false, "tables", program.imageBase.add(header.segmentTableOffset.toLong()), tablesBytes, 0, (header.dataOffset - header.segmentTableOffset).toLong(), "", null, true, true, false, log)

            val nameBytes = MemoryBlockUtils.createFileBytes(program, provider, header.moduleNameOffset.toLong(), header.moduleNameSize.toLong(), monitor)
            MemoryBlockUtils.createInitializedBlock(program, false, "name", program.imageBase.add(header.moduleNameOffset.toLong()), nameBytes, 0, header.moduleNameSize.toLong(), "", null, true, true, false, log)

            for (segment in segments) {
                val segmentSize = when(segment.id) {
                    0 -> segment.size // maxOf(header.codeSize, segment.size)
                    1 -> segment.size
                    2 -> segment.size // maxOf(header.dataSize, segment.size)
                    3 -> maxOf(header.bssSize, segment.size)
                    else -> throw IllegalStateException("Unknown segment id ${segment.id}")
                }

                if (segmentSize == 0 || program.memory.getBlock(getSegmentName(segment.id)) != null) {
                    continue
                }

                val segmentName = getSegmentName(segment.id)
                val (r, w, x) = getSegmentPermissions(segment.id)

                when (segment.id) {
                    0, 1, 2 -> {
                        val fileBytes = MemoryBlockUtils.createFileBytes(program, provider, segment.offset.toLong(), segment.size.toLong(), monitor)
                        MemoryBlockUtils.createInitializedBlock(program, false, segmentName, program.imageBase.add(segment.offset.toLong()), fileBytes, 0, segmentSize.toLong(), "", null, r, w, x, log)
                    }
                    3 -> {
                        var offset = segment.offset
                        if (offset == 0) {
                            offset = 0x00800000
                        }
                        MemoryBlockUtils.createInitializedBlock(program, false, segmentName, program.imageBase.add(offset.toLong()), segmentSize.toLong(), "", null, r, w, x, log)
                    }
                    else -> throw IllegalStateException("Unknown segment ID ${segment.id}")
                }
            }
        }
    }

    protected open fun declareImportsAndExports(program: Program, provider: ByteProvider, monitor: TaskMonitor, log: MessageLog) {
        provider.getInputStream(0).reader {
            val header = read<CRO0Header>()

            val numExternals = header.namedImportTableNum + header.indexedImportTableNum + header.anonymousImportTableNum
            val externalsStart = program.imageBase.add(0x0a000000)
            if (numExternals > 0) {
                MemoryBlockUtils.createUninitializedBlock(program, false, "EXTERNALS", externalsStart, (numExternals * 4L), "", null, true, false, false, log)
            }

            seek(header.importModuleTableOffset)
            val importModules = readList<CRO0Header.ImportModuleTableEntry>(header.importModuleTableNum)
            for (module in importModules) {
                seek(module.nameOffset)
                val name = readNullTerminatedString()
                program.externalManager.addExternalLibraryName(name, SourceType.IMPORTED)
            }
        }
    }

    protected fun setLabels(program: Program, provider: ByteProvider, monitor: TaskMonitor) {
        provider.getInputStream(0).reader {
            val header = read<CRO0Header>()

            for ((name, addr) in mapOf(
                "_cro_OnLoad" to header.onLoadOffset,
                "_cro_OnExit" to header.onExitOffset,
                "_cro_OnUnresolved" to header.onUnresolvedOffset,
            )) {
                if (addr != 0xFFFFFFFF.toInt()) {
                    program.createFromReference(0, addr - program.memory.getBlock(".text").start.offset.toInt(), name)
                }
            }

            seek(header.moduleNameOffset)
            val name = readNullTerminatedString()

            seek(header.namedExportTableOffset)
            val namedExports = readList<CRO0Header.NamedExportTableEntry>(header.namedExportTableNum)
            monitor.message = "Creating labels for named exports"
            namedExports.forEach { exportTableEntry ->
                seek(exportTableEntry.nameOffset)
                val exportName = readNullTerminatedString()
                val (segment, offset) = exportTableEntry.segmentOffset.segOff
                program.createFromReference(segment, offset, exportName)
            }

            monitor.message = "Creating labels for indexed exports"
            seek(header.indexedExportTableOffset)
            val indexedExports = readList<CRO0Header.IndexedExportTableEntry>(header.indexedExportTableNum)
            indexedExports.forEachIndexed { i, exportTableEntry ->
                val (segment, offset) = exportTableEntry.segmentOffset.segOff
                program.createFromReference(segment, offset, "${name}_export_indexed_${i}")
            }

        }
    }

    protected open fun applyPatches(program: Program, provider: ByteProvider) {
        provider.getInputStream(0).reader {
            val header = read<CRO0Header>()

            seek(header.segmentTableOffset)
            val segments = readList<CRO0Header.SegmentTableEntry>(header.segmentTableNum)

            seek(header.relocationPatchesOffset)
            for (patch in readList<CRO0Header.PatchEntry>(header.relocationPatchesNum)) {
                val (segment, offset) = patch.segmentOffset.segOff

                val block = program.memory.getBlock(getSegmentName(segment))
                val patchAddress = block.start.add(offset.toLong())

                val targetSegment = patch.segmentIndex

                val targetAddress = try {
                    val targetBlock = program.memory.getBlock(getSegmentName(targetSegment.toInt()))
                    val target = targetBlock.start.add(patch.addend.toLong())

                    if (target > targetBlock.end) {
                        println("WARNING: Target address ($target) for patch ($patchAddress:${patch.addend.hex}) is outside of segment $targetSegment:${targetBlock.start}-${targetBlock.end}. This may cause issues in analysis!")
                    }
                    target
                } catch (e: NullPointerException) {
                    val target = program.addressFactory.getConstantAddress((segments.first { it.id == targetSegment.toInt() }.offset + patch.addend).toLong())
                    println("WARNING: Target address ($target) for patch ($patchAddress:${patch.addend.hex}) points to segment $targetSegment but is missing. This may cause issues in analysis!")
                    target
                }

                val arr = ByteArray(4)
                when (patch.patchType) {
                    2.toUByte() -> {
                        // Absolute jump
                        ByteBuffer.wrap(arr).order(ByteOrder.LITTLE_ENDIAN).putInt(targetAddress.offset.toInt())
                    }
                    3.toUByte() -> {
                        // Relative jump
                        ByteBuffer.wrap(arr).order(ByteOrder.LITTLE_ENDIAN).putInt(targetAddress.offset.toInt() - patchAddress.offset.toInt())
                    }
                    else -> {
                        throw IllegalStateException("Unknown patch type ${patch.patchType}")
                    }
                }

                program.memory.setBytes(patchAddress, arr)
            }
        }
    }
}
