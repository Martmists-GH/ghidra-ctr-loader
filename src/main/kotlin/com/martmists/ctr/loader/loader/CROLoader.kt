package com.martmists.ctr.loader.loader

import com.martmists.ctr.ext.reader
import com.martmists.ctr.loader.format.CRO0Header
import ghidra.app.util.Option
import ghidra.app.util.bin.BinaryReader
import ghidra.app.util.bin.ByteProvider
import ghidra.app.util.importer.MessageLog
import ghidra.app.util.opinion.AbstractLibrarySupportLoader
import ghidra.app.util.opinion.LoadSpec
import ghidra.program.model.lang.LanguageCompilerSpecPair
import ghidra.program.model.listing.Program
import ghidra.util.task.TaskMonitor


class CROLoader : AbstractLibrarySupportLoader() {
    override fun getName() = "CRO Loader"

    override fun findSupportedLoadSpecs(provider: ByteProvider): MutableCollection<LoadSpec> {
        val loadSpecs = mutableListOf<LoadSpec>()
        val reader = BinaryReader(provider, true)

        if (reader.readAsciiString(0x80, 4).equals("CRO0")) {
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
        provider.getInputStream(0).reader {
            val header = read<CRO0Header>()

            // TODO: Symbols, memory sections, etc.
        }
    }
}
