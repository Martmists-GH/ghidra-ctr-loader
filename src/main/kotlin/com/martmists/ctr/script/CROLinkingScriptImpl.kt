package com.martmists.ctr.script

import com.martmists.ctr.common.CROUtilities
import com.martmists.ctr.ext.reader
import com.martmists.ctr.ext.segOff
import com.martmists.ctr.ext.stripNulls
import com.martmists.ctr.loader.format.CRO0Header
import com.martmists.ctr.reader.Reader
import ghidra.app.script.GhidraScript
import ghidra.app.util.bin.MemoryByteProvider
import ghidra.framework.model.DomainFile
import ghidra.program.model.address.Address
import ghidra.program.model.address.AddressSet
import ghidra.program.model.listing.CodeUnit
import ghidra.program.model.listing.Program
import ghidra.program.model.symbol.SourceType
import java.nio.ByteBuffer
import java.nio.ByteOrder

open class CROLinkingScriptImpl : GhidraScript(), CROUtilities {
    private var exportIndex = 0L
    override fun nextExportIndex(): Long {
        return exportIndex++
    }

    private fun getAllCROFiles(): List<DomainFile> {
        return currentProgram.domainFile.parent.files.filter { it.name.endsWith(".cro") || it.name.endsWith(".crs") }
    }

    private fun DomainFile.getProgram(): Program {
        return getImmutableDomainObject(this, DomainFile.DEFAULT_VERSION, monitor) as? Program ?: throw IllegalStateException("Not a program")
    }

    override fun run() {
        val data = currentProgram.getModuleData()
        val namedImports = data.namedImports.entries.toMutableSet()

        // Scan all files for anonymous imports to here
        getAllCROFiles().map {
            val program = it.getProgram()
            program to program.getModuleData()
        }.forEach { (moduleProgram, moduleData) ->
            println(moduleData)
            monitor.message = "Handling module ${moduleData.name}"

            // Find locations of named imports
            monitor.message = "Creating named labels for module ${moduleData.name}"
            for (entry in namedImports.toList()) {
                val (name, import) = entry
                val export = moduleData.namedExports[name] ?: continue
                val (segment, offset) = export.segmentOffset.segOff
                val reference = currentProgram.createReferenceTo(moduleProgram, segment, offset, name, monitor)
                currentProgram.applyPatches(import.listOffset, reference)
                namedImports.remove(entry)
            }

            // Create data at anonymous imports
            monitor.message = "Creating anonymous labels for module ${moduleData.name}"
            moduleData.importedModules[data.name]?.let { module ->
                module.anonymous.forEach { entry ->
                    val (segment, offset) = entry.segmentOffset.segOff
                    currentProgram.createFromReference(segment, offset, "${data.name}_export_anonymous_${segment}_${offset}")
                }
            }

            data.importedModules[moduleData.name]?.let { module ->
                // Find locations of indexed imports
                monitor.message = "Creating indexed externals for module ${moduleData.name}"
                for (entry in module.indexed) {
                    val export = moduleData.indexedExports[entry.indexOffset]
                    val (segment, offset) = export.segmentOffset.segOff
                    val reference = currentProgram.createReferenceTo(moduleProgram, segment, offset, "${moduleData.name}_export_indexed_${entry.indexOffset}", monitor)
                    currentProgram.applyPatches(entry.listOffset, reference)
                }

                // Find locations of anonymous imports
                monitor.message = "Creating anonymous externals for module ${moduleData.name}"
                for (entry in module.anonymous) {
                    val (segment, offset) = entry.segmentOffset.segOff
                    val reference = currentProgram.createReferenceTo(moduleProgram, segment, offset, "${moduleData.name}_export_anonymous_${segment}_${offset}", monitor)
                    currentProgram.applyPatches(entry.listOffset, reference)
                }
            }
        }
    }
}
