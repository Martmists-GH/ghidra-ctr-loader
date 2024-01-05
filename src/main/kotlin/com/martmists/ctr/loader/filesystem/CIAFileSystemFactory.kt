package com.martmists.ctr.loader.filesystem

import ghidra.app.util.bin.ByteProvider
import ghidra.formats.gfilesystem.FSRLRoot
import ghidra.formats.gfilesystem.FSUtilities
import ghidra.formats.gfilesystem.FileSystemService
import ghidra.formats.gfilesystem.factory.GFileSystemFactoryByteProvider
import ghidra.formats.gfilesystem.factory.GFileSystemProbeByteProvider
import ghidra.util.task.TaskMonitor
import java.util.*


class CIAFileSystemFactory : GFileSystemFactoryByteProvider<CIAFileSystem>, GFileSystemProbeByteProvider {
    override fun create(targetFSRL: FSRLRoot, byteProvider: ByteProvider, fsService: FileSystemService, monitor: TaskMonitor): CIAFileSystem {
        val fs = CIAFileSystem(targetFSRL, byteProvider, fsService)
        fs.mount(monitor)
        return fs
    }

    override fun probe(provider: ByteProvider, fsService: FileSystemService, taskMonitor: TaskMonitor): Boolean {
        val filename = provider.fsrl.name
        var ext: String = FSUtilities.getExtension(filename, 1) ?: return false
        ext = ext.lowercase(Locale.getDefault())
        return ext == ".cia"
    }
}
