package com.martmists.ctr.loader.filesystem

import com.martmists.ctr.ext.*
import com.martmists.ctr.loader.format.ExeFSHeader
import com.martmists.ctr.loader.format.IVFCHeader
import com.martmists.ctr.loader.format.NCCHExHeader
import com.martmists.ctr.loader.format.NCCHHeader
import ghidra.app.util.bin.ByteProvider
import ghidra.formats.gfilesystem.*
import ghidra.formats.gfilesystem.annotations.FileSystemInfo
import ghidra.formats.gfilesystem.fileinfo.FileAttributes
import ghidra.util.exception.CancelledException
import ghidra.util.task.TaskMonitor
import java.io.IOException
import kotlin.experimental.and
import kotlin.math.min


@FileSystemInfo(
    type = "cxi",
    description = "CXI Container",
    factory = CXIFileSystemFactory::class,
    priority = FileSystemInfo.PRIORITY_HIGH,
)
class CXIFileSystem(private val fsFSRL: FSRLRoot, private var provider: ByteProvider, private val fsService: FileSystemService) : GFileSystem {
    private val fsih: FileSystemIndexHelper<IVFCHeader.Level3Header.FileMetadata?> = FileSystemIndexHelper(this, fsFSRL)
    private val refManager = FileSystemRefManager(this)
    private var fileCount = 0L
    private var closed = false

    /**
     * Mounts (opens) the file system.
     *
     * @param monitor A cancellable task monitor.
     */
    fun mount(monitor: TaskMonitor) {
        val stream = provider.getInputStream(0)
        stream.reader {
            val ncch = read<NCCHHeader>()

            seek(ncch.exefsOffset.mediaUnits)
            val exefsHeader = read<ExeFSHeader>()

            for (file in exefsHeader.fileHeaders_10) {
                if (file.filename_8.stripNulls() == "") {
                    continue
                }

                fsih.storeFile(
                    "/exefs/${file.filename_8.stripNulls()}",
                    fileCount++,
                    false,
                    file.size.toLong(),
                    null,
                )
            }

            seek(ncch.romfsOffset.mediaUnits + 0x1000)
            val level3HeaderStart = tell()
            val level3Header = read<IVFCHeader.Level3Header>()

            seek(level3HeaderStart + level3Header.directoryMetaTableOffset)
            val rootDirectory = read<IVFCHeader.Level3Header.DirectoryMetadata>()

            fun addFilesRecursively(parentPath: String, folder: IVFCHeader.Level3Header.DirectoryMetadata) {
                var childDirOffset = folder.childDirectoryOffset
                while (childDirOffset != -1) {
                    seek(level3HeaderStart + level3Header.directoryMetaTableOffset + childDirOffset)
                    val child = read<IVFCHeader.Level3Header.DirectoryMetadata>()
                    addFilesRecursively("$parentPath/${folder.name.stripNulls()}", child)
                    childDirOffset = child.siblingOffset
                }

                var childFileOffset = folder.childFileOffset
                while (childFileOffset != -1) {
                    seek(level3HeaderStart + level3Header.fileMetaTableOffset + childFileOffset)
                    val file = read<IVFCHeader.Level3Header.FileMetadata>()
                    fsih.storeFile(
                        "$parentPath/${folder.name.stripNulls()}/${file.name.stripNulls()}",
                        fileCount++,
                        false,
                        file.dataSize,
                        file,
                    )
                    childFileOffset = file.siblingOffset
                }
            }

            addFilesRecursively("/romfs", rootDirectory)
        }
    }

    @Throws(IOException::class)
    override fun close() {
        closed = true
        refManager.onClose()
        provider.close()
        fsih.clear()
    }

    override fun getName() = fsFSRL.container.name
    override fun getFSRL() = fsFSRL
    override fun isClosed() = closed
    override fun getFileCount() = fsih.fileCount
    override fun getRefManager() = refManager

    @Throws(IOException::class)
    override fun lookup(path: String) = fsih.lookup(path)

    @Throws(IOException::class, CancelledException::class)
    override fun getByteProvider(file: GFile, monitor: TaskMonitor): ByteProvider {
        val metadata = fsih.getMetadata(file)

        if (file.path.startsWith("/exefs")) {
            val fileName = file.path.removePrefix("/exefs/")
            return provider.getInputStream(0).reader {
                val ncch = read<NCCHHeader>()
                val ncchEx = read<NCCHExHeader>()

                seek(ncch.exefsOffset.mediaUnits)
                val exefsHeader = read<ExeFSHeader>()
                val exefsStart = tell()
                val codeSection = exefsHeader.fileHeaders_10.first { it.filename_8.stripNulls() == fileName }

                val size = if (ncchEx.sci.flags and 0x1 == 1.toByte()) {
                    skip(codeSection.offset.toLong())
                    val exefsCode = readBytes(codeSection.size)
                    exefsCode.lzssSize()
                } else {
                    codeSection.size
                }

                fsService.getDerivedByteProviderPush(provider.fsrl, file.fsrl, file.path, size.toLong(), { out ->
                    provider.getInputStream(0).reader {
                        seek(exefsStart + codeSection.offset)
                        var code = readBytes(codeSection.size)
                        if (ncchEx.sci.flags and 0x1 == 1.toByte()) {
                            code = code.lzss()
                        }
                        out.write(code)
                    }
                }, monitor)
            }
        } else {
            return provider.getInputStream(0).reader {
                val ncch = read<NCCHHeader>()

                seek(ncch.romfsOffset.mediaUnits + 0x1000)
                val level3HeaderStart = tell()
                val level3Header = read<IVFCHeader.Level3Header>()

                fsService.getDerivedByteProviderPush(provider.fsrl, file.fsrl, file.path, metadata!!.dataSize, { out ->
                    val stream = provider.getInputStream(level3HeaderStart + level3Header.fileDataOffset + metadata.dataOffset)
                    var remaining = metadata.dataSize
                    while (remaining > 0) {
                        val buffer = ByteArray(min(0x1000L, remaining).toInt())
                        val read = stream.read(buffer)
                        if (read == -1) {
                            break
                        }
                        out.write(buffer, 0, read)
                        remaining -= read
                    }
                }, monitor)
            }
        }
    }

    @Throws(IOException::class)
    override fun getListing(directory: GFile?) = fsih.getListing(directory)

    override fun getFileAttributes(file: GFile, monitor: TaskMonitor): FileAttributes {
        val metadata = fsih.getMetadata(file)
        val result = FileAttributes()
        if (metadata != null) {

        }
        return result
    }
}
