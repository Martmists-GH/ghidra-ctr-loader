package com.martmists.ctr.loader.filesystem

import com.martmists.ctr.ext.*
import com.martmists.ctr.loader.format.*
import com.martmists.ctr.reader.Reader
import ghidra.app.util.bin.ByteProvider
import ghidra.formats.gfilesystem.*
import ghidra.formats.gfilesystem.annotations.FileSystemInfo
import ghidra.formats.gfilesystem.fileinfo.FileAttributes
import ghidra.util.exception.CancelledException
import ghidra.util.task.TaskMonitor
import java.io.ByteArrayInputStream
import java.io.File
import java.io.FileInputStream
import java.io.IOException
import java.io.InputStream
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import kotlin.experimental.and
import kotlin.math.min


@FileSystemInfo(
    type = "cia",
    description = "CIA Container",
    factory = CIAFileSystemFactory::class,
    priority = FileSystemInfo.PRIORITY_HIGH,
)
class CIAFileSystem(fsFSRL: FSRLRoot, provider: ByteProvider, fsService: FileSystemService) : MountableGFileSystem by CXIFileSystem(fsFSRL, CIAByteProvider(provider), fsService) {
    class CIAByteProvider(private val provider: ByteProvider) : ByteProvider by provider {
        private var startOffset: Long

        init {
            val source = provider.getInputStream(0)
            source.reader {
                val header = read<CIAHeader>()
                align(64)
                var pos = tell()
                val caCert = Certificate.parse(this)
                val ticketCert = Certificate.parse(this)
                val tmdCert = Certificate.parse(this)
                require(tell() - pos == header.certificateChainSize.toLong()) { "Certificate chain size mismatch; expected ${header.certificateChainSize}, got ${tell() - pos}" }
                align(64)
                pos = tell()
                val ticket = Ticket.parse(this)
                require(tell() - pos == header.ticketSize.toLong()) { "Ticket size mismatch; expected ${header.ticketSize}, got ${tell() - pos}" }
                align(64)
                pos = tell()
                val tmd = readBytes(header.tmdSize)
                require(tell() - pos == header.tmdSize.toLong()) { "TMD size mismatch; expected ${header.tmdSize}, got ${tell() - pos}" }
                align(64)

                // TODO: Verify in TMD that there is no encryption
                // TODO: Add support for multiple NCCH containers in CIA

                startOffset = tell()
            }
        }

        override fun getInputStream(index: Long): InputStream {
            return OffsetInputStream(provider, startOffset + index)
        }
    }

    class OffsetInputStream(private val provider: ByteProvider, private val offset: Long) : InputStream() {
        private var mark = 0L
        private var currentPos = 0L
        private var stream = provider.getInputStream(offset)

        override fun markSupported() = true

        override fun mark(readlimit: Int) {
            mark = currentPos + readlimit
        }

        override fun reset() {
            stream.close()
            stream = provider.getInputStream(offset + mark)
            currentPos = mark
        }

        override fun read() = stream.read().also { currentPos++ }
        override fun read(b: ByteArray) = read(b, 0, b.size).also { currentPos += it }
        override fun read(b: ByteArray, off: Int, len: Int) = stream.read(b, off, len).also { currentPos += it }
        override fun readNBytes(len: Int) = stream.readNBytes(len).also { currentPos += it.size }
        override fun readNBytes(b: ByteArray?, off: Int, len: Int) = stream.readNBytes(b, off, len).also { currentPos += it }
        override fun skip(n: Long) = stream.skip(n).also { currentPos += n }
        override fun skipNBytes(n: Long) = stream.skipNBytes(n).also { currentPos += n }
        override fun readAllBytes() = stream.readAllBytes().also { currentPos += it.size }
        override fun available() = stream.available()

        override fun close() {
            stream.close()
        }
    }
}
