package com.martmists.ctr.reader

import java.io.FileInputStream
import java.io.InputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.reflect.*
import kotlin.reflect.full.isSubclassOf

class Reader(private val littleEndian: Boolean, open val stream: InputStream) {
    private var offset = 0L

    init {
        if (stream.markSupported()) {
            stream.mark(0)
        }
    }

    fun tell(): Long {
        return offset
    }

    fun skip(size: Long) {
        offset += size
        stream.skip(size)
    }

    fun reset() {
        offset = 0
        stream.reset()
        stream.mark(0)
    }

    fun seek(offset: Int) = seek(offset.toLong())
    fun seek(offset: Long) {
        if (stream is FileInputStream) {
            this.offset = offset
            stream.channel.position(offset)
        } else if (stream.markSupported()) {
            reset()
            skip(offset)
        } else {
            skip(offset - this.offset)
        }
    }

    inline fun <reified T : Any> read() = read(typeOf<T>(), T::class)
    inline fun <reified T : Any> readList(size: Int) = readList(size, typeOf<T>(), T::class)
    inline fun <reified T: Any> readSizedList() = readList<T>(read())
    fun readString(size: Int) = readList<Char>(size).joinToString("")
    fun readSizedString() = readString(read())
    fun readNullTerminatedString(): String {
        val sb = StringBuilder()
        while (true) {
            val c = read<Char>()
            if (c == 0.toChar()) {
                break
            }
            sb.append(c)
        }
        return sb.toString()
    }

    fun readBytes(size: Int): ByteArray {
        offset += size
        return stream.readNBytes(size)
    }

    fun remaining() = stream.readAllBytes().also {
        offset += it.size.toLong()
    }

    @PublishedApi
    internal fun <T : Any> read(type: KType, clazz: KClass<T>) : T {
        return if (clazz.isData) {
            val objs = mutableListOf<Any>()
            val constructor = clazz.constructors.first()
            val known = mutableMapOf<String, Any>()
            for (param in constructor.parameters) {
                val name = param.name!!
                if (name.startsWith("align_")) {
                    val align = name.substring(6).toInt()
                    val padding = (align - (offset % align)) % align
                    skip(padding)
                    objs.add(0)
                    continue
                }

                val item = if (name.startsWith("magic")) {
                    val expectedPair = name.substring(6).let {
                        try {
                            it.toInt(16) to read<Int>()
                        } catch (e: NumberFormatException) {
                            it to readString(it.length)
                        }
                    }
                    if (expectedPair.first != expectedPair.second) {
                        throw IllegalArgumentException("Expected magic value of ${expectedPair.first}, got ${expectedPair.second}")
                    }
                    expectedPair.first
                } else {
                    val t = param.type
                    val cls = t.classifier as KClass<*>
                    if (cls.isSubclassOf(List::class)) {
                        val size = known["${name}_size"] ?: known["${name}_count"] ?: name.split("_").last().toIntOrNull() ?: throw IllegalArgumentException("List type must have an associated size or count field of type Int, or specify the name!")
                        val subtype = t.arguments.first().type!!
                        val subcls = subtype.classifier as KClass<*>
                        readList(size as Int, subtype, subcls)
                    } else if (cls.isSubclassOf(ByteArray::class)) {
                        val size =
                            known["${name}_size"] ?: known["${name}_count"] ?: name.split("_").last().toIntOrNull()
                            ?: throw IllegalArgumentException("ByteArray must have an associated size or count field of type Int, or specify the name!")
                        readBytes(size as Int)
                    } else if (cls.isSubclassOf(String::class)) {
                        val size =
                            known["${name}_size"] ?: known["${name}_count"] ?: name.split("_").last().toIntOrNull()
                            ?: throw IllegalArgumentException("ByteArray must have an associated size or count field of type Int, or specify the name!")
                        readString(size as Int)
                    } else {
                        read(t, cls)
                    }
                }
                objs.add(item)
                known[name] = item
            }
            constructor.call(*objs.toTypedArray())
        } else {
            when (clazz) {
                Byte::class -> readPrimitive(1).get()
                UByte::class -> readPrimitive(1).get().toUByte()
                Char::class -> readPrimitive(1).get().toInt().toChar()
                Short::class -> readPrimitive(2).short
                UShort::class -> readPrimitive(2).short.toUShort()
                Int::class -> readPrimitive(4).int
                UInt::class -> readPrimitive(4).int.toUInt()
                Long::class -> readPrimitive(8).long
                ULong::class -> readPrimitive(8).long.toULong()
                else -> throw UnsupportedOperationException("Unsupported type: ${clazz.simpleName}")
            }
        } as T
    }

    @PublishedApi
    internal fun <T : Any> readList(size: Int, type: KType, clazz: KClass<T>) : List<T> {
        if (size > 64) {
            println("Warning: Reading a list of size $size")
        }
        return (0 until size).map { read(type, clazz) }.toList()
    }

    protected open fun readPrimitive(size: Int): ByteBuffer {
        offset += size
        return ByteBuffer.wrap(stream.readNBytes(size)).order(if (littleEndian) ByteOrder.LITTLE_ENDIAN else ByteOrder.BIG_ENDIAN)
    }
}
