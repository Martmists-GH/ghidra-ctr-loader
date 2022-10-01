package com.martmists.ctr.ext

import com.martmists.ctr.reader.Reader
import java.io.InputStream
import kotlin.contracts.InvocationKind
import kotlin.contracts.contract

fun InputStream.reader(littleEndian: Boolean = true) : Reader = Reader(littleEndian, this)
fun <T> InputStream.reader(littleEndian: Boolean = true, autoClose: Boolean = true, block: Reader.() -> T): T {
    contract {
        callsInPlace(block, InvocationKind.EXACTLY_ONCE)
    }

    val res = block(reader(littleEndian))
    if (autoClose) {
        close()
    }

    return res
}
