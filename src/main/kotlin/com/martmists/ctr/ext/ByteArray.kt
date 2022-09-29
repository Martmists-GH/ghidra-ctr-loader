package com.martmists.ctr.ext

import java.nio.ByteBuffer
import java.nio.ByteOrder

fun ByteArray.lzssSize(): Int {
    return size + ByteBuffer.wrap(sliceArray(size - 4 until size)).order(ByteOrder.LITTLE_ENDIAN).int
}

fun ByteArray.lzss(): ByteArray {
    val offSizeComp = ByteBuffer.wrap(sliceArray(size-8 until size-4)).order(ByteOrder.LITTLE_ENDIAN).int
    val addSize = ByteBuffer.wrap(sliceArray(size-4 until size)).order(ByteOrder.LITTLE_ENDIAN).int
    var compStart = 0
    val codeLen = size
    val codeCompSize = offSizeComp and 0xFFFFFF
    val codeCompEnd = codeCompSize - ((offSizeComp shr 24) and 0xFF)
    val codeDecSize = codeLen + addSize

    if (codeCompSize <= codeLen) {
        compStart = codeLen - codeCompSize
    }

    val dec = ByteArray(codeDecSize)
    copyInto(dec)
    dec.fill(0, size, codeDecSize)

    val dataEnd = compStart + codeDecSize
    var ptrIn = compStart + codeCompEnd
    var ptrOut = codeDecSize

    while (ptrIn > compStart && ptrOut > compStart) {
        if (ptrOut < ptrIn) {
            throw IllegalStateException("ptrOut < ptrIn")
        }

        val ctrlByte = dec[--ptrIn].toInt()
        for (i in 7 downTo 0) {
            if (ptrIn <= compStart || ptrOut <= compStart) {
                break
            }
            if ((ctrlByte shr i) and 1 != 0) {
                ptrIn -= 2
                val segCode = ByteBuffer.wrap(dec.sliceArray(ptrIn until ptrIn+2)).order(ByteOrder.LITTLE_ENDIAN).short.toInt()
                if (ptrIn < compStart) {
                    throw IllegalStateException("ptrIn < compStart")
                }

                val segOff = (segCode and 0xFFF) + 2
                val segLen = ((segCode shr 12) and 0xF) + 3

                if (ptrOut - segLen < compStart) {
                    throw IllegalStateException("ptrOut - segLen < compStart")
                }
                if (ptrOut + segOff >= dataEnd) {
                    throw IllegalStateException("ptrOut + segOff >= dataEnd")
                }

                for (c in 0 until segLen) {
                    val data = dec[ptrOut + segOff]
                    dec[--ptrOut] = data
                }
            } else {
                dec[--ptrOut] = dec[--ptrIn]
            }
        }
    }

    if (ptrIn != compStart) {
        throw IllegalStateException("ptrIn != compStart")
    }
    if (ptrOut != compStart) {
        throw IllegalStateException("ptrOut != compStart")
    }

    return dec
}
