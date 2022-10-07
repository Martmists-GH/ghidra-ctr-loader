package com.martmists.ctr.ext

val Int.mediaUnits: Long
    get() = this * 0x200L

val Int.hex: String
    get() = "0x${this.toString(16)}"

val Int.segOff: Pair<Int, Int>
    get() = (this and 0xF) to (this shr 4)
