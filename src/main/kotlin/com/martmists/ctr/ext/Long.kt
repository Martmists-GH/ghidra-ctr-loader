package com.martmists.ctr.ext

val Long.mediaUnits: Long
    get() = this * 0x200L

val Long.hex: String
    get() = "0x${this.toString(16)}"
