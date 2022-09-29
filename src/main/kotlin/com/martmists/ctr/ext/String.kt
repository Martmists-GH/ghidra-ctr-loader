package com.martmists.ctr.ext

fun String.stripNulls() = this.replace("\u0000", "")
