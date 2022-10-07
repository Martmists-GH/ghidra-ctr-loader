package com.martmists.ctr.script

import ghidra.app.script.GhidraScript

open class CRORemoveMetadataImpl : GhidraScript() {
    private fun tryRemoveBlock(name: String) {
        val block = currentProgram.memory.getBlock(name)
        if (block != null) {
            currentProgram.memory.removeBlock(block, monitor)
        }
    }

    override fun run() {
        tryRemoveBlock("name")
        tryRemoveBlock("header")
        tryRemoveBlock("tables")
    }
}
