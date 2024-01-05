package com.martmists.ctr.loader.filesystem

import ghidra.formats.gfilesystem.GFileSystem
import ghidra.util.task.TaskMonitor

interface MountableGFileSystem : GFileSystem {
    /**
     * Mounts (opens) the file system.
     *
     * @param monitor A cancellable task monitor.
     */
    fun mount(monitor: TaskMonitor)
}
