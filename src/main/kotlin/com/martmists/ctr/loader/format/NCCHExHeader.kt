package com.martmists.ctr.loader.format

data class NCCHExHeader(
    val sci: SystemControlInfo,
    val aci: AccessControlInfo,
    val accessDescSignature_256: ByteArray,
    val ncchPubKey_256: ByteArray,
    val aci2: AccessControlInfo,
) {
    data class SystemControlInfo(
        val applicationTitle_8: String,
        val reserved1_5: ByteArray,
        val flags: Byte,
        val remasterVersion: Short,
        val textCodeSetInfo: CodeSetInfo,
        val stackSize: Int,
        val readOnlyCodeSetInfo: CodeSetInfo,
        val reserved2: Int,
        val dataCodeSetInfo: CodeSetInfo,
        val bssSize: Int,
        val dependencyModuleList_384: ByteArray,
        val systemInfo: SystemInfo,
    ) {
        data class CodeSetInfo(
            val address: Int,
            val physRegionSize: Int,
            val size: Int,
        )

        data class SystemInfo(
            val saveDataSize: Long,
            val jumpId: Long,
            val reserved1_48: ByteArray,
        )
    }

    data class AccessControlInfo(
        val arm11LocalCaps: Arm11LocalSystemCaps,
        val arm11KernelCaps: Arm11KernelCaps,
        val arm9AccessControl: Arm9AccessControl,
    ) {
        data class Arm11LocalSystemCaps(
            val programId: Long,
            val coreVersion: Int,
            val flag1_2: Short,
            val flag0: Byte,
            val priority: Byte,
            val resourceLimitDescriptors_32: ByteArray,
            val storageInfo_32: ByteArray,
            val serviceAccessControl_256: ByteArray,
            val extendedServiceAccessControl_16: ByteArray,
            val reserved1_15: ByteArray,
            val resourceLimitCategory: Byte,
        )

        data class Arm11KernelCaps(
            val descriptors_112: ByteArray,
            val reserved1_16: ByteArray,
        )

        data class Arm9AccessControl(
            val descriptors_15: ByteArray,
            val arm9DescriptorVersion: Byte,
        )
    }
}
