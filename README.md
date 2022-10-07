# Ghidra CTR Loader

This is a Ghidra loader for Nintendo 3DS executables.

## Features

Currently supports:

- CXI Imports
- CRO Imports
- CRS Imports (from CXI only)
- CRO multi-file analysis (i.e. linking imports and exports together)

Planned:

- Support for .bss sections and relocations
- Support for multiple .rodata/.data sections in static.crs
- CIA Imports
