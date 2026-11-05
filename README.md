# PS3 Firmware Extractor / Decrypter

**Version 3.15 — Windows GUI and read-only firmware inventory**

A Python/Tkinter application for inspecting and unpacking PlayStation 3 firmware packages, invoking external PS3Tools/scetool-compatible utilities to decrypt supported SELF/SPRX executables to ELF, and producing extraction, key-audit and embedded-format inventory reports. Intended for firmware research, homebrew development and diagnostics on firmware files you are authorized to examine. **This is not a PS3 emulator, nor a firmware flasher.**

## Requirements

- Windows 10/11 x64; Python 3 with Tkinter (`py -3 -m tkinter` verifies it).
- Python standard library for the GUI and inventory scripts (no pip packages required by the included Python source).
- Compatible Windows command-line PS3Tools utilities, including `unself.exe`, `unpkg.exe`, `pupunpack.exe` and other tools used by the selected workflow. See `instrumented_ps3tools_source/` for the bundled C sources and `KEY_TRACE_BUILD_README.txt` for instrumented builds. The exact tools needed vary by operation.
- Where needed, a compatible `scetool.exe` and its own required runtime dependencies. The source distribution intentionally does not bundle third-party executables, DLLs or cryptographic key material. Obtain them lawfully and place executables in `tools/`.
- Decryption requires appropriate keys supplied separately by the user. Do not commit keys or decrypted firmware output to GitHub.
- For compiling the included instrumented C tools on Windows, use an appropriate MinGW-w64/GCC toolchain and follow `instrumented_ps3tools_source/build-windows-audit.ps1` and `KEY_TRACE_BUILD_README.txt`; external library requirements depend on the selected build and are not included automatically.

## Run from source

```bat
py -3 --version
py -3 -m tkinter
START_WINDOWS.bat
```

Or `py -3 ps3_spkg_extractor_gui.py`. The launcher starts the Python GUI directly; no Python-to-EXE compilation is required. Keep the other `.py` modules beside the main script. Supply compatible external binaries under `tools/` before using extraction/decryption features.

## Using the GUI

1. Start `START_WINDOWS.bat` and select an input file and operation in the GUI.
2. Choose an output directory; confirm overwrite prompts carefully.
3. For firmware packages, run the supported unpack/extract workflow. Enable nested SELF decryption only if tools and keys are configured.
4. Review the operation log and generated JSON reports. Converted executables are written under the output `ELF/` tree while preserving relative paths.
5. Use the FSELF, MSELF and general-format inventory options for **read-only** discovery. A detected signature is not proof that an embedded object is independently executable.

## Formats and support levels

| Format | Capability |
|---|---|
| PS3 PUP / `PS3UPDAT.PUP` | Firmware package inspection/extraction through supported backends |
| PS3 SPKG / core firmware packages | Header analysis, extraction and audit where supported by backend |
| PS3 PKG | Extraction through configured compatible tools; not all PKG variants are supported |
| SELF / SPRX / SCE | SCE header analysis and SELF-to-ELF conversion when backend and keys support the file |
| ELF (32/64-bit; PPC, MIPS, SPU candidates) | Read-only header/embedded signature inventory and validation |
| FSELF | Fast executable/header inventory; filename or SCE magic alone does **not** verify FSELF subtype |
| MSELF (`MSF\0`) | Signature and conservative header checks; entry-table extraction **not implemented** |
| ZIP, GZIP, BZIP2, XZ, ZLIB, TAR, 7ZIP, RAR | Format signature inventory; detection does **not** imply extraction support |
| NPD, PARAM.SFO and other recognized markers | Identification/inspection only unless a dedicated workflow exists |

## Reports and limitations

Generated reports can include `firmware_format_inventory.json`, `firmware_fself_inventory.json`, `firmware_mself_inventory.json`, conversion results and selected-key audit records. The v3.15 unified scan avoids multiple directory walks and applies stronger SCE/ELF header checks. The separate embedded-container audit and legacy scanners remain available. Embedded signature hits are *candidates*, and MSELF table extraction, definitive FSELF subtype identification, and arbitrary embedded executable carving are not implemented. Some firmware types are encrypted or compressed and require a compatible backend.

## Build and redistribution

The GUI is Python source and runs without a compile step. To build the optional native audit tools from scratch, install a Windows C toolchain, read `KEY_TRACE_BUILD_README.txt`, then run the provided PowerShell build script with dependencies it specifies. Validate outputs on a disposable test fixture before use. Third-party source in `instrumented_ps3tools_source/` retains its own copyright and licensing; see its `COPYING` and other notices. Do not assume all dependencies or keys can be redistributed.

## Safety

This application is intended for offline analysis. Do not replace PS3 system files with generated results without independent verification. Keep firmware images, cryptographic keys and decrypted proprietary binaries out of public commits.
