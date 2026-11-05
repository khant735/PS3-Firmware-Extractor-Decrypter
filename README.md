# PS3 Firmware Extractor / Decrypter

**Version 3.15 — Windows GUI / unified firmware scanner**

A Python/Tkinter application for inspecting and extracting PlayStation 3 firmware packages, converting supported SELF/SPRX files to ELF through separately supplied PS3Tools-compatible backends, and generating read-only format inventories and key-selection audit reports.

> Research and diagnostics only. This is neither a PS3 emulator nor a firmware flasher. Use firmware and keys you are authorized to handle.

## Requirements

- Windows 10 or 11 (64-bit recommended)
- Python 3 with Tkinter (standard library; verify with `py -3 -m tkinter`)
- Optional: compatible PS3Tools command-line binaries (`pupunpack.exe`, `unpkg.exe`, `unself.exe`, etc.) in `tools/` for the corresponding extraction/decryption operations
- Optional: compatible `scetool.exe` and its runtime dependencies
- User-supplied compatible keys where required; **never commit keys, decrypted firmware, or proprietary binaries**
- For optional native tools: MinGW-w64/GCC or another compatible Windows C build environment, plus any external dependencies specified by the included C sources/build scripts

## Run from source

1. Download or clone the source repository.
2. Verify Python and Tkinter:
   ```bat
   py -3 --version
   py -3 -m tkinter
   ```
3. Run `START_WINDOWS.bat`, or `py -3 ps3_spkg_extractor_gui.py`.
4. Keep the accompanying Python modules next to the GUI. Install compatible backend executables under `tools/` for extraction/decryption.

The GUI itself does **not** require compiling into an EXE or installing pip packages. To build optional instrumented PS3Tools C utilities, consult `KEY_TRACE_BUILD_README.txt` and the provided PowerShell build script. Third-party C code retains its original license notices.

## Intended workflow

1. Launch the GUI and choose a PS3 firmware file, package or supported operation.
2. Select an output directory and run the extraction operation.
3. If needed, configure a compatible external decryptor and authorized keys for SELF/SPRX → ELF.
4. Review logs and generated JSON reports. Converted ELF files are stored under the output `ELF/` directory preserving relative paths.
5. Use unified read-only scanning to inventory embedded format signatures. Do not interpret raw signature hits as verified independent files.

## Supported file types and scope

| File type | Support |
| --- | --- |
| `PS3UPDAT.PUP` / PUP | Firmware inspection and extraction via supported backend |
| SPKG / CoreOS packages | Extraction and audit where backend supports the variant |
| PKG | Extraction via compatible backend; not every variant |
| SELF, SPRX, SCE | Header checks; SELF/SPRX → ELF when backend and keys support it |
| ELF (PowerPC, MIPS, SPU) | Read-only header validation and embedded-signature inventory |
| FSELF | Fast candidate inventory; definitive subtype identification not implemented |
| MSELF (`MSF\\0`) | Signature/header checks only; entry-table extraction not implemented |
| ZIP, GZIP, BZIP2, XZ, ZLIB, TAR, 7Z, RAR | Signature detection; not necessarily unpacking |
| NPD, PARAM.SFO | Identification/inspection; not general-purpose decryption |

## Reports

Depending on operation, the app can generate `firmware_format_inventory.json`, `firmware_fself_inventory.json`, `firmware_mself_inventory.json`, SELF→ELF conversion results, and selected-key audit records (key identifiers only, not key bytes).

v3.15 combines the format, FSELF and MSELF inventories into a single directory traversal and validates more SCE/ELF header fields. Some signatures are false positives or embedded data. MSELF entry-table extraction, definitive FSELF identification and arbitrary embedded executable carving are not implemented.

## Build and distribution

- **Python GUI:** no compilation necessary; launch the main `.py` script.
- **Optional C tools:** build separately using the source's documented Windows PowerShell script and an appropriate C toolchain. Install required third-party development libraries as needed.
- **Redistribution:** preserve third-party license notices; do not redistribute proprietary keys, encrypted/decrypted firmware, or third-party executables without permission.

## Source publication

The repository is being populated from the sanitized v3.15 source distribution. No cryptographic key databases or proprietary firmware are intended to be tracked.
