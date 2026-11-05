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

## Windows batch files (`.bat`)

The repository contains **eight Windows batch launchers**. They are convenience wrappers for the Python scripts; they do not compile the application. All require a working Python 3 launcher (`py -3`) on Windows. Run them from an extracted/cloned source checkout, rather than opening them inside a ZIP. The launcher names below match the files in the repository.

| Batch file | What it does | How to use it / output |
| --- | --- | --- |
| [`START_WINDOWS.bat`](START_WINDOWS.bat) | Opens the main Tkinter GUI by running `py -3 ps3_spkg_extractor_gui.py`. | **Double-click** to start the application. It changes to the batch file's own directory and pauses after the GUI exits so errors remain visible. This is the normal starting point. |
| [`AUDIT_EXISTING_WINDOWS.bat`](AUDIT_EXISTING_WINDOWS.bat) | Audits the integrity of files from a **previously extracted** `dev_flash` TAR; it does **not** decrypt or unpack firmware again. It invokes `audit_existing_extraction.py`, which compares TAR member sizes with files in `dev_flash_extracted/`. | **Double-click**, then enter the extraction folder containing both `decrypted/` and `dev_flash_extracted/`. Creates `firmware_tar_integrity.json` and `firmware_tar_integrity.csv` in that folder. Also prints special checks for `mcore_tk.self` if present. Requires a decrypted `dev_flash` TAR with a `*.plaintext` filename in `decrypted/`. |
| [`AUDIT_SPKG_OVERLAYS_WINDOWS.bat`](AUDIT_SPKG_OVERLAYS_WINDOWS.bat) | Runs a **read-only** search for SPKG header/overlay artifacts and possible original `.pkg` files in an already extracted firmware tree. Matches filenames and records hashes; it **does not** establish that an overlay cryptographically matches a package. | **Double-click** and provide the existing firmware output directory. Calls `spkg_overlay_audit.py`; writes `spkg_overlay_audit.json` and `spkg_overlay_audit.csv` to a sibling folder named `<input-folder>_spkg_overlay_reports`. |
| [`AUDIT_EMBEDDED_WINDOWS.bat`](AUDIT_EMBEDDED_WINDOWS.bat) | Examines one binary for candidate embedded ELF/SCE headers and heuristic LV1-style file tables. It is an inspection tool, **not an extractor or decryptor**. | **Double-click** and paste the full path to an ELF/SELF file. Calls `embedded_container_audit.py`; produces `<input-filename>.embedded_audit.json` next to the input file. The script may hash and scan the entire input, so large files can take longer. |
| [`SCAN_FIRMWARE_FORMATS_WINDOWS.bat`](SCAN_FIRMWARE_FORMATS_WINDOWS.bat) | Runs the v3.15 **unified read-only firmware inventory** with `firmware_format_scan.py`. Searches an extracted directory for format signatures and validates some ELF/SCE header fields. This scan also generates the fast FSELF and MSELF inventory reports. | **Drag an extracted firmware folder onto this batch file** (or pass its directory path as the first command-line argument). Unlike most other launchers, it does **not** prompt for a path. Writes `firmware_format_inventory.json`, `firmware_fself_inventory.json` and `firmware_mself_inventory.json` into the selected folder. Signature detections are not proof of extractable files. |
| [`SCAN_FIRMWARE_FSELF_WINDOWS.bat`](SCAN_FIRMWARE_FSELF_WINDOWS.bat) | Runs the **fast** FSELF inventory with `firmware_fself_scan.py`: checks relevant filenames and top-level executable headers. It **does not** prove a candidate is a fake/debug SELF or perform exhaustive embedded scanning. | **Double-click**, enter the extracted firmware folder, and review `firmware_fself_inventory.json` written to that folder. |
| [`SCAN_FIRMWARE_FSELF_DEEP_WINDOWS.bat`](SCAN_FIRMWARE_FSELF_DEEP_WINDOWS.bat) | Runs the slower FSELF **deep diagnostic** mode (`firmware_fself_scan.py --deep`) including embedded ELF/SCE signature searches and heuristic LV1-style table inspection. May take substantially longer; reported table matches are not verified archive entries. | **Drag an extracted firmware folder onto the batch file** or run `SCAN_FIRMWARE_FSELF_DEEP_WINDOWS.bat "C:\\path\\to\\firmware-folder"` from Command Prompt. This launcher doesn't ask for a folder interactively. Writes `firmware_fself_inventory.json` into the selected folder, potentially replacing the fast-mode report. |
| [`SCAN_FIRMWARE_MSELF_WINDOWS.bat`](SCAN_FIRMWARE_MSELF_WINDOWS.bat) | Runs the dedicated **read-only** MSELF discovery scanner (`firmware_mself_scan.py`). Searches for `MSF\\0` and checks basic header version information, but **cannot** verify/extract MSELF entry tables. | **Double-click**, enter the extracted firmware folder, and read `firmware_mself_inventory.json` in that folder. |

**Important:** The inventory scripts share report filenames. Running one dedicated scanner after the unified scan can **replace its corresponding JSON report**. Copy reports you want to compare before rerunning them. The batch files pause at the end so you can read console output. Existing extracted firmware input is required for all the audit/scan launchers; **only `START_WINDOWS.bat` opens the GUI for new extraction jobs**.

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
