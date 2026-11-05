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

## Cryptographic keys and `keysets.csv`

The application uses **two separate key stores**. Keys are **not bundled** with this public repository. Supply only key material you are authorized to use.

| Store | Used for | Required location |
| --- | --- | --- |
| **Package keys** | `unpkg.exe` decrypting SCE-wrapped `.pkg` / `.spkg` files, including supported CoreOS packages | `ps3keys/` containing binary `pkg-key-*` files |
| **SELF executable keysets** | `unself.exe` converting supported SELF/SPRX files to ELF | `keysets.csv` in the project root; the GUI generates `self_keys/` automatically |

The `PS3_KEYS` environment variable is set by the GUI to the appropriate directory when invoking these backends. **Package keys are not read from `keysets.csv`**, and the SELF key cache is not a substitute for `ps3keys/pkg-key-*`.

### Key types and their roles

- **AES ERK (`aes_erk`)**: AES key material used by the supported SELF backend.
- **AES RIV (`aes_riv`)**: Initialization-vector material paired with the relevant keyset.
- **ECDSA public key (`ecdsa_public`)**: Optional public-key material for operations supported by the backend, such as signature verification.
- **ECDSA private key (`ecdsa_private`)**: Optional private-key material for signing-capable tooling; ordinary read-only scanning does not require it. The GUI's SELF exporter supports the field, but this does not make the GUI a signer.
- **Curve type (`curve_type`)**: Optional elliptic-curve identifier exported as a four-byte big-endian value.
- **Category (`category`)**: Key-family label; categories can represent executable classes such as `lv0`, `lv1`, `lv2`, or `app`. The backend determines which keyset is applicable.

The precise required keys depend on the firmware generation, executable class, SCE metadata, and selected external backend. There is **no single universal keyset** that decrypts every PS3 firmware file. PUP unpacking, ELF inspection, signature scanning, FSELF/MSELF candidate detection, and ordinary ZIP/TAR extraction do **not** require a SELF key database.

### Building `keysets.csv` from existing authorized keysets

The v3.15 GUI reads the following **exact CSV column names**:

```csv
category,aes_erk,aes_riv,ecdsa_public,ecdsa_private,curve_type
```

1. In a text editor or spreadsheet, create a new UTF-8 CSV file named **`keysets.csv`** in the repository root, alongside `ps3_spkg_extractor_gui.py`.
2. Add **one row per existing keyset**. Use a category label accepted by the PS3Tools backend. Supply each binary key or IV as a **plain hexadecimal string**, with no `0x` prefix or spaces. The `curve_type` field is also hexadecimal. Leave optional fields empty if they are unavailable.
3. Save the file as **CSV UTF-8**, retaining the header exactly as shown. Do not place actual keys in GitHub issues, logs, screenshots or commits.
4. Start `START_WINDOWS.bat`. Under **Key database CSV**, select the CSV file if it is not in the default location. When a SELF decryption workflow begins, the application exports the usable records to the private `self_keys/` directory.
5. Verify that your chosen backend supports the keyset family and firmware being processed. A correctly formatted CSV **does not guarantee successful decryption**.

The importer currently requires at least one usable key entry and does not independently validate key lengths, firmware-version compatibility, or cryptographic correctness. If the file is missing, the GUI reports **`SELF key database CSV is missing`**. If it contains no usable key files, it reports **`SELF key database contained no usable key entries`**.

**Exact exporter mapping (v3.15):**

| CSV field | Generated binary file | Encoding |
| --- | --- | --- |
| `category` + `aes_erk` | `<category>-key-000` | Hex decoded into raw bytes |
| `category` + `aes_riv` | `<category>-iv-000` | Hex decoded into raw bytes |
| `category` + `ecdsa_public` | `<category>-pub-000` | Hex decoded into raw bytes |
| `category` + `ecdsa_private` | `<category>-priv-000` | Hex decoded into raw bytes |
| `category` + `curve_type` | `<category>-ctype-000` | Four-byte big-endian integer |

The `000` suffix represents the **zero-based CSV row index** and increments for subsequent records; it is not a firmware version. The GUI fingerprints `keysets.csv` using SHA-256 and reuses the generated cache when unchanged. If the database changes, it rebuilds the cache while preserving the old one if exporting fails.

### Package key files: `ps3keys/pkg-key-*`

For supported SCE-wrapped PKG/SPKG decryption, the source checks that **`tools/unpkg.exe`** exists and that **`ps3keys/`** contains at least one filename matching `pkg-key-*`. These files must be in the backend's expected **raw binary format**; do not rename a text CSV or paste hexadecimal text into them. Obtain the required compatible key files from your own authorized key collection or a source you have permission to use, and consult your exact `unpkg` backend's documentation for its expected package-key variants and naming.

The current source does **not** provide a complete, authoritative firmware-by-firmware list of package keys, nor does it include a converter that automatically generates `ps3keys/pkg-key-*` from `keysets.csv`. Some custom-firmware packages may require keys different from those for retail firmware.

### Example private directory layout

```text
PS3-Firmware-Extractor-Decrypter/
├── keysets.csv             # user-supplied, private
├── ps3keys/                # user-supplied package key files
│   ├── pkg-key-000
│   └── pkg-key-001
├── self_keys/              # generated automatically from keysets.csv
│   ├── app-key-000
│   ├── app-iv-000
│   └── ...
└── tools/
    ├── unself.exe
    └── unpkg.exe
```

The names and entries above are illustrative; they are **not** a claim that these particular keys are sufficient for any given firmware.

### Key-selection tracing and security

When an **instrumented** PS3Tools backend emits `KEY_AUDIT_REQUEST` and `KEY_AUDIT_SELECTED` messages, the GUI records requested/selected **key identifiers** in its audit reports (including `successful_keys.json`). It does not deliberately log raw key bytes. An older, uninstrumented backend may report no selected key even when conversion succeeds. A reported metadata-header match alone does not prove that the entire executable decrypted correctly.

The repository's `.gitignore` is intended to exclude `keysets.csv`, `ps3keys/`, `self_keys/` and generated firmware output. **Check your staged files before every public push**: a `.gitignore` does not protect files that were already committed or explicitly force-added. Do not publish private ECDSA signing keys or other secret material.

### Reference implementations

- [euss/ps3tools](https://github.com/euss/ps3tools) — backend utilities and binary key-file conventions.
- [Sorvigolova/scetool](https://github.com/Sorvigolova/scetool) — SCE processing and alternative keyset conventions.
- [RPCS3](https://github.com/RPCS3/rpcs3) — reference for PS3 executable formats and cryptographic handling.

These projects are **references**, not guaranteed sources for every required key. Different backends can expect different formats, so their key databases are not necessarily directly interchangeable with this GUI's CSV schema.

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
