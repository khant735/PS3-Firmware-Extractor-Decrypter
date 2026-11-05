PS3 SPKG Extractor GUI v1.8 — SELF key cache correction

Fix: SELF keysets are now exported to <application>/self_keys/ instead of output/<run>/keys/.
The cache is reused when the keysets.csv SHA-256 is unchanged and rebuilt when it changes.
The existing PKG key directory ps3keys/ remains unchanged.
The output folder contains extracted components, ELF files, and reports, not generated SELF keys.

Install: unzip to a new folder; copy your Windows ps3tools .exe files into tools/.
Run START_WINDOWS.bat. Select CORE_OS_PACKAGE.pkg and CORE_OS package unpack.
Keep 'Decrypt nested SELF files' enabled to produce ELF outputs.

Existing output/<run>/keys directories from v1.6/v1.7 may be deleted after
successful extraction. Do not delete the application's ps3keys/ directory.

This build was syntax-checked; Windows runtime test is still required.

Version 1.9: Output directory defaults to output/<input filename without extension>.
If that folder exists, Yes overwrites it after confirmation, No lets you choose an EMPTY destination folder, and Cancel leaves it unchanged.
This applies to all supported input types; package parsing is still format-dependent.

Version 2.0: Decrypted ELF files are placed in output/<input name>/ELF/.
Nested source directory structure is preserved under ELF/ to avoid filename collisions.
Source SELF files remain in their original extracted locations. Reports reference ELF/ paths.

Version 2.1: Adds successful_keys.json with a per-operation PKG/SELF audit.
Includes backend, success/failure, source/output, database provenance, and candidate key identifiers/fingerprints.
IMPORTANT: unself/unpkg do not expose the winning key. selected_key is null, not guessed.
No raw key bytes are written into reports. Failed runs preserve partial key audits.


v2.3: Key Audit GUI tab lists selected/requested keysets and results; load JSON and export CSV.
The checkbox Hide missing private-key (ERROR) messages filters only optional `priv file: ... (ERROR)` log lines. It does not suppress actual errors or change decryption, and can be unchecked to display them on subsequent runs.
