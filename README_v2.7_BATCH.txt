PS3 Firmware SPKG / PUP / SELF Extractor v2.7

New operations:
- Batch firmware inspect: select update_files.tar; inventories all regular members, their SHA256, size, SCE signatures and type. No extraction or decryption. Auto selects this mode for update_files.tar.
- Batch firmware decrypt: explicitly select this operation for update_files.tar. Requires tools/unpkg.exe and ps3keys/pkg-key-*. Each SCE PKG and dev_flash member is staged and tried with unpkg -s. Errors are isolated per entry. RL_FOR_*.img files are inventoried, not decrypted.

Reports: output/update_files/firmware_batch_report.json and .csv. Successful payloads are preserved under decrypted/; no implicit inner extraction is attempted. For individual CORE_OS extraction use the existing CORE OS or SPKG operation. Files with .tar.aa in their names are SCE containers, not plaintext TAR.

Batch decrypt is EXPERIMENTAL. unpkg -s may not support dev_flash container semantics. Check per-file status and decrypted header; no success is claimed for failed entries. No firmware images are modified in place.

Verified locally: Python syntax compilation, read-only inventory of supplied 191,915,008-byte update_files.tar: 50 entries (24 PKG, 24 dev_flash, 2 IMG), all with SCE outer headers. Windows runtime and actual decryption not tested in this environment.
