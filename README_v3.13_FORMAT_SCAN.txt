Version 3.13 adds read-only firmware format inventory after nested extraction.
Output: firmware_format_inventory.json
Standalone: drag extracted firmware directory onto SCAN_FIRMWARE_FORMATS_WINDOWS.bat.
Detects ELF32/ELF64/SPU, SCE/SELF candidates, MSELF, NPD/EDAT/SDAT,
PKG, PUP, ZIP, TAR, PARAM.SFO, gzip, xz, bzip2, 7z, rar, and zlib at file start.
Extension hints cover SELF, SPRX, PRX, FSELF, MSELF, EDAT, SDAT, RIF,
RAP, SFO, PKG, SPKG, PUP, TAR, IRX, IMG, BIN and others.
IMPORTANT: This is a discovery scanner, not universal decryption.
Some types have only extension hints or candidate-level validation.
Encrypted or compressed embedded data is not necessarily visible.
