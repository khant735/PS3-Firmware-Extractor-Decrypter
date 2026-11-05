v3.14 performance changes

Default FSELF inventory: top-level SCE/ELF header-only checks, no full SHA256, no brute-force LV1 table scan. Does NOT confirm fake/debug SELF subtype.
Deep FSELF audit: run SCAN_FIRMWARE_FSELF_DEEP_WINDOWS.bat with extracted firmware directory as argument. This retains original exhaustive scanning and SHA256.
Format discovery: mmap.find with a bounded end offset instead of copying 64 MiB for every file.
Reports include elapsed_seconds for FSELF, MSELF and format discovery.
Other costs still present: repeated full-tree walks, MSELF scans of up to 512 MiB per file, separate format signature searches, full hashing in other audit/report passes, and external decryption subprocesses.
No actual PS3 firmware benchmark was performed.
