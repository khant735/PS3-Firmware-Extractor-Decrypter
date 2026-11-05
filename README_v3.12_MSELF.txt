PS3 SPKG Extractor GUI v3.12 - MSELF discovery

New: read-only MSELF magic scanner runs automatically after nested PUP/package extraction even if no SELF decryption summary exists.
Standalone: SCAN_FIRMWARE_MSELF_WINDOWS.bat <enter extracted firmware directory>.
Output: firmware_mself_inventory.json in the selected extraction root.

RPCS3 reference: rpcs3/Emu/Cell/lv2/sys_fs.cpp verify_mself validates MSF\0 magic, version 1 and sizeof(FsMselfEntry).
This implementation validates only magic and version. It DOES NOT validate the entry size, parse an entry table, extract entries or decrypt nested SELF files. All findings are marked header_candidate, not confirmed MSELF containers. An entry-table parser requires independently verified FsMselfHeader/FsMselfEntry definitions and real fixture testing.

No source firmware files are modified. No real firmware extraction has been tested in this environment.
