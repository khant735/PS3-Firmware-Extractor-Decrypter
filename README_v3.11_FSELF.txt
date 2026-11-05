PS3 SPKG Extractor GUI v3.11 - recursive embedded FSELF inventory

Normal PUP extraction now runs the recursive FSELF audit after nested SELF processing
when nested processing is enabled and the extraction stage completes.

The report firmware_fself_inventory.json is written to the firmware output folder.
It records inspected files, nested ELF/SCE headers, candidate LV1-style file tables,
.fself entries, skipped files, and scan counts.

For an existing extracted firmware folder, run SCAN_FIRMWARE_FSELF_WINDOWS.bat.

LIMITATIONS: Read-only audit; no carving, signing, decryption or FSELF-to-ELF
conversion. Candidate tables are heuristic. Files larger than 256 MiB are skipped.
The scanner sees extracted files, not encrypted or unexpanded contents inside PUP.
