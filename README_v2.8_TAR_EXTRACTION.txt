PS3 SPKG Extractor GUI v2.8

New operation: Batch firmware decrypt + TAR extract

Choose update_files.tar, select the new operation, and run.
- Decrypts 48 SCE firmware containers with the existing external unpacker.
- Detects decrypted dev_flash TAR archives by ustar header.
- Extracts validated regular files/directories to output/update_files/dev_flash_extracted.
- Preserves each decrypted plaintext in output/update_files/decrypted.
- Rejects links, special entries, path traversal, duplicate regular-file paths, and oversized members.
- Does not attempt to decode unknown firmware payloads.
- firmware_batch_report.json and .csv contain per-entry extraction statuses.
- CORE_OS inner table is still preserved, not automatically expanded in this batch mode.

Local test: 2 supplied decrypted TAR samples validated and extracted (70 directory entries + 15 entries with 14 regular files). Full 24-archive Windows test pending.
