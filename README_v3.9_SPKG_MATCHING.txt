PS3 SPKG Extractor GUI v3.9 — read-only SPKG overlay matching improvements

- Detects original .pkg files with numbered prefixes, e.g. 013_CORE_OS_PACKAGE.pkg.
- Inventories .pkg members of TAR and ZIP archives without extracting them.
- Separately reports package files, package archive members, and archives inspected.
- Retains full candidate locations and distinguishes ambiguous vs unmatched entries.
- Writes spkg_overlay_audit.json and .csv in sibling report directory.
- Does not delete, modify, decrypt, or re-extract original firmware files.
- Does not parse PUP package contents or recursively decode nested TAR/ZIP members.
- An unmatched overlay is not proof of a missing/corrupt package; original encrypted packages may not have been retained.
- Does not cryptographically validate overlays or test decrypted body equivalence.

Launch GUI and select 'Audit SPKG overlays (existing)' or run AUDIT_SPKG_OVERLAYS_WINDOWS.bat.
Select the existing output/PS3UPDAT directory.
