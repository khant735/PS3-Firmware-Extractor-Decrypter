PS3 SPKG Extractor GUI v3.10 — embedded executable / Fake SELF discovery

New read-only embedded_container_audit.py module:
- Scans complete supplied files for ELF headers with bounded program header tables.
- Scans SCE signatures and checks the common SCE header and declared payload bounds.
- Reports LV1-style named embedded-file tables when a conservative table heuristic matches.
- Does NOT assume an SCE container is a Fake SELF solely from its filename or magic.
- Does NOT decrypt or carve payloads without verified container and table semantics.
- Integrates with existing nested ELF scan and writes embedded_container_audit.json.
- Existing v3.9 overlay filename matching remains unchanged.

Run standalone on Windows:
  AUDIT_EMBEDDED_WINDOWS.bat
or:
  py -3 embedded_container_audit.py "C:\path\ps2_netemu.elf"

Limitations: LV1 table parser is a heuristic; validate against a complete known LV1 ELF.
Compressed, encrypted and encoded payloads may have no visible SCE/ELF signature.
Only the files present on disk are inspected; missing ELF segments cannot be reconstructed.
