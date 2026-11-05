PS3 SPKG Extractor GUI v3.4 — source integration / low-space analysis

The main GUI now has an "Analyze existing plaintext (v3.4)" button.
Select your existing decrypted folder and a report directory. The new tool
reads existing files and writes only firmware_v34_report.json and .csv.
No re-decryption, firmware copies, renaming, or hardware flashing occurs.

It recognises SYS_CON signature 1B2D700F, decodes the provisional header
layout from BitEdits ps3tools/syscon.c (mixed big/little endian), checks
CORE_OS inner package table, TAR and UPL XML, and labels opaque BDIT/BDPT
and MULTI_CARD firmware as not yet structurally verified.

Recommended names are informational only. Existing .plaintext files remain
untouched. This deliberately does not claim to recover info0/info1 from
plaintext; that requires original encrypted SCE PKG and a successful
unpkg full extraction, which is not implemented by this analysis pass.

Original BitEdits source: https://github.com/BitEdits/ps3tools
Its syscon.c was studied for header layout. This module is a new Python
implementation, not a compiled or bundled copy of that C source.

For CLI:
  py -3 firmware_v34.py --input "C:\path\to\decrypted" --report-dir "D:\reports"

This is a v3.4 analysis integration, NOT full firmware-package metadata
recovery or a Windows C backend compilation. Existing v3.1 workflows remain.
