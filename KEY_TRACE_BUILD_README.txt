PS3 SPKG Extractor v2.2 key tracing SOURCE package

The GUI now parses KEY_AUDIT_REQUEST and KEY_AUDIT_SELECTED records.
IMPORTANT: the bundled tools directory does NOT contain newly compiled instrumented binaries.
Build instrumented_ps3tools_source/build-windows-audit.ps1 from an MSYS2 UCRT64 environment with gcc and zlib, then run START_WINDOWS.bat.
Do not replace existing working tools until the new builds have been tested.
The selected identifier denotes the AES metadata-header match; overall decryption is separately validated by the GUI. No raw key bytes are logged.
For older uninstrumented binaries, selected_key remains null.
