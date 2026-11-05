PS3 SPKG Extractor GUI v3.5 — integrated Auto firmware workflow

Auto on a PS3UPDAT.PUP now unpacks the PUP and processes update_files.tar:
- decrypt SCE firmware packages using bundled/external unpkg.exe and ps3keys
- export info0/info1 (64 bytes each) for .pkg members with full unpkg
- move decrypted content into decrypted/ (no extra content copy)
- extract dev_flash TAR payloads, audit them, and inventory extracted files
- unpack recognised CORE_OS tables with cosunpkg.exe; unpack TAR inner packages
- analyse decrypted files including SYS_CON headers; produce JSON/CSV reports
- optionally decrypt nested SELF/SPRX files when the GUI option is enabled

Outputs: firmware_auto/firmware_batch_report.json, package_metadata/, decrypted/,
dev_flash_extracted/, firmware_packages_extracted/, firmware_v34_report.json,
auto_summary.json and other existing reports.

REQUIREMENTS: Windows, Python 3.9+, Tkinter, tools/pupunpack.exe, tools/unpkg.exe,
tools/cosunpkg.exe, ps3keys/pkg-key-* compatible with the supplied firmware.

LIMITATIONS: This is not a proof of full internal decryption of BDPT, BDIT,
SYS_CON, or MULTI_CARD firmware blobs. They remain preserved as plaintext
package payloads. Full Auto requires ample free space and does not resume
partially completed output directories. Do not use 'Replace existing' on
valuable prior extractions. Testing against a real 4.93 PUP remains necessary.
