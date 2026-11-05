PS3 Firmware Extractor v3.8 — SPKG overlay audit

New: "Audit SPKG overlays (existing)" GUI button, or run AUDIT_SPKG_OVERLAYS_WINDOWS.bat.
Select your existing firmware extraction output directory. This is READ-ONLY.
No full firmware re-extraction, SELF conversion, or additional copies of packages are required.

The audit finds package files and SPKG overlay members (including *.pkg.spkg_hdr.1)
inside TAR files or as extracted files, hashes their contents, and associates packages
by exact basename. Results: spkg_overlay_audit.json and .csv in a sibling folder.

LIMITATION: this stage does NOT implement overlay substitution or attempt two-path
package decryption. It cannot establish cryptographic validity or identical decrypted
bodies. A basename match is only a filename match. Missing overlays are reported,
not considered evidence of a failed firmware extraction.
