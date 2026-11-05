v2.6 changes
- SPKG header catalogue: select spkg_hdr.tar and choose this operation. Generates spkg_header_catalogue.json with member names, sizes, SHA256 and nearby exact-filename package matches. Matches are NOT cryptographic validation.
- SPKG external extractor: if spkg_extract is absent, attempts the bundled unpkg -s backend for SCE-wrapped .pkg/.spkg. If the plaintext is a structurally valid CORE OS table, uses cosunpkg when installed; otherwise retains the plaintext without guessing its format.
- All existing v2.5 operations retained.
- Do not assume BDIT/BDPT compatibility. Decryption success requires real Windows testing.
- The header catalogue does not expose or invent decryption keys.
