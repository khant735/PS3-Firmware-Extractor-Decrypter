Version 3.7 - SPRX discovery and embedded executable inventory
- Auto nested conversion now discovers .self and .sprx in the full extracted tree (not just one subfolder).
- Uses SCE magic to choose decryption; plaintext ELF and unsupported/opaque files are inventoried, not passed to unself.
- Keeps original encrypted sources; converted files are stored in ELF/ with source-relative paths.
- executable_discovery.json lists file extensions, header types, and sizes.
- embedded_executable_inventory.json scans converted ELF outputs for nested ELF/SCE signatures and validates basic ELF header bounds.
- IMPORTANT: embedded discovery is report-only. Embedded SELF/ELF extraction is NOT yet implemented because signature offsets do not establish safe container lengths.
- The Windows unself.exe tool and valid keys are still required. No Windows firmware test was performed here.
