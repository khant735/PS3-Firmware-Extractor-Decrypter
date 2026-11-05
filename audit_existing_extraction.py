#!/usr/bin/env python3
"""Audit a v3.0/v3.1 extracted firmware directory without decrypting again."""
import argparse
from pathlib import Path
from ps3_spkg_extractor_gui import audit_dev_flash_tars

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('output',type=Path,help='Existing extraction folder (contains decrypted/ and dev_flash_extracted/)')
    args=ap.parse_args()
    root=args.output.resolve()
    extracted=root/'dev_flash_extracted'
    if not extracted.is_dir():ap.error('Missing dev_flash_extracted directory: '+str(extracted))
    tars=sorted((root/'decrypted').glob('*.plaintext'))
    import tarfile
    tars=[p for p in tars if 'dev_flash' in p.name.lower() and tarfile.is_tarfile(p)]
    if not tars:ap.error('No decrypted dev_flash TAR plaintext files found in '+str(root/'decrypted'))
    print('Auditing',len(tars),'decrypted dev_flash TAR files...')
    report=audit_dev_flash_tars(tars,extracted,root)
    matches=[r for r in report['entries'] if Path(r['member']).name.lower()=='mcore_tk.self']
    if matches:
        print('\nmcore_tk.self:')
        for r in matches:print('  TAR size:',r['archive_size'],'Extracted size:',r['extracted_size'],'Status:',r['status'])
    else:print('\nmcore_tk.self: not found in audited TAR members')
    print('Reports:',root/'firmware_tar_integrity.json','and .csv')

if __name__=='__main__':main()
