"""Recursive read-only FSELF/embedded executable inventory for extracted PUP trees."""
import argparse
import json
import mmap
import time
import os
from embedded_container_audit import elf_header, sce_header
from pathlib import Path
from embedded_container_audit import audit

EXTS={'.elf','.self','.fself','.sprx','.prx','.bin','.irx'}
SKIP={'embedded_executables','__pycache__'}
MAX_SIZE=256*1024*1024

def scan(root, emit=print, deep=False):
    started=time.perf_counter()
    root=Path(root).resolve()
    if not root.is_dir(): raise ValueError('Extraction directory does not exist')
    records=[]; candidates=[]; skipped=[]; counts={'scanned':0,'fself_named':0,'lv1_tables':0,'embedded_fself_entries':0,'embedded_headers':0, 'fast_header_checks':0}
    for path in sorted(root.rglob('*')):
        if not path.is_file() or any(part in SKIP for part in path.relative_to(root).parts):continue
        if path.name in {'embedded_container_audit.json','embedded_executable_inventory.json','firmware_fself_inventory.json'} or (path.name.startswith('firmware_') and path.suffix=='.json'):continue
        rel=str(path.relative_to(root)); size=path.stat().st_size
        if not size or size>MAX_SIZE:
            if path.suffix.lower() in EXTS:skipped.append({'path':rel,'reason':'empty or over size limit','size':size})
            continue
        try:
            named=path.suffix.lower() in EXTS
            with path.open('rb') as source, mmap.mmap(source.fileno(),0,access=mmap.ACCESS_READ) as buf:
                magic=bytes(buf[:4])
                # Fast mode only examines header structures. It does not claim to
                # discover embedded executables inside arbitrary parent files.
                if not deep:
                    if not named and magic not in (b'SCE\x00',b'\x7fELF'):
                        continue
                    header=(sce_header(buf,0) if magic==b'SCE\x00' else
                            elf_header(buf,0) if magic==b'\x7fELF' else None)
                    counts['fast_header_checks']+=1
                    counts['scanned']+=1
                    if path.suffix.lower()=='.fself':counts['fself_named']+=1
                    records.append({'path':rel,'size':size,'extension':path.suffix.lower(),
                                    'top_level_magic':magic.hex(),
                                    'headers':[{'offset':0,'kind':'SCE' if magic==b'SCE\x00' else 'ELF',**header}] if header else [],
                                    'lv1_style_tables':[],
                                    'fself_status':'filename_hint_only' if path.suffix.lower()=='.fself' else 'not_verified',
                                    'note':'SCE magic does not establish Fake/Debug SELF subtype'})
                    continue
                if not named and magic not in (b'SCE\x00',b'\x7fELF'):
                    if (buf.find(b'SCE\x00')<0 and buf.find(b'\x7fELF')<0 and buf.find(b'.fself')<0):
                        continue
            result=audit(path)
            counts['scanned']+=1
            if path.suffix.lower()=='.fself':counts['fself_named']+=1
            tables=result.get('lv1_style_tables',[])
            counts['lv1_tables']+=len(tables)
            headers=[h for h in result.get('headers',[]) if h['offset']>0]
            counts['embedded_headers']+=len(headers)
            for table in tables:
                for entry in table['entries']:
                    if entry['name'].lower().endswith('.fself'):
                        counts['embedded_fself_entries']+=1
                        candidates.append({'parent':rel,'table_offset':table['offset'],**entry,'status':'table candidate; not extracted'})
            records.append({'path':rel,'size':size,'extension':path.suffix.lower(),'top_level_magic':magic.hex(),
                            'headers':result.get('headers',[]),'lv1_style_tables':tables})
        except (OSError,ValueError,OverflowError) as exc:
            skipped.append({'path':rel,'reason':str(exc)})
    output={'schema_version':1,'mode':'read-only-deep' if deep else 'read-only-fast','root':str(root),'counts':counts,'files':records,
            'embedded_fself_candidates':candidates,'skipped':skipped,
            'notes':['Candidate LV1 tables are heuristic, not verified archive structures.',
                     'No candidate bytes are carved or decrypted.','Only extracted filesystem contents are scanned; opaque encrypted/compressed PUP data is not directly searched.']}
    dest=root/'firmware_fself_inventory.json'
    dest.write_text(json.dumps(output,indent=2),encoding='utf-8')
    output['elapsed_seconds']=round(time.perf_counter()-started,3)
    dest.write_text(json.dumps(output,indent=2),encoding='utf-8')
    emit(f"Firmware FSELF scan: {counts['scanned']} executable files; {counts['embedded_fself_entries']} table candidates; report: {dest.name}")
    return output

if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('directory',type=Path)
    ap.add_argument('--deep',action='store_true',help='Run original exhaustive embedded signature and LV1 table audit')
    args=ap.parse_args();scan(args.directory,deep=args.deep)
