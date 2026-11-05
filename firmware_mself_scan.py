"""v3.12 read-only MSELF discovery and conservative header validation.

RPCS3 sys_fs.cpp verify_mself: magic MSF\0, version 1, entry size
sizeof(FsMselfEntry). The exact entry layout is deliberately NOT guessed here.
"""
import argparse
import json
import mmap
import time
from pathlib import Path

MAGIC=b'MSF\x00'
SKIP_DIRS={'__pycache__','embedded_executables','.git'}
SKIP_NAMES={'firmware_mself_inventory.json','firmware_fself_inventory.json'}
MAX_BYTES=512*1024*1024

def inspect(data, offset=0):
    size=len(data)
    result={'offset':offset,'status':'candidate','magic':'MSF\\0'}
    if offset+16>size:
        result.update(status='invalid',reason='truncated header')
        return result
    # Big-endian header values are consistent with RPCS3 be_t fields.
    version=int.from_bytes(data[offset+4:offset+8],'big')
    result['version_be']=version
    if version!=1:
        result.update(status='invalid',reason='unsupported format version')
        return result
    # Preserve raw words rather than assigning unverified field offsets.
    result['header_first_32_bytes']=bytes(data[offset:offset+32]).hex()
    result.update(status='header_candidate',reason='magic and version valid; entry layout/entry_size not yet independently validated')
    return result

def scan(root,emit=print):
    root=Path(root).resolve()
    if not root.is_dir():raise ValueError('Not a directory: '+str(root))
    started=time.perf_counter()
    findings=[]; skipped=[]; stats={'files_examined':0,'files_with_mself_magic':0,'header_candidates':0,'invalid_headers':0,'verified_entry_tables':0,'extracted_entries':0}
    for path in sorted(root.rglob('*')):
        if not path.is_file():continue
        rel=path.relative_to(root)
        if any(p in SKIP_DIRS for p in rel.parts) or path.name in SKIP_NAMES:continue
        stats['files_examined']+=1
        try:
            size=path.stat().st_size
            if size==0:continue
            if size>MAX_BYTES:
                skipped.append({'path':str(rel),'reason':'over scan size limit','size':size});continue
            with path.open('rb') as fp, mmap.mmap(fp.fileno(),0,access=mmap.ACCESS_READ) as data:
                pos=0; found=[]
                while (pos:=data.find(MAGIC,pos))!=-1:
                    found.append(inspect(data,pos));pos+=len(MAGIC)
                if found:
                    stats['files_with_mself_magic']+=1
                    stats['header_candidates']+=sum(x['status']=='header_candidate' for x in found)
                    stats['invalid_headers']+=sum(x['status']=='invalid' for x in found)
                    findings.append({'path':str(rel),'size':size,'matches':found})
        except (OSError,ValueError,OverflowError) as exc:
            skipped.append({'path':str(rel),'reason':str(exc)})
    report={'schema_version':1,'mode':'read-only','root':str(root),'counts':stats,'elapsed_seconds':round(time.perf_counter()-started,3),'files':findings,'skipped':skipped,
            'limitations':['MSELF entry layout and entry-size validation are not implemented.',
                           'No MSELF payload extraction or SELF decryption is performed.',
                           'Scanning is limited to files already extracted/decrypted from the PUP.']}
    dest=root/'firmware_mself_inventory.json'
    dest.write_text(json.dumps(report,indent=2),encoding='utf-8')
    emit(f"MSELF discovery: {stats['files_examined']} files examined, {stats['header_candidates']} header candidates, {stats['verified_entry_tables']} verified tables; {dest.name}")
    return report

if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('directory',type=Path)
    scan(ap.parse_args().directory)
