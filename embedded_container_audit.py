"""Read-only ELF/SCE/FSELF and LV1-style embedded file-table audit.

Does not infer signatures, decrypt, or extract unverified ranges.
"""
import argparse
import hashlib
import json
import mmap
import re
from pathlib import Path

SCE=b'SCE\x00'
ELF=b'\x7fELF'
NAME=re.compile(rb'^[A-Za-z0-9_.-]{1,96}$')

def elf_header(data, at=0):
    n=len(data)
    if at+64>n or data[at:at+4]!=ELF:return None
    bits=data[at+4]; enc=data[at+5]
    if bits not in (1,2) or enc not in (1,2) or data[at+6]!=1:return None
    order='little' if enc==1 else 'big'
    u=lambda a,b:int.from_bytes(data[at+a:at+b],order)
    phoff=u(28,32) if bits==1 else u(32,40)
    entsize=u(42,44) if bits==1 else u(54,56)
    count=u(44,46) if bits==1 else u(56,58)
    if count and (entsize<32 or phoff+entsize*count>n-at):return None
    return {'class':32 if bits==1 else 64,'endianness':order,'machine':u(18,20),'program_headers':count}

def sce_header(data, at):
    if at+32>len(data) or data[at:at+4]!=SCE:return None
    # SCE common header: magic, version, flags, type, metadata offset, header length, data length.
    order='big'
    u=lambda a,b:int.from_bytes(data[at+a:at+b],order)
    hdr=u(16,24); payload=u(24,32)
    valid=hdr>=32 and hdr<=len(data)-at and payload<=len(data)-at-hdr
    return {'version':u(4,8),'flags':u(8,10),'sce_type':u(10,12),
            'metadata_offset':u(12,16),'header_length':hdr,'data_length':payload,
            'bounds_valid':valid,'container_end':at+hdr+payload if valid else None,
            'classification':'SCE container candidate (FSELF not proven by magic alone)'}

def file_tables(data):
    """Conservative candidate LV1 table scan; table is not universal to ELF files.

    Table: count u32, length u32, then variable-length records of index/u32,
    offset/u32, length/u32, NUL-terminated filename, 4-byte alignment.
    Both byte orders checked. Offsets are relative to the end of table.
    """
    found=[]; n=len(data)
    for at in range(0,min(n-8,8*1024*1024),4):
        for order in ('big','little'):
            u=lambda pos:int.from_bytes(data[pos:pos+4],order)
            count=u(at); length=u(at+4)
            if not 2<=count<=128 or not 8+count*16<=length<=65536 or at+length>n:continue
            pos=at+8; rows=[]; ok=True
            for _ in range(count):
                if pos+13>at+length:ok=False;break
                idx=u(pos); start=u(pos+4); size=u(pos+8)
                term=data.find(b'\0',pos+12,min(pos+110,at+length))
                if term<0:ok=False;break
                name=bytes(data[pos+12:term])
                if not NAME.fullmatch(name) or not 0<size<=n or start+size>n-(at+length):ok=False;break
                absolute=at+length+start
                rows.append({'index':idx,'name':name.decode('ascii'),'offset':absolute,'length':size,
                             'magic':bytes(data[absolute:absolute+4]).hex()})
                pos=(term+1+3)&~3
            if ok and len(rows)==count and len(set(r['index'] for r in rows))==count and len(set(r['name'] for r in rows))==count:
                if any(r['name'].lower().endswith(('.fself','.self','.elf')) for r in rows):
                    found.append({'offset':at,'byte_order':order,'table_length':length,'entries':rows,
                                  'status':'candidate: table layout inferred; verify against source format'})
    return found

def audit(path):
    path=Path(path)
    with path.open('rb') as f:
        if not f.seek(0,2):return {'file':str(path),'size':0,'error':'empty file'}
        f.seek(0)
        with mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as data:
            matches=[]
            for magic,kind in ((ELF,'ELF'),(SCE,'SCE')):
                start=0
                while True:
                    at=data.find(magic,start)
                    if at<0:break
                    start=at+1
                    parsed=elf_header(data,at) if kind=='ELF' else sce_header(data,at)
                    if parsed is not None:matches.append({'offset':at,'kind':kind,**parsed})
            tables=file_tables(data)
            return {'schema_version':1,'file':str(path),'size':len(data),
                    'sha256':hashlib.sha256(data).hexdigest(),'headers':sorted(matches,key=lambda x:x['offset']),
                    'lv1_style_tables':tables,'fself_note':'A .fself name is a hint only; inspect SCE and ELF headers before claiming a Fake SELF.',
                    'limitations':['Signature absence does not exclude compressed/encrypted executables.',
                                   'LV1 table parser is a conservative heuristic, not proof of an LV1 file table.',
                                   'No decryption, signing, or extraction performed.']}

def main():
    ap=argparse.ArgumentParser(description='Read-only embedded executable audit')
    ap.add_argument('input',type=Path)
    ap.add_argument('--output',type=Path)
    a=ap.parse_args(); result=audit(a.input)
    output=a.output or a.input.with_suffix(a.input.suffix+'.embedded_audit.json')
    output.write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(f"Headers: {len(result.get('headers',[]))}; LV1-style tables: {len(result.get('lv1_style_tables',[]))}; report: {output}")
if __name__=='__main__':main()
