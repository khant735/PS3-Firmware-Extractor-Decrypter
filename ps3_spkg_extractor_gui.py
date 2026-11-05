#!/usr/bin/env python3
"""PS3 firmware package extractor GUI. Python 3.9+; tkinter; no third-party modules."""
import csv
import hashlib
import re
import json
import os
import queue
import shutil
import subprocess
import sys
import re
import tarfile
import threading
import time
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

BASE = Path(sys.executable).resolve().parent if getattr(sys, 'frozen', False) else Path(__file__).resolve().parent
SUPPORTED = {".pup", ".pkg", ".spkg", ".self", ".tar", ".zip"}
def elf_info(path):
    """Basic ELF header verification, including PowerPC/SPU machine and program header bounds."""
    with open(path, "rb") as f:
        h=f.read(64)
    if len(h)<52 or h[:4]!=b"\x7fELF":
        return None
    bits=h[4]; endian=h[5]
    if bits not in (1,2) or endian not in (1,2) or h[6]!=1:
        return None
    order="little" if endian==1 else "big"
    machine=int.from_bytes(h[18:20],order)
    phoff=int.from_bytes(h[28:32],order) if bits==1 else int.from_bytes(h[32:40],order)
    phentsize=int.from_bytes(h[42:44],order) if bits==1 else int.from_bytes(h[54:56],order)
    phnum=int.from_bytes(h[44:46],order) if bits==1 else int.from_bytes(h[56:58],order)
    size=path.stat().st_size
    if phnum and (not phentsize or phoff+phentsize*phnum>size):
        return None
    return {"class":32 if bits==1 else 64,"machine":{23:"SPU",20:"PowerPC",21:"PowerPC64"}.get(machine,f"0x{machine:04X}"),"size":size,"sha256":sha256(path)}

def discover_executable_files(work):
    """Discover encrypted SCE files and plaintext ELF modules, without relying on suffixes."""
    results=[]
    excluded={'ELF','embedded_executables'}
    for p in work.rglob('*'):
        if not p.is_file() or any(part in excluded for part in p.relative_to(work).parts):
            continue
        if p.suffix.lower() not in ('.self','.sprx','.bin','.prx','.irx') and p.name.lower() not in ('lv0','lv0.2','lv1'):
            continue
        with p.open('rb') as f: magic=f.read(4)
        kind='sce' if magic==b'SCE\x00' else 'elf' if magic==b'\x7fELF' else 'empty' if p.stat().st_size==0 else 'other'
        results.append({'path':str(p.relative_to(work)),'extension':p.suffix.lower(),'kind':kind,'size':p.stat().st_size})
    return results


def scan_embedded_executables(work, emit):
    """Non-destructive nested ELF/SCE inventory. Offsets alone do not prove payload bounds."""
    import mmap
    rows=[]
    for p in (work/'ELF').rglob('*.elf') if (work/'ELF').exists() else []:
        size=p.stat().st_size
        if size<64 or size>256*1024*1024:
            continue
        with p.open('rb') as f:
            with mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as data:
                for magic,kind in ((b'SCE\x00','SCE'),(b'\x7fELF','ELF')):
                    cursor=1
                    while True:
                        off=data.find(magic,cursor)
                        if off<0:break
                        cursor=off+4
                        if kind=='ELF':
                            if off+52>size or data[off+4] not in (1,2) or data[off+5] not in (1,2) or data[off+6]!=1:continue
                            endian='big' if data[off+5]==2 else 'little'
                            bits=data[off+4]
                            phoff=int.from_bytes(data[off+(28 if bits==1 else 32):off+(32 if bits==1 else 40)],endian)
                            phentsize=int.from_bytes(data[off+(42 if bits==1 else 54):off+(44 if bits==1 else 56)],endian)
                            phnum=int.from_bytes(data[off+(44 if bits==1 else 56):off+(46 if bits==1 else 58)],endian)
                            if phnum and (phentsize==0 or phoff+phentsize*phnum>size-off):continue
                            confidence='ELF header and program-header bounds checked'
                        else:
                            if off+32>size:continue
                            # SCE magic is only a candidate; container length is not established.
                            confidence='SCE signature candidate; container boundaries unverified'
                        rows.append({'parent':str(p.relative_to(work)),'offset':off,'kind':kind,'validation':confidence,'extracted':False})
    # v3.10: separate header-validated read-only FSELF/LV1-style audit.
    from embedded_container_audit import audit as audit_embedded
    audits=[]
    for p in (work/'ELF').rglob('*.elf') if (work/'ELF').exists() else []:
        if p.stat().st_size>256*1024*1024 or p.stat().st_size==0:continue
        try:
            report=audit_embedded(p)
            audits.append({'parent':str(p.relative_to(work)),
                           'headers':report.get('headers',[]),
                           'lv1_style_tables':report.get('lv1_style_tables',[])})
        except (OSError, ValueError) as exc:
            emit(f'Embedded container audit skipped {p.name}: {exc}')
    (work/'embedded_container_audit.json').write_text(json.dumps({
        'schema_version':1,'mode':'read-only', 'files':audits},indent=2),encoding='utf-8')
    emit(f'Embedded container audit: {len(audits)} ELF files checked; report embedded_container_audit.json')
    dest=work/'embedded_executable_inventory.json' 
    dest.write_text(json.dumps({'schema_version':1,'note':'Discovery only: no byte carving without validated container boundaries.','entries':rows},indent=2),encoding='utf-8')
    emit(f'Embedded executable scan: {len(rows)} candidate(s), inventory: {dest.name}; no unverified payloads carved.')
    return rows


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024*1024), b""):
            h.update(chunk)
    return h.hexdigest()

def key_file_candidates(directory, pattern):
    """Non-secret key identifiers and fingerprints, not key bytes."""
    return [{"identifier":f.name,"sha256":sha256(f)} for f in sorted(directory.glob(pattern)) if f.is_file()]

def key_report_record(stage, source, output, status, tool, database, candidates, evidence, trace=None):
    trace = trace or {}
    return {"stage":stage,"source":str(source),"output":str(output),
            "status":status,"backend":Path(tool).name if tool else None,
            "key_database":str(database),"candidate_keys":candidates,
            "selected_key":trace.get("selected_key"),"requested_keys":trace.get("requested_keys",[]),"key_identification":"backend header match" if trace.get("selected_key") else "not reported by backend",
            "evidence":evidence}

def sniff(p):
    if p.suffix.lower()==".tar" and tarfile.is_tarfile(p): return "TAR archive"
    with p.open("rb") as f: head=f.read(32)
    if head.startswith(b"SCEUF"): return "PS3 firmware PUP (SCEUF)"
    if head.startswith(b"\x7fELF"): return "ELF (already decrypted)"
    if head.startswith(b"SCE\x00"): return "SCE container (SELF/SPKG candidate)"
    if head.startswith(b"\x7fPKG"): return "Sony PKG"
    if head.startswith(b"PK\x03\x04"): return "ZIP"
    if head.startswith(b"\x00\x00\x00\x00"): return "Unknown binary (inspect)"
    return "Unknown / format-specific"

def spkg_header_catalogue(archive, output):
    """Catalogue TAR members and match exact package basenames; never treat headers as keys."""
    if not tarfile.is_tarfile(archive):
        raise RuntimeError("SPKG header catalogue requires a valid TAR archive")
    entries=[]
    with tarfile.open(archive) as tf:
        for member in tf.getmembers():
            if not member.isfile():
                continue
            name=Path(member.name).name
            if not name or name in (".",".."):
                continue
            fp=tf.extractfile(member)
            if fp is None: continue
            digest=hashlib.sha256(); count=0; prefix=b""
            while True:
                chunk=fp.read(1024*1024)
                if not chunk:break
                if not prefix:prefix=chunk[:32]
                digest.update(chunk);count+=len(chunk)
            # Header naming conventions are not standardized; only exact stem matches are candidates.
            pkg_name=name
            for suffix in (".spkg_hdr", ".spkg_header", ".hdr"):
                if pkg_name.lower().endswith(suffix):
                    pkg_name=pkg_name[:-len(suffix)];break
            entries.append({"header_member":member.name,"size":count,"sha256":digest.hexdigest(),
                            "first_32_bytes":prefix.hex(),"candidate_package_name":pkg_name,
                            "matched_package":None,"match_basis":None})
    # Search only nearby folders, not the entire disk. Never claim cryptographic verification.
    dirs=[archive.parent,archive.parent.parent,archive.parent.parent.parent]
    for row in entries:
        name=row["candidate_package_name"]
        if not name.lower().endswith('.pkg'):continue
        for directory in dirs:
            candidate=directory/name
            if candidate.is_file():
                row["matched_package"]=str(candidate)
                row["match_basis"]="filename only (NOT cryptographically verified)"
                break
    report={"schema_version":1,"source":str(archive),"header_count":len(entries),
            "warning":"Headers are not decryption keys; filename matching does not verify package authenticity.",
            "entries":entries}
    (output/'spkg_header_catalogue.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    return report

def extract_firmware_tar(path, target, seen, max_total=2*1024**3):
    """Validate first; extract only regular files/directories, refuse collisions and links."""
    import io
    target=target.resolve()
    records=[]
    with tarfile.open(path,'r:*') as tf:
        for m in tf:
            if not (m.isfile() or m.isdir()):
                raise ValueError('Unsupported TAR entry type: '+m.name)
            raw=m.name.replace('\\','/')
            from pathlib import PurePosixPath
            parts=PurePosixPath(raw).parts
            if not parts or raw.startswith('/') or '..' in parts or ':' in raw or '\\' in m.name:
                raise ValueError('Unsafe TAR path: '+m.name)
            dest=target.joinpath(*parts)
            if dest.resolve()!=target and target not in dest.resolve().parents:
                raise ValueError('Unsafe TAR destination: '+m.name)
            if m.isfile() and m.size>max_total:
                raise ValueError('Oversized TAR member: '+m.name)
            records.append((m,dest))
        # Preflight against prior archive content and existing files.
        local=set()
        for m,dest in records:
            rel=dest.relative_to(target).as_posix().casefold()
            if m.isfile():
                if rel in local or rel in seen or dest.exists() or dest.is_symlink():
                    raise ValueError('Duplicate/conflicting TAR member: '+m.name)
                local.add(rel)
            elif dest.exists() and not dest.is_dir():
                raise ValueError('Directory collides with file: '+m.name)
        total=sum(m.size for m,_ in records if m.isfile())
        if total>max_total:raise ValueError('TAR expanded size exceeds safety limit')
        for m,dest in records:
            if m.isdir():
                dest.mkdir(parents=True,exist_ok=True)
            else:
                dest.parent.mkdir(parents=True,exist_ok=True)
                with tf.extractfile(m) as src, dest.open('xb') as dst:
                    shutil.copyfileobj(src,dst,1024*1024)
        seen.update(local)
    return {'entries':len(records),'files':len(local),'bytes':total}

def audit_dev_flash_tars(tars, extracted_root, report_root, emit=print):
    """Compare TAR member lengths and SHA256 with extracted files; never modify originals."""
    from pathlib import PurePosixPath
    entries=[]
    for tar in sorted(map(Path,tars)):
        if not tar.is_file() or not tarfile.is_tarfile(tar):
            continue
        with tarfile.open(tar,'r:*') as tf:
            for member in tf:
                if not member.isfile(): continue
                name=member.name.replace('\\','/')
                parts=PurePosixPath(name).parts
                if not parts or name.startswith('/') or '..' in parts or ':' in name or '\\' in member.name:
                    entries.append({'tar':tar.name,'member':member.name,'archive_size':member.size,'extracted_size':None,'status':'unsafe archive path','archive_sha256':None,'extracted_sha256':None})
                    continue
                source=tf.extractfile(member)
                digest=hashlib.sha256()
                for chunk in iter(lambda:source.read(1024*1024),b''):
                    digest.update(chunk)
                dest=extracted_root.joinpath(*parts)
                row={'tar':tar.name,'member':member.name,'archive_size':member.size,'extracted_size':None,'status':'missing','archive_sha256':digest.hexdigest(),'extracted_sha256':None}
                if dest.is_file() and not dest.is_symlink():
                    row['extracted_size']=dest.stat().st_size
                    row['extracted_sha256']=sha256(dest)
                    row['status']='match' if member.size==row['extracted_size'] and digest.hexdigest()==row['extracted_sha256'] else 'mismatch'
                    if member.size==0 and row['status']=='match':row['status']='empty in original TAR'
                    elif member.size>0 and row['extracted_size']==0:row['status']='empty after extraction (CORRUPT)'
                entries.append(row)
    counts={status:sum(r['status']==status for r in entries) for status in sorted(set(r['status'] for r in entries))}
    report={'schema_version':1,'note':'Archive member bytes compared to extracted file bytes. Empty archive entries are distinct from truncated output.','total':len(entries),'counts':counts,'entries':entries}
    report_root.mkdir(parents=True,exist_ok=True)
    (report_root/'firmware_tar_integrity.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    with (report_root/'firmware_tar_integrity.csv').open('w',newline='',encoding='utf-8-sig') as f:
        writer=csv.DictWriter(f,fieldnames=['tar','member','archive_size','extracted_size','status','archive_sha256','extracted_sha256']);writer.writeheader();writer.writerows(entries)
    emit('TAR integrity audit: %d members | %s'%(len(entries),counts))
    for row in entries:
        if row['status'] not in ('match','empty in original TAR'):
            emit('TAR INTEGRITY: %s | %s'%(row['status'],row['member']))
    return report

def extract_inner_firmware_packages(rows, output, emit, tools, run_tool):
    """Extract only identified inner formats; leave every plaintext source untouched."""
    result=[]
    seen=set()
    inner_root=output/'firmware_packages_extracted'
    for row in rows:
        if row['kind']!='pkg' or not row.get('decrypted_file'):
            continue
        source=output/row['decrypted_file']
        fmt=row.get('inner_magic') or 'unknown'
        item={'member':row['member'],'plaintext':row['decrypted_file'],
              'format':fmt,'status':'unsupported / preserved','output':None,
              'files':0,'bytes':0,'error':None}
        if fmt=='TAR' or fmt.startswith('CORE_OS table'):
            folder=inner_root/('%03d_'%len(result)+re.sub(r'[^A-Za-z0-9_.-]','_',Path(row['member']).name))
            try:
                folder.mkdir(parents=True,exist_ok=False)
                if fmt=='TAR':
                    details=extract_firmware_tar(source,folder,set())
                    item.update(status='extracted',output=str(folder.relative_to(output)),
                                files=details['files'],bytes=details['bytes'])
                else:
                    backend=(tools/'cosunpkg.exe') if tools else None
                    if not backend or not backend.is_file():
                        item['status']='backend unavailable / preserved'
                    else:
                        run_tool(backend,[source,folder])
                        children=[f for f in folder.rglob('*') if f.is_file() and not f.is_symlink()]
                        if not children:raise RuntimeError('cosunpkg produced no extracted files')
                        item.update(status='extracted',output=str(folder.relative_to(output)),
                                    files=len(children),bytes=sum(f.stat().st_size for f in children))
                if item['status']!='extracted':folder.rmdir()
            except Exception as exc:
                item['status']='extraction failed / preserved'
                item['error']=str(exc)
        result.append(item)
        emit('Inner package: %s | %s | %s'%(row['member'],fmt,item['status']))
    report={'schema_version':1,'note':'Original decrypted package payloads are preserved. Unsupported formats are not extraction failures.',
            'total':len(result),'extracted':sum(x['status']=='extracted' for x in result),
            'unsupported':sum(x['status']=='unsupported / preserved' for x in result),
            'backend_unavailable':sum(x['status']=='backend unavailable / preserved' for x in result),
            'failed':sum(x['status']=='extraction failed / preserved' for x in result),
            'entries':result}
    (output/'firmware_inner_package_report.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    with (output/'firmware_inner_package_report.csv').open('w',newline='',encoding='utf-8-sig') as f:
        w=csv.DictWriter(f,fieldnames=['member','plaintext','format','status','output','files','bytes','error'])
        w.writeheader();w.writerows(result)
    return report

def inventory_firmware_tree(root, output):
    """Inventory extracted firmware paths; classify by magic and extension independently."""
    from collections import Counter
    roots=[root / 'dev_flash',root / 'dev_flash3']
    rows=[]; extensions=Counter(); signatures=Counter(); total_bytes=0
    for top in roots:
        if not top.is_dir(): continue
        for path in sorted(top.rglob('*')):
            if path.is_symlink():
                raise ValueError('Unexpected symlink in firmware tree: '+str(path))
            if not path.is_file(): continue
            rel=path.relative_to(root).as_posix()
            with path.open('rb') as f: head=f.read(512)
            if head.startswith(b'SCE\x00'): signature='SCE container'
            elif head.startswith(b'\x7fELF'): signature='ELF'
            elif head.startswith(b'PK\x03\x04'): signature='ZIP'
            elif head.startswith(b'\x89PNG\r\n\x1a\n'): signature='PNG'
            elif head.startswith(b'\xff\xd8\xff'): signature='JPEG'
            elif head.startswith(b'OTTO'): signature='OpenType font'
            elif head.startswith(b'\x00\x01\x00\x00'): signature='TrueType font (probable)'
            elif len(head)>=262 and head[257:262]==b'ustar': signature='TAR'
            elif head.lstrip().startswith(b'<?xml'): signature='XML'
            else: signature='unrecognized / data'
            ext=path.suffix.lower() or '(none)'
            size=path.stat().st_size
            rows.append({'path':rel,'extension':ext,'signature':signature,'size':size,'sha256':sha256(path),
                         'self_candidate':ext in ('.self','.sprx') and signature=='SCE container'})
            extensions[ext]+=1; signatures[signature]+=1; total_bytes+=size
    report={'schema_version':1,'root':str(root),'total_files':len(rows),'total_bytes':total_bytes,
            'extension_counts':dict(sorted(extensions.items())),
            'signature_counts':dict(sorted(signatures.items())),
            'note':'Extensions and signatures are independent; unknown formats are preserved without conversion.',
            'files':rows}
    (output/'firmware_file_inventory.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    with (output/'firmware_file_inventory.csv').open('w',newline='',encoding='utf-8-sig') as f:
        w=csv.DictWriter(f,fieldnames=['path','extension','signature','size','sha256','self_candidate'])
        w.writeheader();w.writerows(rows)
    return report

def batch_firmware_archive(archive, output, emit, tools=None, decrypt=False, run_tool=None, extract_tars=False, extract_inner=False, recover_metadata=False):
    """Inventory all TAR members; optional per-member SCE decryption, never assume TAR by name."""
    if not tarfile.is_tarfile(archive):
        raise RuntimeError("Batch firmware analysis requires a valid outer TAR archive")
    rows=[]
    keydir=BASE/'ps3keys'
    backend=(tools/'unpkg.exe') if tools else None
    can_decrypt=bool(backend and backend.is_file() and keydir.is_dir() and list(keydir.glob('pkg-key-*')))
    if decrypt and not can_decrypt:
        raise RuntimeError('Batch decryption requires tools/unpkg.exe and ps3keys/pkg-key-*')
    if decrypt: (output/'decrypted').mkdir(exist_ok=True)
    seen=set()
    if extract_tars:(output/'dev_flash_extracted').mkdir(exist_ok=True)
    with tarfile.open(archive,'r:*') as tf:
        for index,m in enumerate(tf):
            if not m.isfile(): continue
            f=tf.extractfile(m)
            if f is None: continue
            digest=hashlib.sha256(); first=b''; n=0
            while True:
                block=f.read(1024*1024)
                if not block: break
                if not first: first=block[:512]
                digest.update(block); n+=len(block)
            name=Path(m.name).name
            kind=('pkg' if name.lower().endswith('.pkg') else 'dev_flash' if name.lower().startswith('dev_flash') else 'image' if name.lower().endswith('.img') else 'other')
            magic=('SCE' if first.startswith(b'SCE\x00') else 'ELF' if first.startswith(b'\x7fELF') else 'ZIP' if first.startswith(b'PK\x03\x04') else 'TAR' if len(first)>=262 and first[257:262]==b'ustar' else 'unknown')
            row={'member':m.name,'size':n,'sha256':digest.hexdigest(),'kind':kind,'outer_magic':magic,'header_hex':first[:32].hex(' '),'status':'inspected','decrypted_file':None,'inner_magic':None,'inner_header_hex':None,'error':None}
            if decrypt and magic=='SCE' and kind in ('pkg','dev_flash'):
                # Stage only one member at a time. Never trust member paths or use them as filesystem paths.
                staged=output/'_batch_input.tmp'
                dest=output/'decrypted'/('%03d_'%index+re.sub(r'[^A-Za-z0-9_.-]','_',name)+'.plaintext')
                try:
                    f=tf.extractfile(m)
                    with staged.open('wb') as out:
                        shutil.copyfileobj(f,out,1024*1024)
                    env=os.environ.copy();env['PS3_KEYS']=str(keydir.resolve())
                    if recover_metadata and kind=='pkg':
                        # Full unpkg exports info0/info1/content. Move content, never copy.
                        meta_dir=output/'package_metadata'/('%03d_'%index+re.sub(r'[^A-Za-z0-9_.-]','_',name))
                        meta_dir.mkdir(parents=True,exist_ok=True)
                        run_tool(backend,[staged,meta_dir],env=env)
                        for field in ('info0','info1'):
                            fp=meta_dir/field
                            if not fp.is_file() or fp.stat().st_size!=64:
                                raise RuntimeError('Missing/invalid '+field)
                        content=meta_dir/'content'
                        if not content.is_file():raise RuntimeError('unpkg did not export content')
                        content.replace(dest)
                        row['metadata_dir']=str(meta_dir.relative_to(output))
                        row['metadata_status']='info0/info1 recovered'
                    else:
                        run_tool(backend,['-s',staged,dest],env=env)
                    if not dest.is_file() or dest.stat().st_size<16:
                        raise RuntimeError('No usable decrypted payload')
                    with dest.open('rb') as d: head=d.read(512)
                    row['status']='decrypted; inner format not extracted'
                    row['decrypted_file']=str(dest.relative_to(output))
                    row['inner_header_hex']=head[:32].hex(' ')
                    if head[:4]==b'\x00\x00\x00\x01' and len(head)>=8:
                        count=int.from_bytes(head[4:8],'big')
                        if 1<=count<=255 and 16+48*count<=dest.stat().st_size:
                            row['inner_magic']='CORE_OS table (%d entries)'%count
                    elif len(head)>=262 and head[257:262]==b'ustar':
                        row['inner_magic']='TAR'
                    elif head.startswith(b'\x7fELF'):row['inner_magic']='ELF'
                    elif head.startswith(b'SCE\x00'):row['inner_magic']='SCE'
                    elif head.startswith(b'PK\x03\x04'):row['inner_magic']='ZIP'
                    else:row['inner_magic']='opaque / unrecognized'
                    if extract_tars and kind=='dev_flash' and row['inner_magic']=='TAR':
                        try:
                            details=extract_firmware_tar(dest,output/'dev_flash_extracted',seen)
                            row['tar_extraction']=details
                            row['status']='decrypted; TAR extracted'
                        except Exception as tar_exc:
                            row['tar_extraction_error']=str(tar_exc)
                            row['status']='decrypted; TAR extraction failed (plaintext retained)'

                except Exception as exc:
                    row['status']='decryption failed';row['error']=str(exc)
                    if dest.exists():dest.unlink()
                finally:
                    if staged.exists():staged.unlink()
            rows.append(row)
            emit('%02d %s | %s | %d bytes | %s'%(len(rows),name,magic,n,row['status']))
    if not rows:raise RuntimeError('No regular files in TAR')
    inner_report=extract_inner_firmware_packages(rows,output,emit,tools,run_tool) if extract_inner else None
    report={'schema_version':1,'source':str(archive),'mode':'decrypt' if decrypt else 'inspect',
            'warning':'SCE is an outer container; filename .tar.aa does not establish plaintext TAR. Decryption does not imply extraction or verification.',
            'total':len(rows),'counts':{k:sum(r['kind']==k for r in rows) for k in ('pkg','dev_flash','image','other')},
            'tar_extraction_passed':sum(r['status']=='decrypted; TAR extracted' for r in rows),
            'tar_extraction_failed':sum('tar_extraction_error' in r for r in rows),
            'decryption_passed':sum(r['status'].startswith('decrypted;') for r in rows),
            'decryption_failed':sum(r['status']=='decryption failed' for r in rows),
            'inner_packages':{k:inner_report[k] for k in ('total','extracted','unsupported','backend_unavailable','failed')} if inner_report else None,
            'entries':rows}
    (output/'firmware_batch_report.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    with (output/'firmware_batch_report.csv').open('w',newline='',encoding='utf-8-sig') as f:
        columns=list(dict.fromkeys(key for row in rows for key in row))
        w=csv.DictWriter(f,fieldnames=columns,extrasaction='ignore');w.writeheader();w.writerows(rows)
    return report

def safe_extract_tar(path, target):
    target=target.resolve()
    with tarfile.open(path) as tf:
        for m in tf.getmembers():
            dest=(target/m.name).resolve()
            if dest != target and target not in dest.parents:
                raise ValueError("Unsafe TAR path: "+m.name)
            if m.issym() or m.islnk() or m.isdev():
                raise ValueError("TAR contains links/devices; extraction refused")
        tf.extractall(target, filter="data") if hasattr(tarfile, "data_filter") else tf.extractall(target)

def safe_extract_zip(path,target):
    target=target.resolve()
    with zipfile.ZipFile(path) as z:
        for info in z.infolist():
            dest=(target/info.filename).resolve()
            if dest != target and target not in dest.parents:
                raise ValueError("Unsafe ZIP path: "+info.filename)
            if (info.external_attr >> 16) & 0o170000 == 0o120000:
                raise ValueError("ZIP contains symlink")
        z.extractall(target)

import zipfile

class App:
    def __init__(self,root):
        self.root=root; root.title("PS3 Firmware SPKG / PUP / SELF Extractor v3.8");root.geometry("1120x790")
        self.events=queue.Queue()
        self.source=tk.StringVar(); self.dest=tk.StringVar(value=str(BASE/"output"))
        self.tool=tk.StringVar(value=str(BASE/"tools"))
        self.keydb=tk.StringVar(value=str(BASE/"keysets.csv"))
        self.mode=tk.StringVar(value="Auto")
        self.decrypt=tk.BooleanVar(value=True)
        self.hide_priv_errors=tk.BooleanVar(value=True)
        self.last_audit=[]
        self.running=False
        self.last_results=[]
        self.last_work=None
        frame=ttk.Frame(root,padding=12);frame.pack(fill="both",expand=True)
        ttk.Label(frame,text="PS3 Firmware Package Extractor",font=("Segoe UI",17,"bold")).pack(anchor="w")
        ttk.Label(frame,text="Supports formats through external ps3tools backends; firmware coverage depends on supplied keys and tools.",wraplength=860).pack(anchor="w",pady=(2,12))
        for label,var,kind in [("Input file",self.source,"file"),("Output directory",self.dest,"dir"),("Tools directory",self.tool,"dir"),("Key database CSV",self.keydb,"file")]:
            row=ttk.Frame(frame);row.pack(fill="x",pady=3)
            ttk.Label(row,text=label,width=19).pack(side="left")
            ttk.Entry(row,textvariable=var).pack(side="left",fill="x",expand=True)
            ttk.Button(row,text="Browse",command=lambda v=var,k=kind:self.browse(v,k)).pack(side="left",padx=(6,0))
        row=ttk.Frame(frame);row.pack(fill="x",pady=10)
        ttk.Label(row,text="Operation",width=19).pack(side="left")
        ttk.Combobox(row,textvariable=self.mode,state="readonly",values=["Auto","Inspect only","PUP unpack","CORE_OS package unpack","SELF to ELF","TAR unpack","ZIP unpack","SPKG external extractor","SPKG header catalogue","Batch firmware inspect","Batch firmware decrypt","Batch firmware decrypt + TAR extract","Batch firmware decrypt + full extract"],width=38).pack(side="left")
        ttk.Checkbutton(row,text="Decrypt nested SELF/SPRX files (when possible)",variable=self.decrypt).pack(side="left",padx=18)
        ttk.Checkbutton(row,text="Hide missing private-key (ERROR) messages",variable=self.hide_priv_errors).pack(side="left",padx=8)
        buttons=ttk.Frame(frame);buttons.pack(fill="x",pady=5)
        self.runbtn=ttk.Button(buttons,text="Extract / Inspect",command=self.start);self.runbtn.pack(side="left")
        ttk.Button(buttons,text="Analyze existing plaintext (v3.4)",command=self.launch_v34).pack(side="left",padx=7)
        ttk.Button(buttons,text="Audit SPKG overlays (existing)",command=self.audit_spkg_overlays).pack(side="left",padx=7)
        ttk.Button(buttons,text="Show supported tools",command=self.tools_info).pack(side="left",padx=7)
        ttk.Button(buttons,text="Open output folder",command=self.open_output).pack(side="left")
        self.progress=ttk.Progressbar(frame,mode="indeterminate");self.progress.pack(fill="x",pady=8)
        # Larger, bold notebook tabs for improved readability on Windows.
        tab_style=ttk.Style(root)
        tab_style.configure("TNotebook.Tab", font=("Segoe UI", 11, "bold"), padding=(20, 11))
        notebook=ttk.Notebook(frame);notebook.pack(fill="both",expand=True,pady=(5,0))
        logtab=ttk.Frame(notebook);resultstab=ttk.Frame(notebook);audittab=ttk.Frame(notebook)
        notebook.add(logtab,text="Extraction log")
        notebook.add(resultstab,text="File results")
        notebook.add(audittab,text="Key audit")
        auditbar=ttk.Frame(audittab);auditbar.pack(fill="x",pady=5)
        ttk.Button(auditbar,text="Load key report",command=self.load_key_audit).pack(side="left",padx=3)
        ttk.Button(auditbar,text="Export CSV",command=self.export_key_audit_csv).pack(side="left",padx=3)
        self.audit_status=ttk.Label(auditbar,text="No key audit loaded");self.audit_status.pack(side="right")
        auditframe=ttk.Frame(audittab);auditframe.pack(fill="both",expand=True)
        self.audit_tree=ttk.Treeview(auditframe,columns=("source","stage","selected","requests","status"),show="headings")
        for col,title,width in [("source","Input file",280),("stage","Operation",140),("selected","Selected keyset",140),("requests","Requested keysets",430),("status","Result",100)]:
            self.audit_tree.heading(col,text=title);self.audit_tree.column(col,width=width,minwidth=75,stretch=True)
        av=ttk.Scrollbar(auditframe,orient="vertical",command=self.audit_tree.yview);ah=ttk.Scrollbar(auditframe,orient="horizontal",command=self.audit_tree.xview)
        self.audit_tree.configure(yscrollcommand=av.set,xscrollcommand=ah.set)
        self.audit_tree.grid(row=0,column=0,sticky="nsew");av.grid(row=0,column=1,sticky="ns");ah.grid(row=1,column=0,sticky="ew")
        auditframe.grid_rowconfigure(0,weight=1);auditframe.grid_columnconfigure(0,weight=1)
        self.log=scrolledtext.ScrolledText(logtab,wrap="word",height=19,font=("Consolas",10));self.log.pack(fill="both",expand=True)
        bar=ttk.Frame(resultstab);bar.pack(fill="x",pady=5)
        ttk.Button(bar,text="Export CSV",command=lambda:self.export_report("csv")).pack(side="left",padx=3)
        ttk.Button(bar,text="Export JSON",command=lambda:self.export_report("json")).pack(side="left",padx=3)
        ttk.Button(bar,text="Copy SHA-256",command=self.copy_hash).pack(side="left",padx=3)
        ttk.Button(bar,text="Load existing results",command=self.load_report).pack(side="left",padx=3)
        self.result_status=ttk.Label(bar,text="No results loaded")
        self.result_status.pack(side="right",padx=5)
        columns=("name","type","architecture","size","status","sha256")
        tableframe=ttk.Frame(resultstab);tableframe.pack(fill="both",expand=True)
        self.tree=ttk.Treeview(tableframe,columns=columns,show="headings",selectmode="browse")
        for name,title,width in [("name","Filename",245),("type","Type",75),("architecture","Architecture",115),("size","Size (bytes)",105),("status","Status",100),("sha256","SHA-256",350)]:
            self.tree.heading(name,text=title,command=lambda c=name:self.sort_results(c))
            self.tree.column(name,width=width,minwidth=60,stretch=name in ("name","sha256"))
        vs=ttk.Scrollbar(tableframe,orient="vertical",command=self.tree.yview)
        hs=ttk.Scrollbar(tableframe,orient="horizontal",command=self.tree.xview)
        self.tree.configure(yscrollcommand=vs.set,xscrollcommand=hs.set)
        self.tree.grid(row=0,column=0,sticky="nsew");vs.grid(row=0,column=1,sticky="ns");hs.grid(row=1,column=0,sticky="ew")
        tableframe.grid_rowconfigure(0,weight=1);tableframe.grid_columnconfigure(0,weight=1)
        self.tree.bind("<<TreeviewSelect>>",self.show_selection)
        self.details=tk.StringVar(value="Select a file to see its details.")
        ttk.Label(resultstab,textvariable=self.details,wraplength=1020,justify="left").pack(fill="x",pady=8)
        self.log.insert("end","Choose a firmware file. Supported tool names: pupunpack, unpkg, cosunpkg, unself.\n")
        self.log.insert("end","SPKG is not guaranteed to be a standard archive. Unsupported formats are reported, not silently treated as decrypted.\n")
        root.after(120,self.poll)
    def set_results(self,rows,work):
        self.last_results=rows;self.last_work=Path(work)
        for item in self.tree.get_children():self.tree.delete(item)
        for i,r in enumerate(rows):
            self.tree.insert("", "end", iid=str(i),values=(r.get("name",""),r.get("type",""),r.get("architecture",""),r.get("size",""),r.get("status",""),r.get("sha256","")))
        ok=sum(r.get("status")=="passed" for r in rows)
        fail=sum(r.get("status")=="failed" for r in rows)
        self.result_status.configure(text=f"{len(rows)} files | {ok} ELF passed | {fail} failed")
        self.details.set(f"Report folder: {work}")
    def show_selection(self,event=None):
        selected=self.tree.selection()
        if not selected:return
        r=self.last_results[int(selected[0])]
        self.details.set(" | ".join(f"{k}: {v}" for k,v in r.items() if k not in ("name", "sha256"))+"\nSHA-256: "+str(r.get("sha256","Unavailable")))
    def copy_hash(self):
        selected=self.tree.selection()
        if not selected:return
        value=self.last_results[int(selected[0])].get("sha256")
        if value:self.root.clipboard_clear();self.root.clipboard_append(value)
    def sort_results(self,column):
        self.last_results.sort(key=lambda r: int(r.get(column,0)) if column=="size" else str(r.get(column,"")).casefold())
        self.set_results(self.last_results,self.last_work)
    def export_report(self,kind):
        if not self.last_results:
            messagebox.showinfo("No results","Run an extraction or load a previous report first.");return
        path=filedialog.asksaveasfilename(defaultextension="."+kind,filetypes=[(kind.upper()+" report","*."+kind)],initialfile="ps3_extraction_results."+kind)
        if not path:return
        try:
            if kind=="json":Path(path).write_text(json.dumps({"output":str(self.last_work),"files":self.last_results},indent=2),encoding="utf-8")
            else:
                cols=("name","type","architecture","size","status","sha256","source","error")
                with open(path,"w",newline="",encoding="utf-8-sig") as f:
                    writer=csv.DictWriter(f,fieldnames=cols,extrasaction="ignore");writer.writeheader();writer.writerows(self.last_results)
            messagebox.showinfo("Exported","Saved report to:\n"+path)
        except OSError as e:messagebox.showerror("Export failed",str(e))
    def load_report(self):
        path=filedialog.askopenfilename(filetypes=[("JSON reports","*.json")])
        if not path:return
        try:
            obj=json.loads(Path(path).read_text(encoding="utf-8"))
            if not isinstance(obj,dict) or not isinstance(obj.get("files"),list):raise ValueError("Not a v1.7 file report")
            self.set_results(obj["files"],obj.get("output",str(Path(path).parent)))
        except (OSError,ValueError,TypeError) as e:messagebox.showerror("Invalid report",str(e))
    def collect_file_results(self,work,summary):
        elf_by_output={r.get("output"):r for r in (summary or {}).get("results",[])}
        elf_by_source={r.get("source"):r for r in (summary or {}).get("results",[])}
        rows=[]
        for f in sorted(work.rglob("*")):
            if not f.is_file() or "keys" in f.relative_to(work).parts or "self_keys" in f.relative_to(work).parts:continue
            if f.name in ("extraction_manifest.json","self_decryption_results.json","file_results.json","file_results.csv","successful_keys.json"):continue
            rel=f.relative_to(work).as_posix()
            if f.name=="CORE_OS_PACKAGE.plaintext":continue
            status="extracted";architecture="";source="";error=""
            if rel in elf_by_source:
                status="source SELF"
            if rel in elf_by_output:
                record=elf_by_output[rel]
                status=record.get("status","unknown");source=record.get("source","");error=record.get("error","")
            info=elf_info(f) if f.suffix.lower()==".elf" else None
            if info:architecture=info["machine"]
            elif f.suffix.lower()==".elf":status="failed validation"
            typ=f.suffix.lstrip(".").upper() or "BINARY"
            rows.append({"name":rel,"type":typ,"architecture":architecture,"size":f.stat().st_size,"status":status,"sha256":sha256(f),"source":source,"error":error})
        for rel,r in elf_by_output.items():
            if r.get("status")=="failed" and not any(x["name"]==rel for x in rows):
                rows.append({"name":rel,"type":"ELF","architecture":"","size":0,"status":"failed","sha256":"","source":r.get("source",""),"error":r.get("error","")})
        return rows
    def browse(self,var,kind):
        v=filedialog.askdirectory() if kind=="dir" else filedialog.askopenfilename()
        if v:var.set(v)
    def launch_v34(self):
        if getattr(sys, "frozen", False):
            subprocess.Popen([sys.executable, "--firmware-v34"], cwd=str(BASE))
            return
        script=BASE/"firmware_v34.py"
        if not script.is_file():
            messagebox.showerror("Missing module",str(script));return
        subprocess.Popen([sys.executable,str(script)],cwd=str(BASE))

    def audit_spkg_overlays(self):
        from tkinter import filedialog, messagebox
        import threading
        root=filedialog.askdirectory(title="Select existing firmware extraction folder")
        if not root:return
        dest=Path(root).resolve().parent/(Path(root).name+"_spkg_overlay_reports")
        def task():
            try:
                from spkg_overlay_audit import scan
                report=scan(root,dest)
                self.emit("SPKG overlay audit: %d overlays; %d filename matches; %d ambiguous; %d unmatched"%(report['overlay_count'],report['matched_by_filename'],report['ambiguous'],report['unmatched']))
                self.emit("Packages: %d files, %d archive members; %d archives inspected"%(report["package_files_found"],report["package_archive_members_found"],report["archives_inspected"]))
                self.emit("Read-only report: "+str(dest/'spkg_overlay_audit.json'))
                self.emit("NOTE: no decryption, cryptographic verification or payload equivalence performed")
            except Exception as ex:self.emit("SPKG overlay audit ERROR: "+str(ex))
        threading.Thread(target=task,daemon=True).start()

    def tools_info(self):
        messagebox.showinfo("Backend tools","Place executable tools in the selected Tools directory:\n\npupunpack — PUP extraction\nunpkg — decrypt outer SCE PKG (-s mode)\ncosunpkg — unpack decrypted CORE OS content\nunself — SELF to ELF\nscetool — optional, not used for SCE PKG\nspkg_extract — optional format-specific extractor\n\nFirmware coverage depends on the available package keys. Retail package keys are not guaranteed to work with custom firmware.")
    def open_output(self):
        p=Path(self.dest.get());p.mkdir(parents=True,exist_ok=True)
        import sys
        if os.name=="nt":os.startfile(str(p))
        elif sys.platform=="darwin":subprocess.Popen(["open",str(p)])
        else:subprocess.Popen(["xdg-open",str(p)])
    def set_key_audit(self,records):
        self.last_audit=list(records)
        for item in self.audit_tree.get_children():self.audit_tree.delete(item)
        for i,r in enumerate(records):
            trace=r.get("trace") or {}
            selected=r.get("selected_key") or trace.get("selected_key") or "Not reported"
            requested=r.get("requested_keys") or trace.get("requested_keys") or []
            self.audit_tree.insert("","end",iid=str(i),values=(r.get("source",""),r.get("stage",""),selected,", ".join(requested),r.get("status","")))
        self.audit_status.configure(text=f"{len(records)} operations")
    def load_key_audit(self):
        filename=filedialog.askopenfilename(title="Open successful_keys.json",filetypes=[("JSON files","*.json")])
        if not filename:return
        try:
            data=json.loads(Path(filename).read_text(encoding="utf-8"))
            self.set_key_audit(data.get("records",[]) if isinstance(data,dict) else data)
        except Exception as e:messagebox.showerror("Key audit",str(e))
    def export_key_audit_csv(self):
        if not self.last_audit:messagebox.showinfo("Key audit","No audit data loaded.");return
        filename=filedialog.asksaveasfilename(defaultextension=".csv",filetypes=[("CSV files","*.csv")])
        if not filename:return
        import csv
        with open(filename,"w",newline="",encoding="utf-8-sig") as f:
            w=csv.writer(f);w.writerow(["source","stage","selected_key","requested_keys","status"])
            for r in self.last_audit:
                trace=r.get("trace") or {}
                w.writerow([r.get("source",""),r.get("stage",""),r.get("selected_key") or trace.get("selected_key") or "", ";".join(r.get("requested_keys") or trace.get("requested_keys") or []),r.get("status","")])
    def emit(self,msg):self.events.put(msg)
    def is_optional_priv_error(self,line):
        return bool(re.search(r"\bpriv file:\s+.*\(ERROR\)\s*$",line,re.IGNORECASE))
    def append_log(self,msg):
        lines=msg.splitlines()
        if self.hide_priv_errors.get():lines=[line for line in lines if not self.is_optional_priv_error(line)]
        if lines:self.log.insert("end","\n".join(lines)+"\n");self.log.see("end")
    def poll(self):
        while not self.events.empty():
            m=self.events.get()
            if isinstance(m,tuple) and m[0]=="__KEY_AUDIT__":
                self.set_key_audit(m[1])
            elif isinstance(m,tuple) and m[0]=="__RESULTS__":
                self.set_results(m[1],m[2])
            elif m=="__DONE__":
                self.running=False;self.runbtn.configure(state="normal");self.progress.stop()
            else:self.append_log(m)
        self.root.after(120,self.poll)
    def start(self):
        if self.running:return
        p=Path(self.source.get())
        if not p.is_file():messagebox.showerror("Input missing","Select an existing file.");return
        out=Path(self.dest.get()).expanduser()
        target=out/p.stem
        replace_existing=False
        if target.exists():
            if not target.is_dir():
                messagebox.showerror("Output conflict", "A file already exists at the output path:\n"+str(target));return
            choice=messagebox.askyesnocancel(
                "Output folder already exists",
                "Destination:\n"+str(target)+"\n\n"
                "YES — Overwrite this extraction folder (deletes its existing contents).\n"
                "NO — Choose a different output folder.\n"
                "CANCEL — Do nothing.")
            if choice is None:return
            if choice is False:
                selected=filedialog.askdirectory(title="Choose a new extraction destination",initialdir=str(out))
                if not selected:return
                target=Path(selected).expanduser()
                if target.exists() and any(target.iterdir()):
                    messagebox.showerror("Folder not empty", "Choose an empty folder to avoid overwriting files.");return
            else:
                replace_existing=True
        self.running=True;self.runbtn.configure(state="disabled");self.progress.start(12)
        opts=(p,Path(self.tool.get()),Path(self.keydb.get()),self.mode.get(),self.decrypt.get(),target,replace_existing)
        threading.Thread(target=self.work,args=opts,daemon=True).start()
    def find_tool(self,folder,name):
        for n in (name+".exe",name):
            p=folder/n
            if p.is_file():return str(p)
        return shutil.which(name)
    def parse_key_trace(self, output):
        requests=re.findall(r"KEY_AUDIT_REQUEST id=([A-Za-z0-9_-]+)",output)
        selected=re.findall(r"KEY_AUDIT_SELECTED id=([A-Za-z0-9_-]+) index=([0-9]+)",output)
        return {"requested_keys":requests,"selected_key":selected[-1][0] if selected else None,
                "matched_key_index":int(selected[-1][1]) if selected else None}

    def run_tool(self,tool,args,env=None):
        if not tool:raise RuntimeError("Missing external tool; see 'Show supported tools'")
        self.last_key_trace={}
        cmd=[tool]+[str(x) for x in args]
        self.emit("$ "+subprocess.list2cmdline(cmd))
        cp=subprocess.run(cmd,cwd=str(BASE),stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,errors="replace",env=env,timeout=300)
        self.emit(cp.stdout.strip())
        self.last_key_trace=self.parse_key_trace(cp.stdout)
        if cp.returncode!=0:raise RuntimeError("Backend returned exit status "+str(cp.returncode))
    def export_keys(self,db):
        """Build a reusable SELF key cache outside every extraction directory."""
        if not db.is_file():
            raise RuntimeError("SELF key database CSV is missing: "+str(db))
        import csv
        import hashlib
        import tempfile
        digest=hashlib.sha256(db.read_bytes()).hexdigest()
        keydir=BASE/"self_keys"
        stamp=keydir/".keysets_sha256"
        if stamp.is_file() and stamp.read_text(encoding="ascii").strip()==digest and any(keydir.glob("*-key-*")):
            self.emit("SELF key cache reused: "+str(keydir))
            return keydir
        # Stage all files before publishing. Never write the keyset into output/.
        stage=Path(tempfile.mkdtemp(prefix=".self_keys_build_",dir=str(BASE)))
        try:
            count=0
            with db.open(encoding="utf-8-sig",newline="") as f:
                for i,r in enumerate(csv.DictReader(f)):
                    cat=r["category"].lower()
                    for suffix,col in (("key","aes_erk"),("iv","aes_riv"),("pub","ecdsa_public"),("priv","ecdsa_private")):
                        if r.get(col):
                            (stage/f"{cat}-{suffix}-{i:03d}").write_bytes(bytes.fromhex(r[col]))
                    if r.get("curve_type"):
                        (stage/f"{cat}-ctype-{i:03d}").write_bytes(int(r["curve_type"],16).to_bytes(4,"big"))
                    count+=1
            if not count or not any(stage.glob("*-key-*")):
                raise RuntimeError("SELF key database contained no usable key entries")
            (stage/".keysets_sha256").write_text(digest,encoding="ascii")
            # Replace only the application-owned cache. Preserve the old cache
            # if exporting a new database fails.
            backup=BASE/".self_keys_previous"
            if backup.exists():
                shutil.rmtree(backup)
            if keydir.exists():
                keydir.rename(backup)
            try:
                stage.rename(keydir)
            except Exception:
                if backup.exists() and not keydir.exists():backup.rename(keydir)
                raise
            if backup.exists():shutil.rmtree(backup)
            self.emit(f"SELF key cache rebuilt: {count} entries at {keydir}")
            return keydir
        finally:
            if stage.exists():shutil.rmtree(stage)
    def decrypt_self_files(self,files,work,tools,db,key_audit=None):
        backend=self.find_tool(tools,"unself")
        if not backend:
            self.emit("SELF decryption skipped: tools/unself.exe not found.")
            return {"attempted":0,"passed":0,"failed":0,"skipped":len(files),"results":[]}
        keydir=self.export_keys(db)
        env=os.environ.copy()
        env["PS3_KEYS"]=str(keydir.resolve())
        results=[]
        db_fingerprint=sha256(db)
        candidate_count=sum(1 for _ in keydir.glob("*-key-*"))
        for item in files:
            # Keep decrypted executables separate from the extracted source files.
            # Preserve nested source paths to prevent same-name collisions.
            rel_source=item.relative_to(work)
            target=work/"ELF"/rel_source.with_suffix(".elf")
            target.parent.mkdir(parents=True,exist_ok=True)
            # Never accept an ELF left over from an earlier attempt.
            if target.exists(): target.unlink()
            row={"source":str(item.relative_to(work)),"output":str(target.relative_to(work))}
            try:
                source_size=item.stat().st_size
                row['source_size']=source_size
                if source_size==0:
                    row.update(status='empty source',error='EMPTY SOURCE FILE: 0 bytes; backend not invoked')
                    self.emit(f'ELF SKIP EMPTY SOURCE: {item.name} | 0 bytes')
                    results.append(row)
                    if key_audit is not None:
                        key_audit.append(key_report_record('SELF to ELF',row['source'],row['output'],row['status'],backend,{'name':db.name,'sha256':db_fingerprint,'candidate_count':candidate_count},[],row['error']))
                    continue
                self.run_tool(backend,[item,target],env)
                info=elf_info(target) if target.is_file() else None
                if info is None:
                    raise RuntimeError("No structurally valid ELF output")
                row.update({"status":"passed",**info})
                self.emit(f"ELF PASS: {item.name} | {info['machine']} | {info['size']} bytes")
            except Exception as e:
                row.update({"status":"failed","error":str(e)})
                self.emit(f"ELF FAIL: {item.name}: {e}")
                if target.exists() and elf_info(target) is None:
                    target.unlink()
            if key_audit is not None:
                key_audit.append(key_report_record(
                    "SELF to ELF",row["source"],row["output"],row["status"],backend,
                    {"name":db.name,"sha256":db_fingerprint,"candidate_count":candidate_count},
                    [],"Backend completed and ELF header validated" if row["status"]=="passed" else row.get("error","Backend failed"),self.last_key_trace))
            results.append(row)
        passed=sum(x['status']=='passed' for x in results)
        failed=sum(x['status']=='failed' for x in results)
        empty=sum(x['status']=='empty source' for x in results)
        self.emit(f'SELF/SPRX-to-ELF summary: {passed} passed; {failed} failed; {empty} empty sources skipped.')
        return {'attempted':passed+failed,'passed':passed,'failed':failed,'skipped':empty,'empty_sources':empty,'results':results}
    def verify_extraction(self, work, mode):
        """Reject invalid paths/truncation, but allow proven source-empty TAR members."""
        files=[p for p in work.rglob("*") if p.is_file() and p.name != "extraction_manifest.json" and "keys" not in p.relative_to(work).parts and p.name not in ("CORE_OS_PACKAGE.decrypted", "CORE_OS_PACKAGE.plaintext")]
        if not files:
            raise RuntimeError("Backend returned success but produced no extracted files.")
        # Only trust empty-file exceptions that were byte-verified against a
        # source TAR by audit_dev_flash_tars. Never whitelist filenames alone.
        verified_empty=set()
        audit_path=work/'firmware_auto'/'firmware_tar_integrity.json'
        if audit_path.is_file():
            audit=json.loads(audit_path.read_text(encoding='utf-8'))
            for row in audit.get('entries',[]):
                if (row.get('status')=='empty in original TAR' and
                    row.get('archive_size')==0 and row.get('extracted_size')==0 and
                    row.get('archive_sha256')==hashlib.sha256(b'').hexdigest() and
                    row.get('extracted_sha256')==hashlib.sha256(b'').hexdigest()):
                    from pathlib import PurePosixPath
                    name=row.get('member','').replace('\\','/')
                    parts=PurePosixPath(name).parts
                    if parts and not name.startswith('/') and '..' not in parts and ':' not in name:
                        verified_empty.add((work/'firmware_auto'/'dev_flash_extracted').joinpath(*parts))
        bad=[]; recognized=[]; source_empty=[]
        for f in files:
            rel=str(f.relative_to(work))
            if any(ord(ch)<32 or ord(ch)==65533 for ch in rel):
                bad.append(rel+' (invalid path)')
            if f.stat().st_size==0:
                if f in verified_empty:
                    source_empty.append(rel)
                else:
                    bad.append(rel+' (unverified empty file)')
            try:
                with f.open('rb') as fp: head=fp.read(4)
                if head in (b"\x7fELF",b"SCE\x00",b"PK\x03\x04",b"\x7fPKG"):
                    recognized.append(rel)
            except OSError as ex:
                bad.append(rel+' (unreadable: '+str(ex)+')')
        self.emit(f"Output audit: {len(files)} files, {len(recognized)} recognized binary headers, {len(source_empty)} verified source-empty entries, {len(bad)} invalid outputs")
        if source_empty:
            self.emit('Source-empty TAR entries retained (not errors): '+repr(source_empty[:10]))
        if bad:
            raise RuntimeError("Invalid output: "+repr(bad[:5]))
        if mode=="CORE_OS package unpack" and not recognized:
            raise RuntimeError("CORE OS output is unverified: no recognizable ELF/SELF/PKG/ZIP headers.")
        return len(files)
    def work(self,p,tools,db,mode,do_nested,work,replace_existing):
        key_audit=[]
        try:
            work.parent.mkdir(parents=True,exist_ok=True)
            if replace_existing:
                if work.is_symlink() or not work.is_dir():
                    raise RuntimeError("Refusing to overwrite non-directory or symlink destination")
                shutil.rmtree(work)
            work.mkdir(parents=True,exist_ok=True)
            if any(work.iterdir()):raise RuntimeError("Destination folder must be empty")
            original_input=p
            self.emit("Input: "+str(p));self.emit("Detected: "+sniff(p))
            self.emit("SHA256: "+sha256(p))
            ext=p.suffix.lower()
            auto_requested=(mode=="Auto")
            if mode=="Auto":
                mode={".pup":"PUP unpack",".self":"SELF to ELF",".tar":"TAR unpack",".zip":"ZIP unpack",".spkg":"SPKG external extractor"}.get(ext,"Inspect only")
                if ext==".pkg" and p.name.upper()=="CORE_OS_PACKAGE.PKG":mode="CORE_OS package unpack"
                if ext==".tar" and p.name.lower()=="update_files.tar":mode="Batch firmware decrypt + full extract"
                elif ext==".pkg":self.emit("Unknown PKG type: select a compatible operation explicitly.")
            self.emit("Selected operation: "+mode)
            if mode in ('Batch firmware inspect','Batch firmware decrypt','Batch firmware decrypt + TAR extract','Batch firmware decrypt + full extract'):
                report=batch_firmware_archive(p,work,self.emit,tools,
                    decrypt=(mode!='Batch firmware inspect'),run_tool=self.run_tool,
                    extract_tars=(mode in ('Batch firmware decrypt + TAR extract','Batch firmware decrypt + full extract')),
                    extract_inner=(mode=='Batch firmware decrypt + full extract'))
                self.emit('Batch inventory: '+str(report['counts']))
                self.emit('Batch decrypt: %d passed, %d failed'%(report['decryption_passed'],report['decryption_failed']))
                self.emit('Reports: firmware_batch_report.json / .csv')
                if mode in ('Batch firmware decrypt + TAR extract','Batch firmware decrypt + full extract'):
                    self.emit('TAR extraction: %d passed, %d failed'%(report['tar_extraction_passed'],report['tar_extraction_failed']))
                    plaintext_tars=[work/r['decrypted_file'] for r in report['entries'] if r['kind']=='dev_flash' and r.get('tar_extraction') and r.get('decrypted_file')]
                    audit=audit_dev_flash_tars(plaintext_tars,work/'dev_flash_extracted',work,self.emit)
                    self.emit('TAR integrity report: firmware_tar_integrity.json / .csv')
                    inventory=inventory_firmware_tree(work/'dev_flash_extracted',work)
                    self.emit('Firmware inventory: %d files, %d bytes, %d extensions; firmware_file_inventory.json / .csv'%(inventory['total_files'],inventory['total_bytes'],len(inventory['extension_counts'])))
                    if mode=='Batch firmware decrypt + full extract':
                        self.emit('Inner package report: '+str(report['inner_packages'])+'; firmware_inner_package_report.json / .csv')
            elif mode=="Inspect only":
                with p.open("rb") as fp: header=fp.read(32)
                self.emit("Header (32 bytes): "+header.hex(" "))
                if header.startswith(b"SCE\x00"):
                    self.emit("SCE container: encrypted or signed wrapper; not a plaintext CORE OS file table.")
                self.emit("Inspection complete; no extraction or decryption attempted.")
            elif mode=="SPKG header catalogue":
                report=spkg_header_catalogue(p,work)
                self.emit(f"SPKG headers catalogued: {report['header_count']}; filename matches: {sum(bool(x['matched_package']) for x in report['entries'])}")
                self.emit("Report: "+str(work/'spkg_header_catalogue.json'))
                self.emit("Header names are not decryption keys; package matches are filename-only.")
            elif mode=="ZIP unpack":safe_extract_zip(p,work)
            elif mode=="TAR unpack":safe_extract_tar(p,work)
            elif mode=="PUP unpack":
                # pupunpack creates its own destination directory and fails with
                # EEXIST when the GUI's output folder is passed directly.
                # Extract to a fresh sibling directory, then move the results
                # into the GUI-managed output folder for subsequent processing.
                pup_stage=work.parent/(work.name+".__pup_stage__")
                if pup_stage.exists() or pup_stage.is_symlink():
                    raise RuntimeError("Temporary PUP staging directory already exists: "+str(pup_stage))
                try:
                    self.run_tool(self.find_tool(tools,"pupunpack"),[p,pup_stage])
                    if not pup_stage.is_dir():
                        raise RuntimeError("pupunpack did not create its output directory")
                    for item in pup_stage.iterdir():
                        shutil.move(str(item),str(work/item.name))
                finally:
                    if pup_stage.is_dir() and not pup_stage.is_symlink():
                        shutil.rmtree(pup_stage)
                # Auto means full firmware workflow, not just unpacking the PUP wrapper.
                if auto_requested:
                    firmware_tar=work/'update_files.tar'
                    if not firmware_tar.is_file():
                        raise RuntimeError('PUP has no update_files.tar; firmware batch cannot continue')
                    self.emit('AUTO: decrypting firmware packages, extracting TAR/CORE_OS and recovering metadata')
                    batch_dir=work/'firmware_auto'
                    batch_dir.mkdir()
                    report=batch_firmware_archive(firmware_tar,batch_dir,self.emit,tools,
                        decrypt=True,run_tool=self.run_tool,extract_tars=True,
                        extract_inner=True,recover_metadata=True)
                    self.emit('AUTO firmware: %d decrypted; %d failed; %d TAR extracted'%(
                        report['decryption_passed'],report['decryption_failed'],report['tar_extraction_passed']))
                    plaintext_tars=[batch_dir/r['decrypted_file'] for r in report['entries']
                                    if r['kind']=='dev_flash' and r.get('tar_extraction') and r.get('decrypted_file')]
                    if plaintext_tars:
                        audit_dev_flash_tars(plaintext_tars,batch_dir/'dev_flash_extracted',batch_dir,self.emit)
                        inventory_firmware_tree(batch_dir/'dev_flash_extracted',batch_dir)
                    try:
                        from firmware_v34 import run as analyze_plaintext
                        analyzed=analyze_plaintext(batch_dir/'decrypted',batch_dir)
                        self.emit('AUTO: format and SYS_CON analysis completed for %d payloads'%len(analyzed))
                    except Exception as analysis_error:
                        self.emit('AUTO: analysis unavailable: '+str(analysis_error))
                    (batch_dir/'auto_summary.json').write_text(json.dumps({
                        'decrypted':report['decryption_passed'],'failed':report['decryption_failed'],
                        'tar_extracted':report['tar_extraction_passed'],
                        'inner_packages':report['inner_packages'],
                        'metadata_recovered':sum(bool(r.get('metadata_dir')) for r in report['entries'])
                    },indent=2),encoding='utf-8')

            elif mode=="CORE_OS package unpack":
                with p.open("rb") as fp: header=fp.read(16)
                if header.startswith(b"SCE\x00"):
                    backend=self.find_tool(tools,"unpkg")
                    if not backend:
                        raise RuntimeError("Encrypted SCE package: tools/unpkg.exe is required. scetool 0.3.1 cannot write PKG output.")
                    # ps3tools unpkg -s writes the decrypted CORE OS payload to a named file.
                    # unpkg INPUT OUTPUT instead creates info0, info1, content in a directory.
                    decrypted=work/"CORE_OS_PACKAGE.plaintext"
                    keydir=BASE/"ps3keys"
                    if not keydir.is_dir() or not list(keydir.glob("pkg-key-*")):
                        raise RuntimeError("Missing ps3keys/pkg-key-*; cannot decrypt SCE PKG.")
                    env=os.environ.copy();env["PS3_KEYS"]=str(keydir.resolve())
                    self.emit("SCE PKG detected; using ps3tools unpkg -s (NOT scetool/cosunpkg).")
                    self.emit("Package key directory: "+str(keydir))
                    try:
                        self.run_tool(backend,["-s",p,decrypted],env=env)
                    except Exception as ex:
                        key_audit.append(key_report_record("PKG decrypt",original_input,decrypted.relative_to(work),"failed",backend,
                            str(keydir),key_file_candidates(keydir,"pkg-key-*"),str(ex)))
                        raise
                    if not decrypted.is_file() or decrypted.stat().st_size<16:
                        raise RuntimeError("unpkg did not produce a decrypted CORE OS content file; check package key compatibility.")
                    key_audit.append(key_report_record("PKG decrypt",original_input,decrypted.relative_to(work),"passed",backend,
                        str(keydir),key_file_candidates(keydir,"pkg-key-*"),"Decrypted content file produced; CORE OS table checked separately",self.last_key_trace))
                    p=decrypted
                    with p.open("rb") as fp: header=fp.read(16)
                    self.emit("Decrypted content header: "+header.hex(" "))
                if len(header)<16 or header[:4]!=b"\x00\x00\x00\x01":
                    raise RuntimeError("Not a plaintext CORE OS archive (expected 00000001 magic); refusing cosunpkg.")
                count=int.from_bytes(header[4:8],"big")
                if not (1<=count<=255) or 16+48*count>p.stat().st_size:
                    raise RuntimeError("Invalid plaintext CORE OS file count/table length; refusing extraction.")
                backend=self.find_tool(tools,"cosunpkg")
                self.run_tool(backend,[p,work])
            elif mode=="SPKG external extractor":
                backend=self.find_tool(tools,"spkg_extract")
                if backend:
                    self.run_tool(backend,[p,work])
                else:
                    # Existing ps3tools backend: attempt SCE PKG decryption only.
                    # The result is NOT assumed to be a CORE OS table.
                    with p.open('rb') as fp: header=fp.read(16)
                    if not header.startswith(b'SCE\x00') or p.suffix.lower() not in ('.pkg','.spkg'):
                        raise RuntimeError("No generic SPKG backend; built-in fallback only accepts SCE-wrapped .pkg/.spkg")
                    backend=self.find_tool(tools,'unpkg')
                    keydir=BASE/'ps3keys'
                    if not backend or not keydir.is_dir() or not list(keydir.glob('pkg-key-*')):
                        raise RuntimeError("SCE PKG fallback needs tools/unpkg.exe and ps3keys/pkg-key-* files")
                    decrypted=work/(p.name+'.plaintext')
                    env=os.environ.copy();env['PS3_KEYS']=str(keydir.resolve())
                    self.emit('Generic SPKG backend absent; trying existing unpkg -s on SCE package (experimental).')
                    try:
                        self.run_tool(backend,['-s',p,decrypted],env=env)
                    except Exception as ex:
                        key_audit.append(key_report_record('SPKG PKG decrypt',original_input,decrypted.name,'failed',backend,str(keydir),key_file_candidates(keydir,'pkg-key-*'),str(ex)))
                        raise
                    if not decrypted.is_file() or decrypted.stat().st_size<16:
                        raise RuntimeError('unpkg -s produced no usable decrypted output')
                    with decrypted.open('rb') as fp: plainhead=fp.read(16)
                    self.emit('Decrypted payload header: '+plainhead.hex(' '))
                    key_audit.append(key_report_record('SPKG PKG decrypt',original_input,decrypted.name,'passed',backend,str(keydir),key_file_candidates(keydir,'pkg-key-*'),'unpkg -s produced plaintext payload; inner format may remain unsupported',self.last_key_trace))
                    if plainhead[:4]==b'\x00\x00\x00\x01':
                        count=int.from_bytes(plainhead[4:8],'big')
                        if 1<=count<=255 and 16+48*count<=decrypted.stat().st_size:
                            cos=self.find_tool(tools,'cosunpkg')
                            if cos:
                                self.emit('Validated CORE OS table; unpacking with cosunpkg.')
                                self.run_tool(cos,[decrypted,work])
                            else:self.emit('CORE OS table detected, but cosunpkg is unavailable; plaintext retained.')
                        else:self.emit('CORE OS-like magic with invalid table bounds; plaintext retained without cosunpkg.')
                    else:self.emit('Not a CORE OS plaintext table; preserving decrypted payload for inspection.')
            elif mode=="SELF to ELF":
                target=work/p.name
                shutil.copy2(p,target)
                self.verify_extraction(work,mode)
                single_summary=self.decrypt_self_files([target],work,tools,db,key_audit)
                if single_summary["passed"]!=1:
                    raise RuntimeError("SELF decryption failed; see log.")
            else:raise RuntimeError("Unsupported operation")
            if mode not in ("Inspect only","SELF to ELF","SPKG header catalogue","Batch firmware inspect","Batch firmware decrypt","Batch firmware decrypt + TAR extract","Batch firmware decrypt + full extract"):
                self.verify_extraction(work,mode)
            summary=None
            if mode=="SELF to ELF":
                summary=single_summary
            if do_nested and mode in ("PUP unpack","CORE_OS package unpack","TAR unpack","ZIP unpack","SPKG external extractor","Batch firmware decrypt + TAR extract","Batch firmware decrypt + full extract"):
                inventory=discover_executable_files(work)
                (work/'executable_discovery.json').write_text(json.dumps({'schema_version':1,'files':inventory},indent=2),encoding='utf-8')
                self.emit('Executable discovery: '+', '.join(f"{ext}: {sum(r['extension']==ext for r in inventory)}" for ext in ('.self','.sprx','.prx','.irx')))
                selfs=sorted(work/r['path'] for r in inventory if r['kind']=='sce' and (r['extension'] in ('.self','.sprx') or r['extension']=='.bin'))
                empty_sources=sorted(work/r['path'] for r in inventory if r['kind']=='empty' and r['extension'] in ('.self','.sprx'))
                selfs=sorted(set(selfs+empty_sources))
                self.emit(f"Nested SELF/SPRX candidates found: {len(selfs)}")
                if selfs:
                    summary=self.decrypt_self_files(selfs,work,tools,db,key_audit)
            if do_nested and mode in ("PUP unpack","CORE_OS package unpack","TAR unpack","ZIP unpack","SPKG external extractor","Batch firmware decrypt + TAR extract","Batch firmware decrypt + full extract"):
                if summary is not None:
                    scan_embedded_executables(work,self.emit)
                # v3.15: one memory-mapped walk produces all three inventories.
                from firmware_format_scan import scan as scan_firmware_formats
                scan_firmware_formats(work,self.emit)
            if summary is not None:
                (work/"self_decryption_results.json").write_text(json.dumps(summary,indent=2),encoding="utf-8")
            (work/"successful_keys.json").write_text(json.dumps({
                "schema_version":1,"note":"Selected key identifiers are reported when instrumented backends emit KEY_AUDIT_SELECTED; raw key bytes are never recorded.",
                "records":key_audit},indent=2),encoding="utf-8")
            self.events.put(("__KEY_AUDIT__",list(key_audit)))
            self.emit(f"Key audit: {len(key_audit)} nested operations recorded in successful_keys.json; batch package key selections appear in the console log")
            rows=self.collect_file_results(work,summary)
            (work/"file_results.json").write_text(json.dumps({"output":str(work),"files":rows},indent=2),encoding="utf-8")
            with (work/"file_results.csv").open("w",encoding="utf-8-sig",newline="") as fp:
                writer=csv.DictWriter(fp,fieldnames=("name","type","architecture","size","status","sha256","source","error"))
                writer.writeheader();writer.writerows(rows)
            self.events.put(("__RESULTS__",rows,str(work)))
            self.emit(f"Results report: {len(rows)} entries; JSON and CSV saved in output folder")
            manifest={"input":str(original_input),"sha256":sha256(original_input),"detected":sniff(original_input),"operation":mode,"timestamp":time.strftime("%Y-%m-%dT%H:%M:%S"),"output":str(work),"backend":"unpkg -s -> cosunpkg" if mode=="CORE_OS package unpack" else None}
            (work/"extraction_manifest.json").write_text(json.dumps(manifest,indent=2),encoding="utf-8")
            if mode in ("Inspect only","SPKG header catalogue","Batch firmware inspect"): self.emit("INSPECTION COMPLETE (no extraction): "+str(work))
            elif mode in ("Batch firmware decrypt","Batch firmware decrypt + TAR extract","Batch firmware decrypt + full extract"): self.emit("BATCH COMPLETE (per-file statuses in firmware_batch_report.json): "+str(work))
            elif summary and summary["failed"]:
                self.emit("PARTIAL SUCCESS: package extracted, but some SELF decryptions failed: "+str(work))
            else: self.emit("SUCCESS (output checks passed): "+str(work))
        except Exception as e:
            if work.is_dir() and key_audit:
                try:
                    (work/"successful_keys.json").write_text(json.dumps({
                        "schema_version":1,"incomplete":True,"error":str(e),
                        "note":"Selected key is recorded only when instrumented backends emit KEY_AUDIT_SELECTED.","records":key_audit},indent=2),encoding="utf-8")
                    self.events.put(("__KEY_AUDIT__",list(key_audit)))
                except OSError:pass
            self.emit("ERROR: "+str(e))
        finally:self.events.put("__DONE__")
if __name__=="__main__":
    if "--firmware-v34" in sys.argv:
        from firmware_v34 import gui as firmware_v34_gui
        firmware_v34_gui()
        sys.exit(0)
    root=tk.Tk()
    try:root.tk.call("tk","scaling",1.1)
    except tk.TclError:pass
    App(root);root.mainloop()
