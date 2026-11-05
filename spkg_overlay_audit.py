"""Read-only SPKG overlay and original-package discovery audit (v3.9)."""
import argparse,csv,hashlib,json,os,re,tarfile,zipfile
from pathlib import Path

SUFFIXES=('.spkg_hdr.1','.spkg_hdr','.spkg_header','.hdr')
PREFIX=re.compile(r'^(?:\d{1,4}[_ .-]+|(?:file|section|entry)[_ .-]+\d{1,4}[_ .-]+)',re.I)

def digest_stream(f):
    h=hashlib.sha256();n=0;head=b''
    while True:
        b=f.read(1024*1024)
        if not b:break
        if not head:head=b[:64]
        n+=len(b);h.update(b)
    return n,h.hexdigest(),head

def normalize(name):
    name=Path(name.replace('\\','/')).name
    while True:
        newer=PREFIX.sub('',name,count=1)
        if newer==name:break
        name=newer
    return name.lower()

def pkgname(name):
    base=Path(name.replace('\\','/')).name
    for suffix in SUFFIXES:
        if base.lower().endswith(suffix):
            candidate=base[:-len(suffix)]
            return candidate if candidate.lower().endswith('.pkg') else None
    return None

def scan(root,output):
    root=Path(root).resolve();output=Path(output).resolve()
    if not root.is_dir():raise ValueError('Existing extraction folder not found')
    if output==root or root in output.parents and output.name=='':raise ValueError('Reports must be in a separate folder')
    files=[p for p in root.rglob('*') if p.is_file() and output not in p.parents]
    packages={};overlays=[];warnings=[];archive_count=0
    def add_package(name,location,origin):
        if not name.lower().endswith('.pkg'):return
        packages.setdefault(normalize(name),[]).append({'path':location,'source_type':origin})
    def add_overlay(name,source,source_type,member,stream):
        target=pkgname(name)
        if not target:return
        n,h,head=digest_stream(stream)
        overlays.append(dict(source=source,source_type=source_type,member=member,package_name=target,size=n,sha256=h,header_magic=head[:4].hex(),first_32_bytes=head[:32].hex()))
    for p in files:
        rel=p.relative_to(root).as_posix()
        add_package(p.name,rel,'file')
        if pkgname(p.name):
            with p.open('rb') as f:add_overlay(p.name,rel,'file','',f)
    # Search TAR/ZIP member tables without unpacking or copying package payloads.
    # Archives are read only; no nested decompression of untrusted archive members.
    for p in files:
        rel=p.relative_to(root).as_posix()
        if p.suffix.lower() not in ('.tar','.aa','.zip') and 'spkg_hdr' not in p.name.lower():continue
        try:
            if tarfile.is_tarfile(p):
                archive_count+=1
                with tarfile.open(p,'r:*') as tf:
                    for m in tf:
                        if not m.isfile():continue
                        loc=rel+'::'+m.name
                        add_package(m.name,loc,'tar_member')
                        if pkgname(m.name):
                            f=tf.extractfile(m)
                            if f:
                                with f:add_overlay(m.name,rel,'tar_member',m.name,f)
            elif p.suffix.lower()=='.zip' and zipfile.is_zipfile(p):
                archive_count+=1
                with zipfile.ZipFile(p) as zf:
                    for m in zf.infolist():
                        if m.is_dir():continue
                        loc=rel+'::'+m.filename
                        add_package(m.filename,loc,'zip_member')
                        if pkgname(m.filename):
                            with zf.open(m) as f:add_overlay(m.filename,rel,'zip_member',m.filename,f)
        except (OSError,tarfile.TarError,zipfile.BadZipFile,RuntimeError,ValueError) as e:
            warnings.append({'file':rel,'error':str(e)})
    for row in overlays:
        candidates=packages.get(normalize(row['package_name']),[])
        # One physical package may be represented as an extracted file and TAR member.
        row['candidate_packages']=[x['path'] for x in candidates]
        row['candidate_sources']=[x['source_type'] for x in candidates]
        row['match_status']='unmatched' if not candidates else 'ambiguous' if len(candidates)>1 else 'filename match only'
        row['cryptographic_verification']='not performed'
        row['body_equivalence']='not tested (requires verified decryption of both paths)'
    report={'schema_version':2,'audit':'SPKG header overlay (read-only)','root':str(root),'overlay_count':len(overlays),
        'matched_by_filename':sum(x['match_status']=='filename match only' for x in overlays),
        'ambiguous':sum(x['match_status']=='ambiguous' for x in overlays),
        'unmatched':sum(x['match_status']=='unmatched' for x in overlays),
        'package_files_found':sum(x['source_type']=='file' for xs in packages.values() for x in xs),
        'package_archive_members_found':sum(x['source_type']!='file' for xs in packages.values() for x in xs),
        'archives_inspected':archive_count,'warnings':warnings,
        'limitations':['Original encrypted packages may have been discarded after extraction.',
          'Only on-disk .pkg files and direct TAR/ZIP members are indexed; PUP and nested archives are not decoded.',
          'Filename matches do not prove cryptographic compatibility or header authenticity.',
          'Legacy/overlay decryption and decrypted-body hash equivalence are NOT performed.'],
        'entries':overlays}
    output.mkdir(parents=True,exist_ok=True)
    target=output/'spkg_overlay_audit.json';temp=target.with_suffix('.json.tmp')
    try:
        temp.write_text(json.dumps(report,indent=2),encoding='utf-8');os.replace(temp,target)
    finally:
        if temp.exists():temp.unlink()
    with (output/'spkg_overlay_audit.csv').open('w',newline='',encoding='utf-8-sig') as f:
        fields=['source','source_type','member','package_name','size','sha256','header_magic','match_status','candidate_packages','candidate_sources','cryptographic_verification','body_equivalence']
        w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore');w.writeheader()
        for row in overlays:w.writerow({**row,'candidate_packages':'; '.join(row['candidate_packages']),'candidate_sources':'; '.join(row['candidate_sources'])})
    return report

if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('existing_output');ap.add_argument('--reports',default=None)
    a=ap.parse_args();dest=Path(a.reports) if a.reports else Path(a.existing_output).resolve().parent/(Path(a.existing_output).name+'_spkg_overlay_reports')
    r=scan(a.existing_output,dest)
    print('SPKG overlays:',r['overlay_count'],'| filename matches:',r['matched_by_filename'],'| ambiguous:',r['ambiguous'],'| unmatched:',r['unmatched'])
    print('Package files:',r['package_files_found'],'| archive members:',r['package_archive_members_found'],'| archives:',r['archives_inspected'])
    print('Reports:',dest)
