"""Read-only, signature-first firmware format inventory. No decryption is attempted.

Labels distinguish verified headers, plausible candidates and extension-only hints.
"""
import argparse, json, mmap, struct, hashlib, time
from firmware_mself_scan import inspect as inspect_mself
from embedded_container_audit import sce_header, elf_header
from pathlib import Path

SKIP_DIRS={'.git','__pycache__','embedded_executables','instrumented_ps3tools_source'}
MAX_FILE=1024*1024*1024
MAGICS=[('SCE_SELF_SPRX_FSELF',b'SCE\x00'),('ELF',b'\x7fELF'),('MSELF',b'MSF\x00'),('NPD_EDAT_SDAT',b'NPD\x00'),('PKG',b'\x7fPKG'),('PUP',b'SCEUF'),('ZIP',b'PK\x03\x04'),('GZIP',b'\x1f\x8b\x08'),('XZ',b'\xfd7zXZ\x00'),('BZIP2',b'BZh'),('7ZIP',b'7z\xbc\xaf\x27\x1c'),('RAR',b'Rar!\x1a\x07'),('ZLIB',b'\x78\x9c'),('ZLIB',b'\x78\xda'),('ZLIB',b'\x78\x01')]
EXTENSIONS={'.self':'SELF extension','.sprx':'SPRX extension','.prx':'PRX extension','.fself':'FSELF extension','.mself':'MSELF extension','.elf':'ELF extension','.edat':'EDAT extension','.sdat':'SDAT extension','.rif':'RIF licence extension','.rap':'RAP licence extension','.sfo':'SFO metadata extension','.pkg':'PKG extension','.spkg':'SPKG extension','.pup':'PUP extension','.tar':'TAR extension','.irx':'IRX extension','.img':'image extension','.bin':'generic BIN extension','.rpx':'RPX extension'}

def inspect(kind, data, off):
    available=len(data)-off
    result={'format':kind,'offset':off,'confidence':'signature_candidate'}
    if kind=='ELF':
        if available<52:return dict(result,confidence='invalid',reason='truncated ELF header')
        cls=data[off+4]; endian=data[off+5]
        if cls not in (1,2) or endian not in (1,2) or data[off+6]!=1:
            return dict(result,confidence='invalid',reason='invalid ELF identification')
        order='little' if endian==1 else 'big'; width=52 if cls==1 else 64
        if available<width:return dict(result,confidence='invalid',reason='truncated ELF header')
        machine=int.from_bytes(data[off+18:off+20],order)
        phoff=int.from_bytes(data[off+(28 if cls==1 else 32):off+(32 if cls==1 else 40)],order)
        phentsize=int.from_bytes(data[off+(42 if cls==1 else 54):off+(44 if cls==1 else 56)],order)
        phnum=int.from_bytes(data[off+(44 if cls==1 else 56):off+(46 if cls==1 else 58)],order)
        if phnum and (phentsize < (32 if cls==1 else 56) or phoff < width or phoff+phentsize*phnum>available):
            return dict(result,confidence='invalid',reason='program header table out of bounds')
        return dict(result,confidence='header_valid',elf_class=32 if cls==1 else 64,byte_order=order,machine=machine,architecture={8:'MIPS',20:'PowerPC',21:'PowerPC64',23:'SPU'}.get(machine,'other'),program_headers=phnum)
    if kind=='SCE_SELF_SPRX_FSELF':
        if available<0x20:return dict(result,confidence='invalid',reason='truncated SCE header')
        version=int.from_bytes(data[off+4:off+8],'big')
        header_type=int.from_bytes(data[off+8:off+10],'big')
        metadata_offset=int.from_bytes(data[off+12:off+16],'big')
        header_len=int.from_bytes(data[off+16:off+24],'big')
        data_len=int.from_bytes(data[off+24:off+32],'big')
        result.update(version=version,sce_type=header_type,metadata_offset=metadata_offset,header_length=header_len,data_length=data_len)
        if version not in (1,2) or header_type not in (1,2,3,4) or header_len<0x20 or header_len>available or data_len>available or header_len+data_len>available or metadata_offset>header_len:
            return dict(result,confidence='invalid',reason='SCE header fields or lengths invalid')
        return dict(result,confidence='header_candidate',note='SCE bounds plausible; FSELF/NPDRM subtype not proven')
    if kind=='MSELF':
        m=inspect_mself(data,off)
        return dict(result,confidence='header_candidate' if m['status']=='header_candidate' else 'invalid',**{k:v for k,v in m.items() if k not in ('offset','status')})
    if kind=='NPD_EDAT_SDAT':
        if available<0x80:return dict(result,confidence='invalid',reason='truncated NPD header')
        return dict(result,confidence='header_candidate',version=int.from_bytes(data[off+4:off+8],'big'),note='EDAT/SDAT subtype not verified')
    if kind in ('ZIP','PKG'):return dict(result,confidence='header_candidate')
    return result

def scan(root, emit=print):
    root=Path(root).resolve()
    if not root.is_dir():raise ValueError('Not a directory: '+str(root))
    started=time.perf_counter()
    entries=[]; skipped=[]; totals={}; files_seen=0; mself_files=[]; fself_files=[]; fcounts={"scanned":0,"fself_named":0,"lv1_tables":0,"embedded_fself_entries":0,"embedded_headers":0,"fast_header_checks":0}; mcounts={"files_examined":0,"files_with_mself_magic":0,"header_candidates":0,"invalid_headers":0,"verified_entry_tables":0,"extracted_entries":0}
    for path in sorted(root.rglob('*')):
        if not path.is_file():continue
        rel=path.relative_to(root)
        if any(x in SKIP_DIRS for x in rel.parts) or (path.name.startswith('firmware_') and path.suffix=='.json'):continue
        files_seen+=1
        mcounts["files_examined"]+=1
        item={'path':str(rel),'size':None,'extension_hint':EXTENSIONS.get(path.suffix.lower()),'matches':[]}
        try:
            size=path.stat().st_size;item['size']=size
            if size==0:
                item['status']='empty';entries.append(item);continue
            if size>MAX_FILE:
                skipped.append({'path':str(rel),'size':size,'reason':'size_limit'});continue
            with path.open('rb') as fh,mmap.mmap(fh.fileno(),0,access=mmap.ACCESS_READ) as data:
                # Signature search is intentionally bounded to the first 64 MiB of each file.
                scan_end=min(len(data),64*1024*1024)
                for kind,magic in MAGICS:
                    pos=0; found=0
                    while (pos:=data.find(magic,pos,scan_end))>=0:
                        if kind=='ZLIB' and pos!=0:pos+=len(magic);continue
                        item['matches'].append(inspect(kind,data,pos));found+=1;pos+=len(magic)
                        if found>=256:
                            item.setdefault('warnings',[]).append('signature_limit_'+kind);break
                # TAR magic lives at offset 257, not the beginning.
                if len(data)>=262 and data[257:262]==b'ustar':item['matches'].append({'format':'TAR','offset':0,'confidence':'header_candidate'})
                # PARAM.SFO header: little-endian PSF\0.
                if len(data)>=20 and data[:4]==b'\x00PSF':item['matches'].append({'format':'PARAM_SFO','offset':0,'confidence':'header_candidate'})
            # Build FSELF/MSELF companion reports from the same memory mapping pass.
            mm=[m for m in item['matches'] if m['format']=='MSELF']
            if mm:
                mcounts['files_with_mself_magic']+=1
                mcounts['header_candidates']+=sum(m['confidence']=='header_candidate' for m in mm)
                mcounts['invalid_headers']+=sum(m['confidence']=='invalid' for m in mm)
                mself_files.append({'path':str(rel),'size':size,'matches':[{'offset':m['offset'],'status':'header_candidate' if m['confidence']=='header_candidate' else 'invalid',**{k:v for k,v in m.items() if k not in ('format','offset','confidence')}} for m in mm]})
            if path.suffix.lower() in {'.elf','.self','.fself','.sprx','.prx','.bin','.irx'} or any(m['offset']==0 and m['format'] in ('ELF','SCE_SELF_SPRX_FSELF') for m in item['matches']):
                fcounts['scanned']+=1;fcounts['fast_header_checks']+=1
                if path.suffix.lower()=='.fself':fcounts['fself_named']+=1
                headers=[{'offset':m['offset'],'kind':m['format'],'confidence':m['confidence']} for m in item['matches'] if m['offset']==0 and m['format'] in ('ELF','SCE_SELF_SPRX_FSELF')]
                fself_files.append({'path':str(rel),'size':size,'extension':path.suffix.lower(),'headers':headers,'lv1_style_tables':[],'fself_status':'filename_hint_only' if path.suffix.lower()=='.fself' else 'not_verified','note':'Fast mode: no LV1 table or FSELF subtype validation'})
            if item['matches'] or item['extension_hint']:
                for m in item['matches']:totals[m['format']]=totals.get(m['format'],0)+1
                entries.append(item)
        except (OSError,ValueError,OverflowError) as exc:skipped.append({'path':str(rel),'reason':str(exc)})
    report={'schema_version':2,'mode':'read_only_unified','files_examined':files_seen,'elapsed_seconds':round(time.perf_counter()-started,3),'files_reported':len(entries),'signature_counts':totals,'files':entries,'skipped':skipped,'limitations':['Signature hits are not proof of decryptability or payload integrity.','Only first 64 MiB of each file is searched for embedded signatures.','Encrypted or compressed contents cannot be discovered without unpacking.','RIF/RAP, IRX, SPKG and image extension hints are not validated by signatures.','EDAT vs SDAT and NPDRM are not conclusively classified.','No decryption or extraction performed.']}
    (root/'firmware_mself_inventory.json').write_text(json.dumps({'schema_version':2,'mode':'read-only-unified','root':str(root),'counts':mcounts,'files':mself_files,'skipped':skipped,'limitations':['MSELF entry layout not verified; no extraction or decryption.']},indent=2),encoding='utf-8')
    (root/'firmware_fself_inventory.json').write_text(json.dumps({'schema_version':2,'mode':'read-only-unified-fast','root':str(root),'counts':fcounts,'files':fself_files,'embedded_fself_candidates':[],'skipped':skipped,'notes':['No LV1 table extraction or FSELF subtype verification in fast mode.']},indent=2),encoding='utf-8')
    dest=root/'firmware_format_inventory.json';dest.write_text(json.dumps(report,indent=2),encoding='utf-8')
    emit(f'Format discovery: {files_seen} files, {len(entries)} interesting, {len(skipped)} skipped; {dest.name}')
    return report

if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('directory',type=Path);scan(ap.parse_args().directory)
