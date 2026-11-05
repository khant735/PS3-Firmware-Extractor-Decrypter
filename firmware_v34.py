"""Read-only PS3 firmware payload classifier and SYS_CON header decoder.
Does not modify or duplicate firmware. GPL-3.0-or-later distribution bundle.
"""
import argparse, csv, hashlib, json, re, struct, tarfile
from pathlib import Path
from xml.etree import ElementTree as ET

MAGIC=b'\x1b\x2d\x70\x0f'

def sha256(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
    return h.hexdigest()

def syscon_header(h):
    if len(h)<64 or not h.startswith(MAGIC):return None
    return {'magic':'1B2D700F','checksum_words_1':[f'{struct.unpack_from(">I",h,o)[0]:08X}' for o in range(4,36,4)],
            'offset0_le':struct.unpack_from('<I',h,0x24)[0],
            'firmware_size_le':struct.unpack_from('<I',h,0x28)[0],
            'binary_size_le':struct.unpack_from('<I',h,0x2c)[0],
            'checksum_words_2':[f'{struct.unpack_from(">I",h,o)[0]:08X}' for o in range(0x30,0x40,4)],
            'note':'Names are provisional, as in BitEdits ps3tools syscon.c; no checksum validation.'}

def coreos(h,size):
    if len(h)<16 or h[:4]!=b'\0\0\0\1':return None
    n=int.from_bytes(h[4:8],'big')
    if not 1<=n<=255 or 16+48*n>size:return None
    return n

def inspect(path):
    size=path.stat().st_size
    with path.open('rb') as f:h=f.read(max(16384,16+48*255))
    name=path.name
    original=re.sub(r'^\d{3}_','',name)
    original=re.sub(r'\.plaintext$','',original,flags=re.I)
    result={'file':name,'size':size,'sha256':sha256(path),'original_member':original,'header_hex':h[:64].hex(' '),'type':'unknown binary','recommended_name':original,'details':{}}
    sc=syscon_header(h)
    n=coreos(h,size)
    if sc:result.update(type='SYS_CON firmware image',details=sc)
    elif n is not None:result.update(type='CORE_OS inner package',recommended_name='CORE_OS_PACKAGE.pkg',details={'entry_count':n})
    elif h.startswith(b'<?xml') or h.lstrip().startswith(b'<UpdatePackageList'):
        try:
            with path.open('rb') as f: root=ET.parse(f).getroot()
            if root.tag.split('}')[-1]=='UpdatePackageList':
                types={}
                for x in root.iter():
                    if x.tag.split('}')[-1]=='Type' and x.text:
                        types[x.text.strip()]=types.get(x.text.strip(),0)+1
                result.update(type='UPL XML',recommended_name='UPL.xml',details={'package_type_counts':types})
        except (ET.ParseError,ValueError):pass
    elif tarfile.is_tarfile(path):
        result.update(type='TAR archive',recommended_name='BLUETOOTH_FIRMWARE.tar' if original.upper()=='BLUETOOTH_FIRMWARE.pkg' else original,
                      details={'archive':'valid TAR (not extracted)'})
    elif h.startswith(b'\x7fELF'):result['type']='ELF'
    elif h.startswith(b'SCE\x00'):result['type']='SCE container'
    elif original.upper().startswith(('BDIT_','BDPT_')):result['type']='Blu-ray firmware image (by package name; structure unverified)'
    elif original.upper().startswith('MULTI_CARD_'):result['type']='Multi-card firmware image (by package name; structure unverified)'
    return result

def run(folder,report_dir):
    folder=Path(folder).resolve();report_dir=Path(report_dir).resolve()
    if not folder.is_dir():raise ValueError('Input directory not found')
    paths=sorted(p for p in folder.rglob('*') if p.is_file() and (p.name.endswith('.plaintext') or p.name.endswith('.pkg') or p.name.endswith('.xml')))
    if not paths:raise ValueError('No plaintext or package files found')
    rows=[inspect(p) for p in paths]
    report_dir.mkdir(parents=True,exist_ok=True)
    (report_dir/'firmware_v34_report.json').write_text(json.dumps({'schema_version':1,'read_only':True,'input':str(folder),'count':len(rows),'entries':rows},indent=2),encoding='utf-8')
    with (report_dir/'firmware_v34_report.csv').open('w',newline='',encoding='utf-8-sig') as f:
        w=csv.DictWriter(f,fieldnames=['file','size','sha256','original_member','type','recommended_name','header_hex','details']);w.writeheader()
        for r in rows:w.writerow({**r,'details':json.dumps(r['details'])})
    return rows

def gui():
    import tkinter as tk
    from tkinter import filedialog,ttk,messagebox,scrolledtext
    root=tk.Tk();root.title('PS3 Firmware v3.4 — Existing plaintext analysis (read-only)');root.geometry('950x610')
    source=tk.StringVar();out=tk.StringVar()
    for label,var in [('Existing decrypted folder',source),('Report destination',out)]:
        frame=ttk.Frame(root,padding=8);frame.pack(fill='x');ttk.Label(frame,text=label,width=25).pack(side='left');ttk.Entry(frame,textvariable=var).pack(side='left',fill='x',expand=True)
        ttk.Button(frame,text='Browse',command=lambda v=var:v.set(filedialog.askdirectory() or v.get())).pack(side='left')
    txt=scrolledtext.ScrolledText(root,font=('Consolas',10));txt.pack(fill='both',expand=True,padx=8,pady=8)
    def go():
        try:
            rows=run(source.get(),out.get())
            txt.delete('1.0','end')
            for r in rows:
                txt.insert('end',f"{r['file']}\n  {r['type']} | {r['size']} bytes\n  Recommended: {r['recommended_name']}\n")
                if r['type']=='SYS_CON firmware image':txt.insert('end',f"  Header: {r['details']['firmware_size_le']} / {r['details']['binary_size_le']} bytes\n")
            txt.insert('end',f'\nAnalyzed {len(rows)} files. Reports saved to {out.get()}\nNo firmware files changed.\n')
        except Exception as e:messagebox.showerror('Analysis failed',str(e))
    ttk.Button(root,text='Analyze existing files (no changes)',command=go).pack(pady=8)
    root.mainloop()

if __name__=='__main__':
    a=argparse.ArgumentParser();a.add_argument('--input');a.add_argument('--report-dir');args=a.parse_args()
    if args.input:
        rows=run(args.input,args.report_dir or args.input);print('Analyzed',len(rows),'files')
    else:gui()
