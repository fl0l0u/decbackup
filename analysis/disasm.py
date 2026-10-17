# Reverse-engineering helper (run with a python that has capstone +
# pyelftools; see analysis/README.md).
import sys, struct
from elftools.elf.elffile import ELFFile
from capstone import *

path, wanted = sys.argv[1], sys.argv[2:]
dumpall = '--all' in wanted
wanted = [w for w in wanted if not w.startswith('--')]
f = open(path,'rb'); e = ELFFile(f)
symtab = e.get_section_by_name('.symtab')
funcs = {s.name:(s['st_value'], s['st_size']) for s in symtab.iter_symbols() if s['st_info']['type']=='STT_FUNC'}
# build plt map: jmp qword [rip+X] in .plt/.plt.sec -> GOT addr -> reloc name
got = {}
for sec in e.iter_sections():
    if sec['sh_type']=='SHT_RELA':
        syms = e.get_section(sec['sh_link'])
        for r in sec.iter_relocations():
            sym = syms.get_symbol(r['r_info_sym'])
            if sym.name: got[r['r_offset']] = sym.name
pltmap = {}
md0 = Cs(CS_ARCH_X86, CS_MODE_64); md0.detail=True
for nm in ('.plt','.plt.sec'):
    s = e.get_section_by_name(nm)
    if not s: continue
    for i in md0.disasm(s.data(), s['sh_addr']):
        if i.mnemonic=='jmp' and 'rip' in i.op_str:
            v = int(i.op_str.split('[')[1].rstrip(']').split('+')[-1],16) if '+' in i.op_str else 0
            # capstone gives 'qword ptr [rip + 0x...]'
            try:
                tgt = i.address + i.size + int(i.op_str.rsplit('+',1)[1].rstrip(']'),16)
            except: tgt=None
            if tgt in got: pltmap[i.address]=got[tgt]
        if i.mnemonic=='push' and 'rip' in i.op_str and 'qword' not in i.op_str:
            pltmap[i.address]=pltmap.get(i.address,'?')
# also symtab FUNC at same addr
for s in symtab.iter_symbols():
    if s['st_info']['type']=='STT_FUNC' and s['st_shndx']=='SHN_UNDEF':
        pltmap[s['st_value']]=s.name
# sections for address lookup
secs = [s for s in e.iter_sections() if s['sh_type']=='SHT_PROGBITS']
def read_at(addr,n):
    for s in secs:
        if s['sh_addr'] <= addr < s['sh_addr']+s['sh_size']:
            return s.data()[addr-s['sh_addr']:addr-s['sh_addr']+n]
    return None
def cstr(addr):
    d = read_at(addr,256)
    if not d: return ''
    return d.split(b'\0')[0].decode('latin1')
md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail=True
def disasm(name):
    if name not in funcs: print("NOFUNC", name); return
    addr, size = funcs[name]
    d = read_at(addr, size if size else 4096)
    print(f"===== {name} @ {hex(addr)} size={size} =====")
    for i in md.disasm(d, addr):
        tag=""
        if i.mnemonic in ('call','jmp'):
            try:
                t=int(i.op_str,16)
                if t in pltmap: tag="  ; -> "+pltmap[t]
                else:
                    for fn,(a,sz) in funcs.items():
                        if a==t: tag="  ; -> "+fn
            except: pass
        # annotate rip lea string refs
        if i.mnemonic=='lea' and 'rip' in i.op_str and 'ptr [' in i.op_str:
            try:
                sign = '+' if ' + ' in i.op_str else '-'
                v = int(i.op_str.rsplit(sign,1)[1].rstrip(']'),16)
                tgt = i.address+i.size + (v if sign=='+' else -v)
                s = cstr(tgt)
                if s and all(32<=ord(c)<127 for c in s): tag=f"  ; str@{tgt:x} = {s!r}"
            except: pass
        print(f"{i.address:#x} {i.bytes.hex():<16} {i.mnemonic} {i.op_str}{tag}")
if dumpall:
    for nm in funcs: disasm(nm)
else:
    for w in wanted: disasm(w)
