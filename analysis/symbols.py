# Reverse-engineering helper (run with a python that has capstone +
# pyelftools; see analysis/README.md).
import sys
from elftools.elf.elffile import ELFFile
e = ELFFile(open(sys.argv[1],'rb'))
for sec in e.iter_sections():
    if sec.name in ('.dynsym',):
        for s in sec.iter_symbols():
            if s['st_info']['type']=='STT_FUNC' and 'crypto' in s.name.lower() or 'backup' in s.name.lower() or 'fwcrypto' in s.name.lower():
                print(s.name)
