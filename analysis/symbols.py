# Reverse-engineering helper (run with a python that has capstone +
# pyelftools; see analysis/README.md).
#
# Crypto-relevant symbols in .dynsym: name contains 'crypto' or 'backup'
# ('fwcrypto' is a subset of 'crypto'; the type test is parenthesized so
# non-function symbols named e.g. 'backup' are not matched).
import sys

from elftools.elf.elffile import ELFFile

with open(sys.argv[1], 'rb') as f:
    e = ELFFile(f)
    for sec in e.iter_sections():
        if sec.name in ('.dynsym',):
            for s in sec.iter_symbols():
                name = s.name.lower()
                if s['st_info']['type'] == 'STT_FUNC' and ('crypto' in name or 'backup' in name):
                    print(s.name)
