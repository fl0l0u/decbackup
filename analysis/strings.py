# Reverse-engineering helper (run with a python that has capstone +
# pyelftools; see analysis/README.md).
import re
import sys

minlen = int(sys.argv[2]) if len(sys.argv) > 2 else 4
pat = re.compile(rb'[\x20-\x7e]{%d,}' % minlen)
with open(sys.argv[1], 'rb') as f:
    data = f.read()
for m in pat.finditer(data):
    print(hex(m.start()), m.group().decode())
