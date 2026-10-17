# Reverse-engineering helper (run with a python that has capstone +
# pyelftools; see analysis/README.md).
import sys, re
data = open(sys.argv[1],'rb').read()
minlen = int(sys.argv[2]) if len(sys.argv)>2 else 4
pat = re.compile(rb'[\x20-\x7e]{%d,}' % minlen)
for m in pat.finditer(data):
    print(hex(m.start()), m.group().decode())
