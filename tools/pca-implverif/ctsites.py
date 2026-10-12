#!/usr/bin/env python3
"""ctsites.py <memcheck stderr>: one line per error context: kind | innermost source site | call chain (5 frames)."""
import re, sys
t = open(sys.argv[1]).read()
for i, b in enumerate(re.split(r'\n==\d+== \n', t)):
    ls = [re.sub(r'^==\d+== ', '', l) for l in b.split('\n') if l.strip()]
    if not ls or not ls[0].startswith(('Conditional', 'Use of')): continue
    fr = [re.sub(r'^(at|by) 0x[0-9A-F]+: ', '', x.strip()) for x in ls if x.strip().startswith(('at', 'by'))]
    kind = 'branch' if ls[0].startswith('Cond') else 'address'
    print(f'{kind:8s}| {fr[0]} <- ' + ' <- '.join(fr[1:4]))
