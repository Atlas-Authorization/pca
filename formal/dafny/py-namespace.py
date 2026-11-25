#!/usr/bin/env python3
"""py-namespace.py DIR PACKAGE: rewrite the imports of a Dafny Python translation so its modules live under PACKAGE.

Dafny's Python backend imports its modules by top-level name (`import GoalIr`, `import _dafny`, `from System_ import *`) and
asserts `"GoalIr" == __name__`. Both break (or clash with another extraction) once the directory is a package, so:
  import X              -> import PACKAGE.X as X
  import X as Y         -> import PACKAGE.X as Y
  from X import ...     -> from PACKAGE.X import ...
  assert "X" == __name__ -> assert __name__.rpartition(".")[2] == "X"
X ranges over the module files and directories at the top of DIR. Fails if a top-level name is still imported bare.
"""
import os
import re
import sys

d, pkg = sys.argv[1], sys.argv[2]
names = sorted({os.path.splitext(n)[0] for n in os.listdir(d) if n != "__init__.py" and (n.endswith(".py") or os.path.isdir(os.path.join(d, n)))})
alt = "|".join(re.escape(n) for n in names)
imp_as = re.compile(r"^(\s*)import (%s) as (\w+)\s*$" % alt)
imp = re.compile(r"^(\s*)import (%s)\s*$" % alt)
frm = re.compile(r"^(\s*)from (%s)((?:\.\w+)*) import " % alt)
nm = re.compile(r"^(\s*)assert \"(\w+)\" == __name__\s*$")
bare = re.compile(r"^\s*(import|from) (%s)\b(?! as)" % alt)
n = 0
for root, _, files in os.walk(d):
    for f in files:
        if not f.endswith(".py"):
            continue
        p = os.path.join(root, f)
        out = []
        for line in open(p, encoding="utf-8").read().split("\n"):
            for rx, fmt in ((imp_as, r"\1import %s.\2 as \3"), (imp, r"\1import %s.\2 as \2"), (frm, r"\1from %s.\2\3 import ")):
                if rx.match(line):
                    line = rx.sub(fmt % pkg, line)
                    n += 1
                    break
            else:
                m = nm.match(line)
                if m:
                    line = '%sassert __name__.rpartition(".")[2] == "%s"' % (m.group(1), m.group(2))
                    n += 1
            out.append(line)
        open(p, "w", encoding="utf-8").write("\n".join(out))
for root, _, files in os.walk(d):
    for f in files:
        if f.endswith(".py"):
            for i, line in enumerate(open(os.path.join(root, f), encoding="utf-8"), 1):
                if re.match(r"^\s*(import|from) (%s)\b" % alt, line) and pkg not in line:
                    sys.exit("py-namespace: unrewritten import %s:%d: %s" % (f, i, line.strip()))
print("   py-namespace: %d line(s) rewritten in %d module(s)" % (n, len(names)))
