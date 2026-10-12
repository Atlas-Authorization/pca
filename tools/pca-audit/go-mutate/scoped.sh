#!/usr/bin/env bash
# Scoped go-mutate run (queue job, repo root): only mutants on the lines listed in scope-lines.txt ("file:line", or
# "file:*" for a whole file). Writes /tmp/gomut-scoped.json and prints survivors.
set -eu
T=tools/pca-audit/go-mutate; D=$(pwd)/sdks/go-pca
(cd $T && go build -o /tmp/gomutate .)
/tmp/gomutate -dir "$D" -files pca.go,strictjson.go,threshold.go -list > /tmp/gomut-list.txt
IDS=$(python3 - "$T/scope-lines.txt" <<'PY'
import sys,re
scope=set(l.strip() for l in open(sys.argv[1]) if l.strip())
whole={s.split(':')[0] for s in scope if s.endswith(':*')}
ids=[]
for l in open('/tmp/gomut-list.txt'):
    m=re.match(r'(\d+) (\S+):(\d+) ',l)
    if m and (m.group(2) in whole or f'{m.group(2)}:{m.group(3)}' in scope): ids.append(m.group(1))
print(','.join(ids))
PY
)
echo "scoped mutants: $(echo $IDS | tr ',' '\n' | wc -l)"
/tmp/gomutate -dir "$D" -files pca.go,strictjson.go,threshold.go -ids "$IDS" -j "${J:-2}" -out /tmp/gomut-scoped.json | tail -60
