#!/usr/bin/env bash
# Runs ON a queue box (repo root of the job's private workspace): Stryker.NET over sdks/dotnet-pca/AtlasPca with the corpus test
# project as the oracle. Writes the JSON report to tools/pca-audit/native-mutation/results/dotnet-stryker.json (pull that path) and
# a compact survivor list (Survived + NoCoverage) to tools/pca-audit/native-mutation/results/dotnet-survivors.json in the
# native-check-equivalents.mjs format ({crate,file,mutant,line,occurrence,lineno}).
#   q submit --need dotnet --cores 8 --mem 12 --wall 7200 --pull tools/pca-audit/native-mutation/results -- bash tools/pca-audit/native-mutation/net-stryker-box.sh
set -euo pipefail
ROOT="$PWD"
export PATH="$HOME/.dotnet/tools:$PATH" DOTNET_CLI_TELEMETRY_OPTOUT=1
# pinned: newer dotnet-stryker packages do not install on the boxes' .NET 8 SDK ("DotnetToolSettings.xml was not found")
command -v dotnet-stryker >/dev/null 2>&1 || dotnet tool install -g dotnet-stryker --version "${STRYKER_VERSION:-4.8.1}"
cd sdks/dotnet-pca/AtlasPca.Corpus.Tests
rm -rf StrykerOutput
# the suite must be green first (Stryker silently drops tests that fail its initial run)
dotnet test -c Release 2>&1 | grep -E "^\s+Failed |Passed!|Failed!|error CS" | head -20
# stryker-config.json: coverage-analysis "all" (per-test capture, the default, mis-attributed coverage on this suite: mutants killed
# by an exact-boundary assertion were reported Survived) and additional-timeout 60000 ("off"/"all" run the whole ~40 s suite per
# mutant; the default +5 s timeout fired spuriously on a loaded box and reported equivalent mutants as Timeout = "killed").
# test-case-filter Category!=Huge + corpus tests on a 512 MiB stack (BigStack.cs): a depth-cap-removing mutant overflowed the stack on
# 100000-level inputs, which kills the shared VsTest host and turned whole runner sessions into spurious Timeout/Survived results.
dotnet stryker --config-file stryker-config.json --concurrency "${CONC:-$(nproc)}" 2>&1 | grep -vE '^\s*$' | tail -30
REP="$(ls -d StrykerOutput/*/reports/mutation-report.json | tail -1)"
mkdir -p "$ROOT/tools/pca-audit/native-mutation/results"
cp "$REP" "$ROOT/tools/pca-audit/native-mutation/results/dotnet-stryker.json"
python3 - "$REP" "$ROOT/tools/pca-audit/native-mutation/results/dotnet-survivors.json" <<'PY'
import json, sys, collections
d = json.load(open(sys.argv[1])); out = []; c = collections.Counter()
for f, v in d['files'].items():
    src = v['source'].split('\n'); rel = 'AtlasPca/' + f.replace('\\', '/').split('/AtlasPca/')[-1]
    for m in v['mutants']:
        c[m['status']] += 1
        if m['status'] == 'Timeout': print('TIMEOUT', m['location']['start']['line'], m['mutatorName'], '|', ' '.join(str(m.get('replacement', '')).split())[:80])
        if m['status'] in ('Survived', 'NoCoverage'):
            ln = m['location']['start']['line']
            rep = ' '.join(str(m.get('replacement', '')).split())[:160]
            # occurrence = which copy of this (trimmed) text in the mutated source: the site key of native-check-equivalents.mjs
            occ = [i + 1 for i, l in enumerate(src) if l.strip() == src[ln - 1].strip()].index(ln) + 1
            out.append({'crate': 'dotnet-pca', 'file': rel, 'mutant': f"{m['mutatorName']}: {rep}", 'line': src[ln - 1].strip(), 'occurrence': occ, 'lineno': ln, 'status': m['status']})
json.dump(out, open(sys.argv[2], 'w'), indent=1)
print(dict(c)); [print(o['lineno'], o['mutant'][:90], '|', o['line'][:120]) for o in out]
PY
