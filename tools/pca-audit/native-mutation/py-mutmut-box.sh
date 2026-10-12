#!/usr/bin/env bash
# Queue job (run from the repo root of a private snapshot): mutmut over sdks/python-pca; results -> /tmp/pymut/.
# Shardable: MM_GLOB is a mutant-name glob, e.g. '*[0-3]' / '*[4-6]' / '*[7-9]' (last digit of the mutant number).
# Memory: each child loads the adversarial corpus; 8 children OOM at 12G, use MM_CHILDREN=4 with --mem 28.
# Resumable: the run stops itself after MM_BUDGET_S seconds (set it below the job's wall) and always writes results plus
# /tmp/pymut/mutants-state.tgz. Copy that tarball to sdks/python-pca/mutants.state.tgz (untracked, never commit it) and
# resubmit: the next run restores it and mutmut continues where it stopped (only valid while sources and tests are unchanged).
set -u
R=$(pwd); OUT=/tmp/pymut; rm -rf "$OUT"; mkdir -p "$OUT"
python3 -m venv "$OUT/venv" && . "$OUT/venv/bin/activate" && pip -q install mutmut pytest cryptography dilithium-py fastapi httpx django >/dev/null
ln -sfn ../packages "$R/sdks/packages"   # mutmut runs tests from sdks/python-pca/mutants; ../../packages must resolve
cd "$R/sdks/python-pca" && rm -rf mutants
[ -f mutants.state.tgz ] && tar xzf mutants.state.tgz && echo "restored mutants state"
timeout --signal=INT --kill-after=120 "${MM_BUDGET_S:-100000}" mutmut run --max-children "${MM_CHILDREN:-4}" ${MM_GLOB:+"$MM_GLOB"} > "$OUT/run.log" 2>&1
echo "mutmut run rc=$?"
mutmut results --all true > "$OUT/results.txt" 2>&1 || mutmut results > "$OUT/results.txt" 2>&1
tar czf "$OUT/mutants-state.tgz" mutants
for m in $(grep -E "survived|timeout|suspicious|no tests" "$OUT/results.txt" | awk '{print $1}' | sed 's/:$//'); do mutmut show "$m" 2>/dev/null | grep -E "^# |^[-+][^-+]"; done > "$OUT/diffs.txt"
tail -c 300 "$OUT/run.log" | tr '\r' '\n' | tail -1; grep -c survived "$OUT/results.txt"
