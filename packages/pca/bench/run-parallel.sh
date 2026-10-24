#!/usr/bin/env bash
# Run the PCActn verification benchmark in parallel without sharing a core between measurements.
#   bash packages/pca/bench/run-parallel.sh OUTDIR [N]
# 1. Pre-signs every scenario once (one process per suite, in parallel) and merges them into
#    packages/pca/bench/fixtures/verify-fixtures.json.gz (public data only: grants, PCActns, signer sets).
# 2. Measures from those fixtures: one queue of suites per PHYSICAL core (one logical CPU per core, so SMT siblings never
#    run two measurements at once), each process pinned with taskset; suites are spread over the queues by expected cost.
# 3. Merges the per-suite results into OUTDIR/verify.json and records the host in OUTDIR/verify-host.txt.
set -euo pipefail
OUT="${1:?outdir}"; N="${2:-1000}"
HERE="$(cd "$(dirname "$0")" && pwd)"
BENCH="$HERE/verify-bench.mjs"
FX="$HERE/fixtures/verify-fixtures.json.gz"
mkdir -p "$OUT/parts" "$HERE/fixtures"

SUITES=(less-cat1 hybrid-ed25519-less-cat1 hybrid-ed25519-slh-dsa-sha2-256s slh-dsa-sha2-256s hybrid-ed25519-slh-dsa-sha2-128f
        slh-dsa-sha2-128f hybrid-ed25519-ml-dsa-87 hybrid-ed25519-ml-dsa-65 hybrid-nested-ed25519-ml-dsa-65 ed25519 ml-dsa-87
        ml-dsa-65 fn-dsa-1024 fn-dsa-512)
# relative cost estimates (seconds per depth-8 verify, from a smoke run), used only to balance the queues
declare -A COST=([less-cat1]=2.8 [hybrid-ed25519-less-cat1]=2.8 [hybrid-ed25519-slh-dsa-sha2-256s]=0.19 [slh-dsa-sha2-256s]=0.16
  [hybrid-ed25519-slh-dsa-sha2-128f]=0.16 [slh-dsa-sha2-128f]=0.13 [hybrid-ed25519-ml-dsa-87]=0.08 [hybrid-ed25519-ml-dsa-65]=0.13
  [hybrid-nested-ed25519-ml-dsa-65]=0.07 [ed25519]=0.12 [ml-dsa-87]=0.05 [ml-dsa-65]=0.07 [fn-dsa-1024]=0.01 [fn-dsa-512]=0.01)

# one logical CPU per physical core
mapfile -t CPUS < <(lscpu -p=CPU,CORE,SOCKET | grep -v '^#' | sort -t, -k3,3n -k2,2n -k1,1n | awk -F, '!seen[$3","$2]++ {print $1}')
Q=${#CPUS[@]}
echo "physical cores used: $Q (cpus ${CPUS[*]})"

# 1. fixtures (parallel; signing is not measured)
if [ ! -s "$FX" ]; then
  printf '%s\n' "${SUITES[@]}" | xargs -P "$(nproc)" -I{} node "$BENCH" --gen-fixtures "$OUT/parts/fx-{}.json" --suites {}
  node "$HERE/merge.mjs" fixtures "$FX" "$OUT"/parts/fx-*.json
fi

# 2. greedy assignment of suites to queues by cost
declare -a LOAD QUEUE
for ((i = 0; i < Q; i++)); do LOAD[$i]=0; QUEUE[$i]=""; done
for s in "${SUITES[@]}"; do
  best=0
  for ((i = 1; i < Q; i++)); do (( $(awk "BEGIN{print (${LOAD[$i]} < ${LOAD[$best]})}") )) && best=$i; done
  QUEUE[$best]="${QUEUE[$best]} $s"; LOAD[$best]=$(awk "BEGIN{print ${LOAD[$best]} + ${COST[$s]}}")
done
pids=()
for ((i = 0; i < Q; i++)); do
  [ -n "${QUEUE[$i]}" ] || continue
  cpu=${CPUS[$i]}
  echo "cpu $cpu:${QUEUE[$i]}"
  (
    for s in ${QUEUE[$i]}; do
      BENCH_CPU=$cpu taskset -c "$cpu" node "$BENCH" --fixtures "$FX" --suites "$s" --n "$N" --out "$OUT/parts/res-$s.json" > "$OUT/parts/log-$s.txt" 2>&1
    done
  ) &
  pids+=($!)
done
rc=0; for p in "${pids[@]}"; do wait "$p" || rc=1; done
[ "$rc" = 0 ] || { tail -5 "$OUT"/parts/log-*.txt; exit 1; }
node "$HERE/merge.mjs" results "$OUT/verify.json" "$OUT"/parts/res-*.json
{ lscpu; echo; free -g; echo; uname -srm; echo; echo "node $(node --version)"; echo "cpus used: ${CPUS[*]}"; } > "$OUT/verify-host.txt"
