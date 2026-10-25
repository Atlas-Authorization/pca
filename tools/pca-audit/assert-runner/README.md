# assert-runner

Measures one TypeScript source file's Stryker mutants by hand-applying each one and running vitest, and says HOW each
mutant is detected. Detection kinds: `KILLED_ASSERT` (at least one test fails on an `AssertionError`), `KILLED_ERROR` (tests
fail, but only on an uncaught error), `TIMEOUT`, `SURVIVED`, `CRASH` (vitest produced no report), `NOLOC` (the mutant's
original text is no longer in the source).

Mutants come from Stryker's own instrumenter (`@stryker-mutator/instrumenter` 10.0.0, the version the CI runs), so the
locations and replacement code are exact. Vitest runs with ONE fork per worker, the json reporter, and no bail (every
listed test runs, so an assertion failure anywhere is seen).

## Usage (on the box)

    ~/pca-tools/assert-runner/assert-runner.sh -w <workspace> -s <src/file.ts> -t "<test files>" [-j 4] [options]

- `-w` a workspace root holding `packages/pca` (src, circuits, fixtures, testdata, tsconfig.json), a root `tsconfig.base.json`
  and `node_modules` (symlinks to `~/w-flag/node_modules` and `~/w-flag/packages/pca/node_modules` are fine). It is copied
  `-j` times; the original is never modified. Set `PKG=packages/<name>` for another package (default `packages/pca`).
- `-s` the source file, relative to the package (`src/zk.ts`).
- `-t` the test files, relative to the package, space-separated in ONE quoted argument. They must pass on the unmodified
  source (checked first; the run stops otherwise).
- `-j` parallel workers (default 4). Keep the box load sane.
- `-o` output directory (default a new `~/assert-runner-out.XXXX`).
- `-b <all.txt> -g pca/src/zk.ts` keep only the mutants listed in a backlog / merge log ("UNLISTED SURVIVOR" lines).
- `-l 100-200` only mutants starting on these lines. `-m mutants.jsonl` reuse a mutant list (e.g. a filtered results file).
- `-T` per-mutant vitest timeout in ms (default 300000). `KEEP_WS=1` keeps the workspace copies.

Output: `results.jsonl` (one line per mutant: result, the first failing assertions / errors), `summary.txt` (counts plus
every mutant that is not `KILLED_ASSERT`). Re-list later with `node ~/pca-tools/assert-runner/summarize.cjs results.jsonl
KILLED_ERROR,SURVIVED`. A worker can be stopped between mutants with `touch <outdir>/out<k>.jsonl.STOP`; a re-run with the
same `-o` resumes.

Example (zk.ts, backlog sites only, the zk test files):

    ~/pca-tools/assert-runner/assert-runner.sh -w ~/w-mine -s src/zk.ts -j 4 -o ~/ar-zk \
      -b ~/w-chk/backlog/all.txt -g pca/src/zk.ts \
      -t "src/zk.test.ts src/zk-bls12381.test.ts src/zk-canonical.test.ts src/mutation-kill-r13-g1-zk-policyvm.test.ts"

To build a workspace from the Mac HEAD: `git archive HEAD packages/pca tsconfig.base.json | gzip` on the Mac, unpack on
the box, add the two node_modules symlinks, and (for zk.ts) build the circuit as CI does:
`curl -fsSL -o ~/circom https://github.com/iden3/circom/releases/download/v2.2.2/circom-linux-amd64 && chmod +x ~/circom &&
(cd packages/pca && CIRCOM=~/circom bash circuits/setup.sh)`.

Notes: a mutant that throws inside a test expecting a value is `KILLED_ERROR`; to turn it into an assertion, capture the
outcome (`settle(() => f())` returning `{ ok: true, value }` / `{ ok: false, error: { name, message } }`) and `toEqual` the
exact expected outcome. Static (module-level) mutants are applied to the file like any other, so a fresh process sees them.

## Faster: two phases

Each mutant runs the whole test list without bail, so a long list is slow. A KILLED_ASSERT on a subset is also an
assertion kill on the full list, so: run the fast, targeted test files first, then only the rest against the full list.

    AR=~/pca-tools/assert-runner/assert-runner.sh
    $AR -w ~/w-mine -s src/zk.ts -j 4 -o ~/ar-a -b ~/w-chk/backlog/all.txt -g pca/src/zk.ts -t "<fast targeted tests>"
    node -e 'const fs=require("fs");const r=new Map(fs.readFileSync(process.argv[1],"utf8").trim().split("\n").map(l=>{const x=JSON.parse(l);return [x.id,x.result]}));
      fs.writeFileSync(process.argv[3],fs.readFileSync(process.argv[2],"utf8").trim().split("\n").filter(l=>r.get(JSON.parse(l).id)!=="KILLED_ASSERT").join("\n")+"\n")' \
      ~/ar-a/results.jsonl ~/ar-a/mutants.jsonl ~/ar-rest.jsonl
    $AR -w ~/w-mine -s src/zk.ts -j 4 -o ~/ar-b -m ~/ar-rest.jsonl -t "<full test list>"

Measured with it (g1, 2026-10-24): zk.ts 757 backlog mutants in ~15 min (phase 1, 3 files) + ~10 min (phase 2, 23 left).

## Gotchas

- Snarkjs-backed tests need `packages/pca/circuits/build` (the CI step) and, under Stryker's threads pool,
  `test-support/snarkjs-single-thread.ts` (already wired into the zk test files). This runner uses forks.
- A test that spawns child processes (e.g. a script entry point run with tsx) sees the hand-applied mutant directly.
- Read fixtures in tests by literal path, not through the module's own path helpers, or a path mutant breaks the
  whole suite (a suite-level error, not an assertion).
