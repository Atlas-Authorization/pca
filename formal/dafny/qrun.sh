#!/usr/bin/env bash
# qrun.sh '<shell command>' [PULL_DIR]
#   Run a Dafny command on the farm THROUGH THE PCAQ QUEUE (cloud-box tooling/remote.sh): a private snapshot of the working tree is unpacked
#   on a box, the command runs in formal/dafny with Dafny 4.11.0 (/work/tools/dafny; installed on demand by install-dafny.sh) on PATH.
#   PULL_DIR (relative to formal/dafny) is copied back after the run (to the same path in this checkout); the caller moves it away.
#   env: CORES (default 4)  MAX_WALL_S (default 3600)  passed through to remote.sh.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
CMD="${1:?command}"; PULLD="${2:-}"
INNER="set -e; test -x /work/tools/dafny/dafny || bash formal/dafny/install-dafny.sh >&2; export PATH=/work/tools/dafny:\$PATH; cd formal/dafny; $CMD"
if [ -n "$PULLD" ]; then
  NODEPS=1 PREP=none CORES="${CORES:-4}" MAX_WALL_S="${MAX_WALL_S:-3600}" JOBS="${JOBS:-dafny}" PULL="formal/dafny/$PULLD" "$ROOT/cloud-box tooling/remote.sh" "$INNER"
else
  NODEPS=1 PREP=none CORES="${CORES:-4}" MAX_WALL_S="${MAX_WALL_S:-3600}" JOBS="${JOBS:-dafny}" "$ROOT/cloud-box tooling/remote.sh" "$INNER"
fi
