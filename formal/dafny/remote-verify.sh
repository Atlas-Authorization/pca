#!/usr/bin/env bash
# remote-verify.sh '<shell command>'   run the command in formal/dafny on the farm through the pcaq queue (see qrun.sh), with dafny on PATH.
# PULL_FROM=<dir relative to formal/dafny> PULL_TO=<local dir> copies that directory back afterwards.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
if [ -n "${PULL_FROM:-}" ] && [ -n "${PULL_TO:-}" ]; then
  rm -rf "$HERE/$PULL_FROM"
  "$HERE/qrun.sh" "$1" "$PULL_FROM"; rc=$?
  mkdir -p "$PULL_TO"; [ -d "$HERE/$PULL_FROM" ] && cp -R "$HERE/$PULL_FROM/." "$PULL_TO/" && rm -rf "$HERE/$PULL_FROM"
  exit $rc
fi
exec "$HERE/qrun.sh" "$1"
