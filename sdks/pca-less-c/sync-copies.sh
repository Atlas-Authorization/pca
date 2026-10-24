#!/usr/bin/env bash
# This directory is the canonical copy of the LESS C. The Rust crate and the Go module each carry a copy INSIDE their package
# (sdks/rust-pca/less-c, sdks/go-pca/lessc) so that a crates.io build with `--features less` and a `go build -tags less` of the
# published module need nothing outside them. This script refreshes both copies; `--check` only reports drift (exit 1).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
files=(LICENSE atlas_less.c atlas_less.h)
for f in "$here"/include/*.h "$here"/lib/*.c; do files+=("${f#"$here"/}"); done
drift=0
for dst in "$here/../rust-pca/less-c" "$here/../go-pca/lessc"; do
  for f in "${files[@]}"; do
    if [ "${1:-}" = --check ]; then
      cmp -s "$here/$f" "$dst/$f" || { echo "drift: ${dst#"$here"/../}/$f"; drift=1; }
    else
      mkdir -p "$(dirname "$dst/$f")"; cp "$here/$f" "$dst/$f"
    fi
  done
  if [ -d "$dst" ]; then
    while IFS= read -r g; do
      rel="${g#"$dst"/}"; [ -e "$here/$rel" ] || { if [ "${1:-}" = --check ]; then echo "extra: ${dst#"$here"/../}/$rel"; drift=1; else rm -f "$g"; fi; }
    done < <(find "$dst" -type f)
  fi
done
exit $drift
