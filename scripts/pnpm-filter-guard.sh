#!/usr/bin/env bash
# pnpm-filter-guard.sh: make `pnpm --filter X ...` FAIL when X matches no workspace project.
# pnpm exits 0 with "No projects matched the filters" by default, so a renamed or unlisted package turns a job into a
# silent no-op. Run once per job (after pnpm is set up): it puts a wrapper named `pnpm` first on PATH for later steps.
# The wrapper checks every --filter / -F value with `pnpm --filter X exec` and refuses the call if one matches nothing.
set -euo pipefail
dir="${RUNNER_TEMP:-/tmp}/pnpm-guard"
mkdir -p "$dir/ok"
cat >"$dir/pnpm" <<'WRAP'
#!/usr/bin/env bash
self="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/pnpm"
real=""
while IFS= read -r p; do [ "$p" = "$self" ] || { real="$p"; break; }; done < <(type -ap pnpm)
[ -n "$real" ] || { echo "pnpm-guard: the real pnpm was not found on PATH" >&2; exit 127; }
if [ -z "${PNPM_GUARD_INNER:-}" ]; then
  args=("$@"); filters=(); i=0
  while [ "$i" -lt "${#args[@]}" ]; do
    a="${args[$i]}"
    case "$a" in
      --filter=*) filters+=("${a#--filter=}") ;;
      -F=*)       filters+=("${a#-F=}") ;;
      --filter|-F) i=$((i + 1)); filters+=("${args[$i]:-}") ;;
    esac
    i=$((i + 1))
  done
  for f in "${filters[@]+"${filters[@]}"}"; do
    [ -n "$f" ] || { echo "pnpm-guard: empty --filter value" >&2; exit 1; }
    key="$(printf '%s' "$PWD|$f" | cksum | tr ' ' '_')"
    [ -e "$(dirname "$self")/ok/$key" ] && continue
    # '.' is the workspace root, which pnpm 9's recursive exec leaves out; it matches when the root package exists
    if [ "$f" = "." ]; then
      [ -f package.json ] || { echo "::error::pnpm-guard: the filter '.' matches no project ($PWD has no package.json)" >&2; exit 1; }
      : >"$(dirname "$self")/ok/$key"; continue
    fi
    n="$(PNPM_GUARD_INNER=1 "$real" --filter "$f" exec node -p '"PNPMGUARD:"+process.cwd()' 2>/dev/null | grep -c '^PNPMGUARD:' || true)"
    if [ "${n:-0}" -lt 1 ]; then
      echo "::error::pnpm-guard: the filter '$f' matches no workspace project (the command would silently do nothing)" >&2
      exit 1
    fi
    : >"$(dirname "$self")/ok/$key"
  done
fi
exec "$real" "$@"
WRAP
chmod +x "$dir/pnpm"
if [ -n "${GITHUB_PATH:-}" ]; then echo "$dir" >>"$GITHUB_PATH"; fi
echo "pnpm-guard installed at $dir"
