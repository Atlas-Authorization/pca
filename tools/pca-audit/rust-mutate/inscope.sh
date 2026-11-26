#!/usr/bin/env bash
# Runs "$@" for the pca-rust mutation workflow: inside the memory scope its setup step found (SCOPE_PROPS: the systemd-run
# properties; empty = no scope, the per-process cap alone), then writes the scope's own memory.events (its oom_kill count) to
# $MEMEV for the OOM attribution check. sudo resets the environment (sudo-rs ignores -E), so the scope gets all of it as arguments.
inner() {
  "$@"; rc=$?
  if [ -n "${MEMEV:-}" ]; then
    cg="/sys/fs/cgroup$(cut -d: -f3- /proc/self/cgroup | head -1)"
    cat "$cg/memory.events" > "$MEMEV"; echo "memory.peak $(cat "$cg/memory.peak" 2>/dev/null || echo n/a)"
  fi
  return $rc
}
if [ -n "${SCOPE_PROPS:-}" ]; then
  read -r -a props <<< "$SCOPE_PROPS"
  mapfile -d '' -t envs < <(env -0)
  exec sudo -n env "${envs[@]}" systemd-run --scope -q "${props[@]}" --uid="$(id -u)" --gid="$(id -g)" -- bash -c "$(declare -f inner); inner \"\$@\"" bash "$@"
fi
inner "$@"
