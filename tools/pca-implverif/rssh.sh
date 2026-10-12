#!/usr/bin/env bash
# rssh.sh <ip> <cmd>  -- ssh with retries (shared boxes are often saturated: banner-exchange timeouts)
IP="$1"; shift
for i in $(seq 1 12); do
  out=$(ssh -i ~/.ssh/pca_tee_vm -o ConnectTimeout=45 -o ServerAliveInterval=15 -o LogLevel=ERROR -o StrictHostKeyChecking=no -o UserKnownHostsFile=$HOME/.pca-vm-state/known_hosts pca@$IP "$@" 2>&1); rc=$?
  case "$out" in *"banner exchange"*|*"Connection reset"*|*"Connection timed out"*) sleep 15; continue;; esac
  printf '%s\n' "$out"; exit $rc
done
echo "rssh: gave up"; exit 255
