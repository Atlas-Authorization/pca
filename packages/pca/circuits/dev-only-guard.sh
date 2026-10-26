# Sourced by setup.sh, policyvm.setup.sh and policyvm.bls12381.setup.sh. These scripts run a ONE-PERSON trusted setup:
# whoever runs them can forge proofs for the keys they produce. They exist for tests and local fixtures only.
# A key for real use comes from a multi-party ceremony (circuits/ceremony/, docs/pca/validation/ceremony-runbook.md).
if [ "${PCA_DEV_SETUP:-}" != "1" ]; then
  echo "refusing to run: $(basename "$0") makes a single-party, DEV-ONLY trusted setup." >&2
  echo "set PCA_DEV_SETUP=1 to confirm you want throwaway keys; for a real key use circuits/ceremony/." >&2
  exit 2
fi
echo "################################################################" >&2
echo "# DEV-ONLY single-party trusted setup: NOT for production use.  #" >&2
echo "# The operator of this run can forge proofs for these keys.     #" >&2
echo "################################################################" >&2
mkdir -p "$(dirname "${BASH_SOURCE[0]}")/build"
printf '{"ceremony":"single-party","dev_only":true,"script":"%s"}\n' "$(basename "$0")" > "$(dirname "${BASH_SOURCE[0]}")/build/CEREMONY.json"
