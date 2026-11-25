#!/usr/bin/env bash
# Runs ON a cloud box inside a PRIVATE copy of the repo (root = repo copy). Never touches the Mac working tree.
#   bash tools/pca-audit/swift-mutate/linux-prep.sh [sdks/swift-pca]
# 1. Installs a Linux Swift toolchain once to $HOME/swift (SWV, default 6.2, the package needs tools 6.2; an existing install is reused).
# 2. Patches the COPY of sdks/swift-pca so it builds on Linux:
#    - CryptoKit -> swift-crypto (`import Crypto`, Sources AND Tests; the test targets get the Crypto product). AtlasPCAStepUp
#      stays: its only CryptoKit use is Curve25519 (swift-crypto has it), the Keychain store is `#if canImport(Security)` and
#      URLSession comes from FoundationNetworking, so it builds and its tests run on Linux (it is mutated like the verifier).
#    ML-DSA needs no patch: the package vendors it (the CMLDSA C target), so the post-quantum vectors (ML-DSA-65 / -87, their hybrids and the nested
#    hybrid, on every signed surface) run on Linux and `PCASuites.supported` (the runtime capability manifest) lists them there.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; ORIG="$PWD"; SWV="${SWV:-6.2}"; PLAT=ubuntu24.04
# LINUX_PREP_PATCH_ONLY=1: only the source patch below (the mutation shards decide from it whether they need the toolchain at all)
mkdir -p "$HOME/.cache"
if [ "${LINUX_PREP_PATCH_ONLY:-0}" != 1 ]; then
if [ ! -x "$HOME/swift/usr/bin/swift" ]; then
  exec 8>"$HOME/.cache/swift-install.lock"; flock 8
  if [ ! -x "$HOME/swift/usr/bin/swift" ]; then
    T=$(mktemp -d); mkdir -p "$HOME/swift"
    curl -fsSL --retry 5 --retry-all-errors --retry-delay 5 -o "$T/swift.tgz" "https://download.swift.org/swift-$SWV-release/${PLAT//./}/swift-$SWV-RELEASE/swift-$SWV-RELEASE-$PLAT.tar.gz"
    tar -xzf "$T/swift.tgz" -C "$HOME/swift" --strip-components=1 && rm -rf "$T"
  fi
  exec 8>&-
fi
export PATH="$HOME/swift/usr/bin:$PATH"
swift --version
fi

P="${1:-sdks/swift-pca}"; cd "$ORIG/$P"
grep -rl "import CryptoKit" Sources Tests | xargs -r sed -i 's/^import CryptoKit$/import Crypto/'
python3 - <<'PY'
import os
s = open('Package.swift').read()
# the patch is appended to the manifest, so it holds whatever targets the manifest declares: every Swift target (sources and tests) gets
# swift-crypto's Crypto product (the sources import Crypto after the sed above).
# Which directories hold Swift is decided HERE, not when the manifest is evaluated: a consumer's resolver evaluates the manifest of a tagged
# dependency from the repository object store (its file path is /Package.swift), where a directory scan finds nothing, so the Crypto
# product would be left off every target and swift-crypto would resolve as unused, then be missing once the checkout is evaluated.
if 'atlasLinuxPrep' not in s:
    dirs = []
    for top in ('Sources', 'Tests'):
        for name in sorted(os.listdir(top)):
            d = os.path.join(top, name)
            if os.path.isdir(d) and any(f.endswith('.swift') for _, _, fs in os.walk(d) for f in fs):
                dirs.append(d)
    lit = ', '.join('"%s"' % d for d in dirs)
    s += """
// atlasLinuxPrep: Linux copy of the package (CryptoKit -> swift-crypto)
package.dependencies.append(.package(url: "https://github.com/apple/swift-crypto.git", from: "4.0.0"))
let atlasSwiftDirs: Set<String> = [%s]
for t in package.targets where (t.type == .regular || t.type == .executable || t.type == .test) {
    if atlasSwiftDirs.contains(t.path ?? ((t.type == .test ? "Tests/" : "Sources/") + t.name)) {
        t.dependencies.append(.product(name: "Crypto", package: "swift-crypto"))
    }
}
""" % lit
    open('Package.swift', 'w').write(s)
PY
[ "${LINUX_PREP_PATCH_ONLY:-0}" = 1 ] && exit 0
# keep the whole log: the last 15 lines hide a compile error behind the warnings printed after it
swift build --build-tests -c debug > "$HOME/swift-prep-build.log" 2>&1 && rc=0 || rc=$?
tail -15 "$HOME/swift-prep-build.log"
if [ "$rc" -ne 0 ]; then
  echo "::group::compile errors"
  # compiler errors only (the doc comments mentioning "error:" print as warnings); || true: head closing the pipe must not mask the build status
  { grep -E ": error:" -B2 -A8 "$HOME/swift-prep-build.log" | head -400; } || true
  echo "::endgroup::"
  exit "$rc"
fi
# every later step of this job has ML-DSA (the vendored CMLDSA target): a replay that would skip for want of it fails instead (Tests/AtlasPCAVerifyTests/PqRequirement.swift)
[ -z "${GITHUB_ENV:-}" ] || echo "PCA_REQUIRE_PQ=1" >> "$GITHUB_ENV"
