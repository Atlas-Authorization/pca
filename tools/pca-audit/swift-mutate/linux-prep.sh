#!/usr/bin/env bash
# Runs ON a cloud box inside a PRIVATE copy of the repo (root = repo copy). Never touches the Mac working tree.
#   bash tools/pca-audit/swift-mutate/linux-prep.sh [sdks/swift-pca]
# 1. Installs a Linux Swift toolchain once to $HOME/swift (SWV, default 6.0.3; an existing install is reused).
# 2. Builds liboqs (pinned tag OQS_TAG, ML-DSA-65 only, static, no OpenSSL) once per box into $HOME/.cache/liboqs-$OQS_TAG
#    (flock-guarded: concurrent jobs on one box wait for the first build).
# 3. Patches the COPY of sdks/swift-pca so it builds on Linux:
#    - CryptoKit -> swift-crypto (`import Crypto`), the iOS-only AtlasPCAStepUp target removed;
#    - a C target COQS (shim over liboqs' OQS_SIG_ml_dsa_65_verify) and MLDSA.swift's Linux branch calls it. liboqs >= 0.12
#      implements FIPS 204 final; its plain verify is pure ML-DSA with the EMPTY context string, the same semantics as the
#      macOS CryptoKit path (MLDSA65.PublicKey.isValidSignature(_:for:)) and the TS reference (@noble/post-quantum ml_dsa65
#      verify without ctx). pk 1952 bytes, sig 3309 bytes, raw FIPS 204 encodings (no ASN.1), as on macOS.
#    So the post-quantum vectors (pq_artifact, ml-dsa-65 / hybrid threshold shares and capability hops) are really RUN on Linux.
set -euo pipefail
ORIG="$PWD"; SWV="${SWV:-6.0.3}"; PLAT=ubuntu24.04; OQS_TAG="${OQS_TAG:-0.14.0}"
mkdir -p "$HOME/.cache"
if [ ! -x "$HOME/swift/usr/bin/swift" ]; then
  exec 8>"$HOME/.cache/swift-install.lock"; flock 8
  if [ ! -x "$HOME/swift/usr/bin/swift" ]; then
    T=$(mktemp -d); mkdir -p "$HOME/swift"
    curl -fsSL -o "$T/swift.tgz" "https://download.swift.org/swift-$SWV-release/${PLAT//./}/swift-$SWV-RELEASE/swift-$SWV-RELEASE-$PLAT.tar.gz"
    tar -xzf "$T/swift.tgz" -C "$HOME/swift" --strip-components=1 && rm -rf "$T"
  fi
  exec 8>&-
fi
export PATH="$HOME/swift/usr/bin:$PATH"
swift --version

OQS="$HOME/.cache/liboqs-$OQS_TAG"
if [ ! -f "$OQS/lib/liboqs.a" ]; then
  exec 9>"$HOME/.cache/liboqs.lock"; flock 9
  if [ ! -f "$OQS/lib/liboqs.a" ]; then
    command -v cmake >/dev/null || sudo -n apt-get install -y -qq cmake >/dev/null
    T=$(mktemp -d)
    git clone -q --depth 1 --branch "$OQS_TAG" https://github.com/open-quantum-safe/liboqs.git "$T/src"
    cmake -S "$T/src" -B "$T/b" -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$OQS" -DBUILD_SHARED_LIBS=OFF \
      -DOQS_MINIMAL_BUILD="SIG_ml_dsa_65" -DOQS_USE_OPENSSL=OFF -DOQS_BUILD_ONLY_LIB=ON -DOQS_DIST_BUILD=ON \
      -DCMAKE_POSITION_INDEPENDENT_CODE=ON >/dev/null
    cmake --build "$T/b" -j"$(nproc)" >/dev/null && cmake --install "$T/b" >/dev/null
    rm -rf "$T"
  fi
  exec 9>&-
fi
test -f "$OQS/lib/liboqs.a" && test -f "$OQS/include/oqs/oqs.h"

P="${1:-sdks/swift-pca}"; cd "$ORIG/$P"
rm -rf Sources/AtlasPCAStepUp Tests/AtlasPCAStepUpTests
grep -rl "import CryptoKit" Sources | xargs -r sed -i 's/import CryptoKit/import Crypto/'
mkdir -p Sources/COQS/include
cat > Sources/COQS/include/coqs_shim.h <<'H'
#include <stddef.h>
#include <stdint.h>
/* 1 iff sig is a valid ML-DSA-65 (FIPS 204, empty context) signature on msg under pk; pk 1952 B, sig 3309 B. */
int atlas_mldsa65_verify(const uint8_t *msg, size_t msg_len, const uint8_t *sig, size_t sig_len, const uint8_t *pk);
H
cat > Sources/COQS/coqs_shim.c <<'C'
#include "coqs_shim.h"
#include <oqs/oqs.h>
int atlas_mldsa65_verify(const uint8_t *msg, size_t msg_len, const uint8_t *sig, size_t sig_len, const uint8_t *pk) {
  if (sig_len != OQS_SIG_ml_dsa_65_length_signature) return 0;
  static const uint8_t empty = 0;
  return OQS_SIG_ml_dsa_65_verify(msg_len ? msg : &empty, msg_len, sig, sig_len, pk) == OQS_SUCCESS;
}
C
OQS="$OQS" python3 - <<'PY'
import os
oqs = os.environ['OQS']
s = open('Package.swift').read()
if 'swift-crypto' not in s:
    s = ''.join(l for l in s.splitlines(True) if 'AtlasPCAStepUp' not in l)
    s = s.replace('    targets: [', '    dependencies: [.package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0")],\n    targets: [', 1)
    s = s.replace('.target(name: "AtlasPCAVerify", path: "Sources/AtlasPCAVerify")',
                  '.target(name: "COQS", path: "Sources/COQS", cSettings: [.unsafeFlags(["-I%s/include"])], linkerSettings: [.unsafeFlags(["-L%s/lib", "-loqs"])]),\n'
                  '        .target(name: "AtlasPCAVerify", dependencies: [.product(name: "Crypto", package: "swift-crypto"), "COQS"], path: "Sources/AtlasPCAVerify")' % (oqs, oqs))
    assert '"COQS"' in s, 'Package.swift: AtlasPCAVerify target not found'
    open('Package.swift', 'w').write(s)
p = 'Sources/AtlasPCAVerify/MLDSA.swift'
m = open(p).read()
if 'COQS' not in m:
    m = m.replace('import Foundation\n', 'import Foundation\nimport COQS\n', 1)
    old = '        if #available(macOS 26.0, iOS 26.0, *) {'
    assert old in m, 'MLDSA.swift: availability branch not found'
    m = m.replace(old,
        '        #if os(Linux)\n'
        '        return msg.withUnsafeBufferPointer { mb in sig.withUnsafeBufferPointer { sb in pk.withUnsafeBufferPointer { pb in\n'
        '            atlas_mldsa65_verify(mb.baseAddress, mb.count, sb.baseAddress, sb.count, pb.baseAddress) == 1 } } }\n'
        '        #else\n' + old, 1)
    old2 = '        return false\n    }\n\n    static func verifyB64u'
    assert old2 in m, 'MLDSA.swift: tail not found'
    m = m.replace(old2, '        return false\n        #endif\n    }\n\n    static func verifyB64u', 1)
    open(p, 'w').write(m)
PY
swift build --build-tests -c debug 2>&1 | tail -15
