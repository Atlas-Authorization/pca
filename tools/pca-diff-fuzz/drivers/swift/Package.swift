// swift-tools-version:5.9
import PackageDescription

// Swift differential driver for the PCA cross-language gate (scripts/pca-conformance-all.mjs). It links the native
// verifier `AtlasPCAVerify` from sdks/swift-pca (on Linux: the patched copy that tools/pca-audit/swift-mutate/linux-prep.sh
// lays out at the same relative path) and reaches its internal strict parser / canonicalizer / chain verifier through
// `@testable import`, so it is built with testability on:
//   swift build -c release -Xswiftc -enable-testing
let package = Package(
    name: "PCADriver",
    platforms: [.macOS(.v12)],
    dependencies: [.package(path: "../../../../sdks/swift-pca")],
    targets: [
        .executableTarget(name: "pcadriver", dependencies: [.product(name: "AtlasPCAVerify", package: "swift-pca")], path: "Sources/pcadriver"),
    ]
)
