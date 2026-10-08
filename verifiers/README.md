# Native PCA verifiers

The reference verifier is the TypeScript [`@atlasauth/pca`](../packages/pca) in this repo. Beyond it, PCA
ships **nine** independent, offline PCActn verifiers — one per language — each maintained in its own repo
and each passing the full shared [conformance corpus](../conformance) (including the post-quantum
`ml-dsa-65` and `hybrid-ed25519-ml-dsa-65` vectors).

A verifier runs the stateless eight-check core (`wire`, `version`, `audience`, `validity`, `chain`,
`plan_inclusion`, `leaf_signature`, `counter`), fail-closed, in the normative order. A PCActn that
verifies in one language verifies identically in every other.

| Language | Repo | Install | Notes |
|----------|------|---------|-------|
| Go | [Atlas-Authorization/pca-go](https://github.com/Atlas-Authorization/pca-go) | `go get github.com/Atlas-Authorization/pca-go` | Shares the exported primitives (`canonicalize`, `merkle_root`, `verify_chain`, …). |
| Python | [Atlas-Authorization/pca-python](https://github.com/Atlas-Authorization/pca-python) | `pip install atlas-pca` | Zero-dependency core; optional `cryptography` extra for native Ed25519, pure-Python RFC 8032 fallback. |
| Ruby | [Atlas-Authorization/pca-ruby](https://github.com/Atlas-Authorization/pca-ruby) | `gem install atlas-pca` | Needs OpenSSL 3 for raw Ed25519. |
| Java | [Atlas-Authorization/pca-java](https://github.com/Atlas-Authorization/pca-java) | Maven / Gradle (`net.atlasauth.pca`) | Needs BouncyCastle ≥ 1.80. |
| PHP | [Atlas-Authorization/pca-php](https://github.com/Atlas-Authorization/pca-php) | Composer (`atlas/pca`) | Namespace `Atlas\Pca`. |
| Rust | [Atlas-Authorization/pca-rust](https://github.com/Atlas-Authorization/pca-rust) | `cargo add atlas-pca` | Crate `atlas-pca`. |
| .NET | [Atlas-Authorization/pca-dotnet](https://github.com/Atlas-Authorization/pca-dotnet) | NuGet (`AtlasPca`) | Walk-up conformance loader. |
| Swift | [Atlas-Authorization/pca-swift](https://github.com/Atlas-Authorization/pca-swift) | Swift Package Manager | Also ships a principal-device step-up client. |
| Kotlin | [Atlas-Authorization/pca-kotlin](https://github.com/Atlas-Authorization/pca-kotlin) | Gradle | Needs BouncyCastle ≥ 1.80; also ships a step-up client. |

## Writing your own verifier

The corpus in [`../conformance`](../conformance) is all you need to self-certify a new implementation:

1. Implement canonical JSON and `hash_canonical`; check against `primitives.canonical`.
2. Implement the Merkle tree and `verify_inclusion`; check against `primitives.merkle`.
3. Implement `verify_chain` (hop signatures, parent links, caveat-prefix attenuation).
4. Implement `verify_pcactn_core`: chain root equals grant, plan inclusion from the PCActn's own action
   fields, leaf signature under the leaf holder, counter well-formed.
5. Run every entry in `vectors.json` and compare `allow` and each per-check result.

See [`../docs/guides/verify-in-your-language.md`](../docs/guides/verify-in-your-language.md) for the full
walkthrough.
