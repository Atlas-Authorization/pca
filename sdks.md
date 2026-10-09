# PCA verifier / SDK matrix

Every PCA verifier is an **offline** PCActn verifier: it runs the stateless eight-check core (`wire`,
`version`, `audience`, `validity`, `chain`, `plan_inclusion`, `leaf_signature`, `counter`), fail-closed,
in the normative order, and passes the **same shared conformance corpus**. A PCActn that verifies in one
language verifies identically in every other.

| Language | Package / repo | Install | Post-quantum | Status |
|----------|----------------|---------|--------------|--------|
| TypeScript (reference) | `@atlasauth/pca` | npm (planned); reference implementation in this repo | Yes (`ml-dsa-65`, `hybrid-ed25519-ml-dsa-65`) | Reference |
| Go | [`pca-go`](https://github.com/Atlas-Authorization/pca-go) | `go get github.com/Atlas-Authorization/pca-go` | Yes | Stable core |
| Python | [`pca-python`](https://github.com/Atlas-Authorization/pca-python) | `pip install "git+https://github.com/Atlas-Authorization/pca-python"` (PyPI planned) | Yes (via `[pq]` extra) | Stable core |
| Ruby | [`pca-ruby`](https://github.com/Atlas-Authorization/pca-ruby) | vendor `lib/atlas_pca.rb`, or `gem … git:` (RubyGems planned) | Yes | Stable core |
| PHP | [`pca-php`](https://github.com/Atlas-Authorization/pca-php) | vendor `src/` (namespace `Atlas\Pca`; Packagist planned) | Yes | Stable core |
| .NET | [`pca-dotnet`](https://github.com/Atlas-Authorization/pca-dotnet) | project reference to `AtlasPca/` (NuGet planned) | Yes | Stable core |
| Swift | [`pca-swift`](https://github.com/Atlas-Authorization/pca-swift) | Swift Package Manager | Yes | Stable core (+ step-up client) |
| Java | [`pca-java`](https://github.com/Atlas-Authorization/pca-java) | add sources `net.atlasauth.pca` (needs BouncyCastle >= 1.80) | Yes | Stable core |
| Rust | [`pca-rust`](https://github.com/Atlas-Authorization/pca-rust) | `atlas-pca = { git = "…/pca-rust" }` (crates.io planned) | Yes | Stable core |
| Kotlin | [`pca-kotlin`](https://github.com/Atlas-Authorization/pca-kotlin) | Gradle (needs BouncyCastle >= 1.80) | Yes | Stable core (+ step-up client) |

Notes:

- **Post-quantum** columns refer to the `ml-dsa-65` (FIPS-204) and `hybrid-ed25519-ml-dsa-65` signature
  suites. Every verifier supports all three — `ed25519`, `ml-dsa-65`, and `hybrid-ed25519-ml-dsa-65` —
  and passes the full conformance corpus including the post-quantum vectors.
- **Install** reflects today's availability. Public package-registry releases are planned; until then,
  add each verifier from its repo as shown.
- **Swift** and **Kotlin** verifiers also ship a principal-device **step-up** client for the threshold
  co-sign flow.

The higher framework rungs (threshold/step-up, attestation, revocation, zero-knowledge, bonds, payments)
are implemented and tested, and described in the [README](./README.md), where any remaining production
requirement for a given rung (real TEE hardware, distributed/HSM custody, a no-dealer MPC offline phase,
a fuller policy circuit) is stated inline; the eight-check PCActn core above is the stable,
conformance-covered interoperability contract.
