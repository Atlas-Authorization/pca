# PCA SDK and developer map

Status: **Preview**. Docs: <https://atlasauth.net/pca>.

## JavaScript / TypeScript packages

| Package | Role | Key entry points |
|---|---|---|
| `@atlasauth/pca` | Core primitives: grants, capabilities, plan commitment, PCActn build/verify, Policy VM, risk and trust budget, threshold, ledger, revocation | `mintGrant`, `delegate`, `attenuate`, `commitPlan`, `buildPCActn`, `verifyPCActnCore`, `decide` |
| `@atlasauth/pca-agent` | Agent client for the hosted flow | `createAgent`, `agent.act()` |
| `@atlasauth/backend` | Resource-server verifier and guard | `verifyPCActn`, `requirePCA` |

```
npm install @atlasauth/pca @atlasauth/pca-agent @atlasauth/backend
```

Guides: [agent quickstart](docs/guides/agent-quickstart.md), [resource-server quickstart](docs/guides/resource-server-quickstart.md), [API reference](docs/reference/api.md), [wire formats](docs/reference/wire-formats.md).

## Reference verifiers

Each verifier checks a PCActn's core clauses (capability chain, plan inclusion, Ed25519 leaf signature, counter), reads `../../conformance/vectors.json`, and passes every vector. Run from the repo root.

| Language | Directory | Run |
|---|---|---|
| Go | [`verifiers/go-pca`](verifiers/go-pca) | `cd verifiers/go-pca && go test ./...` |
| Python | [`verifiers/python-pca`](verifiers/python-pca) | `cd verifiers/python-pca && python3 -m unittest test_conformance` |
| Rust | [`verifiers/rust-pca`](verifiers/rust-pca) | `cd verifiers/rust-pca && cargo test` |
| Java | [`verifiers/java-pca`](verifiers/java-pca) | from `verifiers/java-pca`, compile `src` and `ConformanceTest.java` (JDK only) and run `ConformanceTest` |
| PHP | [`verifiers/php-pca`](verifiers/php-pca) | `php verifiers/php-pca/conformance.php` |
| Ruby | [`verifiers/ruby-pca`](verifiers/ruby-pca) | `ruby verifiers/ruby-pca/conformance.rb` |
| .NET | [`verifiers/dotnet-pca`](verifiers/dotnet-pca) | `dotnet run --project verifiers/dotnet-pca/Conformance` |

Writing your own: [Verify in your language](docs/guides/verify-in-your-language.md).

## Conformance suite

[`conformance/`](conformance/README.md) holds `vectors.json` (21 vectors plus canonical-JSON and Merkle primitives) and `keys.json` (fixed test keys). Every implementation must produce the same `allow` and the same per-check pass/fail results.

## Playground

[`playground/`](playground) is a client-side demo that runs the real `@atlasauth/pca` library in the browser. Serve it with `cd playground && python3 -m http.server 8080` (ES modules need `http://`). See [Playground](docs/guides/playground.md).

## Claude plugin

[Atlas-Authorization/atlas-claude-skills](https://github.com/Atlas-Authorization/atlas-claude-skills) teaches Claude Code the Atlas platform.
