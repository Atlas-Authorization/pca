# @atlasauth/pca-verified

> Maturity: **production**, pending CI. See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

PCA Verified is the conformance programme for Proof-Carrying Authority. If you build a PCA verifier or producer in any language, this runner drives it through a documented JSON-lines **driver protocol** over a versioned, hash-pinned **corpus**, scores it per layer and per **profile**, and, when a profile passes in full, produces a **signed conformance statement** that anyone can verify, turn into a **badge**, and list in a transparency-logged **registry**.

It has no dependency on a PCA checkout: the corpus ships inside the package and is checked against its pinned SHA-256 before every run.

## Quickstart

```sh
npx @atlasauth/pca-verified run --driver "python3 driver.py" --profile core-verifier
```

`driver.py` is any program that reads `<in.jsonl>` and writes `<out.jsonl>` (see the [protocol](https://github.com/Atlas-Authorization/pca/blob/main/docs/reference/pca-verified-protocol.md)). Working templates in two languages are in the package:

```sh
cp node_modules/@atlasauth/pca-verified/templates/python/driver.py .    # needs: pip install atlas-pca
cp -r node_modules/@atlasauth/pca-verified/templates/go ./driver-go     # then: go mod init pcadriver && go get github.com/Atlas-Authorization/pca-go@latest
```

Replace the SDK calls with calls into your implementation. A kind you do not implement is answered `{"id": ..., "error": "unsupported"}`; that layer is reported as unsupported, never as passed.

## Profiles

| Profile | What passing it says |
|---|---|
| `core-verifier` | Verifies PCActns: strict wire format, signatures and bindings, delegation chains, policy caveats, and an honest suite manifest |
| `producer` | Signs and builds PCA artifacts byte for byte as the reference does |
| `pq` | Declares `ml-dsa-65` and the Ed25519 + ML-DSA-65 hybrid and verifies every vector that uses only declared suites (others must be refused) |
| `stateful` | Replay, counter ordering, revocation mid-sequence and trust-budget depletion behave as the reference does |

`--profile all` runs all four. Exit code 0 means every requested profile passed in full; 1 that one did not; 2 a usage error.

## Attest, verify, badge

```sh
# sign a statement for every profile that passed (the key stays with you; the run prints the public key to publish)
pca-verified run --driver "python3 driver.py" --profile core-verifier \
  --name my-verifier --impl-version 1.4.0 --vendor "My Company" --generate-key --out out/

# a third party checks it: signature, corpus hash, whole-profile coverage, and (with --report) the results digest
pca-verified verify out/core-verifier.statement.json --report out/report.json --trust-key <public key>

# a badge (SVG + shields.io endpoint JSON), only from a statement that verifies
pca-verified badge out/core-verifier.statement.json --out out/ --trust-key <public key>
```

Two trust tiers: **self-attested** (signed by a key) and **CI-attested** (a GitHub Actions workflow of a named repository also attested the exact statement bytes with a Sigstore build-provenance bundle, verified offline against the pinned Sigstore root):

```sh
pca-verified verify out/core-verifier.statement.json --attestation bundle.json --ci-repo my-org/my-verifier --require-tier ci-attested
```

`verify` prints the tier; the registry listing shows it for every entry. A bundle that does not verify fails the statement; it never downgrades silently.

A statement binds the implementation name and version, the corpus version and hash, the profile, a digest of every per-item result, the runner version and the signer's key. A self-attested statement does not say who the signer is: pin the key you trust with `--trust-key`.

## Registry

```sh
pca-verified registry init registry/
pca-verified registry add registry/ out/core-verifier.statement.json
pca-verified registry export registry/ --out registry.json
pca-verified registry verify registry.json --key <registry key> [--previous older.json]
pca-verified registry page registry.json --key <registry key> --out site/    # static listing + badges
```

The registry is an append-only RFC 9162 Merkle log (`@atlasauth/pca-scitt`) of statements. `verify` checks every receipt against the pinned registry key, re-verifies every statement, and with `--previous` that history was not rewritten.

## API

`runConformance`, `verifyReport`, `createStatements`, `verifyStatementEnvelope`, `makeBadge`, `registryInit`, `registryAdd`, `registryExport`, `verifyRegistryExport`, `renderRegistryPage`, `loadBundledCorpus`, `loadCorpusFiles`, `judge`, `runDriver`, `cli`.

## Fail-closed behaviour

| Situation | Result |
|---|---|
| Driver hangs, crashes or skips an item | that item is a `fault`; the rest still run; the profile fails |
| Driver writes a line that is not JSON, an unknown id or a repeated id | protocol violation; no profile passes, no statement is issued |
| Driver does not implement a kind | `unsupported`; the profile is not claimed |
| Partial run (`--limit`) | `incomplete`; nothing can be attested |
| Report edited after the run | `verify --report` and `verifyReport` refuse it |
| Attestation that does not verify, or `--require-tier ci-attested` with none | `verify` refuses it |
| Statement for a corpus the verifier does not know, a partial profile, a swapped key or a changed payload | `verify` refuses it |
| Badge or registry entry requested for a statement that does not verify | refused; nothing is written |

## Limits

Passing shows agreement with the reference on this corpus: it is not an audit and says nothing about timing or resource limits. The corpus covers the wire format, PCActn verification, chains, caveat evaluation, producers and stateful sequences; it does not cover framework adapters. The registry's transparency log makes entries public and tamper-evident; it does not vouch for the signer. The CI tier ties a statement to a repository and workflow run, not to the repository you expected: state it with `--ci-repo`.

## License

MIT - see LICENSE
