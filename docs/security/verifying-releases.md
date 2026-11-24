# Verifying PCA releases

From 0.5.0, every PCA package is built and published by GitHub Actions in its source repository, not from a
developer's machine. Each release leaves records you can check yourself:

| Registry | Packages | Source repository | What you can verify |
|---|---|---|---|
| npm | `@atlasauth/pca*`, `create-pca-app` | [Atlas-Authorization/pca](https://github.com/Atlas-Authorization/pca) | npm registry signature and npm provenance (SLSA v1) |
| PyPI | `atlas-pca`, `atlas-pca-*` | [Atlas-Authorization/pca-python](https://github.com/Atlas-Authorization/pca-python) | PEP 740 attestation from PyPI Trusted Publishing |
| crates.io | `atlas-pca`, `stark-pca`, `pca-folding-ivc` | [Atlas-Authorization/pca-rust](https://github.com/Atlas-Authorization/pca-rust) | the crate's checksum against the attested `.crate` on the GitHub Release |

Every GitHub Release also carries the exact files that were published, a `SHA256SUMS` file, and a GitHub
build-provenance attestation for each file.

Versions before 0.5.0 were published without provenance: the checks below report "not found" for them.

## npm

In a project that depends on PCA packages:

```sh
npm audit signatures
```

npm checks the registry signature of every installed package and the provenance attestation of every package that
has one. A PCA package that fails either check is reported by name. To see the attestation of one version:

```sh
npm view @atlasauth/pca@0.5.0 dist.attestations --json
```

The package page on npmjs.com shows the same provenance: the repository, the workflow file
(`.github/workflows/release.yml`) and the commit it was built from.

## PyPI

Each file on PyPI has an attestation that names the repository and workflow that uploaded it. Check one with the
[`pypi-attestations`](https://pypi.org/project/pypi-attestations/) tool:

```sh
uvx pypi-attestations verify pypi --repository https://github.com/Atlas-Authorization/pca-python \
  pypi:atlas_pca-0.5.0-py3-none-any.whl
```

It prints `OK: <file>` when the attestation is valid and was made by that repository. The raw attestation is served
by PyPI's integrity API:

```sh
curl -s https://pypi.org/integrity/atlas-pca/0.5.0/atlas_pca-0.5.0-py3-none-any.whl/provenance
```

The source distributions are reproducible: two builds of the same tag give byte-identical files, with no
build-machine account names or times in the archive headers.

## crates.io

crates.io does not store provenance. Cargo verifies every crate it downloads against the checksum in the crates.io
index, so a crate is tied to its build when that index checksum is the SHA-256 of the attested `.crate` on the GitHub
Release:

```sh
# the checksum Cargo enforces
curl -s https://index.crates.io/at/la/atlas-pca | jq -r 'select(.vers == "0.5.0") | .cksum'

# the attested file from the GitHub Release
gh release download v0.5.0 --repo Atlas-Authorization/pca-rust --pattern 'atlas-pca-0.5.0.crate'
sha256sum atlas-pca-0.5.0.crate
gh attestation verify atlas-pca-0.5.0.crate --repo Atlas-Authorization/pca-rust
```

The two checksums must be equal. (In the index URL, `at/la` is the first two and the next two letters of the crate
name: `st/ar/stark-pca`, `pc/a-/pca-folding-ivc`.) The release workflow makes the same comparison after publishing and
does not create the GitHub Release if they differ.

## Any release asset

For any file on a GitHub Release of these three repositories, with the [GitHub CLI](https://cli.github.com/) signed
in:

```sh
gh release download v0.5.0 --repo Atlas-Authorization/pca
sha256sum -c SHA256SUMS
gh attestation verify atlasauth-pca-0.5.0.tgz --repo Atlas-Authorization/pca \
  --signer-workflow Atlas-Authorization/pca/.github/workflows/release.yml
```

`gh attestation verify` exits non-zero unless the file has a valid attestation from that repository.
`--signer-workflow` also requires that it came from the release workflow and not from any other workflow in the
repository. Use `Atlas-Authorization/pca-python` or `Atlas-Authorization/pca-rust` in both flags for those
repositories.

An npm tarball you download with `npm pack @atlasauth/pca@0.5.0` is the same file as the one on the GitHub Release,
so you can run `gh attestation verify` on it directly.

## SBOM, dependency audit and the security evidence report

From 0.5.0, each GitHub Release of the three repositories also carries the following files.

- **A CycloneDX SBOM** (`sbom-npm.cdx.json`, `sbom-pypi.cdx.json`, `sbom-crates.cdx.json`). It lists every published
  package of the release and the dependencies it brings in. For npm, this is the release set installed as a user
  installs it, production dependencies only. For PyPI, it is each distribution's dependencies resolved with all extras
  for CPython 3.12 on Linux x86-64. For crates.io, it is each crate's dependency graph from the release lockfile. An SBOM
  attestation binds the SBOM to every package file of the release:

  ```sh
  gh attestation verify atlasauth-pca-0.5.0.tgz --repo Atlas-Authorization/pca \
    --predicate-type https://cyclonedx.org/bom
  ```

- **A dependency audit, run before anything is published.** The audit uses `npm audit` for the npm release set,
  `pip-audit` for each Python distribution and `cargo audit` for the Rust lockfile. A finding rated high or critical
  stops the release. So does a finding that cannot be rated at all, because an unknown is not treated as safe. The
  only exception is a reviewed entry in the repository's allowlist. Each entry names the advisory and the package,
  says why it does not affect the released packages, and expires within 180 days. Findings below the threshold and
  allowlisted findings are listed in the evidence report.
- **The security evidence report** (`security-evidence-<repository>-<version>.md`, and a `.json` with the same
  content). It contains:
  - the exact commit and the package versions;
  - every gate that decided the release, each with its GitHub Actions run id and result: CI, the cross-language
    conformance gate with its per-language results, the mutation-testing merge with its score, and the formal proofs,
    Kani and symbolic-model runs and model-to-code conformance where the repository has them;
  - the SBOM and dependency-audit results;
  - every outstanding exception, for example a gate that passed on a release-candidate commit rather than on the
    release commit, a waived cross-language disagreement, or an allowlisted vulnerability.

  The workflow refuses to publish a release whose required gates have no passing run.

Both files are listed in `SHA256SUMS` and have a build-provenance attestation, so they are verified like any other
asset (see above). Each package's stability is stated by its maturity tier: see [Maturity tiers](../maturity.md).

## Reporting a problem

If any of these checks fails for a PCA release from 0.5.0 on, do not install that version, and open an issue on its
source repository with the package, the version and the command output.
