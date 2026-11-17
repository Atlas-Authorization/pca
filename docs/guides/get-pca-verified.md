# Get your implementation PCA Verified

You wrote a PCA verifier or producer in some language and want to show it conforms. Four steps, no account, no permission.

## 1. Write a driver

A driver reads JSON lines and writes JSON lines; the [protocol](../reference/pca-verified-protocol.md) is short. Start from a
working one: the package ships a Python driver (over the Atlas Python verifier) and a Go driver (over the Atlas Go verifier).

```sh
npx @atlasauth/pca-verified corpus | head       # the corpus you will be judged on
# templates/python/driver.py and templates/go/main.go are in the package: copy one and replace the SDK calls with yours
```

A kind your driver does not implement is answered `{"id": ..., "error": "unsupported"}`; that layer is then reported as
unsupported and the profile that needs it is not claimed.

## 2. Run it

```sh
npx @atlasauth/pca-verified run --driver "python3 driver.py" --profile core-verifier
```

You get a per-layer summary, a deterministic `report.json`, and a non-zero exit code if the profile does not pass in full.
`--profile all` tries every profile (`core-verifier`, `producer`, `pq`, `stateful`).

## 3. Attest it

```sh
npx @atlasauth/pca-verified run --driver "python3 driver.py" --profile core-verifier \
  --name my-verifier --impl-version 1.4.0 --vendor "My Company" --generate-key --out out/
```

This writes `out/core-verifier.statement.json` (and your signing key in `out/signing-key.pem`: keep it, and publish the matching
public key with your release so people can pin it; the run prints it, and `pca-verified pubkey out/signing-key.pem` prints it again). Anyone can check it:

```sh
npx @atlasauth/pca-verified verify out/core-verifier.statement.json --report out/report.json --trust-key <your public key>
npx @atlasauth/pca-verified badge  out/core-verifier.statement.json --out out/ --trust-key <your public key>
```

The badge (`badge.svg`, plus `badge.json` in the shields.io endpoint format) is only made from a statement that verifies.

## Stronger: CI-attested

A statement signed with your own key is self-attested. To tie it to a build, run the same command in a GitHub Actions workflow of
your repository and attest the statement bytes:

```yaml
permissions: { contents: read, id-token: write, attestations: write }
steps:
  - run: npx @atlasauth/pca-verified run --driver "python3 driver.py" --profile core-verifier --name my-verifier --impl-version "$GITHUB_REF_NAME" --key key.pem --out out/
  - id: attest
    uses: actions/attest-build-provenance@v2
    with: { subject-path: out/*.cose }
```

Anyone can then check `npx @atlasauth/pca-verified verify out/core-verifier.statement.json --attestation <bundle> --ci-repo you/your-repo --require-tier ci-attested`.
See [trust tiers](../reference/pca-verified-protocol.md#trust-tiers).

## 4. List it

Send the statement to a registry operator, or run your own:

```sh
npx @atlasauth/pca-verified registry init registry/
npx @atlasauth/pca-verified registry add registry/ out/core-verifier.statement.json
npx @atlasauth/pca-verified registry export registry/ --out registry.json
npx @atlasauth/pca-verified registry page registry.json --key <registry key> --out site/
```

`site/index.html` lists verified implementations by profile and version, and `registry.json` lets anyone re-check every entry
and that nothing was removed or rewritten (`registry verify ... --previous`).

## Reading a failure

The summary lists the first items that did not pass, with the reason (`allow: expected false, got true`, `first failed check:
expected audience, got validity`, `hang`, ...). Item ids are stable within a corpus version. A `fault` means your driver hung,
crashed or did not answer that line; a `protocol violation` means it wrote something that is not one JSON object per answered
line. Fix the driver first: no profile passes a run with a violation.
