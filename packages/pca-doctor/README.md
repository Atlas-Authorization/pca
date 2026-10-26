# @atlasauth/pca-doctor

> Maturity: **experimental**. Its API may change or be removed in any release, and it is outside the stable and production tiers. See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

Checks the assumptions a Proof-Carrying Authority deployment depends on, against the live deployment, and prints pass /
warn / fail with a remediation for each check. The protocol can be correct while the deployment around it is not: a
skewed clock, a replay store that is not atomic or not durable, a proxy configuration that trusts forged forwarding
headers, or a suite / post-quantum pin policy that accepts more than intended.

> Status: **0.4.2, unaudited.**

## Install

```sh
npm i -D @atlasauth/pca-doctor
```

## Run it

```sh
npx pca-doctor --url https://api.example.com
```

Check groups: `clock`, `store`, `proxy`, `suites`, `caveats` (select with `--only a,b` or `--skip a,b`).

- **clock**: skew against a reference clock (`--reference`, default an HTTPS endpoint; `--max-skew-ms`, default 60000).
- **store**: atomicity and durability of your replay store, using an adapter module in the
  [`@atlasauth/pca-store-conformance`](https://www.npmjs.com/package/@atlasauth/pca-store-conformance) interface
  (`--store ./my-adapter.js`, `--store-option k=v`).
- **proxy**: the trusted-proxy settings against the real number of hops; it sends forged forwarding headers to see whether
  the deployment believes them (`--no-probe` to skip sending them).
- **suites**: the allowed signature suites and post-quantum key pins.
- **caveats**: that the installed `@atlasauth/pca` enforces root caveats (`--pca-dir` points at the deployed application).

Configuration can also come from a JSON or JS file (`--config`) or the environment (`PCA_DOCTOR_URL`,
`TRUSTED_PROXY_COUNT`, `PCA_ALLOWED_SUITES`, `PCA_PQ_PINS`, ...); flags override both. `--strict` makes warnings fail,
`--json` prints machine-readable output. Run `npx pca-doctor --help` for every option.

## When the doctor itself cannot tell

- A run in which nothing was checked (no groups, or every check skipped) is a **fail**, in the text summary, in `--json` and in the exit code: a doctor that looked at nothing must not report a healthy deployment.
- A check that throws is reported as a failed check with its group in the id; the other groups still run.
- Configuration is validated first. A non-numeric or negative number, a `warnFraction` outside (0, 1], a malformed URL or an unknown proxy header gives one `config` failure and runs nothing. Environment values are parsed strictly (`TRUSTED_PROXY_COUNT=many` is an error, not NaN) and error messages never echo the value of `PCA_PQ_PINS`.
- Nothing printed carries a credential: URL userinfo, `token=` / `password=` pairs, bearer credentials and long token runs in details, remediations, `--json` observations and error messages are replaced with `[redacted]`. That includes adapter options such as a database URL.

## In CI

Run it against a staging deployment after each deploy, with `--strict --json`, and fail the pipeline on a non-zero exit.

## Programmatic use

```ts
import { runDoctor } from '@atlasauth/pca-doctor';

const results = await runDoctor({ url: 'https://api.example.com' });
```
