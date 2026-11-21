# @atlasauth/pca-doctor

> Maturity: **production** (supported for production use). See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

Checks the assumptions a Proof-Carrying Authority deployment depends on, against the live deployment, and prints pass /
warn / fail with a remediation for each check. The protocol can be correct while the deployment around it is not: a
skewed clock, a replay store that is not atomic or not durable, a proxy configuration that trusts forged forwarding
headers, or a suite / post-quantum pin policy that accepts more than intended.

> Status: **0.5.0.** The doctor checks a deployment's wiring; it does not replace the verifier's own checks.

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

## Fail-closed behaviour

| Missing or invalid | Result |
|---|---|
| No check ran, or every check was skipped | Overall verdict **fail** (text, `--json` and exit code 1) |
| An unknown check group, or none given | Usage error, exit code 2 |
| A non-numeric or negative number, a bad `warnFraction`, a malformed or non-http(s) URL, an unknown proxy header | One `config` failure; no check runs |
| A check throws (including a throwing dependency) | That check is a failed result naming its group; the other groups still run |
| `--strict` and any warning | Overall verdict fail |
| Deployment URL missing | `clock` and `proxy.probe` are skipped (a run with only skips fails) |
| Deployment has no `Date` header | `clock` warns and falls back to the local clock |
| Store adapter missing | Store checks are skipped; an adapter that cannot be loaded, or fails, is a **fail** |
| Store declares itself non-durable | `store.durability` warns |
| Trusted-proxy count missing | `proxy.config` is skipped; a count smaller than the real hop count warns |
| A forged forwarding header is believed by the deployment | `proxy.probe` fails; if the probe cannot conclude it warns or skips |
| Allowed signature suites unset | Warn; an empty list or an unknown suite fails |
| Post-quantum pins malformed or disabled binding | Fail; post-quantum suites without pins warn |
| `@atlasauth/pca` not found beside the application, older than 0.4.1, or ignoring root caveats | Fail |
| Root-caveat enforcement switched off, or a custom required list that drops the defaults | Fail, respectively warn |

## Limits

- It checks a deployment from the outside and through configuration you give it. It cannot see settings you do not pass, and a skipped check is not a pass.
- The clock check measures skew to about the round-trip time of one request against one reference; it does not prove the clock stays correct.
- The store check proves behaviour only for the adapter you point it at, over the rounds it runs; it does not prove the production store.
- The proxy probe needs a rate-limited public path that reports its remaining quota; without one it cannot conclude.
- It reads and reports. It never changes a deployment, and it is not a substitute for an independent audit.
