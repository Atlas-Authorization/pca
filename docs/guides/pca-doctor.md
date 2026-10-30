# pca-doctor: check a live deployment's assumptions

PCA's guarantees rest on a few things the library cannot check by itself: clocks agree, the replay store is atomic and
durable, the API derives client addresses only from the proxies it really sits behind, and the verifier's suite policy
and caveat enforcement are what you think they are. `pca-doctor` checks each of them against a live deployment and
prints `PASS`, `WARN`, `FAIL` or `SKIP` per check, with a `fix:` line for everything that is not a pass.

```sh
npx @atlasauth/pca-doctor --url https://api.example.com \
  --store ./my-store-adapter.mjs \
  --trusted-proxy-count 1 --proxy-hops 1 \
  --config ./pca-doctor.json
```

```
pca-doctor: https://api.example.com
  PASS  clock                deployment clock +0.4 s relative to https://www.google.com/generate_204 (+-1.1 s ...)
  PASS  store.atomicity      my postgres store: consumeOnce: 10 rounds of 32 concurrent conflicting calls linearizable ...
  WARN  suites.allowed       allowedSuites is unset: every registered suite is accepted (14: ...)
                             fix: Set the verifier's allowedSuites to exactly the suites your issuers sign with ...
Summary: 7 pass, 1 warn, 0 fail, 1 skip -> WARN
```

Exit code: `1` if any check fails (with `--strict`, a warning too), `0` otherwise, `2` for usage errors. `--json`
prints `{ target, verdict, results: [{ id, status, detail, remediation, observed }] }`.

## Configuration

Settings come from a config file (`--config`, JSON or a JS module with a default export), then the environment, then
flags; later sources win.

```json
{
  "url": "https://api.example.com",
  "clock": { "referenceUrl": "https://www.google.com/generate_204", "maxSkewMs": 60000, "warnFraction": 0.25 },
  "store": { "adapter": "./my-store-adapter.mjs", "options": { "url": "postgres://..." }, "concurrency": 32, "rounds": 10 },
  "proxy": { "trustedProxyCount": 1, "header": "x-forwarded-for", "hops": 1, "probePath": "/v1/pca/suites" },
  "verifier": {
    "allowedSuites": ["ed25519", "hybrid-ed25519-ml-dsa-65"],
    "pqPins": { "<issuer ed25519 identity>": "<pq public key>" },
    "trustedRoot": true,
    "allowUnboundPq": false,
    "insecureAllowUnenforced": false,
    "pcaDir": "/srv/my-api"
  }
}
```

| Environment variable | Config field |
|---|---|
| `PCA_DOCTOR_URL` | `url` |
| `PCA_DOCTOR_REFERENCE_URL` | `clock.referenceUrl` |
| `PCA_DOCTOR_STORE` | `store.adapter` |
| `TRUSTED_PROXY_COUNT`, `TRUSTED_PROXY_HEADER` | `proxy.trustedProxyCount`, `proxy.header` (the API's own variable names) |
| `PCA_TRUSTED_PROXY_HOPS` | `proxy.hops` |
| `PCA_ALLOWED_SUITES` (comma list), `PCA_PQ_PINS` (JSON), `PCA_ALLOW_UNBOUND_PQ` | `verifier.*` |

The `verifier` section describes options you pass in code (`requirePCA`, `verifyPCActn`), so it is your statement of
that configuration; `pca-doctor` cannot read it from a running process. Run the doctor from your deployment pipeline with
the same values your code uses.

`--only` / `--skip` select check groups: `clock`, `store`, `proxy`, `suites`, `caveats`.

## The checks

### `clock`: clock skew

Reads the deployment's HTTP `Date` header and a reference's (default `https://www.google.com/generate_204`, or
`--reference local` for the machine running the doctor), and compares them.

- `Date` has one-second resolution, so each reading carries +-0.5 s plus half its round trip. The verdict uses that
  uncertainty.
- **FAIL** when the skew exceeds `maxSkewMs` (default 60 s, `PCACTN_MAX_SKEW_MS`) even at the favourable end of the
  uncertainty. **WARN** when it exceeds `warnFraction` of the limit (default 25%, 15 s) or could exceed the limit.
- Observable remotely: only the clock of whatever writes the `Date` header. A CDN or proxy in front of the API may set
  it; then run the doctor against the origin, or check the hosts directly.
- Fix: NTP (chrony or systemd-timesyncd) on every verifier, issuer and store host, with drift alerts. Retention is `exp +
  skew`, so a clock outside the bound can free a nonce early or reject fresh actions.

### `store.atomicity` and `store.durability`: the replay store

Needs `--store <adapter module>`: the same adapter interface as the
[store conformance kit](store-conformance-kit.md). The doctor talks to your store directly; the store cannot be
exercised through the public API.

- **atomicity**: `rounds` times, `concurrency` clients call `consumeOnce` on one fresh key at the same moment (and race
  `advance` on one stream). The recorded calls are checked for linearizability: two winners for one nonce, or one counter
  value accepted twice, is a **FAIL** with the counterexample. Calls that fail or time out are allowed (the store fails
  closed), but if no call returns a definite answer the result is a **WARN** (inconclusive).
- **durability**: consume a key and advance a counter, close the client, call the adapter's `restart()` if it has one,
  reopen and read back. A consumed key that is consumable again, or a counter that accepts its old value, is a **FAIL**. An
  adapter that declares `capabilities.durable: false` is a **WARN**. Without a `restart()` hook only client reconnection
  is exercised, and the output says so.
- Fix: one atomic statement per operation on a store shared by every verifier instance (`INSERT .. ON CONFLICT ..
  DO UPDATE .. WHERE until < $now RETURNING`, `UPDATE .. WHERE counter < $n RETURNING`, Redis `SET NX PX`, a Lua
  compare-and-set) with synchronous, persistent commits. Then run the full kit, which goes much further (sustained
  contention, retention, multi-process crashes).

Use a dedicated key prefix or database for the probe: it writes fresh keys and deletes nothing.

### `proxy.config` and `proxy.probe`: client addresses behind proxies

The API keys every rate limit, quota and audit address on the client address, derived only from `TRUSTED_PROXY_COUNT`
proxies that append to `TRUSTED_PROXY_HEADER` (default `x-forwarded-for`; `0` means the TCP peer address, and every
forwarding header is ignored).

- **config**: `TRUSTED_PROXY_COUNT` must be an integer from 0 to 16, `x-real-ip` needs a count of at least 1. With
  `hops` (how many proxies really sit in front of the API and append to the header): a count above `hops` is a **FAIL**
  (a client picks its own address, and its own rate-limit bucket, by sending extra entries); below `hops` is a **WARN**
  (every client behind a proxy shares that proxy's bucket). Without `hops`, a non-zero count is a **WARN** because it
  cannot be compared.
- **probe** (when `--url` is given; `--no-probe` disables it): sends plain requests and one request with forged
  `X-Forwarded-For`, `Forwarded` and `X-Real-IP` headers (documentation addresses from RFC 5737) to a public rate-limited
  path (`proxy.probePath`, default `/v1/pca/suites`) and watches `RateLimit-Remaining`. If the forged request lands in a
  fresh bucket while the plain requests keep draining theirs, the deployment trusts client-written entries: **FAIL**. If
  the plain requests' bucket does not drain steadily (a window boundary, shared traffic), the result is a **WARN**
  (inconclusive; run it again).
- Not observable remotely: a count that is too **low** (from one client it looks the same as a correct setting), the
  socket-address fallback for short chains, and deployments that do not return `RateLimit-Remaining` (then **SKIP**).
- The probe costs four requests from your own rate-limit allowance.

### `suites.allowed` and `suites.pq-binding`: signature suite policy

- `allowedSuites` unset: **WARN** (every registered suite is accepted). Empty list: **FAIL** (nothing can verify). A
  name outside the registry (`SIG_SUITES`): **FAIL**.
- `allowUnboundPq: true`: **FAIL**. It accepts PQ keys read from the artifact, which removes the hybrid's protection
  against an Ed25519 forger.
- Malformed `pqPins` (keys must be 43-character base64url Ed25519 identities, values base64url PQ public keys): **FAIL**.
- A post-quantum or hybrid suite accepted with neither `pqPins` nor a stored root grant (`trustedRoot: true`;
  `requirePCA` and `verifyPCActnCore` verify against the grant you stored): **WARN**. Such roots are refused, or their
  PQ key is not pinned.

### `caveats.root` and `verifier.enforcement`: root caveats

From 0.4.1 caveats placed on the root grant (next to its envelope) are enforced like delegated caveats, and an unknown
root caveat type denies. There is no option that turns this off, so the check looks for what can still leave a
deployment unprotected:

- the version of `@atlasauth/pca` your application actually loads (`--pca-dir` = your application's directory; default
  the doctor's own copy): below 0.4.1 is a **FAIL**;
- a functional probe through that same library: a root `max_spend` of 100 USD must deny a 150 USD payment and allow a
  50 USD one, and an unknown root caveat type must deny. An allowed over-limit payment is a **FAIL**; a denied control
  payment makes the probe inconclusive (**WARN**);
- `insecureAllowUnenforced: true` on `requirePCA` is a **FAIL**; a `require` list that drops any default required check
  (`counter_format`, `replay`, `revocation`, `plan_root_authorized`, `audience`, `validity`, `grant_ref_bound`) is a **WARN**.

## What pca-doctor does not do

It checks assumptions; it does not audit your application. It cannot see options you did not give it, it observes the
network path from where it runs, and its store probes are short. A pass on every check is a good sign, not a proof:
run the full [store conformance kit](store-conformance-kit.md) against your store, and keep the doctor in your deploy
pipeline so a configuration change is caught when it ships.
