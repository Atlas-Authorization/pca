---
title: Upgrading to 0.5
order: 90
---

# Upgrading to 0.5

0.5 takes breaking changes. This page lists the ones in the state, secrets and tooling packages, with the code to change. The changelog has the full list.

## Compliance report moved to `@atlasauth/pca-compliance`

`complianceReport`, `reportToMarkdown` and the types `ComplianceInput`, `ComplianceReport`, `ComplianceControl`, `ControlStatus` and `Framework` are gone from `@atlasauth/pca`.

```ts
// before
import { complianceReport, reportToMarkdown } from '@atlasauth/pca';
// after
import { frameworkReport, frameworkReportToMarkdown } from '@atlasauth/pca-compliance';
```

The arguments and the result are unchanged. Install `@atlasauth/pca-compliance` if you do not have it.

## `TokenVault` is strict by default

`new TokenVault(options)` now applies the production profile unless you pass `strict: false`. It throws at construction unless:

- `store` encrypts at rest (`EncryptedConnectionStore` over your durable store, with a `KeyWrapper` for your KMS);
- `replay` is a one-time-use store (a durable `ReplayStore`, as for `requirePCA`);
- `isRevoked` is set (for example `(p) => checkRevocation(p, registry).then((r) => r.revoked)`);
- `audience` is a non-empty string.

There is no default store any more. The plaintext in-memory store moved to `@atlasauth/pca-connect/testing` and is accepted only with `strict: false`:

```ts
// tests and local development
import { InMemoryConnectionStore } from '@atlasauth/pca-connect/testing';
const vault = new TokenVault({ strict: false, store: new InMemoryConnectionStore() });
```

`InMemoryConnectionStore` is no longer exported from the package root.

## `@atlasauth/pca-revoke` is asynchronous

`RevocationStore` methods return promises, so a store can sit on Redis or a database. Everything built on it is async too:

| Before | After |
|---|---|
| `registry.revoke(...)`, `revokeSubtree`, `unrevoke`, `killAgent`, `killSubtree`, `list`, `lookup`, `clear` | the same names, each returns a promise |
| `isRevoked(pcactn, registry)` | removed; use `await checkRevocation(pcactn, registry)` |
| `verifyWithRevocation(...)`, `ingestCaepEvent(...)` | return promises |
| custom `RevocationStore` with synchronous methods | make each method `async`; run `revocationStoreCases` from `@atlasauth/pca-revoke/conformance` against it |

`checkRevocation` differs from `isRevoked` in one way that matters: it never reports "not revoked" because it could not look. A missing chain, a malformed hop, a bad clock or a failing store all come back as `revoked: true`.

`applyRotation` from `@atlasauth/pca-rotate` is async for the same reason, and its `sink` takes the async registry methods.

## State, secrets and tooling packages: what now refuses

These packages now fail closed where they used to continue. Each row is a change you may see in your code.

| Package | Before | Now |
|---|---|---|
| `@atlasauth/pca-events` | `signWebhook` accepted any secret, including an empty one; `parseEvent` accepted any `id`; a replay inside the tolerance window was accepted | a secret under 16 bytes throws (and never verifies); `parseEvent` refuses an event whose `id` is not the digest of its content; `verifyDelivery(secret, payload, header, { replay })` takes the event id once from a `ReplayStore` |
| `@atlasauth/pca-siem` | the full leaf signature was logged; a failing record failed the whole batch; no delivery timeout | a 16-character signature prefix by default (`serialize: { signature: 'full' }` restores it); the other records are delivered and `skipped` counts the bad one; `timeoutMs` (default 10 s) aborts a hung collector |
| `@atlasauth/pca-otel` | a recorded exception was the original error; resources and reasons were exported as given | the recorded exception is a copy with a redacted message; strings pass through `redactSecrets` (override with `redact`) |
| `@atlasauth/pca-doctor` | a run with no checks passed; a check that threw crashed the run | a run that checked nothing fails; a thrown check is a failed check; a bad number or header in the environment is an error |
| `@atlasauth/pca-policy-ci` | `summarize([])` passed; an unknown `maxSeverity` passed everything | an empty run is exit code 2; an unknown threshold throws; an unknown finding severity counts as an error |
| `@atlasauth/pca-explain` | `allow` and `admit` were read for truthiness | only an explicit `true` (with per-check statuses and no failing check) is an allow |
| `@atlasauth/pca-dataflow` | any object shaped like a tagged value flowed; capability sets were mutable | only values made by the module's constructors flow; sets are immutable; a trusted capability needs a non-tool source |
| `@atlasauth/pca-connectors` | a `{var}` value, a scope, `state` or an extra parameter could be anything; `registerProvider` replaced a provider silently | a variable must be a DNS label; scopes must be listed (`allowUnlistedScopes`); `state` needs 16 characters; reserved parameters are refused; replacing a provider needs `{ replace: true }` |
| `@atlasauth/pca-invariants` | `checkInvariants({ numRuns: 0 })` reported success | `numRuns` must be a positive integer |
| `@atlasauth/pca-rag` | the decision digest named admitted ids only | it also binds `allowedIndexes`; the digest value changes |
| `@atlasauth/pca-analyzer` | an ordering comparison against a string could be "proved" always-deny | such a policy is reported approximate and never claims the safe answer |
