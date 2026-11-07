---
title: Product-layer modules
order: 30
---

# Product-layer modules: data-loss prevention, catalog, kill switch, mesh witness store

> **Status: production (pending CI).** These modules live under `@atlasauth/pca/ext/research` (the import path keeps its original name). They are not part of PCA Core. See [maturity tiers](../maturity.md). The QRNG entropy module is not in this group: it is [hardened, awaiting hardware evaluation](../guides/qrng-entropy.md).

Each module below enforces a small claim and says what it does when its input is missing or malformed. Advisory outputs (scores, forecasts, console views) are labelled advisory and never decide an authorization.

## Quick start

```ts
import { evaluateDlp, defaultDlpPolicy, buildCatalog, resolveAction, freezeAgent, isFrozen, EMPTY_FREEZE } from '@atlasauth/pca/ext/research';

// 1. A tainted flow into customer data needs a person; a malformed taint is read as maximally tainted.
const dlp = defaultDlpPolicy({ piiResource: 'customer:*' });
evaluateDlp(dlp, { verb: 'gmail.send', resource: 'customer:42', taint: 1 }); // { outcome: 'step_up', class: 'pii', reason: ... }
evaluateDlp(dlp, { verb: 'gmail.send', resource: 'customer:42', taint: Number.NaN }); // { outcome: 'deny', class: 'pii', reason: ... }

// 2. A verb the catalog does not know is the most dangerous verb.
resolveAction(buildCatalog([]), 'zz.do'); // { spec: { reversibility: 'irreversible', blastRadius: 1, ... }, catalogued: false }

// 3. The kill switch: an agent with no identity is frozen.
const set = freezeAgent(EMPTY_FREEZE, 'agent-7');
isFrozen(set, 'agent-7'); // true
isFrozen(set, ''); // true
```

## Failure behaviour

| Module | Missing or malformed input | Result |
|---|---|---|
| `evaluateDlp` | policy is null or `classes` is not an array | `deny`, reason "malformed DLP policy" |
| `evaluateDlp` | a ceiling that is present but not a number | `deny`, reason names the ceilings |
| `evaluateDlp` | taint is NaN, infinite or not a number | read as maximally tainted: `step_up`, or `deny` above a hard ceiling |
| `defineAction` | no connector or action, a dot or space in the connector, bad reversibility, blast radius outside 0 to 1, empty `amountField` | throws, naming the field |
| `resolveAction` | verb not in the catalog | irreversible, blast radius 1, `catalogued: false` |
| `extendCatalog` | replaces a verb with a lower reversibility class or blast radius | throws |
| `assertCatalogPinned` | digest differs | throws |
| `isFrozen` | empty or non-string agent, null or malformed set | `true` |
| `freezeAgent` | empty agent | throws `TypeError` |
| `recommendPolicy` | `kappa` not positive and finite, or a non-finite count or risk | throws `RangeError` |
| `FileMeshWitnessStore.load` | file is not JSON, wrong shape, or fails its digest | throws; the witness never starts empty over a damaged file |
| `FileMeshWitnessStore.load` | file does not exist | `undefined` (first run) |
| `verifyMeshProof` | any malformed proof or trust setting | verdict with a reason; never throws |

## Limits

- The DLP policy, the catalog and the freeze set are what you declare. A wrong declaration is a wrong decision; the module only refuses to guess.
- `forecast`, `recommendPolicy`, `simulate` and the console views are planning and display tools. They estimate and never authorize.
- `FileMeshWitnessStore` is imported from `@atlasauth/pca/durable-mesh-witness` (Node only) and is for one process. Two witnesses must not share a file.
- Mesh safety depends on the witnesses being independent of the domain they watch.
