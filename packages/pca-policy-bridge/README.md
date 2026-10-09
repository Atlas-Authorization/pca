# @atlasauth/pca-policy-bridge

Import existing authorization policy into Proof-Carrying Authority (PCA). Each translator compiles a policy source into PCA predicates (the shapes `@atlasauth/pca` evaluates, droppable into an envelope's `predicates`) plus a report of what was and was not translated. Anything unmodeled fails closed: it never widens an allow.

Supported sources:

- **Cedar**: `permit` and `forbid` policies (`cedarToPca`)
- **OPA / Rego**: a subset covering `allow` rules written as conjunctions of `input` comparisons (`regoToPca`)
- **OpenFGA / Zanzibar**: ReBAC model plus relationship tuples (`openfgaToPca`)

## Install

```sh
npm i @atlasauth/pca-policy-bridge
```

## Usage

```ts
import { cedarToPca, decide } from '@atlasauth/pca-policy-bridge';

const result = cedarToPca(`
  permit (principal == User::"alice", action == Action::"view", resource == Photo::"p1");
  forbid (principal, action == Action::"delete", resource);
`);

result.report.errors;   // non-empty => incomplete translation, treat as deny
result.report.skipped;  // constructs that were not modeled (each fails closed)
result.predicates;      // permits: plug into Envelope.predicates
result.denies;          // forbids: applied with deny-overrides-permit via decide()

// Evaluate one action under the translation (deny overrides permit).
decide(result, {
  subject: { id: 'User::alice' },
  action: { verb: 'view', resource: 'Photo::p1' },
});
```

`regoToPca(moduleText)` and `openfgaToPca(model, tuples)` return the same `BridgeResult` shape. For Cedar group membership (`principal in Group::"g"`), supply the entity parent map to the evaluator at `env.entity_parents`.

## Boundaries

Each translator documents the subset it models. Not modeled (reported in `report.skipped` / `report.errors`, and failing closed): Cedar arithmetic, set operations and extension functions; Rego iteration, comprehensions, `:=` assignment and general builtins (the whole containing rule is dropped); OpenFGA userset-valued tuples such as `group:eng#member`.

## API

`cedarToPca`, `regoToPca`, `openfgaToPca`, `decide`, and types `BridgeResult`, `TranslationReport`, `PolicySource`.

## Status

Part of [Proof-Carrying Authority](https://github.com/Atlas-Authorization/pca). Policy translation is a static compile step; review the report before granting on its output. PCA's cryptography has not been independently audited.

## License

MIT - see LICENSE
