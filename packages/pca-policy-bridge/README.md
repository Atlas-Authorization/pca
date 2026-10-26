# @atlasauth/pca-policy-bridge

> Maturity: **experimental**. Its API may change or be removed in any release, and it is outside the stable and production tiers. See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

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

## Checked against the real engines

The translators are tested differentially. A generated corpus of policy sets and requests (400 Cedar sets with 3,200 requests, 400 Rego modules with 4,000 inputs, produced by a fixed-seed generator) was decided by the real engines (the `cedar-policy` 4.2.2 authorizer and OPA 0.70.0) and by the bridge. For every request the bridge never allows what the engine denies, and when a translation reports nothing skipped and no errors it equals the engine's decision. A policy using a construct outside the subset is refused or dropped, never approximated, so the bridge may deny where the engine allows. The same holds for OpenFGA: 150 generated models (union, intersection, difference, computed usersets, tuple-to-userset and public `user:*` tuples) with 15,000 checks decided by an OpenFGA 1.8.4 server. The corpus, the engine versions and the script that regenerates them are in the package's `differential` folder.

Behaviours that follow the engines and that you might not expect:

- OpenFGA public tuples (`user:*`) grant every subject of that type. The first run against the server found the bridge treating `user:*` as a user named `user:*`: it denied what the server allowed and, under a difference such as "viewer but not banned", allowed what the server denied.
- Cedar skips a policy whose condition raises an error, such as reading `principal.dept` when the principal has no `dept`. This holds for `unless` as well as `when`, and `a && b` / `a || b` only read `b` when `a` has not decided. The translation adds a trailing condition to the predicate so that a missing attribute makes the policy not apply instead of letting an `unless` grant.
- `action == Action::"view"` inside a `when` or `unless` compares the verb `view`.
- Rego: every action or resource selector in a rule must hold, so a second one narrows the first and a contradiction matches nothing. `not input.p == "x"` holds when `input.p` is absent; any other negated comparison or builtin on an absent path leaves the rule failing, as in OPA. `glob.match` with an empty delimiter list splits on `.` and is not translated when the pattern has a wildcard; use `null` for no delimiters.

## Boundaries

Each translator documents the subset it models. Not modeled (reported in `report.skipped` / `report.errors`, and failing closed): Cedar arithmetic, set operations and extension functions; Rego iteration, comprehensions, `:=` assignment and general builtins (the whole containing rule is dropped); OpenFGA userset-valued tuples such as `group:eng#member`.

## API

`cedarToPca`, `regoToPca`, `openfgaToPca`, `decide`, and types `BridgeResult`, `TranslationReport`, `PolicySource`.

## Status

Part of [Proof-Carrying Authority](https://github.com/Atlas-Authorization/pca). Policy translation is a static compile step; review the report before granting on its output. PCA's cryptography has not been independently audited. The Cedar and Rego readers are fuzzed with oversized and repeated-character inputs and are linear-time on them; hostile policy text cannot stall the translator.

## License

MIT - see LICENSE
