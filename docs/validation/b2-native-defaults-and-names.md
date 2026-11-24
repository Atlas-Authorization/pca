# B2: breaking changes B3 + B6 for the native SDKs and Python (0.5)

Reference: the TypeScript implementation in `packages/pca` (done first). Every SDK mirrors it exactly. The shared
acceptance data is regenerated from TS: `sdks/*/testdata|test-data/authorize-fixtures.json`, `packages/pca/conformance/*`.

## B6a: check names

| Old | New | Where |
|---|---|---|
| core check `counter` (well-formed non-negative safe integer) | `counter_format` | core verifier result (`checks` map), conformance profile, `check_order` |
| stateful `counter` (authorize: "N is not greater than last seen M (replay)") | `replay` | `authorize` result |

* Core verifier reason on failure: `counter_format: missing or not a non-negative safe integer`.
* `authorize` required list (fails closed): `counter_format, replay, revocation, plan_root_authorized, audience,
  validity, grant_ref_bound, operation, params_digest, policy` + `require`.
* `replay`: `pass` unless the store refuses (`fail`). It is set to `pass` right after the checks before the claim (like TS),
  and flips to `fail` when the claim is refused. Reasons: `replay: N is not greater than last seen M (replay)`,
  `replay: N was already claimed (replay)`, `replay: the replay store failed (fail closed)`.
* Alias: a `require` list entry `counter` means `replay` in `authorize` (it always meant the stateful check there).
  The old name is not emitted in any `checks` map. Document the alias in the SDK README/changelog and in the migration guide.
* The decisive-reason prefix in a refusal for a replay is now `replay: ...`.
* The mapping of old public identifiers that expose the check name (constants, enums, tests) is kept under the old name
  as a deprecated alias only where an API exposes it (say so in the changelog).

## B6b: limit-naming denial reasons

`evaluatePredicates` reason when no predicate permits the action:

1. Find the first predicate (in list order) whose verb AND resource match the action and whose `where` is an array.
   In its `where`, find the first condition that does not evaluate to true (tri-valued: `false` or `unknown`).
   If that condition is an `all_of` group, descend into its first non-true child (repeat, depth <= 4).
   Reason: `<describe(condition)> not satisfied for <verb> on <resource>`.
2. If no predicate is in scope (verb/resource do not match any), or none has an unmet condition: unchanged
   `no predicate permits <verb> on <resource>`. Empty list: unchanged `envelope grants no predicates`.

`describe(condition)`:
* leaf: `<name> <op> <operand>`; `name` = `field` with a leading `action.params.` removed (other fields as-is; a
  non-string field is `<field>`).
  `op` text: eq `==`, ne `!=`, lt `<`, lte `<=`, gt `>`, gte `>=`, in `in`, nin `not in`, prefix `starts with`, like `like`,
  matches `matches`, is_a `is a`, member_of `member of`; `exists`: `<name> absent` when `value == false`, else `<name> present`
  (no operand); unknown op: `<name> <condition>`.
  operand: if `ref` is present it is the ref string (non-string ref: `<ref>`); else `value` rendered by `show`.
* group: depth >= 2 -> `(...)`; `all_of` -> `all of (d1; d2; ...)`, `any_of` -> `any of (d1; d2; ...)` (first 8 children,
  children described at depth+1, joined by `; `), `not` -> `not (d)`.
* non-object condition: `<condition>`.

`show(value)`: `null`, `true`, `false`; a number that is a safe integer (|n| <= 2^53-1, integral) prints as a plain decimal
integer, any other number prints `<number>`; a string prints `"s"` when it has at most 64 UTF-16 code units and contains
no U+0000..U+001F, no `"`, no `\`, and no code point above U+FFFF, else `"..."`; an array (top level only, not nested in
an array) prints `[a, b, ...]` of `show` of each element joined by `, ` when it has at most 8 elements, else `[...]`;
anything else (object, nested array) `<value>`.

Examples: `amount <= 500 not satisfied for stripe.refund on charge:ch_1`;
`currency in ["usd", "eur"] not satisfied for ...`.

The TS reference is `firstUnmetLimit` / `describeCondition` / `showValue` in `packages/pca/src/predicates.ts`.

## B3: defaults

* The default of every middleware / guard is the full `authorize` path: policy + replay + revocation required, fail
  closed without a store, revocation source, grant resolver or operation mapping (403, `authorize_config` with `missing`).
* Signature-only (core verifier only) is an explicit opt-in: `signature_only=True` (Python) / `SignatureOnly: true` (Go) /
  `signatureOnly` (Java, .NET, PHP, Rust, Ruby) in the language's idiom. Passing both an authorize option set and
  signature-only is a configuration error that raises at construction.
* No `authorize` options given and not signature-only = authorize mode with an empty option set: every request is
  refused with 403 `authorize_config` naming what is missing (state store, revocation check, ...). It never silently
  downgrades to signature-only.
* Kotlin and Swift ship no middleware: their READMEs state that `authorize` is the recommended entry point and that the
  core verifier is signature-only.
* Python adapters: dependency range `atlas-pca>=0.5,<0.6`; a tool guard built without `authorize` options or
  `signature_only=True` refuses calls (authorize_config) instead of verifying the signature only.
