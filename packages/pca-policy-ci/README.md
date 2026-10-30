# @atlasauth/pca-policy-ci

> Maturity: **production** (supported for production use). See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

A CI gate for Proof-Carrying Authority (PCA) policies. It statically analyzes an envelope, a minted grant, or a delegation chain and reports findings so an unsafe policy fails the build before it ships. It is driven by the `@atlasauth/pca-analyzer` decision procedure.

Rules (each can be toggled):

- `over-broad-grant`: wildcard verb or resource, a provable always-allow, or a dangerous verb with no narrowing condition
- `privilege-escalation`: a delegation hop whose authority is not a subset of its parent
- `redundant-caveat`: a duplicate, subsumed, unsatisfiable, or non-binding caveat or condition
- `dangerous-reachability`: a dangerous action provably reachable with no budget, rate, or step-up gate
- `missing-safety-floor`: no expiry, or no blast-radius, rate, or budget gate on a non-trivial grant
- `schema-mismatch` (with `--schema` or the `schema` option): the policy checked against its action schema or ActionDefs: undeclared verbs and parameters, type, range and enum mismatches, an unsatisfiable predicate, a money verb with no ceiling, unit tags

A hard `error` is only emitted from a proven analyzer verdict; undecidable features (regex resources, cross-field refs, over-large grids) degrade to a `warn` or `info` that says so.

## Install

```sh
npm i -D @atlasauth/pca-policy-ci
```

## Usage

CLI:

```sh
npx pca-policy-ci policies/*.json [--max-severity error|warn|info] [--format text|github] [--quiet]
```

Add `--schema schema.json` to check each policy against an action schema as well.

Three more commands gate a change to a policy:

```sh
npx pca-policy-ci diff old.json new.json [--allow-widen] [--verb stripe.refund --integer --max-exposure-increase 0]
npx pca-policy-ci test policy.json tests.json [--require-digest]
npx pca-policy-ci coverage policy.json tests.json [--min-clauses 1 --min-boundaries 1 --min-mutation 1 --max-survivors 0]
```

`diff` fails on a widening or on a rise in the maximum exposure; `test` replays signed or generated examples against the policy; `coverage` fails when the examples leave clauses, thresholds or mutations unexercised. A policy file may also carry `vetoes` and `tighten` members.

Each file is a JSON envelope, grant, compiled policy, `{ predicates, caveats }`, or an array (treated as a delegation chain). The exit code is non-zero when any finding reaches `--max-severity` (default `error`). `--format github` emits GitHub Actions annotations.

Library:

```ts
import { lint, lintPolicies } from '@atlasauth/pca-policy-ci';

const findings = lint({
  predicates: [{ verb: '*', resource: '*' }],
  caveats: [],
});
// [{ rule: 'over-broad-grant', severity: 'error', message: '...', where: 'predicates[0]' }, ...]

const summary = lintPolicies(
  [{ label: 'refund-agent', policy: envelope }],
  { maxSeverity: 'warn' },
);
process.exit(summary.exitCode);
```

## API

- `lint(input, opts?)`: dispatches to `lintPolicy` (single policy) or `lintChain` (array)
- `lintPolicies(items, opts?)`: labeled batch, returns a `LintSummary` with `counts`, `ok`, `exitCode`
- `summarize(results, opts?)`, `normalizePolicyInput`, `DEFAULT_DANGEROUS_VERBS`
- Options: `rules` to enable/disable or tune each check (dangerous verbs, targets, safety floor)

## Fail-closed behaviour

| Missing or invalid | Result |
|---|---|
| A policy that is not a policy, a bad chain hop, an unreadable file, invalid JSON, a directory | an `error` finding (`malformed-policy`): the gate fails |
| A rule throws while checking | an `error` finding (`internal-error`): a policy that could not be fully checked does not pass |
| No policies were linted (an empty list, `summarize([])`, a glob that matched nothing) | exit code 2 and `reason: 'no policies were linted'`: never a pass |
| `--max-severity` / `maxSeverity` is not `error`, `warn` or `info` | refused (`RangeError` from `summarize`, usage error from the CLI) |
| `diff`, `test` or `coverage` without exactly two files, an unknown option, or a value flag with no value or a non-number | usage error, exit code 2 |
| `--schema` file or an input file that cannot be read or parsed as JSON (`diff`, `test`, `coverage`, `--schema`) | exit code 2, with the reason |
| No policy file given | `error: no policy files given`, exit code 2 |
| A finding whose severity is none of the three | counted as an `error` |
| An analyzer verdict that is not proven (an undecidable feature) | a `warn` or `info` that says so, never an `error`: the gate does not fail a build on a guess, and does not pass a provably unsafe policy |

`--format github` escapes `%`, newlines, `:` and `,` in file names and messages, so a file name cannot add properties to an annotation or start another command.

## Limits

- It is a linter and a gate over policy files, not an authorizer or a proof. A clean run means no rule fired.
- The rules are fixed and versioned with the package; a policy construct no rule knows about is not flagged.
- It reads files you point it at and does not check their provenance or signatures.
- `diff` and `coverage` measure the examples and exposure you give them; they cannot see behaviour the examples do not exercise.
- An analyzer verdict that is not proven (an undecidable feature) is reported as a warning or note, never as a failure.

## Status

Part of [Proof-Carrying Authority](https://github.com/Atlas-Authorization/pca). A clean run means no rule fired, not that a policy is correct; it complements review, not replaces it.

## License

MIT - see LICENSE
