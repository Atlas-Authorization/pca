# @atlasauth/pca-policy-ci

A CI gate for Proof-Carrying Authority (PCA) policies. It statically analyzes an envelope, a minted grant, or a delegation chain and reports findings so an unsafe policy fails the build before it ships. It is driven by the `@atlasauth/pca-analyzer` decision procedure.

Rules (each can be toggled):

- `over-broad-grant`: wildcard verb or resource, a provable always-allow, or a dangerous verb with no narrowing condition
- `privilege-escalation`: a delegation hop whose authority is not a subset of its parent
- `redundant-caveat`: a duplicate, subsumed, unsatisfiable, or non-binding caveat or condition
- `dangerous-reachability`: a dangerous action provably reachable with no budget, rate, or step-up gate
- `missing-safety-floor`: no expiry, or no blast-radius, rate, or budget gate on a non-trivial grant

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

## Status

Part of [Proof-Carrying Authority](https://github.com/Atlas-Authorization/pca). A clean run means no rule fired, not that a policy is correct; it complements review, not replaces it.

## License

MIT - see LICENSE
