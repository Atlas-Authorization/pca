# pca-guides-a

Four small scripts, one per PCA guide. Each runs offline in under a second, prints every outcome, and ends with
`All outcomes as expected.` (exit code 0). If any outcome differs from what the guide says, the script prints the
difference and exits non-zero.

```bash
npm install
npm start          # runs all four, or run one: npm run caveats
```

| Script | Command | Guide |
|---|---|---|
| `src/caveats.ts` | `npm run caveats` | Caveat language: third-party caveats and discharges, `sealed`, narrow blocks, `max_uses`, `derive` |
| `src/workflow.ts` | `npm run workflow` | Authorize a whole workflow: steps, dataflow edges, labels, budget |
| `src/readside.ts` | `npm run readside` | Control what an agent may read: masks, sinks, the token vault, aggregates |
| `src/blueprint.ts` | `npm run blueprint` | Agent blueprints: a fleet ceiling and a group kill |

The scripts use only the public exports of `@atlasauth/pca` and `@atlasauth/pca-grants`, with fixed timestamps and no
network, so the output is the same on every run.
