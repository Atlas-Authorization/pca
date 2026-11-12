# __PCA_APP_NAME__

Let an agent pay under **$200 a day** on its own, ask a person for anything over **$50**, and refuse the rest.

```bash
npm install
npm start
```

One signed mandate holds the terms (merchants, currency, per-charge ceiling, auto-approve line, daily autonomous
total). `authorizeCharge` decides each charge against it:

| Outcome | Meaning |
|---|---|
| `auto` | on the merchant list, right currency, at most $50, and the autonomous $200 is not used up |
| `step_up` | a person must co-sign: over $50, or the autonomous $200 is used up |
| `deny` | wrong merchant, wrong currency, or over the $200 hard ceiling |

`applyHumanCosign` is the only way the autonomous budget goes up.

## Make it yours

- Change `merchants`, `perTransactionCap`, `autoApproveThreshold` and `cumulativeCap` in `src/index.ts`.
- Keep the budget in a durable store with `authorizeChargeAtomic` (compare-and-set) so two servers cannot both spend it.
- Bind a card-network agent token to the mandate: see the agent payments guide in the PCA docs.
- Put the decision behind a real route: `protect()` from `@atlasauth/pca` (see the `delegation` template).
