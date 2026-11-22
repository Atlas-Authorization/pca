# __PCA_APP_NAME__

A [Proof-Carrying Authority](https://www.npmjs.com/package/@atlasauth/pca) quickstart — the whole
`authF` loop in one file.

```bash
npm install
npm start
```

`src/index.ts`:

1. generates a **principal** (human) key and an **agent** (holder) key;
2. mints a **root capability** with a simple policy — a `stripe.refund` predicate capped at `$500`,
   plus reversibility + expiry caveats;
3. has the agent **build + sign** a proof-carrying action (`PCActn`) for an allowed `$42` refund;
4. **verifies it offline** with the full server verifier (`verifyPCActn`) — verdict `ALLOW`;
5. **tampers** with the signed action and verifies again — verdict `DENY`;
6. has a compromised agent sign an action **outside its grant** (`github.delete_repo`) — verdict `DENY`;
7. presents a **forged root** — verdict `DENY`.

No network, no shared secret: the verifier checks the signed action against the grant the verifier itself
holds, and decides whether the action is inside it (predicates, limits, caveats, the authorized plan,
revocation, budget). A well-formed, signed proof alone authorizes nothing: the structural core verifier
(`verifyPCActnCore`) never makes the allow decision. The agent proves each action; the verifier decides.

## What to change next

- Grant more connectors/actions in `permissions` (e.g. `{ gmail: ['send'] }`).
- Tighten `limits` (`{ refund: '$100/day' }`) and watch an over-cap action fail its predicate.
- Move verification to a real resource server — see the `express-rs` template
  (`npm create pca-app@latest my-server --template express-rs`).
