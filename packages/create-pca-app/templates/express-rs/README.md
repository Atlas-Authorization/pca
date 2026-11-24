# __PCA_APP_NAME__

A minimal [Proof-Carrying Authority](https://www.npmjs.com/package/@atlasauth/pca) **resource
server** — it verifies a proof-carrying action on every request before doing any work.

```bash
npm install
npm start           # starts the server on http://localhost:8787

# in another terminal:
npm run client      # calls POST /refund with two valid proofs, a tampered one, and an out-of-scope one
```

- `src/server.ts` — one protected route, `POST /refund`. It reads the `PCA-Action` header (and the
  committed `params` from the JSON body) and verifies **offline** with the full server verifier
  (`src/guard.ts`, `requirePCA`). In-scope -> `200 { allow: true }`; tampered / expired / wrong audience /
  unregistered grant -> `401`; out-of-scope / over-limit / replayed / unauthorized plan / revoked ->
  `403 { allow: false, reasons, checks }`.
- `src/guard.ts` — the verification core, built on `requirePCA`. **The root of trust is decided by the server**: the grant is
  loaded from the server's own store by the action's signed `grant_ref`, `allowedSuites` pins the
  accepted signature suites (Ed25519 only), the audience and the clock are the server's own. **The
  decision is the full verifier**: the grant's predicates and limits, its caveats, the plan root the
  principal authorized, revocation, the replay counter, the trust budget and the threshold the server
  derives. A well-formed, signed proof alone authorizes nothing.
- `src/store.ts` — the demo's grant store (a directory of JSON files, `./.grants`): grants, authorized
  plan roots, revocations.
- `src/client.ts` — mints an agent, registers its grant and authorizes its plan out-of-band, then sends a
  valid action, a tampered copy and a signed action outside the grant (`stripe.delete_customer`), so you
  can watch the server allow the first and deny the other two.

**Never trust a grant (or `cap_chain[0]`) that arrives with the request.** An attacker can mint a root
that names your principal as `issuer` but is signed with their own key (for example a pure
post-quantum one); if your verifier treats the presented root as the trusted root, their key becomes the
trusted key. Register grants with the server out-of-band, as this template does. If you accept
post-quantum suites, add them to `allowedSuites` and pin the principal's PQ key on the server (`pqPins`).

Nothing authorises itself: the agent proves each action, the server's verifier decides.
