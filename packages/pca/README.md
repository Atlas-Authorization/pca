# @atlasauth/pca

Proof-Carrying Authority (PCA) core: authorization for AI agents where each action carries its own proof.
Instead of handing an agent a bearer token, the principal signs a **Root Intent Grant** once. The agent then
attaches a signed, self-describing **PCActn** to every action, and the resource server verifies it offline:
is the action inside the granted authority, is the signing chain intact, is it a node of the committed plan,
and is there trust budget left to do it without a human?

This package contains canonical hashing, Ed25519 and post-quantum signatures, Merkle plan commitments,
attenuable capability chains, hardware attestation verifiers, the PCActn verifier, and the resource-server
guard (`requirePCA`). Source and issues: <https://github.com/Atlas-Authorization/pca>.

```
  principal --grant--> agent --PCActn (per action)--> resource server
   (signs envelope,     (holds a capability,         (verifies offline: chain, plan,
    policy, budget)      emits a proof)               signature, audience, budget)
```

## Install

```sh
npm i @atlasauth/pca
```

Node >= 20. The FN-DSA post-quantum suites use `@atlasauth/pca-fndsa-wasm`, which is installed
automatically as a dependency. Optional dependencies (`@xmldom/xmldom`, `asn1js`, `pkijs`, `snarkjs`,
`xml-crypto`) are used only by some attestation and zero-knowledge features.

## Usage

Agent side: mint a grant and sign a PCActn per action.

```ts
import { agent, generateKeyPair, pcaHeaders } from '@atlasauth/pca';

const AUD = 'ins_acme'; // the resource server this grant is for
const a = agent({
  principal: generateKeyPair(), // the human's key; roots the grant
  goal: 'reconcile October refunds',
  permissions: { stripe: ['refund'] },
  limits: { refund: '$500/day' },
  aud: AUD,
});

const params = { amount: 42, currency: 'usd' };
const { encoded } = a.act('stripe.refund', 'charge:ch_123', params);
// Send it with the request: fetch(url, { headers: pcaHeaders(encoded), ... })
```

Resource server: verify each inbound action. `requirePCA` is framework-neutral and default-deny: a required
check that is not enforced denies. (For Express, Fastify, Hono, Next and fetch, use the middleware packages
`@atlasauth/pca-express`, `-fastify`, `-hono`, `-next`, `-fetch`.)

```ts
import { requirePCA, memoryPcaStore } from '@atlasauth/pca';

const guard = requirePCA({
  audience: AUD, // a PCActn signed for another audience is denied
  resolveGrant: async (ref) => (ref === a.grant.id ? a.grant : null), // your grant store
  budgetStore: memoryPcaStore(), // replay counter + trust budget (use a durable store in production)
  hooks: { revocation: () => ({ enforced: true, ok: true }) }, // plug your revocation check
  context: (_req, p) => ({
    params, // the plaintext params the RS saw; must hash to action.params_digest
    // The plan and its authorization must come from YOUR authoritative source. Echoing the plan
    // from the proof itself, as this demo does, proves nothing about authorization.
    plan: [{ id: 'n0', verb: p.action.verb, resource: p.action.resource,
             params_digest: p.action.params_digest, reversibility_class: p.action.reversibility_class }],
    planAuthorized: true,
    risk: { reversibility: 1, blastRadius: 0.1, confidence: 1, semanticDistance: 0, taint: 0 },
    budget: a.budget,
  }),
});

const result = await guard({ headers: new Headers(pcaHeaders(encoded)) });
if (result.ok) {
  // result.verdict.allow === true; result.pcactn is the verified action
} else {
  // result.status is 401 or 403; result.wwwAuthenticate holds the challenge
}
```

Sending the same PCActn again is denied as a replay (the counter must increase).

## Verification

A resource server accepts an action only if the PCActn passes, in order: wire (strict canonical form),
version, audience, validity window, capability chain (hash-linked, each hop signed, rooted at the grant),
plan inclusion, leaf signature, and counter (anti-replay). Optional hooks add attestation, revocation and
freshness, a liveness beacon, a taint gate, threshold (guardian or human) co-signs, and zero-knowledge
compliance. Delegation can only narrow authority: caveats are append-only. Autonomous actions spend a trust
budget, which bounds what an agent can do between human co-signs.

## Attestation verifiers

Hardware attestation is exposed as namespaced verifiers that plug into the attestation hook and can be
combined in an N-of-M policy: `attestAmdSnp` (AMD SEV-SNP with Milan/Genoa/Turin root pins),
`attestIntelDcap` and `attestIntelCollateral` (Intel TDX quotes and PCS collateral), `attestAzureMaa`
(Azure Attestation tokens), `attestGcpConfidentialSpace`, `attestNvidiaSpdm` with `attestNvidiaRim` and
`attestNvidiaOcsp` (NVIDIA GPU confidential computing), plus `attestPqSoftware` and `attestPuf`. Verification
is offline against pinned roots; most hardware roots are classical (ECDSA or RSA).

## Post-quantum suites

Signed surfaces take an `alg` from the suite registry: `ed25519` (default), `ml-dsa-65`, `ml-dsa-87`,
`slh-dsa-sha2-128f`, `slh-dsa-sha2-256s`, `fn-dsa-512`, `fn-dsa-1024`, and hybrid Ed25519 plus ML-DSA or
SLH-DSA combinations. Key exchange uses a hybrid X25519 + ML-KEM-768 KEM (`hybridKemKeygen`,
`hybridEncapsulate`).

FN-DSA (Falcon, FIPS 206) runs through `@atlasauth/pca-fndsa-wasm`, a WebAssembly build of the Rust `fn-dsa`
crate. It is loaded lazily on first use. If it cannot be loaded, FN-DSA verification fails closed, and
`isFnDsaBackendActive()` reports whether it is available.

```ts
import { randomBytes } from 'node:crypto';
import { b64u, fnDsa512Keygen, signWithSuite, verifyWithSuite } from '@atlasauth/pca';

const msg = new TextEncoder().encode('hello');
const k = fnDsa512Keygen(new Uint8Array(randomBytes(32)));
const sig = signWithSuite('fn-dsa-512', {
  fnDsa512: { verifyingKey: k.verifyingKey, signingKey: k.signingKey, signSeed: new Uint8Array(randomBytes(32)) },
}, msg);
verifyWithSuite('fn-dsa-512', { fnDsa512Pub: b64u(k.verifyingKey) }, msg, sig); // true
```

## Durable state (Node only)

`@atlasauth/pca/durable-state` provides crash-safe, tamper-evident, multi-process-safe key/value state for
rollback protection (for example, the highest allowlist version or revocation epoch ever accepted). It is a
separate subpath because it imports `node:fs`.

```ts
import { openDurableState } from '@atlasauth/pca/durable-state';

const state = await openDurableState({ dir: '/var/lib/myapp/pca-state', hmacKey }); // hmacKey: 32+ bytes, optional
await state.update('epoch', (prev) => Math.max((prev as number) ?? 0, 5)); // atomic read-modify-write
```

It fails closed on corrupt or rolled-back state (`DurableStateError`). Without an `hmacKey`, replacing the
whole directory with an older consistent copy is not detectable locally.

## Related packages

Agent client `@atlasauth/pca-agent`; tool wrappers `@atlasauth/pca-ai-sdk`, `-langchain`, `-openai`,
`-anthropic`, `-mcp`; payment mandates `@atlasauth/pca-payments`; tooling `@atlasauth/pca-cli`,
`@atlasauth/pca-testing`, `@atlasauth/pca-events`, `@atlasauth/pca-otel`.

## Status

Pre-1.0 (0.3.0): the API may change between minor versions. The cryptography and protocol have not been
independently audited, and this is not a substitute for a security review before you protect anything of
value. Some verifier checks report `not-enforced` until you supply the corresponding hook, and the default
profile denies in that case. The zero-knowledge backend currently uses BN254 and is being moved toward a
transparent, post-quantum backend; the AMD SEV-SNP root chain is classical.

## License

MIT - see LICENSE
