# @atlasauth/pca-mpc

Experimental reference prototype: a multi-stakeholder policy VM composed under secure multi-party computation, for Proof-Carrying Authority (PCA). Several stakeholders (for example user, organization, regulator) each evaluate their own private PCA policy to a tiny decision vector `{ allow, t, rQuant }`, then compose them under MPC so only the joint result is revealed: allow if every party allows, the maximum required proof threshold, and the maximum quantized risk. No party reveals its own policy or its own vector.

## Install

```sh
npm i @atlasauth/pca-mpc @atlasauth/pca
```

## Usage

```ts
import { generateKeyPair, encodeKey, mintGrant, DEFAULT_RISK_POLICY } from '@atlasauth/pca';
import { evaluateParty, composeSecure, composeSecureMalicious } from '@atlasauth/pca-mpc';

const principal = generateKeyPair();
const holder = generateKeyPair();

// Each stakeholder builds a PartyPolicy from its own grant + decision input.
function party(id: string, verb = '*') {
  const { grant } = mintGrant({
    principalSecret: principal.secretKey,
    principalPublic: encodeKey(principal.publicKey),
    holder: encodeKey(holder.publicKey),
    goal: 'wire funds',
    envelope: { predicates: [{ verb, resource: '*' }], caveats: [], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY },
  });
  return {
    id,
    decideInput: {
      grant,
      action: { action: { verb: 'wire', resource: 'acct:1', params: {} } },
      risk: { semanticDistance: 0.1, reversibility: 1, blastRadius: 0.1, taint: 0, confidence: 1, age: 0 },
      budget: { B: 1, tau: 0 },
      now: Date.now(),
    },
  };
}

// Local step: each party reduces its private policy to a decision vector.
const vectors = [party('user'), party('org'), party('regulator', 'read')].map((p) => evaluateParty(p));

// Joint step: semi-honest MPC (additive sharing over a prime field + Beaver triples).
const result = composeSecure(vectors);
result.composed;   // { allow: 0, t: 3, rQuant: 5 }  (the regulator only permits 'read', so the joint answer is deny)

// Malicious-with-abort variant (SPDZ-style MACs): correct result, or a thrown abort.
const strict = composeSecureMalicious(vectors);
```

## API

- `evaluateParty(policy, Q?)` - reduce a party's private PCA decision input to a `DecisionVector`.
- `composeSecure(vectors, config?)` - semi-honest composition; returns `composed`, the public Beaver `opened` messages, and per-party views.
- `composeSecureMalicious(vectors, config?)` - dishonest-majority layer with information-theoretic MACs and a MAC check that aborts on deviation; an optional no-dealer offline provider (OT-based) replaces the trusted dealer.
- `composeClear(vectors)` - the cleartext reference that `composeSecure` must equal.
- Lower-level building blocks (field arithmetic, sharing, Beaver triples, oblivious transfer including a post-quantum KEM-based base OT) are exported too.

## Status

This is a research prototype, not a production MPC system. All parties run in one process and exchange data through in-memory structures, so it demonstrates and tests the protocol logic but is not a networked deployment. The semi-honest layer assumes parties follow the protocol and uses a trusted dealer for triples; the malicious layer detects deviation by aborting and can use an OT-based offline phase instead of a dealer. The cryptography has not been audited. The composed verdict informs a decision; it does not authorize anything on its own - the resource server's verifier decides.

## License

MIT - see LICENSE
