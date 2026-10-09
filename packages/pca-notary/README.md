# @atlasauth/pca-notary

External-fact attestation for Proof-Carrying Authority (PCA), in the direction of zkTLS / TLSNotary. A notary witnesses one HTTP request/response and signs a canonical record of it (method, URL, request-header digest, status, and a salted Merkle commitment to the response body). The agent can then disclose a single response field with an inclusion proof while every other field stays hidden, and bind that fact to a specific PCActn. A policy can then gate an action on what an external API actually returned, not on what the agent claims it returned.

## Install

```sh
npm i @atlasauth/pca-notary @atlasauth/pca
```

Node.js only (uses `node:crypto` for salts).

## Usage

```ts
import { generateKeyPair } from '@atlasauth/pca';
import {
  notarizeResponse, discloseField, verifyDisclosedField,
  requireAttestedFact, evaluateAttestedFactCaveat,
} from '@atlasauth/pca-notary';

const notaryKey = generateKeyPair();   // the notary's signing key

// Notary side: witness the exchange and sign it.
const { attestation, witness } = notarizeResponse(
  {
    request: { method: 'GET', url: 'https://api.shop.example/orders/42' },
    response: { status: 200, body: { order: { id: 42, status: 'shipped' }, customer: { email: 'a@b.c' } } },
  },
  { notaryKey },
);

// Prover side: reveal only order.status (paths are arrays of keys / indexes).
const disclosure = discloseField(attestation, witness, ['order', 'status']);

// Verifier side: trust only the notary's public key.
verifyDisclosedField(attestation, disclosure, { notaryKey: notaryKey.publicKey }); // true

// A policy caveat: "only if the notarized order status is 'shipped'".
const caveat = requireAttestedFact({
  notary: notaryKey,
  path: ['order', 'status'],
  equals: 'shipped',
  url: 'https://api.shop.example/orders/42',
});
evaluateAttestedFactCaveat(caveat, { attestation, disclosure }); // { ok: true }
```

To tie a fact to one action, call `bindFactToPcActn(attestation, pcactn)` and have the agent include `factRef(attestation)` in the PCActn's `provenance.trusted_refs`; `factMatchesPcActn` then checks both directions, and the caveat's `bindToPcActn: true` requires it (pass the `pcActn` in the evidence).

## API

`notarizeResponse`, `discloseField`, `verifyNotaryAttestation`, `verifyDisclosedField`, `factRef`, `bindFactToPcActn`, `factMatchesPcActn`, `requireAttestedFact`, `evaluateAttestedFactCaveat`, `isAttestedFactCaveat`, and the `ATTESTED_FACT_CAVEAT` constant. All verification functions fail closed (return `false` / `{ ok: false, reason }`).

## Status

The trust boundary is the notary. The relying party trusts that the notary reported the response faithfully and is not colluding with the agent. This is not trustless zkTLS: the notary does not take part in an MPC-TLS handshake, so it attests to what it observed rather than to a transcript it could not have forged. Selective redaction and the binding into a PCActn are real cryptographic checks, but the notary remains the trust assumption. PCA cryptography has not been independently audited.

## License

MIT - see LICENSE
