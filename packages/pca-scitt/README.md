# @atlasauth/pca-scitt

SCITT transparency receipts for Proof-Carrying Authority (RFC 9943 architecture, RFC 9942 COSE Receipts). Each verified PCActn (or verdict) is signed as a COSE Signed Statement (`COSE_Sign1`), appended to an append-only RFC 6962 Merkle log, and returned with a COSE Receipt carrying an RFC 9162 inclusion proof against the log root. A third party can check it with only the statement, the receipt and a pinned root or the transparency service's public key.

Self-contained: a small deterministic CBOR codec (RFC 8949 core-deterministic) and `node:crypto` for signing. Algorithms: `EdDSA` and `ES256`.

## Install

```sh
npm i @atlasauth/pca-scitt @atlasauth/pca
```

Requires Node (uses `node:crypto` `KeyObject`s).

## Usage

```ts
import { generateKeyPairSync } from 'node:crypto';
import { TransparencyService, verifyReceipt } from '@atlasauth/pca-scitt';

const tsKey = generateKeyPairSync('ed25519');     // transparency service
const issuerKey = generateKeyPairSync('ed25519'); // statement issuer (e.g. the resource server)

const service = new TransparencyService({ alg: 'EdDSA', key: tsKey.privateKey, issuer: 'https://ts.example.com' });

const { statement, receipt, root } = service.appendAndReceipt(
  { verdict: 'allow', verb: 'refund' }, // typically the verified PCActn / decision record
  { alg: 'EdDSA', key: issuerKey.privateKey, issuer: 'https://rs.example.com' },
);

// Auditor side: verify the receipt, the inclusion proof and the statement signature.
verifyReceipt(receipt, statement, { verificationKey: tsKey.publicKey, statementKey: issuerKey.publicKey }); // true
verifyReceipt(receipt, statement, { treeRoot: root }); // true: inclusion against a pinned root
verifyReceipt(receipt, statement, {});                  // false: no trust anchor supplied
```

`verifyReceipt` never throws and fails closed: it needs at least one anchor (`treeRoot` and/or `verificationKey`), and a tampered statement or forged receipt returns `false`.

## API

- Statements: `signStatement`, `verifyStatement`, `statementPayload`, `statementLeaf`.
- Receipts: `buildReceipt`, `verifyReceipt`, `encodeInclusionProof`, `decodeInclusionProof`.
- Service: `TransparencyService` (`register`, `appendAndReceipt`, `getReceipt`, `root`, `size`, `snapshot`), `registerStatement`.
- Codec and constants: `encode`, `decode`, `CborTag`, `COSE_SIGN1_TAG`, `DEFAULT_CONTENT_TYPE`.

## Status

Experimental and unaudited. `TransparencyService` is an in-memory reference implementation (it rebuilds the Merkle tree on each registration), suitable for tests and small logs; it is not a production transparency service. The CBOR codec supports only the subset COSE_Sign1 needs (no floats, no indefinite-length items).

## License

MIT - see LICENSE
