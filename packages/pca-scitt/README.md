# @atlasauth/pca-scitt

SCITT transparency receipts for Proof-Carrying Authority (RFC 9943 architecture, RFC 9942 COSE Receipts). Each verified PCActn (or verdict) is signed as a COSE Signed Statement (`COSE_Sign1`), appended to an append-only RFC 6962 Merkle log, and returned with a COSE Receipt carrying an RFC 9162 inclusion proof against the log root. A third party can check it with only the statement, the receipt and a pinned root or the transparency service's public key.

Self-contained: a small deterministic CBOR codec (RFC 8949 core-deterministic) and `node:crypto` for signing and hashing. Algorithms: `EdDSA` and `ES256`. The log is an RFC 9162 SHA-256 Merkle tree whose leaf entries are the raw Signed Statement bytes, so an independent RFC 9162 verifier can check a receipt's inclusion proof given the statement bytes. Receipts carry a detached payload, as RFC 9942 recommends.

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

- Statements: `signStatement`, `verifyStatement`, `checkStatement` (returns the failure reason), `statementPayload`, `statementLeaf`.
- Receipts: `buildReceipt`, `verifyReceipt`, `encodeInclusionProof`, `decodeInclusionProof`.
- Service: `TransparencyService` (`register`, `appendAndReceipt`, `getReceipt`, `consistencyProof`, `root`, `size`, `snapshot`), `registerStatement`, `verifyConsistencyProof`.
- Codec and constants: `encode`, `decode`, `CborTag`, `COSE_SIGN1_TAG`, `DEFAULT_CONTENT_TYPE`.

## Status

Experimental and unaudited. `TransparencyService` is an in-memory reference implementation (it recomputes the Merkle tree on each registration), suitable for tests and small logs; it is not a production transparency service.

What is validated:

- CBOR codec: every vector in RFC 8949 Appendix A (82, from the machine-readable `cbor/test-vectors` file) is either decoded and re-encoded byte-for-byte (42) or rejected with a stated reason (40: floats and simple values, indefinite-length items, and integers beyond 2^53). The codec is a deliberately small deterministic profile, not a general CBOR library, and rejects non-minimal integers, unsorted or duplicate map keys and trailing bytes.
- COSE_Sign1: the official `cose-wg/Examples` messages (ES256, Ed25519, Ed448 accepted; the negative cases rejected with the specific reason). It is intentionally stricter than RFC 9052: the algorithm must be in the protected header, `external_aad` is always empty, only the tagged form is accepted, and only `EdDSA` and `ES256` are supported (ES384/ES512 are reported as unsupported).
- Merkle tree: the RFC 9162 tree hash, inclusion verification and consistency verification reproduce the roots of the 8-leaf Certificate Transparency test tree and agree with all 196 inclusion and consistency probes from `transparency-dev/merkle` (valid and invalid).
- Interoperability: statements signed by `pycose` 1.1.0 verify here (EdDSA and ES256); statements and receipts made here are decoded by `cbor2` 5.6.5, their signatures verified by `pycose`, and their roots and inclusion paths reproduced by `pymerkle` 6.1.0.
- Merkle leaves are `SHA-256(0x00 || statement bytes)`, so an off-the-shelf RFC 9162 verifier can check an inclusion proof. Logs and receipts created by releases that hashed the leaf differently (canonical JSON of the base64url statement) do not verify. The CBOR decoder keeps a leading U+FEFF in text strings.

Not validated: the RFC 9942 consistency-receipt (signed) form is not implemented (consistency proofs are available unsigned); there are no vectors for RFC 9943 registration policies, issuer-key discovery or a SCITT REST API; and the receipt leaf definition (statement bytes) is this package's choice, since RFC 9943 leaves the entry format to each transparency service.

## License

MIT - see LICENSE
