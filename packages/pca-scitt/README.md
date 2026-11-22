# @atlasauth/pca-scitt

> Maturity: **production**. Breaking changes to APIs or defaults are never made in a patch release. See [maturity tiers](https://github.com/Atlas-Authorization/pca/blob/main/docs/maturity.md).

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
import { verifyReceipt } from '@atlasauth/pca-scitt';
import { TransparencyService } from '@atlasauth/pca-scitt/testing';

const tsKey = generateKeyPairSync('ed25519');     // transparency service
const issuerKey = generateKeyPairSync('ed25519'); // statement issuer (e.g. the resource server)

const service = new TransparencyService({ alg: 'EdDSA', key: tsKey.privateKey, issuer: 'https://ts.example.com' }); // in-memory: tests only, from '@atlasauth/pca-scitt/testing'

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
- Service: `DurableTransparencyService` (`register`, `appendAndReceipt`, `getReceipt`, `getEntry`, `consistencyProof`, `root`, `size`), `FileScittLogStore`, `checkScittLogStore`, `ScittLogError`, `verifyConsistencyProof`. Test doubles on `/testing`: `TransparencyService`, `registerStatement`, `MemoryScittLogStore`.
- Codec and constants: `encode`, `decode`, `CborTag`, `COSE_SIGN1_TAG`, `DEFAULT_CONTENT_TYPE`.

## Durable transparency service

`DurableTransparencyService` is the transparency service to run. All of its state lives in a `ScittLogStore` you supply (`size`, `getEntry`, `getNode`, `append`), with no in-memory default:

```ts
import { DurableTransparencyService, FileScittLogStore, checkScittLogStore } from '@atlasauth/pca-scitt';

const store = FileScittLogStore.open('/var/lib/ts/log.bin');   // single process; use a database-backed store for a fleet
const service = new DurableTransparencyService({ store, alg: 'EdDSA', key: tsKey.privateKey, issuer: 'https://ts.example.com' });
const { receipt, root, index } = await service.register(statement);
const consistency = await service.consistencyProof(oldSize); // verify with verifyConsistencyProof(proof, oldRoot, newRoot)
```

The log keeps the hash of every complete aligned subtree, so an append costs O(log n) store reads and writes, the root costs O(log n), and inclusion and consistency proofs cost O(log^2 n); nothing recomputes the tree. `append` must be a compare-and-set on the size that stores the entry and its new hashes together or not at all; run `checkScittLogStore(() => yourStore)` in your test suite to check that, immutability and a concurrent-append race. `FileScittLogStore` is the reference durable store: one append-only file of checksummed transactions, fsynced, a torn final record dropped on open, corruption elsewhere refused.

The in-memory reference log (`TransparencyService`) and `MemoryScittLogStore` are on `@atlasauth/pca-scitt/testing` only.

## Failure modes

| Missing or wrong | Result |
|---|---|
| No store, or a store without the four methods | `ScittLogError` `store_required` |
| Statement not a COSE_Sign1 with an embedded payload | `bad_statement`, nothing appended |
| Stored subtree hash missing or malformed, entry missing, invalid size | `store_corrupt` |
| The log keeps changing under an append (16 attempts) | `append_contention` |
| Index or size out of range | `out_of_range` |
| `verifyReceipt` with no anchor, a tampered statement, a forged receipt or a wrong root | `false`, never throws |
| Non-canonical CBOR or COSE, high-S ES256 | rejected with a reason |
| `verifyConsistencyProof` with wrong roots or sizes | `false` |

## Limits

- `FileScittLogStore` is single-process and keeps 32 bytes per subtree in memory; replicate or use a database for more.
- Equivocation (two roots for one size) is detectable only by parties that pin roots and compare them; run witnesses.
- The signed consistency-receipt form, RFC 9943 registration policies and a SCITT REST API are not implemented. The receipt leaf is the statement bytes, which RFC 9943 leaves to each service.

## Status

Production. This package is a signer and VERIFIER of statements and receipts. `DurableTransparencyService` over a durable store is the transparency service; the in-memory `TransparencyService` is a test double on `@atlasauth/pca-scitt/testing`, not on the main entry. Verify receipts with `verifyReceipt`.

What is validated:

- CBOR codec: every vector in RFC 8949 Appendix A (82, from the machine-readable `cbor/test-vectors` file) is either decoded and re-encoded byte-for-byte (42) or rejected with a stated reason (40: floats and simple values, indefinite-length items, and integers beyond 2^53). The codec is a deliberately small deterministic profile, not a general CBOR library, and rejects non-minimal integers, unsorted or duplicate map keys and trailing bytes.
- COSE_Sign1: the official `cose-wg/Examples` messages (ES256, Ed25519, Ed448 accepted; the negative cases rejected with the specific reason). It is intentionally stricter than RFC 9052: the algorithm must be in the protected header, `external_aad` is always empty, only the tagged form is accepted, and only `EdDSA` and `ES256` are supported (ES384/ES512 are reported as unsupported).
- Merkle tree: the RFC 9162 tree hash, inclusion verification and consistency verification reproduce the roots of the 8-leaf Certificate Transparency test tree and agree with all 196 inclusion and consistency probes from `transparency-dev/merkle` (valid and invalid).
- Interoperability: statements signed by `pycose` 1.1.0 verify here (EdDSA and ES256); statements and receipts made here are decoded by `cbor2` 5.6.5, their signatures verified by `pycose`, and their roots and inclusion paths reproduced by `pymerkle` 6.1.0.
- Merkle leaves are `SHA-256(0x00 || statement bytes)`, so an off-the-shelf RFC 9162 verifier can check an inclusion proof. Logs and receipts created by releases that hashed the leaf differently (canonical JSON of the base64url statement) do not verify. The CBOR decoder keeps a leading U+FEFF in text strings.

Not validated: the RFC 9942 consistency-receipt (signed) form is not implemented (consistency proofs are available unsigned); there are no vectors for RFC 9943 registration policies, issuer-key discovery or a SCITT REST API; and the receipt leaf definition (statement bytes) is this package's choice, since RFC 9943 leaves the entry format to each transparency service.

## License

MIT - see LICENSE

## Canonical ES256 signatures (low-S)

ECDSA is malleable: `(r, s)` and `(r, n-s)` both verify, so a high-S variant of a Signed Statement would hash to a second Merkle leaf. `signStatement` / the Transparency Service now always emit low-S ES256 signatures and `checkStatement` / `verifyStatement` / `verifyReceipt` reject `s > n/2` (reason `non-canonical signature (high-S)`). Pass `{ allowHighS: true }` (or `allowHighS` in the receipt options) only to ingest third-party material from a non-normalising signer.
