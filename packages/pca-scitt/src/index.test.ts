import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { agent, generateKeyPair, type PCActn } from '@atlasauth/pca';
import {
  type CborKey,
  type CborValue,
  CborTag,
  COSE_SIGN1_TAG,
  HDR_ALG,
  HDR_VDS,
  HDR_VDS_PROOFS,
  PROOF_TYPE_INCLUSION,
  TransparencyService,
  VDS_RFC9162_SHA256,
  decode,
  decodeInclusionProof,
  encode,
  registerStatement,
  signStatement,
  statementLeaf,
  statementPayload,
  verifyReceipt,
  verifyStatement,
} from './index';

const AUD = 'ins_scitt_test';

/** Build a fresh signed PCActn (a PCA decision record) via the pca facade. */
function makePCActn(counter: number, resource = 'msg:1'): PCActn {
  const a = agent({ principal: generateKeyPair(), goal: 'g', permissions: { gmail: ['send'] }, aud: AUD });
  const { pcactn } = a.act('gmail.send', resource, {}, { counter });
  return pcactn;
}

function ed25519Keys() {
  return generateKeyPairSync('ed25519');
}

describe('deterministic CBOR codec', () => {
  it('round-trips every supported value type (decode . encode = identity on bytes)', () => {
    const values: CborValue[] = [
      0,
      23,
      24,
      255,
      256,
      65535,
      65536,
      4294967295,
      4294967296,
      -1,
      -24,
      -256,
      -70000,
      true,
      false,
      null,
      '',
      'hello',
      'üñïçödé',
      new Uint8Array([1, 2, 3, 255, 0]),
      [1, 'two', new Uint8Array([3]), [4, 5]],
      new CborTag(COSE_SIGN1_TAG, [new Uint8Array([9]), new Map<CborKey, CborValue>(), new Uint8Array([8]), new Uint8Array([7])]),
    ];
    for (const v of values) {
      const bytes = encode(v);
      const roundtrip = encode(decode(bytes));
      expect([...roundtrip]).toEqual([...bytes]);
    }
  });

  it('orders map keys canonically regardless of insertion order (re-encode equals)', () => {
    const forward = new Map<CborKey, CborValue>();
    forward.set(1, 'a');
    forward.set(3, 'b');
    forward.set(15, 'c');
    forward.set(395, 'd');
    const reversed = new Map<CborKey, CborValue>();
    reversed.set(395, 'd');
    reversed.set(15, 'c');
    reversed.set(3, 'b');
    reversed.set(1, 'a');
    // Insertion order must not matter: canonical encoding is identical.
    expect([...encode(reversed)]).toEqual([...encode(forward)]);
    // And it round-trips: decode re-encodes to the same canonical bytes.
    expect([...encode(decode(encode(reversed)))]).toEqual([...encode(forward)]);
  });

  it('rejects non-canonical input (non-minimal integer) fail-closed', () => {
    // 0x18 0x05 = uint 5 encoded in 2 bytes (non-minimal; canonical is 0x05).
    expect(() => decode(new Uint8Array([0x18, 0x05]))).toThrow();
    // trailing bytes
    expect(() => decode(new Uint8Array([0x01, 0x02]))).toThrow();
    // indefinite-length array (0x9f) unsupported
    expect(() => decode(new Uint8Array([0x9f, 0xff]))).toThrow();
  });

  it('rejects out-of-order / duplicate map keys', () => {
    // map(2) with keys 3 then 1 (descending) — not canonically ordered.
    expect(() => decode(new Uint8Array([0xa2, 0x03, 0x00, 0x01, 0x00]))).toThrow();
    // map(2) with duplicate key 1.
    expect(() => decode(new Uint8Array([0xa2, 0x01, 0x00, 0x01, 0x01]))).toThrow();
  });
});

describe('Signed Statements (COSE_Sign1)', () => {
  it('signs a statement and verifies it; the payload is the canonical PCActn', () => {
    const { publicKey, privateKey } = ed25519Keys();
    const pcactn = makePCActn(1);
    const statement = signStatement(pcactn, { alg: 'EdDSA', key: privateKey, issuer: 'agent://alpha', subject: pcactn.grant_ref });

    expect(verifyStatement(statement, publicKey)).toBe(true);
    // Structurally a tagged COSE_Sign1.
    const top = decode(statement);
    expect(top).toBeInstanceOf(CborTag);

    // Payload bytes are the strict-canonical PCActn JSON.
    const payload = statementPayload(statement);
    const parsed: unknown = JSON.parse(new TextDecoder().decode(payload));
    if (typeof parsed !== 'object' || parsed === null || !('grant_ref' in parsed)) throw new Error('payload not a PCActn');
    expect(parsed.grant_ref).toBe(pcactn.grant_ref);
  });

  it('fails verification under the wrong key', () => {
    const { privateKey } = ed25519Keys();
    const other = ed25519Keys();
    const statement = signStatement(makePCActn(1), { alg: 'EdDSA', key: privateKey, issuer: 'agent://alpha' });
    expect(verifyStatement(statement, other.publicKey)).toBe(false);
  });

  it('works with ES256 as well', () => {
    const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const statement = signStatement(makePCActn(1), { alg: 'ES256', key: privateKey, issuer: 'agent://es' });
    expect(verifyStatement(statement, publicKey)).toBe(true);
  });
});

describe('register -> receipt -> verify inclusion', () => {
  it('registers a statement and the receipt proves inclusion against the ledger root', () => {
    const issuer = ed25519Keys();
    const ts = ed25519Keys();
    const svc = new TransparencyService({ alg: 'EdDSA', key: ts.privateKey, issuer: 'ts://atlas' });

    const statement = signStatement(makePCActn(1), { alg: 'EdDSA', key: issuer.privateKey, issuer: 'agent://alpha' });
    const { receipt, root, index } = registerStatement(statement, svc);

    expect(index).toBe(0);
    expect(root).toBe(svc.root);

    // Receipt is a COSE_Sign1 carrying RFC9162_SHA256 + inclusion proof.
    const top = decode(receipt);
    if (!(top instanceof CborTag) || !Array.isArray(top.value)) throw new Error('bad receipt');
    const protBytes = top.value[0];
    if (!(protBytes instanceof Uint8Array)) throw new Error('bad protected bytes');
    const protMap = decode(protBytes);
    if (!(protMap instanceof Map)) throw new Error('bad protected');
    expect(protMap.get(HDR_ALG)).toBe(-8);
    expect(protMap.get(HDR_VDS)).toBe(VDS_RFC9162_SHA256);
    const unprot = top.value[1];
    if (!(unprot instanceof Map)) throw new Error('bad unprotected');
    const proofs = unprot.get(HDR_VDS_PROOFS);
    if (!(proofs instanceof Map)) throw new Error('bad proofs');
    expect(proofs.has(PROOF_TYPE_INCLUSION)).toBe(true);

    // Full verification: TS signature + statement signature + inclusion proof.
    expect(verifyReceipt(receipt, statement, { treeRoot: root, verificationKey: ts.publicKey, statementKey: issuer.publicKey })).toBe(true);
    // treeRoot-only anchor also works.
    expect(verifyReceipt(receipt, statement, { treeRoot: root })).toBe(true);
    // verificationKey-only anchor (trusts the signed root) also works.
    expect(verifyReceipt(receipt, statement, { verificationKey: ts.publicKey, statementKey: issuer.publicKey })).toBe(true);
  });

  it('appendAndReceipt + getReceipt and inclusion for every entry in a multi-leaf log', () => {
    const issuer = ed25519Keys();
    const ts = ed25519Keys();
    const svc = new TransparencyService({ alg: 'EdDSA', key: ts.privateKey });

    const entries: { statement: Uint8Array }[] = [];
    for (let i = 1; i <= 5; i++) {
      const r = svc.appendAndReceipt(makePCActn(i, `msg:${i}`), { alg: 'EdDSA', key: issuer.privateKey, issuer: 'agent://alpha' });
      expect(r.index).toBe(i - 1);
      entries.push({ statement: r.statement });
    }
    expect(svc.size).toBe(5);

    // Re-issue a receipt for each entry against the final root and verify inclusion.
    const finalRoot = svc.root;
    for (let i = 0; i < 5; i++) {
      const { receipt, root } = svc.getReceipt(i);
      expect(root).toBe(finalRoot);
      expect(verifyReceipt(receipt, entries[i]!.statement, { treeRoot: finalRoot, verificationKey: ts.publicKey, statementKey: issuer.publicKey })).toBe(true);
    }
  });
});

describe('fail-closed', () => {
  function setup() {
    const issuer = ed25519Keys();
    const ts = ed25519Keys();
    const svc = new TransparencyService({ alg: 'EdDSA', key: ts.privateKey });
    const statement = signStatement(makePCActn(1), { alg: 'EdDSA', key: issuer.privateKey, issuer: 'agent://alpha' });
    const { receipt, root } = registerStatement(statement, svc);
    return { issuer, ts, svc, statement, receipt, root };
  }

  it('a tampered statement fails (inclusion binding + signature both break)', () => {
    const { ts, issuer, receipt, root } = setup();
    const forged = signStatement(makePCActn(999, 'msg:evil'), { alg: 'EdDSA', key: issuer.privateKey, issuer: 'agent://alpha' });
    // Different statement bytes => different leaf => inclusion fails against the real root.
    expect(verifyReceipt(receipt, forged, { treeRoot: root, verificationKey: ts.publicKey, statementKey: issuer.publicKey })).toBe(false);

    // Flip a byte in the statement body — not a valid COSE_Sign1 anymore / different leaf.
    const { statement } = setup();
    const mutated = Uint8Array.from(statement);
    const mLast = mutated.length - 1;
    mutated[mLast] = (mutated[mLast] ?? 0) ^ 0xff;
    expect(verifyReceipt(receipt, mutated, { treeRoot: root })).toBe(false);
  });

  it('a forged receipt fails (bad TS signature, and a tampered inclusion proof)', () => {
    const { ts, issuer, statement, receipt, root } = setup();

    // Forge the TS signature: flip the last byte of the receipt's signature.
    const top = decode(receipt);
    if (!(top instanceof CborTag) || !Array.isArray(top.value)) throw new Error('bad receipt');
    const sig = top.value[3];
    if (!(sig instanceof Uint8Array)) throw new Error('bad sig');
    const badSig = Uint8Array.from(sig);
    const sLast = badSig.length - 1;
    badSig[sLast] = (badSig[sLast] ?? 0) ^ 0xff;
    const forgedReceipt = encode(new CborTag(COSE_SIGN1_TAG, [top.value[0]!, top.value[1]!, top.value[2]!, badSig]));
    expect(verifyReceipt(forgedReceipt, statement, { verificationKey: ts.publicKey, statementKey: issuer.publicKey })).toBe(false);

    // Tamper the inclusion proof: a single-leaf log has an EMPTY path, so inject a bogus sibling.
    const unprot = top.value[1];
    if (!(unprot instanceof Map)) throw new Error('bad unprot');
    const forgedProof = encode([1, 0, [new Uint8Array(32)]]); // claims a sibling where there is none
    const forgedProofs = new Map<CborKey, CborValue>();
    forgedProofs.set(PROOF_TYPE_INCLUSION, [forgedProof]);
    const forgedUnprot = new Map<CborKey, CborValue>();
    forgedUnprot.set(HDR_VDS_PROOFS, forgedProofs);
    const receiptBadProof = encode(new CborTag(COSE_SIGN1_TAG, [top.value[0]!, forgedUnprot, top.value[2]!, sig]));
    expect(verifyReceipt(receiptBadProof, statement, { treeRoot: root })).toBe(false);
  });

  it('a wrong root fails', () => {
    const { ts, issuer, statement, receipt } = setup();
    const wrongRoot = statementLeaf(statement).slice(0, 43); // a 32-byte-ish b64u string that is not the real root
    expect(verifyReceipt(receipt, statement, { treeRoot: wrongRoot, verificationKey: ts.publicKey, statementKey: issuer.publicKey })).toBe(false);
  });

  it('requires at least one anchor (no treeRoot and no verificationKey => false)', () => {
    const { statement, receipt, issuer } = setup();
    expect(verifyReceipt(receipt, statement, { statementKey: issuer.publicKey })).toBe(false);
  });

  it('decodeInclusionProof rejects a path length inconsistent with (index,size)', () => {
    // size 1, index 0 must have an empty path; one sibling is invalid.
    expect(() => decodeInclusionProof(encode([1, 0, [new Uint8Array(32)]]))).toThrow();
  });
});
