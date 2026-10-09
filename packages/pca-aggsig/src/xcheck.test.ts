/**
 * Cross-implementation checks against the independent pure-Python library `py_ecc` 8.0.0
 * (Ethereum Foundation; `G2ProofOfPossession`, the same ciphersuite).
 *
 *  - Direction 1 (fixture): `test-vectors/py_ecc-8.0.0-corpus.json` was produced by py_ecc. Signatures,
 *    PoPs and aggregates must match byte-for-byte, and the aggregates must verify here.
 *  - Direction 2 (live, optional): with `PCA_AGGSIG_XCHECK_PY` set to a Python interpreter that has
 *    py_ecc 8.0.0 installed, artifacts produced HERE are verified by py_ecc, and tampered ones rejected.
 */
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { aggregate, aggregateVerify, fastAggregateVerify, keyGen, popProve, popVerify, publicKeyOf, sign, verify } from './bls';

interface Corpus {
  library: string;
  keys: { sk: string; pk: string; pop: string }[];
  sigs: { key: number; msg: string; sig: string }[];
  aggregateDistinct: { keys: number[]; msgs: string[]; aggregate: string; valid: boolean };
  fastAggregate: { keys: number[]; msg: string; aggregate: string; valid: boolean };
}
const corpus = JSON.parse(readFileSync(join(__dirname, '../test-vectors/py_ecc-8.0.0-corpus.json'), 'utf8')) as Corpus;
const h = hexToBytes;
const hx = bytesToHex;

describe('cross-check vs py_ecc 8.0.0: py_ecc-produced corpus', () => {
  it('is the expected size and includes the edge scalars 1 and r-1 and empty/long messages', () => {
    expect(corpus.library).toBe('py_ecc 8.0.0');
    expect(corpus.keys.length).toBe(5);
    expect(corpus.keys[3]?.sk.endsWith('01')).toBe(true);
    expect(corpus.sigs.some((s) => s.msg === '')).toBe(true);
    expect(corpus.sigs.some((s) => s.msg.length === 2000)).toBe(true);
  });

  it('public keys and proofs-of-possession are byte-identical, and each PoP verifies', () => {
    for (const k of corpus.keys) {
      expect(hx(publicKeyOf(h(k.sk)))).toBe(k.pk);
      expect(hx(popProve(h(k.sk)))).toBe(k.pop);
      expect(popVerify(h(k.pk), h(k.pop))).toBe(true);
    }
  });

  it('signatures are byte-identical and verify', () => {
    for (const s of corpus.sigs) {
      const key = corpus.keys[s.key];
      if (key === undefined) throw new Error('bad corpus');
      expect(hx(sign(h(key.sk), h(s.msg)))).toBe(s.sig);
      expect(verify(h(key.pk), h(s.msg), h(s.sig))).toBe(true);
    }
  });

  it('the distinct-message aggregate is byte-identical and AggregateVerify accepts it', () => {
    const a = corpus.aggregateDistinct;
    const pks = a.keys.map((i) => h(corpus.keys[i]?.pk ?? ''));
    const sigs = a.keys.map((i, n) => sign(h(corpus.keys[i]?.sk ?? ''), h(a.msgs[n] ?? '')));
    expect(hx(aggregate(sigs))).toBe(a.aggregate);
    expect(aggregateVerify(pks, a.msgs.map(h), h(a.aggregate))).toBe(true);
  });

  it('the same-message aggregate is byte-identical and FastAggregateVerify accepts it', () => {
    const f = corpus.fastAggregate;
    const pks = f.keys.map((i) => h(corpus.keys[i]?.pk ?? ''));
    const sigs = f.keys.map((i) => sign(h(corpus.keys[i]?.sk ?? ''), h(f.msg)));
    expect(hx(aggregate(sigs))).toBe(f.aggregate);
    expect(fastAggregateVerify(pks, h(f.msg), h(f.aggregate))).toBe(true);
  });

  it('negative: dropping a signer, swapping a message, or flipping a byte breaks verification', () => {
    const a = corpus.aggregateDistinct;
    const pks = a.keys.map((i) => h(corpus.keys[i]?.pk ?? ''));
    const msgs = a.msgs.map(h);
    expect(aggregateVerify(pks.slice(1), msgs.slice(1), h(a.aggregate))).toBe(false); // missing signer
    const swapped = [...msgs];
    [swapped[0], swapped[1]] = [swapped[1] ?? new Uint8Array(), swapped[0] ?? new Uint8Array()];
    expect(aggregateVerify(pks, swapped, h(a.aggregate))).toBe(false);
    const bad = h(a.aggregate);
    bad[40] = (bad[40] as number) ^ 1;
    expect(aggregateVerify(pks, msgs, bad)).toBe(false);
    // the same message twice is refused outright (distinct-message precondition)
    expect(aggregateVerify([pks[0] as Uint8Array, pks[1] as Uint8Array], [msgs[0] as Uint8Array, msgs[0] as Uint8Array], h(a.aggregate))).toBe(false);
  });
});

const py = process.env.PCA_AGGSIG_XCHECK_PY;
describe.skipIf(py === undefined || py === '')('cross-check vs py_ecc 8.0.0: live, TS-produced artifacts', () => {
  const script = join(__dirname, '../test-vectors/xcheck-py-ecc/xcheck.py');
  const te = new TextEncoder();
  it('py_ecc accepts signatures, PoPs and aggregates produced here, and rejects tampered ones', () => {
    const kps = Array.from({ length: 4 }, () => keyGen());
    const msgs = kps.map((_, i) => te.encode(`ts message ${i}`));
    const sigs = kps.map((k, i) => sign(k.secretKey, msgs[i] as Uint8Array));
    const same = te.encode('ts same message');
    const sameSigs = kps.map((k) => sign(k.secretKey, same));
    const cases = kps.map((k, i) => ({
      pk: hx(k.publicKey), msg: hx(msgs[i] as Uint8Array), sig: hx(sigs[i] as Uint8Array), pop: hx(popProve(k.secretKey)),
    }));
    const tampered = Uint8Array.from(sigs[0] as Uint8Array);
    tampered[10] = (tampered[10] as number) ^ 1;
    cases.push({ ...(cases[0] as (typeof cases)[number]), sig: hx(tampered), pop: hx(popProve((kps[1] as (typeof kps)[number]).secretKey)) });
    const input = {
      cases,
      aggregateDistinct: { pks: kps.map((k) => hx(k.publicKey)), msgs: msgs.map(hx), aggregate: hx(aggregate(sigs)) },
      fastAggregate: { pks: kps.map((k) => hx(k.publicKey)), msg: hx(same), aggregate: hx(aggregate(sameSigs)) },
    };
    const r = spawnSync(py as string, ['-I', script, 'verify'], { input: JSON.stringify(input), encoding: 'utf8' });
    expect(r.status).toBe(0);
    const out = JSON.parse(r.stdout) as {
      results: { sig: boolean | string; pop: boolean | string }[];
      aggregateDistinct: boolean;
      fastAggregate: boolean;
    };
    out.results.slice(0, 4).forEach((x) => expect(x).toEqual({ sig: true, pop: true }));
    expect(out.results[4]).toEqual({ sig: false, pop: false }); // tampered signature, someone else's PoP
    expect(out.aggregateDistinct).toBe(true);
    expect(out.fastAggregate).toBe(true);
  });
});
