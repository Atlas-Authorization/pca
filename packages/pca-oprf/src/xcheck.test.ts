/**
 * Cross-implementation checks against the independent `voprf` Rust crate v0.5.0 (Meta; built on
 * curve25519-dalek), a different codebase and group implementation from `@noble/curves`.
 *
 *  - Direction 1 (fixture): `test-vectors/voprf-crate-0.5.0-corpus.json` was produced by the crate
 *    (`xcheck-voprf-crate gen`). This implementation must reproduce every byte: key derivation,
 *    blinded/evaluated elements, DLEQ proof (with the pinned nonce) and PRF output.
 *  - Direction 2 (live, optional): when `PCA_OPRF_XCHECK_BIN` points at the built `xcheck-voprf-crate`
 *    binary, messages produced HERE (random blinds and random proof nonces) are fed to the crate, which
 *    must re-evaluate them identically, verify our proofs and finalize to our output.
 */
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { hexToBytes } from '@noble/curves/abstract/utils';
import {
  blind,
  blindEvaluate,
  blindEvaluatePoprf,
  blindPoprf,
  deriveKeyPair,
  evaluate,
  evaluatePoprf,
  finalize,
  finalizePoprf,
  randomKeyPair,
  toHex,
} from './oprf';

interface Case {
  label: string;
  mode: 'oprf' | 'voprf' | 'poprf';
  seed: string;
  keyInfo: string;
  skSm: string;
  pkSm?: string;
  input: string;
  info?: string;
  blind: string;
  proofRandomScalar?: string;
  blindedElement: string;
  evaluatedElement: string;
  proof?: string;
  output: string;
}

const corpus = JSON.parse(
  readFileSync(join(__dirname, '../test-vectors/voprf-crate-0.5.0-corpus.json'), 'utf8'),
) as { cases: Case[] };
const rfc = JSON.parse(
  readFileSync(join(__dirname, '../test-vectors/rfc9497-ristretto255-sha512.json'), 'utf8'),
) as { vectors: { mode: string; n: number; Output: string }[] };
const h = (s: string): Uint8Array => hexToBytes(s);

describe('cross-check vs the independent voprf crate 0.5.0: crate-produced corpus', () => {
  it('the corpus is non-trivial (all modes, varied input lengths incl. 300 bytes and non-ASCII)', () => {
    expect(corpus.cases.length).toBe(21);
    expect(new Set(corpus.cases.map((c) => c.mode))).toEqual(new Set(['oprf', 'voprf', 'poprf']));
    expect(Math.max(...corpus.cases.map((c) => c.input.length / 2))).toBe(300);
  });

  it('the crate itself reproduces the official RFC 9497 vector-1 outputs (so it is a valid reference)', () => {
    for (const c of corpus.cases.filter((x) => x.label === 'rfc9497-A.1-vector-1-params')) {
      const v = rfc.vectors.find((x) => x.mode === c.mode.toUpperCase() && x.n === 1);
      expect(c.output).toBe(v?.Output);
    }
  });

  for (const c of corpus.cases) {
    it(`${c.label} / ${c.mode}: this implementation reproduces every crate byte`, () => {
      const m = c.mode;
      const kp = deriveKeyPair(h(c.seed), h(c.keyInfo), m);
      expect(toHex(kp.secretKey)).toBe(c.skSm);
      if (c.pkSm !== undefined) expect(toHex(kp.publicKey)).toBe(c.pkSm);
      const input = h(c.input);
      if (m === 'oprf' || m === 'voprf') {
        const b = blind(input, m, h(c.blind));
        expect(toHex(b.blindedElement)).toBe(c.blindedElement);
        const e = blindEvaluate(
          h(c.skSm),
          h(c.blindedElement),
          m,
          c.pkSm === undefined ? undefined : h(c.pkSm),
          c.proofRandomScalar === undefined ? undefined : h(c.proofRandomScalar),
        );
        expect(toHex(e.evaluatedElement)).toBe(c.evaluatedElement);
        if (c.proof !== undefined) expect(toHex(e.proof as Uint8Array)).toBe(c.proof);
        const out = finalize(
          input,
          b.blind,
          h(c.evaluatedElement),
          m,
          m === 'voprf'
            ? { proof: h(c.proof as string), publicKey: h(c.pkSm as string), blindedElement: h(c.blindedElement) }
            : undefined,
        );
        expect(toHex(out)).toBe(c.output);
        expect(toHex(evaluate(h(c.skSm), input, m))).toBe(c.output);
      } else {
        const info = h(c.info as string);
        const b = blindPoprf(input, info, h(c.pkSm as string), h(c.blind));
        expect(toHex(b.blindedElement)).toBe(c.blindedElement);
        const e = blindEvaluatePoprf(h(c.skSm), h(c.blindedElement), info, h(c.proofRandomScalar as string));
        expect(toHex(e.evaluatedElement)).toBe(c.evaluatedElement);
        expect(toHex(e.proof as Uint8Array)).toBe(c.proof);
        const out = finalizePoprf(input, b.blind, h(c.evaluatedElement), info, {
          proof: h(c.proof as string),
          blindedElement: h(c.blindedElement),
          tweakedKey: b.tweakedKey,
        });
        expect(toHex(out)).toBe(c.output);
        expect(toHex(evaluatePoprf(h(c.skSm), input, info))).toBe(c.output);
      }
    });
  }
});

const bin = process.env.PCA_OPRF_XCHECK_BIN;
describe.skipIf(bin === undefined || bin === '')('cross-check vs the voprf crate 0.5.0: live, TS-produced messages', () => {
  it('the crate accepts and reproduces messages produced here (random blinds and proof nonces)', () => {
    const te = new TextEncoder();
    const cases: Record<string, string>[] = [];
    for (let i = 0; i < 12; i++) {
      const { secretKey, publicKey } = randomKeyPair();
      const input = te.encode(`agent-capability-${i}-${'x'.repeat(i * 7)}`);
      const info = te.encode(`window-${i}`);
      // oprf
      let b = blind(input, 'oprf');
      let e = blindEvaluate(secretKey, b.blindedElement, 'oprf');
      cases.push({
        mode: 'oprf', skSm: toHex(secretKey), input: toHex(input), blind: toHex(b.blind),
        blindedElement: toHex(b.blindedElement), evaluatedElement: toHex(e.evaluatedElement),
        output: toHex(finalize(input, b.blind, e.evaluatedElement, 'oprf')),
      });
      // voprf
      b = blind(input, 'voprf');
      e = blindEvaluate(secretKey, b.blindedElement, 'voprf', publicKey);
      cases.push({
        mode: 'voprf', skSm: toHex(secretKey), pkSm: toHex(publicKey), input: toHex(input), blind: toHex(b.blind),
        blindedElement: toHex(b.blindedElement), evaluatedElement: toHex(e.evaluatedElement),
        proof: toHex(e.proof as Uint8Array),
        output: toHex(finalize(input, b.blind, e.evaluatedElement, 'voprf', {
          proof: e.proof as Uint8Array, publicKey, blindedElement: b.blindedElement,
        })),
      });
      // poprf
      const pb = blindPoprf(input, info, publicKey);
      const pe = blindEvaluatePoprf(secretKey, pb.blindedElement, info);
      cases.push({
        mode: 'poprf', skSm: toHex(secretKey), pkSm: toHex(publicKey), input: toHex(input), info: toHex(info),
        blind: toHex(pb.blind), blindedElement: toHex(pb.blindedElement), evaluatedElement: toHex(pe.evaluatedElement),
        proof: toHex(pe.proof as Uint8Array),
        output: toHex(finalizePoprf(input, pb.blind, pe.evaluatedElement, info, {
          proof: pe.proof as Uint8Array, blindedElement: pb.blindedElement, tweakedKey: pb.tweakedKey,
        })),
      });
    }
    const r = spawnSync(bin as string, ['verify'], { input: JSON.stringify({ cases }), encoding: 'utf8' });
    expect(r.status).toBe(0);
    const results = (JSON.parse(r.stdout) as { results: { ok: boolean; why: string }[] }).results;
    expect(results.length).toBe(cases.length);
    for (const res of results) expect(res).toMatchObject({ ok: true, why: '' });
  });

  it('negative: the crate rejects a TS proof whose bytes were flipped (reason: proof verification)', () => {
    const te = new TextEncoder();
    const { secretKey, publicKey } = randomKeyPair();
    const input = te.encode('tamper');
    const b = blind(input, 'voprf');
    const e = blindEvaluate(secretKey, b.blindedElement, 'voprf', publicKey);
    const proof = Uint8Array.from(e.proof as Uint8Array);
    proof[3] = (proof[3] as number) ^ 1;
    const c = {
      mode: 'voprf', skSm: toHex(secretKey), pkSm: toHex(publicKey), input: toHex(input), blind: toHex(b.blind),
      blindedElement: toHex(b.blindedElement), evaluatedElement: toHex(e.evaluatedElement),
      proof: toHex(proof), output: '',
    };
    const r = spawnSync(bin as string, ['verify'], { input: JSON.stringify({ cases: [c] }), encoding: 'utf8' });
    const res = (JSON.parse(r.stdout) as { results: { ok: boolean; why: string }[] }).results[0];
    expect(res?.ok).toBe(false);
    expect(res?.why).toMatch(/ProofVerification/);
  });
});
