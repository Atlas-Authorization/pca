import { describe, expect, it } from 'vitest';
import { bytesToNumberBE } from '@noble/curves/abstract/utils';
import { randomBytes } from '@noble/hashes/utils';
import { G1_BASE, G2_BASE, R, g1Mul, g2Mul, hashAttrToG1, pairingProduct, randomScalar } from '../bls';
import { dudect, leakyEquals } from './_dudect';

/**
 * dudect-style timing-leakage checks for the operations that touch secret material:
 *   - key issuance      D = ((alpha+r)/beta)*g1, D_j = r*g1 + r_j*H(j)   (secret scalars: the randomisers)
 *   - decryption        K = e(D, C_0) * prod e(w*D_j, C_x) ...           (secret: the decryption key points)
 *
 * Heavy runs (thousands of samples) are opt-in: PCA_AUDIT_TIMING=1. The default run only validates the harness
 * (positive control must be flagged, negative control must not) so CI stays fast and non-flaky.
 * See docs/pca/security/audit-abe-ratchet.md for the recorded numbers and the limits of this method in JS.
 */

const HEAVY = process.env['PCA_AUDIT_TIMING'] === '1';
const SAMPLES = Number(process.env['PCA_AUDIT_TIMING_SAMPLES'] ?? 3000);

describe('timing harness validation', () => {
  it('positive control: an early-exit comparison is flagged as leaking (|t| > 10)', () => {
    const secret = new Uint8Array(randomBytes(32));
    const r = dudect(
      'leaky-compare',
      (cls) => (cls === 0 ? secret.slice() : new Uint8Array(32)), // class 0 matches fully, class 1 mismatches at byte 0
      (guess) => leakyEquals(secret, guess),
      { samples: 800, inner: 1 },
    );
    expect(r.maxAbsT).toBeGreaterThan(10);
  });

  it('negative control: identical work on both classes is not flagged', () => {
    const buf = new Uint8Array(randomBytes(64));
    let acc = 0;
    const r = dudect('same-work', () => buf, (b) => { for (let i = 0; i < b.length; i++) acc = (acc + (b[i] ?? 0)) | 0; return acc; }, { samples: 3000, inner: 200 });
    // the bound is deliberately loose: a noisy host can wobble; the point is that it is nowhere near the control's value
    expect(r.maxAbsT).toBeLessThan(20);
  });
});

describe.skipIf(!HEAVY)('secret-dependent operations (PCA_AUDIT_TIMING=1)', () => {
  it('key issuance: fixed low-weight scalar vs random scalar in the D_j / D\'_j scalar multiplications', () => {
    const lowWeight = 3n; // Hamming weight 2
    const h = hashAttrToG1('verb:read');
    const r = dudect('keygen r_j*H(j), r_j*g2', (cls) => (cls === 0 ? lowWeight : randomScalar()), (k) => [g1Mul(h, k), g2Mul(G2_BASE, k)], { samples: SAMPLES });
    console.log(JSON.stringify(r));
    expect(r.maxAbsT).toBeLessThan(30);
  });

  it('decryption: multi-pairing with a fixed key point vs random key points', () => {
    const fixed = g1Mul(G1_BASE, randomScalar());
    const c = g2Mul(G2_BASE, randomScalar());
    const r = dudect(
      'decrypt e(D_j, C)',
      (cls) => (cls === 0 ? fixed : g1Mul(G1_BASE, randomScalar())),
      (d) => pairingProduct([{ g1: d, g2: c }]),
      { samples: Math.min(SAMPLES, 1500) },
    );
    console.log(JSON.stringify(r));
    expect(r.maxAbsT).toBeLessThan(30);
  });

  it('hash-to-curve of the attribute (public input; reported for completeness)', () => {
    const r = dudect('H1(attr)', (cls) => (cls === 0 ? 'verb:read' : 'x' + Math.random()), (a) => hashAttrToG1(a), { samples: SAMPLES });
    console.log(JSON.stringify(r));
    void bytesToNumberBE;
    void R;
  });
});
