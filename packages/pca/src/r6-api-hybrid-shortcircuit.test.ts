/**
 * R6-API-04: a hybrid signature whose Ed25519 half is garbage must be refused WITHOUT running the post-quantum half.
 * Before the fix `verifyWithSuite` computed both halves eagerly, so an unauthenticated route that verifies a hybrid
 * artifact (principal beacons, witness cosignatures, mesh proofs) paid the full PQ cost (26-69x an Ed25519 reject) for junk
 * whose Ed25519 half needs the victim's SECRET key to forge.
 */
import { describe, expect, it } from 'vitest';
import {
  encodeKey,
  encodeMlDsaPublicKey,
  generateKeyPair,
  mlDsa65Keygen,
  mlDsa87Keygen,
  slhDsa128fKeygen,
  slhDsa256sKeygen,
} from './index';
import { issueLivenessBeacon, verifyLivenessBeacon } from './ext/ledger';
import * as pq from './pq';
import { __setVerifiedCoreModeForTests, VERIFIED_CORE_OPT_IN_MODULES, verifiedCoreOptIn } from './verified-core-mode';

const ms = (f: () => unknown, n: number) => {
  const t = process.hrtime.bigint();
  for (let i = 0; i < n; i++) f();
  return Number(process.hrtime.bigint() - t) / 1e6 / n;
};
const garbageEd = Buffer.alloc(64, 7).toString('base64url');

const SUITES = [
  ['hybrid-ed25519-ml-dsa-65', 'mlDsa', () => mlDsa65Keygen(new Uint8Array(32).fill(5))],
  ['hybrid-nested-ed25519-ml-dsa-65', 'mlDsa', () => mlDsa65Keygen(new Uint8Array(32).fill(6))],
  ['hybrid-ed25519-ml-dsa-87', 'mlDsa87', () => mlDsa87Keygen(new Uint8Array(32).fill(5))],
  ['hybrid-ed25519-slh-dsa-sha2-128f', 'slhDsa', () => slhDsa128fKeygen(new Uint8Array(48).fill(5))],
  ['hybrid-ed25519-slh-dsa-sha2-256s', 'slhDsa256s', () => slhDsa256sKeygen(new Uint8Array(96).fill(5))],
] as const;

describe('R6-API-04: verifyWithSuite checks the Ed25519 half first and short-circuits', () => {
  for (const [alg, opt, kg] of SUITES) {
    it(`${alg}: a garbage Ed25519 half is refused at < 25% of a full hybrid verify (no PQ work)`, () => {
      const ed = generateKeyPair();
      const issuer = encodeKey(ed.publicKey);
      const now = Date.now();
      const good = issueLivenessBeacon({ issuerSecret: ed.secretKey, instance: 'inst', scope: '*', seq: 1, issuedAt: now, suite: { alg, [opt]: kg() } as never });
      const forged = { ...good, sig: garbageEd }; // the PQ half is a REAL signature over the same message
      const o = { issuers: [issuer], now, instance: 'inst', pqPins: { [issuer]: good.pq_pk! } } as never;
      expect(verifyLivenessBeacon(good as never, o).ok).toBe(true);
      expect(verifyLivenessBeacon(forged as never, o).ok).toBe(false);
      const slow = alg.includes('slh-dsa-sha2-256s') ? 3 : 8;
      // The timing runs with the opt-in proved wire encoder (PCA_VERIFIED_CORE=wire) switched off; every other opt-in module
      // stays as configured. Reason: the beacon message is canonicalised BEFORE any signature check, and the proved encoder's
      // printer is quadratic in string length (docs/pca/security/verified-core.md, wire layer, "Cost"): the ML-DSA public key in
      // the signed body alone costs ~0.4 s to print, for the good and the forged beacon alike, which hides the PQ verify this test
      // measures (ratio ~0.9 instead of < 0.1). The ordering under test is in pq.ts verifyWithSuite, which no opt-in module
      // touches, and the decisions themselves were checked above in the configured mode.
      const noWire = VERIFIED_CORE_OPT_IN_MODULES.filter((m) => m !== 'wire' && verifiedCoreOptIn(m)).join(',') || 'none';
      let tGood: number;
      let tForged: number;
      try {
        __setVerifiedCoreModeForTests(noWire);
        expect(verifyLivenessBeacon(forged as never, o).ok).toBe(false);
        ms(() => verifyLivenessBeacon(good as never, o), 2); // warm-up
        tGood = ms(() => verifyLivenessBeacon(good as never, o), slow);
        tForged = ms(() => verifyLivenessBeacon(forged as never, o), slow * 4);
      } finally {
        __setVerifiedCoreModeForTests(undefined);
      }
      // eslint-disable-next-line no-console
      console.log(JSON.stringify({ alg, ms_full_verify: +tGood.toFixed(3), ms_garbage_ed_reject: +tForged.toFixed(3), ratio: +(tForged / tGood).toFixed(3) }));
      expect(tForged / tGood).toBeLessThan(0.25);
    });
  }

  it('the decision is unchanged: valid Ed25519 + bad PQ half still fails, both valid passes (fail-closed BOTH required)', () => {
    const ed = generateKeyPair();
    const issuer = encodeKey(ed.publicKey);
    const k = mlDsa65Keygen(new Uint8Array(32).fill(9));
    const now = Date.now();
    const good = issueLivenessBeacon({ issuerSecret: ed.secretKey, instance: 'inst', scope: '*', seq: 1, issuedAt: now, suite: { alg: 'hybrid-ed25519-ml-dsa-65', mlDsa: k } as never });
    const o = { issuers: [issuer], now, instance: 'inst', pqPins: { [issuer]: encodeMlDsaPublicKey(k.publicKey) } } as never;
    expect(verifyLivenessBeacon(good as never, o).ok).toBe(true);
    const other = issueLivenessBeacon({ issuerSecret: ed.secretKey, instance: 'inst', scope: '*', seq: 2, issuedAt: now, suite: { alg: 'hybrid-ed25519-ml-dsa-65', mlDsa: k } as never });
    expect(verifyLivenessBeacon({ ...good, pq_sig: other.pq_sig } as never, o).ok).toBe(false);
    expect(typeof pq.verifyWithSuite).toBe('function');
  });
});
