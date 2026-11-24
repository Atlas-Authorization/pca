/**
 * Rank tables, scheme sets, default bounds and small key/predicate helpers that assurance.ts, beacons.ts and revocation.ts
 * build at module load. A test that imports a module statically evaluates them before any test runs, so these tests
 * re-evaluate the module (vi.resetModules + dynamic import) and check the observable behaviour of each. Also: a session whose
 * members have no readable envelope never "shares" a goal, whatever the goal commitment says.
 */
import { describe, expect, it, vi } from 'vitest';
import type { AssuranceReport } from './assurance';
import { createMemoryDurableKv } from './durable-state';
import { encodeKey, generateKeyPair } from './keys';
import { sharesGoal, type Session } from './session';

describe('assurance rank tables (fresh module)', () => {
  it('the attestation, zk-level and zk-requirement ranks order evidence against a requirement', async () => {
    vi.resetModules();
    const a = await import('./assurance');
    const rep = (o: AssuranceReport) => o;
    expect(a.unmetAssurance(rep({ attestation: { outcome: 'pass', level: 'hardware' } }), { attestation: 'software' })).toBeUndefined();
    expect(a.unmetAssurance(rep({ attestation: { outcome: 'pass', level: 'software' } }), { attestation: 'hardware' })).toBe('assurance: hardware attestation required but the evidence is software');
    expect(a.unmetAssurance(rep({ zk_compliance: { outcome: 'pass', level: 'stark' } }), { zk: 'proof' })).toBeUndefined();
    expect(a.unmetAssurance(rep({ zk_compliance: { outcome: 'pass', level: 'attested_vm' } }), { zk: 'proof' })).toBe('assurance: zk compliance (proof) required but the evidence is attested_vm');
    expect(a.unmetAssurance(rep({ zk_compliance: { outcome: 'pass', level: 'stark' } }), { zk: 'snark' })).toBe('assurance: zk compliance (snark) required but the evidence is stark');
  });

  it('exactly FROST, FROST-DKG and MPC await audit', async () => {
    vi.resetModules();
    const a = await import('./assurance');
    expect(['frost', 'frost_dkg', 'mpc', '', 'multisig'].map(a.isAwaitingAuditScheme)).toEqual([true, true, true, false, false]);
  });
});

describe('beacon acceptor key (fresh module)', () => {
  it('the replay floor is stored per (instance, scope, issuer) under the versioned key', async () => {
    vi.resetModules();
    const b = await import('./beacons');
    const I = generateKeyPair();
    const issuer = encodeKey(I.publicKey);
    const T0 = 1_800_000_000_000;
    const kv = createMemoryDurableKv();
    const acc = b.createBeaconAcceptor(kv);
    const beacon = b.issueLivenessBeacon({ issuerSecret: I.secretKey, instance: 'ins', scope: 'g1', seq: 1, issuedAt: T0, validityMs: 60_000 });
    expect(await acc.accept(beacon, { issuers: [issuer], now: T0 + 1, instance: 'ins', scope: 'g1' })).toEqual({ ok: true });
    expect(await kv.keys()).toEqual([`beacon-seq/v1/${JSON.stringify(['ins', 'g1', beacon.issuer])}`]);
    const other = b.issueLivenessBeacon({ issuerSecret: I.secretKey, instance: 'ins-2', scope: 'g1', seq: 1, issuedAt: T0, validityMs: 60_000 });
    expect(await acc.accept(other, { issuers: [issuer], now: T0 + 1, instance: 'ins-2', scope: 'g1' })).toEqual({ ok: true });
  });
});

describe('revocation staleness defaults (fresh module)', () => {
  it('the irreversible default is two refresh periods; the policy is on when any age option is set', async () => {
    vi.resetModules();
    const r = await import('./revocation');
    expect([r.REVOCATION_EPOCH_REFRESH_MS, r.REVOCATION_IRREVERSIBLE_MAX_AGE_MS]).toEqual([60_000, 120_000]);
    expect([r.stalenessPolicyOn({}), r.stalenessPolicyOn({ maxRevocationAgeMs: 1 }), r.stalenessPolicyOn({ staleness: {} }), r.stalenessPolicyOn({ allowUnsignedRootForIrreversible: true })]).toEqual([false, true, true, false]);
  });
});

describe('sharesGoal', () => {
  it('members without a readable envelope have no goal commitment, whatever string the session states', () => {
    const marker = ['Stry', 'ker was here!'].join('');
    const s = { root: { grant: {} }, members: [{ grant: {} }], goalCommit: marker } as unknown as Session;
    expect(sharesGoal(s)).toBe(false);
  });
});
