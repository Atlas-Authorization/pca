import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  BondLedger,
  InMemoryBondAccount,
  type BondPlan,
  type SettlementRecord,
  verifySettlement,
} from './bond-settlement';
import {
  BondStoreError,
  type BondStoreErrorCode,
  KvBondStore,
  StoreBondLedger,
  commitBondPlan,
  emptyBondDoc,
  sameSettlement,
} from './bond-store';
import { fileFraudProof, openOptimistic, IRREVERSIBLE_CLASS, type BondedClaim, type DisputableInput, type ObjectiveOracle, type OracleResolution } from './optimistic';
import { createMemoryDurableKv, openDurableState, type DurableKv } from './durable-state';
import { mintGrant } from './envelope';
import { buildPCActn, type PCActn } from './pcactn';
import { decide, type DecideInput } from './policy-vm';
import { b64u, hashCanonicalLenient } from './hash';
import { encodeKey, generateKeyPair } from './keys';
import { DEFAULT_RISK_POLICY, type TrustBudget } from './risk';
import type { Capability } from './capability';
import type { PlanNode } from './merkle';

const P = generateKeyPair();
const A = generateKeyPair();
const G = generateKeyPair();
const gpk = encodeKey(G.publicKey);
const apk = encodeKey(A.publicKey);
const NOW = 1_700_000_000_000;
const W = 60_000;
const fresh: TrustBudget = { B: 1, tau: NOW, asOf: NOW };

const GRANT: Capability = mintGrant({
  principalSecret: P.secretKey,
  principalPublic: encodeKey(P.publicKey),
  holder: apk,
  goal: 'secure my account',
  envelope: {
    predicates: [{ verb: 'revoke_session', resource: '/acct/*' }],
    caveats: [{ type: 'expires', at: 9e15 }],
    agent_binding: {},
    risk_policy: DEFAULT_RISK_POLICY,
  },
}).grant;

function actn(verb: string, reversibility_class = 'reversible'): PCActn {
  const nodes: PlanNode[] = [{ id: 'n1', verb, resource: '/acct/1/s', reversibility_class }];
  return buildPCActn({ aud: 'test-aud', grant: GRANT, chain: [GRANT], plan: nodes, nodeId: 'n1', counter: 1, signerSecret: A.secretKey });
}
function decideInputFor(p: PCActn): DecideInput {
  return {
    grant: GRANT,
    chain: [GRANT],
    action: { action: { verb: p.action.verb, resource: p.action.resource, params: {}, reversibility_class: p.action.reversibility_class } },
    risk: { semanticDistance: 0, reversibility: 1, blastRadius: 0, taint: 0, confidence: 1, age: 0 },
    budget: fresh,
    now: NOW,
    nodeId: p.plan.node_id,
  };
}

const clockAt = (t: number) => {
  const c = { t };
  return { c, fn: () => c.t };
};

async function codeOf(p: Promise<unknown> | (() => unknown)): Promise<BondStoreErrorCode | string> {
  try {
    await (typeof p === 'function' ? p() : p);
  } catch (e) {
    return e instanceof BondStoreError ? e.code : `plain:${(e as Error).message}`;
  }
  return 'none';
}

interface Rig {
  L: StoreBondLedger;
  store: KvBondStore;
  kv: DurableKv;
  clock: { t: number };
  p: PCActn;
  claim: BondedClaim;
}
async function rig(opts: { kv?: DurableKv; bondRef?: string; verb?: string; windowMs?: number; issuedAt?: number; claimedR?: number; fund?: number } = {}): Promise<Rig> {
  const kv = opts.kv ?? createMemoryDurableKv();
  const store = new KvBondStore(kv);
  const clock = clockAt(NOW);
  const L = new StoreBondLedger({ guardianSecret: G.secretKey, store, clock: clock.fn });
  await L.deposit('alice', opts.fund ?? 1000);
  const p = actn(opts.verb ?? 'revoke_session');
  const claim = openOptimistic(p, { bondRef: opts.bondRef ?? 'bond-1', claimedR: opts.claimedR ?? 0, challengeWindowMs: opts.windowMs ?? W, issuedAt: opts.issuedAt ?? NOW, serverNow: NOW }, A.secretKey);
  return { L, store, kv, clock: clock.c, p, claim };
}
const open = (r: Rig, amount = 100) => r.L.openClaim({ claim: r.claim, pcactn: r.p, signerPublic: apk, amount, depositor: 'alice' });
const digest = (c: BondedClaim) => hashCanonicalLenient(c);

describe('StoreBondLedger: fail closed when a required component is missing', () => {
  it('no store, a non-store, or no guardian key refuses to construct', async () => {
    const store = new KvBondStore(createMemoryDurableKv());
    expect(await codeOf(() => new StoreBondLedger({ guardianSecret: G.secretKey } as never))).toBe('store_missing');
    expect(await codeOf(() => new StoreBondLedger({ guardianSecret: G.secretKey, store: {} as never }))).toBe('store_missing');
    expect(await codeOf(() => new StoreBondLedger(undefined as never))).toBe('store_missing');
    expect(await codeOf(() => new StoreBondLedger({ store } as never))).toBe('guardian_key_missing');
    expect(await codeOf(() => new StoreBondLedger({ store, guardianSecret: new Uint8Array(0) }))).toBe('guardian_key_missing');
    expect(await codeOf(() => new StoreBondLedger({ store, guardianSecret: 'x' as never }))).toBe('guardian_key_missing');
    expect(await codeOf(() => new KvBondStore(undefined as never))).toBe('store_missing');
  });

  it('a clock that returns a non-finite time fails the operation and writes nothing', async () => {
    const r = await rig();
    const bad = new StoreBondLedger({ guardianSecret: G.secretKey, store: r.store, clock: () => Number.NaN });
    expect(await codeOf(bad.openClaim({ claim: r.claim, pcactn: r.p, signerPublic: apk, amount: 100, depositor: 'alice' }))).toBe('clock_invalid');
    expect(await r.L.bondStatus('bond-1')).toBe('none');
    expect(await r.L.balanceOf('alice')).toBe(1000);
  });

  it('a store that throws surfaces as store_unavailable; a write that never persisted leaves the book untouched and a retry succeeds once', async () => {
    const r = await rig();
    let fail = true;
    const flaky: DurableKv = { ...r.kv, get: (k) => r.kv.get(k), set: (k, v) => r.kv.set(k, v), keys: () => r.kv.keys(), update: (k, fn) => (fail ? Promise.reject(new Error('disk gone')) : r.kv.update(k, fn)) };
    const L2 = new StoreBondLedger({ guardianSecret: G.secretKey, store: new KvBondStore(flaky), clock: () => NOW });
    const params = { claim: r.claim, pcactn: r.p, signerPublic: apk, amount: 100, depositor: 'alice' };
    expect(await codeOf(L2.openClaim(params))).toBe('store_unavailable');
    expect(await L2.bondStatus('bond-1')).toBe('none');
    expect(await L2.balanceOf('alice')).toBe(1000);
    fail = false;
    const rec = await L2.openClaim(params);
    expect(rec.action).toBe('open');
    expect(await L2.balanceOf('alice')).toBe(900);
  });

  it('a lost acknowledgement (committed, then the call failed) is repaired by retrying: the stored record comes back and nothing moves twice', async () => {
    const r = await rig();
    let lose = true;
    const flaky: DurableKv = {
      get: (k) => r.kv.get(k),
      set: (k, v) => r.kv.set(k, v),
      keys: () => r.kv.keys(),
      update: async (k, fn) => {
        const out = await r.kv.update(k, fn);
        if (lose) throw new Error('connection reset after commit');
        return out;
      },
    };
    const L2 = new StoreBondLedger({ guardianSecret: G.secretKey, store: new KvBondStore(flaky), clock: () => NOW });
    const params = { claim: r.claim, pcactn: r.p, signerPublic: apk, amount: 100, depositor: 'alice' };
    expect(await codeOf(L2.openClaim(params))).toBe('store_unavailable');
    expect(await L2.bondStatus('bond-1')).toBe('open'); // it DID commit
    lose = false;
    const again = await L2.openClaim(params);
    const stored = (await L2.getBond('bond-1'))!.records;
    expect(again).toEqual(stored[0]);
    expect(stored).toHaveLength(1);
    expect(await L2.balanceOf('alice')).toBe(900);
  });

  it('a malformed stored document is refused (store_corrupt), never read as an empty book', async () => {
    const kv = createMemoryDurableKv();
    const L = new StoreBondLedger({ guardianSecret: G.secretKey, store: new KvBondStore(kv), clock: () => NOW });
    const key = 'pca-bond-store/v1';
    const row = { claimId: 'c', depositor: 'd', amount: 1, status: 'open', records: [{}] };
    const docs: unknown[] = [
      'not an object',
      { v: 2, balances: [], bonds: [], highWater: 0 },
      { v: 1, balances: 'x', bonds: [], highWater: 0 },
      { v: 1, balances: [], bonds: [], highWater: -1 },
      { v: 1, balances: [], bonds: [], highWater: 'now' },
      { v: 1, balances: [['a', -5]], bonds: [], highWater: 0 },
      { v: 1, balances: [['a']], bonds: [], highWater: 0 },
      { v: 1, balances: [], bonds: [{ ...row, status: 'weird' }], highWater: 0 },
      { v: 1, balances: [], bonds: [{ ...row, records: [] }], highWater: 0 },
      { v: 1, balances: [], bonds: [row, row], highWater: 0 },
    ];
    for (const d of docs) {
      await kv.set(key, d);
      expect(await codeOf(L.bondStatus('c')), JSON.stringify(d)).toBe('store_corrupt');
      expect(await codeOf(L.deposit('a', 1)), JSON.stringify(d)).toBe('store_corrupt'); // the write path refuses too
    }
  });
});

describe('StoreBondLedger: the challenge-window clock', () => {
  it('opens at the ledger clock, never at the claim issued_at (forward-dated within the skew)', async () => {
    const r = await rig({ issuedAt: NOW + 4_000 });
    const rec = await open(r);
    expect(rec.at).toBe(NOW);
    expect((await r.L.getBond('bond-1'))!.window).toEqual({ registeredAt: NOW, windowMs: W, claimDigest: digest(r.claim) });
    expect(await r.L.challengeStatus('bond-1')).toEqual({ phase: 'open', endsAt: NOW + W, now: NOW });
    r.clock.t = NOW + W; // the last instant a challenge is accepted
    expect(await r.L.challengeStatus('bond-1')).toEqual({ phase: 'open', endsAt: NOW + W, now: NOW + W });
    expect(await codeOf(r.L.release('bond-1'))).toBe('window_open');
    r.clock.t = NOW + W + 1;
    expect(await r.L.challengeStatus('bond-1')).toEqual({ phase: 'finalized', endsAt: NOW + W, now: NOW + W + 1 });
    const rel = await r.L.release('bond-1');
    expect(rel).toMatchObject({ action: 'release', claimId: 'bond-1', amount: 100, from: 'escrow', to: 'alice', at: NOW + W + 1, evidenceDigest: '' });
    expect(verifySettlement(rel, gpk)).toBe(true);
  });

  it('a backdated issued_at does not shorten the window', async () => {
    const r = await rig({ issuedAt: NOW - 4_000 });
    await open(r);
    r.clock.t = NOW + W - 3_999; // past issued_at + window, inside registeredAt + window
    expect(await codeOf(r.L.release('bond-1'))).toBe('window_open');
    expect(await r.L.bondStatus('bond-1')).toBe('open');
  });

  it('claim checks: floor, signature, covered action', async () => {
    const r = await rig();
    const short = await rig({ windowMs: 29_999, bondRef: 'bond-short' });
    expect(await codeOf(short.L.openClaim({ claim: short.claim, pcactn: short.p, signerPublic: apk, amount: 100, depositor: 'alice' }))).toBe('invalid_claim');
    const atFloor = await rig({ windowMs: 30_000, bondRef: 'bond-floor' });
    expect((await atFloor.L.openClaim({ claim: atFloor.claim, pcactn: atFloor.p, signerPublic: apk, amount: 100, depositor: 'alice' })).action).toBe('open');
    const other = encodeKey(generateKeyPair().publicKey);
    expect(await codeOf(r.L.openClaim({ claim: r.claim, pcactn: r.p, signerPublic: other, amount: 100, depositor: 'alice' }))).toBe('invalid_claim');
    expect(await codeOf(r.L.openClaim({ claim: { ...r.claim, claimed_r: 0.9 }, pcactn: r.p, signerPublic: apk, amount: 100, depositor: 'alice' }))).toBe('invalid_claim');
    expect(await codeOf(r.L.openClaim({ claim: { ...r.claim, bond_ref: '' }, pcactn: r.p, signerPublic: apk, amount: 100, depositor: 'alice' }))).toBe('invalid_claim');
    expect(await codeOf(r.L.openClaim({ claim: undefined as never, pcactn: r.p, signerPublic: apk, amount: 100, depositor: 'alice' }))).toBe('invalid_claim');
    // an issued_at the ledger's clock sees as out of skew
    const stale = await rig({ bondRef: 'bond-stale' });
    stale.clock.t = NOW + 6_000;
    expect(await codeOf(stale.L.openClaim({ claim: stale.claim, pcactn: stale.p, signerPublic: apk, amount: 100, depositor: 'alice' }))).toBe('invalid_claim');
    expect(await stale.L.bondStatus('bond-stale')).toBe('none');
  });

  it('a clock that steps backwards cannot reopen a closed window or release early', async () => {
    const r = await rig();
    await open(r);
    r.clock.t = NOW + W + 10;
    await r.L.openBond({ claimId: 'counter-1', amount: 10, depositor: 'alice' }); // records the time high-water mark
    r.clock.t = NOW + 5; // the host clock jumps back
    const rel = await r.L.release('bond-1');
    expect(rel.at).toBe(NOW + W + 10); // time is max(clock, high-water)
    // and a challenger cannot use the rewound clock to file late
    const r2 = await rig({ verb: 'exfiltrate', bondRef: 'bond-3' });
    await open(r2);
    const di = decideInputFor(r2.p);
    const proof = fileFraudProof({ claim: r2.claim, pcactn: r2.p, grant: GRANT, actualDecision: decide(di), decideInput: di })!;
    r2.clock.t = NOW + W + 10;
    await r2.L.openBond({ claimId: 'counter-2', amount: 10, depositor: 'alice' });
    r2.clock.t = NOW + 5;
    expect(await codeOf(r2.L.slashBond({ claimId: 'bond-3', claim: r2.claim, fraudProof: proof, grant: GRANT, openSnapshot: di, treasury: 'treasury' }))).toBe('window_closed');
    expect(await r2.L.bondStatus('bond-3')).toBe('open');
  });
});

describe('StoreBondLedger: slashes are gated by the window and the registered claim', () => {
  const fraud = async () => {
    const r = await rig({ verb: 'exfiltrate', bondRef: 'bond-X' }); // not permitted by the envelope: policy-denied
    const di = decideInputFor(r.p);
    const proof = fileFraudProof({ claim: r.claim, pcactn: r.p, grant: GRANT, actualDecision: decide(di), decideInput: di })!;
    expect(proof).not.toBeNull();
    return { r, di, proof };
  };

  it('slashes on a verified fraud proof inside the window, with the challenger split and exact balances', async () => {
    const { r, di, proof } = await fraud();
    await open(r, 250);
    r.clock.t = NOW + 1_000;
    const rec = await r.L.slashBond({ claimId: 'bond-X', claim: r.claim, fraudProof: proof, grant: GRANT, openSnapshot: di, treasury: 'treasury', challengerAccount: 'chal' });
    expect(rec).toMatchObject({ action: 'slash', claimId: 'bond-X', amount: 250, from: 'escrow', to: 'treasury', at: NOW + 1_000 });
    expect(rec.split).toMatchObject({ challengerReward: 125, victimCompensation: 100, treasuryRemainder: 25, challengerAccount: 'chal' });
    expect(verifySettlement(rec, gpk)).toBe(true);
    expect([await r.L.balanceOf('alice'), await r.L.balanceOf('escrow'), await r.L.balanceOf('chal'), await r.L.balanceOf('pca:pool:compensation'), await r.L.balanceOf('treasury')]).toEqual([750, 0, 125, 100, 25]);
    expect(await r.L.bondStatus('bond-X')).toBe('slashed');
  });

  it('refuses a fraud slash after the window closed (window_closed), the bond stays open', async () => {
    const { r, di, proof } = await fraud();
    await open(r, 250);
    r.clock.t = NOW + W + 1;
    expect(await codeOf(r.L.slashBond({ claimId: 'bond-X', claim: r.claim, fraudProof: proof, grant: GRANT, openSnapshot: di, treasury: 'treasury' }))).toBe('window_closed');
    expect(await r.L.bondStatus('bond-X')).toBe('open');
    expect(await r.L.balanceOf('treasury')).toBe(0);
  });

  it('refuses a claim other than the one registered (claim_mismatch) and an unregistered bond', async () => {
    const { r, di, proof } = await fraud();
    await open(r, 250);
    const other = { ...r.claim, claimed_r: 0.5 };
    expect(await codeOf(r.L.slashBond({ claimId: 'bond-X', claim: other, fraudProof: proof, grant: GRANT, openSnapshot: di, treasury: 'treasury' }))).toBe('claim_mismatch');
    expect(await codeOf(r.L.slashBondOnRevocation({ claimId: 'bond-X', claim: other, revokedCapId: 'cap:leaf', treasury: 'treasury' }))).toBe('claim_mismatch');
    await r.L.openBond({ claimId: 'bond-U', amount: 10, depositor: 'alice' });
    const claimU = { ...r.claim, bond_ref: 'bond-U' };
    expect(await codeOf(r.L.release('bond-U'))).toBe('unregistered');
    expect(await codeOf(r.L.slashBond({ claimId: 'bond-U', claim: claimU, fraudProof: proof, grant: GRANT, openSnapshot: di, treasury: 'treasury' }))).toBe('unregistered');
    expect(await codeOf(r.L.releaseUnregistered('bond-X'))).toBe('conflict'); // a registered claim must use release
    expect((await r.L.releaseUnregistered('bond-U')).action).toBe('release');
    expect(await r.L.bondStatus('bond-X')).toBe('open');
  });

  it('a revocation slash is not window-gated (server-derived evidence) and a forged fraud proof is still refused', async () => {
    const r = await rig({ bondRef: 'bond-R' });
    await open(r, 70);
    r.clock.t = NOW + W + 99;
    const rec = await r.L.slashBondOnRevocation({ claimId: 'bond-R', claim: r.claim, revokedCapId: 'cap:leaf', treasury: 'treasury' });
    expect(rec).toMatchObject({ action: 'slash', amount: 70, to: 'treasury', at: NOW + W + 99 });
    const r2 = await rig({ bondRef: 'bond-F' });
    await open(r2, 50);
    const di = decideInputFor(r2.p);
    const forged = { pcactn_digest: r2.claim.pcactn_digest, bond_ref: 'bond-F', claimed_r: 0, kind: 'policy-denied' as const, decision: { releaseGuardianShare: false, r: 1, optimisticAllowed: false }, evidence: {} as never, r_margin: 1e-9, reason: 'fabricated' };
    expect(await codeOf(r2.L.slashBond({ claimId: 'bond-F', claim: r2.claim, fraudProof: forged, grant: GRANT, openSnapshot: di, treasury: 'treasury' }))).toMatch(/^plain:slashBond: refused/);
    expect(await r2.L.bondStatus('bond-F')).toBe('open');
  });

  const stubOracle = (res: Partial<OracleResolution> & { valid: boolean }): ObjectiveOracle => ({ resolve: (input: DisputableInput) => ({ input, ...res }) });

  it('dispute slash and counter-bond slash use the same recomputed verdicts as the in-memory ledger', async () => {
    const r = await rig({ bondRef: 'bond-DG' });
    await open(r, 100);
    const snap = decideInputFor(r.p);
    const dispute = { pcactn_digest: r.claim.pcactn_digest, bond_ref: r.claim.bond_ref, input: 'reversibility_class' as const };
    const rec = await r.L.slashBondOnDispute({ claimId: 'bond-DG', claim: r.claim, dispute, grant: GRANT, openSnapshot: snap, oracle: stubOracle({ valid: true, class: IRREVERSIBLE_CLASS }), treasury: 'treasury', challengerAccount: 'wt', compensationAccount: 'pool:g1' });
    expect(rec.split).toMatchObject({ challengerReward: 50, victimCompensation: 40, treasuryRemainder: 10 });
    // identical decision from the in-memory ledger
    const M = new BondLedger({ guardianSecret: G.secretKey, accounts: new InMemoryBondAccount({ alice: 1000 }) });
    M.openBond({ claimId: 'bond-DG', amount: 100, depositor: 'alice', at: NOW });
    const mrec = M.slashBondOnDispute({ claimId: 'bond-DG', claim: r.claim, dispute, grant: GRANT, openSnapshot: snap, oracle: stubOracle({ valid: true, class: IRREVERSIBLE_CLASS }), treasury: 'treasury', challengerAccount: 'wt', compensationAccount: 'pool:g1', at: NOW });
    expect(rec.evidenceDigest).toBe(mrec.evidenceDigest);
    expect(rec.split).toEqual(mrec.split);
    for (const a of ['alice', 'escrow', 'wt', 'pool:g1', 'treasury']) expect(await r.L.balanceOf(a)).toBe(M.balanceOf(a));

    // frivolous dispute: counter-bond slashed
    const honest = await rig({ bondRef: 'bond-honest' });
    await honest.L.openBond({ claimId: 'counter-1', amount: 20, depositor: 'alice' });
    const hs = decideInputFor(honest.p);
    const hd = { pcactn_digest: honest.claim.pcactn_digest, bond_ref: honest.claim.bond_ref, input: 'reversibility_class' as const };
    const crec = await honest.L.slashCounterBond({ counterBondId: 'counter-1', claim: honest.claim, dispute: hd, grant: GRANT, openSnapshot: hs, oracle: stubOracle({ valid: true, class: 'reversible' }), treasury: 'treasury' });
    expect(crec).toMatchObject({ action: 'slash', claimId: 'counter-1', amount: 20, to: 'treasury' });
    expect(await honest.L.balanceOf('treasury')).toBe(20);
    expect(await honest.L.balanceOf('alice')).toBe(980);
    expect(await codeOf(honest.L.slashCounterBond({ counterBondId: 'nope', claim: honest.claim, dispute: hd, grant: GRANT, openSnapshot: hs, oracle: stubOracle({ valid: true, class: 'reversible' }), treasury: 'treasury' }))).toBe('plain:slashCounterBond: no counter-bond for nope');
  });
});

describe('StoreBondLedger: every transition is idempotent under retry, with exact outcomes', () => {
  const books = async (r: Rig) => [await r.L.balanceOf('alice'), await r.L.balanceOf('escrow'), await r.L.balanceOf('treasury')];

  it('open: the same call returns the original record and takes the collateral once; different terms conflict', async () => {
    const r = await rig();
    const a = await open(r);
    const b = await open(r);
    expect(b).toEqual(a);
    expect(await books(r)).toEqual([900, 100, 0]);
    expect((await r.L.getBond('bond-1'))!.records).toEqual([a]);
    expect(await codeOf(open(r, 101))).toBe('conflict');
    expect(await codeOf(r.L.openClaim({ claim: r.claim, pcactn: r.p, signerPublic: apk, amount: 100, depositor: 'bob' }))).toBe('conflict');
    expect(await books(r)).toEqual([900, 100, 0]);
    // a plain bond: retry returns the record, a different amount conflicts with the standard refusal text
    const c = await r.L.openBond({ claimId: 'plain', amount: 10, depositor: 'alice' });
    expect(await r.L.openBond({ claimId: 'plain', amount: 10, depositor: 'alice' })).toEqual(c);
    expect(await codeOf(r.L.openBond({ claimId: 'plain', amount: 11, depositor: 'alice' }))).toBe('conflict');
  });

  it('release: the same call returns the stored record; a slash afterwards is refused', async () => {
    const r = await rig();
    await open(r);
    r.clock.t = NOW + W + 1;
    const a = await r.L.release('bond-1');
    r.clock.t = NOW + W + 500; // a later retry still returns the FIRST record (its time included)
    expect(await r.L.release('bond-1')).toEqual(a);
    expect(a.at).toBe(NOW + W + 1);
    expect(await books(r)).toEqual([1000, 0, 0]);
    expect((await r.L.getBond('bond-1'))!.records).toHaveLength(2);
    expect(await codeOf(r.L.slashBondOnRevocation({ claimId: 'bond-1', claim: r.claim, revokedCapId: 'cap:leaf', treasury: 'treasury' }))).toBe('plain:slashBondOnRevocation: bond bond-1 is already released (double-settle refused)');
  });

  it('slash: the same call returns the stored record; a different evidence or a release afterwards is refused', async () => {
    const r = await rig();
    await open(r);
    const s = { claimId: 'bond-1', claim: r.claim, revokedCapId: 'cap:leaf', treasury: 'treasury', challengerAccount: 'wt' };
    const a = await r.L.slashBondOnRevocation(s);
    expect(await r.L.slashBondOnRevocation(s)).toEqual(a);
    expect(await books(r)).toEqual([900, 0, 10]);
    expect(await r.L.balanceOf('wt')).toBe(50);
    expect(await codeOf(r.L.slashBondOnRevocation({ ...s, revokedCapId: 'cap:other' }))).toBe('plain:slashBondOnRevocation: bond bond-1 is already slashed (double-settle refused)');
    r.clock.t = NOW + W + 1;
    expect(await codeOf(r.L.release('bond-1'))).toBe('plain:releaseBond: bond bond-1 is already slashed (double-settle refused)');
    expect(await books(r)).toEqual([900, 0, 10]);
  });

  it('a retry that arrives after the window and after the slash still returns the slash (fraud proof path)', async () => {
    const r = await rig({ verb: 'exfiltrate', bondRef: 'bond-X' });
    await open(r, 250);
    const di = decideInputFor(r.p);
    const proof = fileFraudProof({ claim: r.claim, pcactn: r.p, grant: GRANT, actualDecision: decide(di), decideInput: di })!;
    const s = { claimId: 'bond-X', claim: r.claim, fraudProof: proof, grant: GRANT, openSnapshot: di, treasury: 'treasury' };
    const a = await r.L.slashBond(s);
    r.clock.t = NOW + W + 1;
    expect(await r.L.slashBond(s)).toEqual(a);
    expect(await books(r)).toEqual([750, 0, 250]);
  });

  it('two racing identical releases: one commits, one is a replay, funds move once', async () => {
    const r = await rig();
    await open(r);
    r.clock.t = NOW + W + 1;
    const [x, y] = await Promise.all([r.L.release('bond-1'), r.L.release('bond-1')]);
    expect(sameSettlement(x, y)).toBe(true);
    expect((await r.L.getBond('bond-1'))!.records).toHaveLength(2);
    expect(await books(r)).toEqual([1000, 0, 0]);
  });

  it('a release racing a slash: exactly one wins and the books conserve', async () => {
    const r = await rig();
    await open(r);
    r.clock.t = NOW + W + 1;
    const res = await Promise.allSettled([r.L.release('bond-1'), r.L.slashBondOnRevocation({ claimId: 'bond-1', claim: r.claim, revokedCapId: 'cap:leaf', treasury: 'treasury' })]);
    expect(res.map((x) => x.status).sort()).toEqual(['fulfilled', 'rejected']);
    const [alice, escrow, treasury] = await books(r);
    expect(escrow).toBe(0);
    expect(alice! + treasury!).toBe(1000);
    expect([[1000, 0, 0], [900, 0, 100]]).toContainEqual([alice, escrow, treasury]);
  });
});

describe('commitBondPlan: the reference transition function', () => {
  const rec = (over: Partial<SettlementRecord> = {}): SettlementRecord => ({ claimId: 'b', action: 'release', amount: 5, from: 'escrow', to: 'a', at: 1, evidenceDigest: '', sig: 's', ...over });
  const openPlan = (over: Partial<NonNullable<BondPlan['open']>> = {}): BondPlan => ({
    claimId: 'b',
    expect: 'none',
    next: 'open',
    open: { amount: 5, depositor: 'a', maxOpenClaims: 2, maxOpenAmount: 8, ...over },
    moves: [
      { account: 'a', op: 'debit', amount: 5 },
      { account: 'escrow', op: 'credit', amount: 5 },
    ],
    record: rec({ action: 'open', from: 'a', to: 'escrow' }),
  });

  it('refuses an overdraft at commit time even when the planner saw a stale balance, leaving the doc untouched', () => {
    const d = emptyBondDoc();
    d.balances.set('a', 3);
    expect(commitBondPlan(d, openPlan(), 9)).toEqual({ outcome: 'conflict', reason: 'debit: insufficient balance for a', current: 'none' });
    expect([d.balances.get('a'), d.balances.get('escrow'), d.bonds.size, d.highWater]).toEqual([3, undefined, 0, 0]);
  });

  it('re-checks the per-depositor caps under the store atomicity', () => {
    const d = emptyBondDoc();
    d.balances.set('a', 100);
    expect(commitBondPlan(d, openPlan(), 1).outcome).toBe('committed');
    expect(commitBondPlan(d, { ...openPlan(), claimId: 'b2', record: rec({ claimId: 'b2', action: 'open' }) }, 2)).toEqual({ outcome: 'conflict', reason: 'depositor aggregate open-bond cap exceeded', current: 'none' });
    const d2 = emptyBondDoc();
    d2.balances.set('a', 100);
    const p = openPlan({ maxOpenClaims: 1, maxOpenAmount: 1000 });
    expect(commitBondPlan(d2, p, 1).outcome).toBe('committed');
    expect(commitBondPlan(d2, { ...p, claimId: 'b2', record: rec({ claimId: 'b2', action: 'open' }) }, 2)).toEqual({ outcome: 'conflict', reason: 'depositor open-claim cap reached', current: 'none' });
  });

  it('settling an absent bond, or from the wrong phase, is a conflict naming the current phase; time only moves forward', () => {
    const d = emptyBondDoc();
    const rel: BondPlan = { claimId: 'b', expect: 'open', next: 'released', moves: [], record: rec() };
    expect(commitBondPlan(d, rel, 1)).toEqual({ outcome: 'conflict', reason: 'no bond for b', current: 'none' });
    d.balances.set('a', 10);
    commitBondPlan(d, openPlan(), 50);
    expect(d.highWater).toBe(50);
    expect(commitBondPlan(d, { ...rel, moves: [{ account: 'escrow', op: 'debit', amount: 5 }, { account: 'a', op: 'credit', amount: 5 }] }, 20).outcome).toBe('committed');
    expect(d.highWater).toBe(50); // 20 < 50
    expect(commitBondPlan(d, { ...rel, record: rec({ evidenceDigest: 'x' }) }, 60)).toEqual({ outcome: 'conflict', reason: 'bond b is already released', current: 'released' });
    expect(d.highWater).toBe(50);
    expect(commitBondPlan(d, { ...openPlan() }, 1).outcome).toBe('replayed');
    expect(commitBondPlan(d, { ...openPlan({ amount: 6 }) }, 1)).toEqual({ outcome: 'conflict', reason: 'bond b already exists', current: 'released' });
  });

  it('a malformed open plan is a conflict, never a throw', () => {
    expect(commitBondPlan(emptyBondDoc(), { ...openPlan(), open: undefined }, 1)).toEqual({ outcome: 'conflict', reason: 'malformed open plan', current: 'none' });
    expect(commitBondPlan(emptyBondDoc(), { ...openPlan(), next: 'released' }, 1)).toEqual({ outcome: 'conflict', reason: 'malformed open plan', current: 'none' });
  });

  it('account and claim names that look like object internals are plain keys', async () => {
    const kv = createMemoryDurableKv();
    const L = new StoreBondLedger({ guardianSecret: G.secretKey, store: new KvBondStore(kv), clock: () => NOW });
    await L.deposit('__proto__', 50);
    const rec2 = await L.openBond({ claimId: '__proto__', amount: 20, depositor: '__proto__' });
    expect(rec2).toMatchObject({ claimId: '__proto__', from: '__proto__', amount: 20 });
    expect(await L.balanceOf('__proto__')).toBe(30);
    expect(await L.bondStatus('__proto__')).toBe('open');
    expect(({} as Record<string, unknown>)['amount']).toBeUndefined();
  });
});

describe('KvBondStore: deposit validation', () => {
  it('only positive finite amounts and non-empty accounts', async () => {
    const s = new KvBondStore(createMemoryDurableKv());
    expect(await s.deposit('a', 2.5)).toBe(2.5);
    expect(await s.deposit('a', 0.5)).toBe(3);
    for (const bad of [0, -1, Number.NaN, Number.POSITIVE_INFINITY]) await expect(s.deposit('a', bad)).rejects.toThrow(RangeError);
    await expect(s.deposit('', 1)).rejects.toThrow(RangeError);
    expect((await s.read({ claimId: '', depositor: 'a' })).balances).toEqual([['a', 3]]);
  });
});

// ---- crash recovery on the durable reference store ----------------------------------------------------------

const PKG = resolve(__dirname, '..');
const WORKER = join(__dirname, 'test-support', 'bond-crash-worker.ts');
const dirs: string[] = [];
afterEach(() => {
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});
const tmp = () => {
  const d = mkdtempSync(join(tmpdir(), 'pca-bond-'));
  dirs.push(d);
  return d;
};

describe('crash recovery between "claim open" and "slash" (durable-state store)', () => {
  it('a process that dies after the claim opened comes back with the bond open and escrow intact; the slash then lands exactly once, and a retry replays it', async () => {
    const dir = tmp();
    const r0 = await rig({ kv: await openDurableState({ dir }), bondRef: 'bond-9' });
    await open(r0, 200);
    // the process "crashes": every in-memory object is dropped; only the directory remains
    const kv1 = await openDurableState({ dir });
    const L1 = new StoreBondLedger({ guardianSecret: G.secretKey, store: new KvBondStore(kv1), clock: () => NOW + 10 });
    expect([await L1.bondStatus('bond-9'), await L1.balanceOf('alice'), await L1.balanceOf('escrow')]).toEqual(['open', 800, 200]);
    const slash = await L1.slashBondOnRevocation({ claimId: 'bond-9', claim: r0.claim, revokedCapId: 'cap:leaf', treasury: 'treasury' });
    expect(slash).toMatchObject({ action: 'slash', amount: 200, at: NOW + 10 });
    // crash again, after the slash but before the caller saw the answer: the retry gets the same record
    const L2 = new StoreBondLedger({ guardianSecret: G.secretKey, store: new KvBondStore(await openDurableState({ dir })), clock: () => NOW + 20 });
    expect(await L2.slashBondOnRevocation({ claimId: 'bond-9', claim: r0.claim, revokedCapId: 'cap:leaf', treasury: 'treasury' })).toEqual(slash);
    expect([await L2.bondStatus('bond-9'), await L2.balanceOf('alice'), await L2.balanceOf('escrow'), await L2.balanceOf('treasury')]).toEqual(['slashed', 800, 0, 200]);
    expect((await L2.getBond('bond-9'))!.records).toHaveLength(2);
  });

  const killed = (dir: string, crashAt: string, claim: BondedClaim) =>
    new Promise<{ code: number | null; signal: NodeJS.Signals | null; out: string }>((res) => {
      const c = spawn(process.execPath, ['--import', 'tsx', WORKER, dir, crashAt, b64u(G.secretKey), JSON.stringify(claim), String(NOW + 30)], { cwd: PKG });
      let out = '';
      c.stdout.on('data', (b: Buffer) => (out += b.toString()));
      c.on('close', (code, signal) => res({ code, signal, out }));
    });

  for (const [crashAt, committed] of [['after-temp-write', false], ['after-journal-rename', true]] as const) {
    it(`SIGKILL ${crashAt}: the slash is ${committed ? 'fully applied' : 'not applied at all'} after recovery, never half, and retrying finishes the job exactly once`, async () => {
      const dir = tmp();
      const r0 = await rig({ kv: await openDurableState({ dir }), bondRef: 'bond-k' });
      await open(r0, 200);
      const run = await killed(dir, crashAt, r0.claim);
      expect(run.signal).toBe('SIGKILL');
      expect(run.out).toBe('');
      const L = new StoreBondLedger({ guardianSecret: G.secretKey, store: new KvBondStore(await openDurableState({ dir })), clock: () => NOW + 40 });
      const before = [await L.bondStatus('bond-k'), await L.balanceOf('alice'), await L.balanceOf('escrow'), await L.balanceOf('treasury')];
      expect(before).toEqual(committed ? ['slashed', 800, 0, 200] : ['open', 800, 200, 0]);
      const rec = await L.slashBondOnRevocation({ claimId: 'bond-k', claim: r0.claim, revokedCapId: 'cap:leaf', treasury: 'treasury' });
      expect(rec.at).toBe(committed ? NOW + 30 : NOW + 40); // a committed slash keeps the dead process's record
      expect([await L.bondStatus('bond-k'), await L.balanceOf('alice'), await L.balanceOf('escrow'), await L.balanceOf('treasury')]).toEqual(['slashed', 800, 0, 200]);
      expect((await L.getBond('bond-k'))!.records).toHaveLength(2);
    }, 60_000);
  }
});
