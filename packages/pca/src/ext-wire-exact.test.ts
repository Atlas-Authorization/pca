// Exact-outcome tests for the wire checks, the settlement planner's balance moves, the in-memory ledger's atomic apply, the
// checkpoint-chain and equivocation catch paths, and the beacon acceptor's stored-value rules. Each assertion is the whole
// result, so a mutation of any guard, boundary or constant changes it.
import { describe, expect, it } from 'vitest';
import { BondSettlementPlanner, applyBondMoves, settlementWireCheck, type BondAccount, type BondHead, type BondView, type SettlementRecord } from './bond-settlement';
import { BondLedger, InMemoryBondAccount } from './bond-ledger-testing';
import { claimCheck, fraudProofWireCheck, openOptimistic, verifyClaim, type BondedClaim, type FraudProof } from './optimistic';
import { TransparencyLedger, detectTreeHeadEquivocation, signTreeHead, verifyCheckpointChain, verifyTreeHead, type SignedTreeHead } from './ledger';
import { createBeaconAcceptor, issueLivenessBeacon, verifyLivenessBeacon } from './beacons';
import { createMemoryDurableKv } from './durable-state';
import { b64u } from './hash';
import { encodeKey, generateKeyPair } from './keys';

const A = generateKeyPair();
const G = generateKeyPair();
const apk = encodeKey(A.publicKey);
const NOW = 1_800_000_000_000;

describe('claimCheck: a throwing digest thunk is malformed, with the thrown text', () => {
  const p = { v: 2, id: 'x', action: { verb: 'pay', resource: 'r', reversibility_class: 'reversible' } };
  const claim = openOptimistic(p as never, { bondRef: 'b', claimedR: 0.5, challengeWindowMs: 60_000, issuedAt: NOW, serverNow: NOW }, A.secretKey);
  it('an Error carries its message; anything else is "unknown"', () => {
    expect(claimCheck(claim, () => { throw new Error('boom'); }, apk, { serverNow: NOW })).toEqual({ check: 'malformed', reason: 'claim verification error: boom' });
    expect(claimCheck(claim, () => { throw 'str'; }, apk, { serverNow: NOW })).toEqual({ check: 'malformed', reason: 'claim verification error: unknown' });
  });
  it('verifyClaim reports an unhashable PCActn the same way and never throws', () => {
    const bad = { v: 2, id: 'y', action: undefined, f: () => 1 };
    const r = verifyClaim(claim, bad as never, apk, { serverNow: NOW });
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/^claim verification error: /);
    expect(verifyClaim(claim, p as never, apk, { serverNow: NOW })).toEqual({ ok: true });
    expect(verifyClaim(null as never, p as never, apk)).toEqual({ ok: false, reason: 'malformed claim' });
  });
});

describe('fraudProofWireCheck: every malformed shape is "malformed", every rule is exact', () => {
  const claim = { pcactn_digest: 'd', bond_ref: 'b', claimed_r: 0.5, reversibility_class: 'reversible', issued_at: 1, challenge_window_ms: 1000, sig: 's' } as BondedClaim;
  const proof = (over: Record<string, unknown> = {}): FraudProof =>
    ({ pcactn_digest: 'd', bond_ref: 'b', claimed_r: 0.5, kind: 'policy-denied', decision: { releaseGuardianShare: false, r: 1, optimisticAllowed: false }, evidence: {}, r_margin: 1e-9, reason: 'x', ...over }) as FraudProof;
  it('the proof and the claim must be objects', () => {
    for (const bad of [null, undefined, 'x', 5, true]) expect(fraudProofWireCheck(claim, bad as never), String(bad)).toBe('malformed');
    for (const bad of [null, undefined, 'x', 5, true]) expect(fraudProofWireCheck(bad as never, proof()), String(bad)).toBe('malformed');
    expect(fraudProofWireCheck(claim, proof())).toBe('ok');
  });
  it('the decision must be an object with two booleans and a finite r', () => {
    const d = { releaseGuardianShare: false, r: 1, optimisticAllowed: false };
    for (const bad of [null, undefined, 'x', 5]) expect(fraudProofWireCheck(claim, proof({ decision: bad })), String(bad)).toBe('malformed');
    for (const bad of [0, 1, 'no', null, undefined]) {
      expect(fraudProofWireCheck(claim, proof({ decision: { ...d, releaseGuardianShare: bad } })), `release ${String(bad)}`).toBe('malformed');
      expect(fraudProofWireCheck(claim, proof({ decision: { ...d, optimisticAllowed: bad } })), `allowed ${String(bad)}`).toBe('malformed');
    }
    for (const bad of ['1', null, undefined, Number.NaN, Number.POSITIVE_INFINITY]) expect(fraudProofWireCheck(claim, proof({ decision: { ...d, r: bad } })), `r ${String(bad)}`).toBe('malformed');
  });
  it('the three identifying strings must be strings', () => {
    for (const bad of [5, null, undefined, {}]) {
      expect(fraudProofWireCheck(claim, proof({ pcactn_digest: bad })), `digest ${String(bad)}`).toBe('malformed');
      expect(fraudProofWireCheck(claim, proof({ bond_ref: bad })), `bond ${String(bad)}`).toBe('malformed');
      expect(fraudProofWireCheck(claim, proof({ reason: bad })), `reason ${String(bad)}`).toBe('malformed');
    }
  });
  it('the checks run in order: digest, bond, claimed_r, kind, consistency', () => {
    expect(fraudProofWireCheck(claim, proof({ pcactn_digest: 'e', bond_ref: 'c', claimed_r: 0.1, kind: 'x' }))).toBe('digest');
    expect(fraudProofWireCheck(claim, proof({ bond_ref: 'c', claimed_r: 0.1, kind: 'x' }))).toBe('bond');
    expect(fraudProofWireCheck(claim, proof({ claimed_r: 0.1, kind: 'x' }))).toBe('claimed_r');
    expect(fraudProofWireCheck(claim, proof({ kind: 'x' }))).toBe('kind');
    expect(fraudProofWireCheck(claim, proof({ decision: { releaseGuardianShare: true, r: 1, optimisticAllowed: false } }))).toBe('consistency');
  });
  it('irreversible: from the claim class or the snapshot evidence, and a missing evidence tree is a consistency failure, not a crash', () => {
    const irr = (evidence: unknown) => fraudProofWireCheck(claim, proof({ kind: 'irreversible', evidence }));
    for (const ev of [undefined, null, {}, { action: null }, { action: {} }, { action: { action: null } }, { action: { action: {} } }, { action: { action: { reversibility_class: 'reversible' } } }]) {
      expect(irr(ev), JSON.stringify(ev)).toBe('consistency');
    }
    expect(irr({ action: { action: { reversibility_class: 'irreversible' } } })).toBe('ok');
    expect(fraudProofWireCheck({ ...claim, reversibility_class: 'irreversible' }, proof({ kind: 'irreversible', evidence: undefined }))).toBe('ok');
  });
  it('risk-understated needs r strictly above claimed_r + margin, and the margin is floored at zero', () => {
    const under = (r: number, margin?: unknown) => fraudProofWireCheck(claim, proof({ kind: 'risk-understated', decision: { releaseGuardianShare: true, r, optimisticAllowed: true }, r_margin: margin }));
    expect(under(0.75, 0.25)).toBe('consistency'); // equal is not above
    expect(under(0.7500001, 0.25)).toBe('ok');
    expect(under(0.5, 0)).toBe('consistency');
    expect(under(0.5000001, 0)).toBe('ok');
    expect(under(0.5000001, -5)).toBe('ok'); // a negative margin counts as zero
    expect(under(0.5000000005)).toBe('consistency'); // missing margin: the 1e-9 default
    expect(under(0.5000000015)).toBe('ok');
    expect(under(0.5000000015, 'x')).toBe('ok'); // a non-numeric margin: the default
  });
});

describe('settlementWireCheck: type guards and the split rules, unsigned records are enough (every check but the signature runs first)', () => {
  const split = { amount: 100, challengerReward: 50, victimCompensation: 40, treasuryRemainder: 10, challengerAccount: 'c', victimAccount: 'v', treasuryAccount: 'treasury' };
  const slash = (over: Record<string, unknown> = {}, sp: Record<string, unknown> = {}): SettlementRecord =>
    ({ claimId: 'b', action: 'slash', amount: 100, from: 'escrow', to: 'treasury', at: 1, evidenceDigest: 'ev', split: { ...split, ...sp }, sig: 's', ...over }) as SettlementRecord;
  const check = (r: SettlementRecord) => settlementWireCheck(r, encodeKey(G.publicKey));
  it('a well-formed unsigned slash gets as far as the signature', () => {
    expect(check(slash())).toBe('signature');
  });
  it('names, amounts, times and digests must have the right type (arrays and objects with a length are not strings)', () => {
    for (const bad of [['abc'], { length: 3 }, 5, null, '']) {
      expect(check(slash({ claimId: bad })), `claimId ${JSON.stringify(bad)}`).toBe('shape');
      expect(check(slash({ from: bad })), `from ${JSON.stringify(bad)}`).toBe('shape');
      expect(check(slash({ to: bad })), `to ${JSON.stringify(bad)}`).toBe('shape');
    }
    for (const bad of ['100', null, undefined, 0, -1, Number.NaN, Number.POSITIVE_INFINITY, true]) expect(check(slash({ amount: bad })), `amount ${String(bad)}`).toBe('shape');
    for (const bad of ['1', null, undefined, Number.NaN, Number.POSITIVE_INFINITY, true]) expect(check(slash({ at: bad })), `at ${String(bad)}`).toBe('shape');
    expect(check(slash({ at: 0 }))).toBe('signature'); // time zero is a number
    expect(check(slash({ at: -5 }))).toBe('signature');
    for (const bad of [5, null, undefined, ['ev'], {}]) expect(check(slash({ evidenceDigest: bad })), `evidence ${JSON.stringify(bad)}`).toBe('shape');
    expect(check(slash({ sig: 5 }))).toBe('shape');
  });
  it('a split member that is not a non-negative finite number, or a name that is not a non-empty string, is a split failure', () => {
    for (const bad of ['50', null, undefined, -1, Number.NaN, Number.POSITIVE_INFINITY, true]) {
      expect(check(slash({}, { challengerReward: bad })), `reward ${String(bad)}`).toBe('split');
      expect(check(slash({}, { victimCompensation: bad })), `victim ${String(bad)}`).toBe('split');
      expect(check(slash({}, { treasuryRemainder: bad })), `treasury ${String(bad)}`).toBe('split');
    }
    for (const bad of [['v'], { length: 1 }, 5, null, '']) {
      expect(check(slash({}, { victimAccount: bad })), `victimAccount ${JSON.stringify(bad)}`).toBe('split');
      expect(check(slash({}, { challengerAccount: bad === null ? 7 : bad })), `challengerAccount ${JSON.stringify(bad)}`).toBe('split');
    }
    expect(check(slash({}, { treasuryAccount: 'other' }))).toBe('split');
    expect(check(slash({}, { amount: 101 }))).toBe('split');
  });
  it('an anonymous split pays the treasury everything: a share too small to change the float sum is still a failure', () => {
    const anon = (sp: Record<string, unknown>) => check(slash({}, { challengerAccount: null, challengerReward: 0, victimCompensation: 0, treasuryRemainder: 100, ...sp }));
    expect(anon({})).toBe('signature');
    expect(anon({ challengerReward: 1e-20 })).toBe('split'); // 1e-20 + 0 + 100 === 100 in doubles: only the explicit zero test catches it
    expect(anon({ victimCompensation: 1e-20 })).toBe('split');
    expect(anon({ treasuryRemainder: 99, victimCompensation: 1 })).toBe('split');
    expect(anon({ treasuryRemainder: 99, challengerReward: 1 })).toBe('split');
  });
  it('a named challenger may be paid nothing, and the sum is exact in doubles', () => {
    expect(check(slash({}, { challengerReward: 0, victimCompensation: 0, treasuryRemainder: 100 }))).toBe('signature');
    expect(check(slash({ amount: 0.3 }, { amount: 0.3, challengerReward: 0.1, victimCompensation: 0.2, treasuryRemainder: 0 }))).toBe('split'); // 0.1 + 0.2 !== 0.3
    expect(check(slash({ amount: 0.3 }, { amount: 0.3, challengerReward: 0.1, victimCompensation: 0.1, treasuryRemainder: 0.1 }))).toBe('split'); // (0.1 + 0.1) + 0.1 !== 0.3
    expect(check(slash({ amount: 0.5 }, { amount: 0.5, challengerReward: 0.25, victimCompensation: 0.125, treasuryRemainder: 0.125 }))).toBe('signature');
  });
});

describe('BondSettlementPlanner: the exact balance moves of every plan', () => {
  const planner = new BondSettlementPlanner({ guardianSecret: G.secretKey });
  const head = (over: Partial<BondHead> = {}): BondHead => ({ claimId: 'c', amount: 250, depositor: 'alice', status: 'open', ...over });
  const view = (bond?: BondHead): BondView => ({ bond: () => bond, balanceOf: () => 1000, openTotals: () => ({ count: 0, sum: 0 }) });
  const claim = { pcactn_digest: 'd', bond_ref: 'c', claimed_r: 0, reversibility_class: 'reversible', issued_at: 1, challenge_window_ms: 1000, sig: 's' } as BondedClaim;
  it('open: the depositor is debited, escrow credited, record at the given time', () => {
    const p = planner.planOpen(view(), { claimId: 'c', amount: 100, depositor: 'alice', now: 5 });
    expect(p.moves).toEqual([{ account: 'alice', op: 'debit', amount: 100 }, { account: 'escrow', op: 'credit', amount: 100 }]);
    expect([p.expect, p.next, p.open]).toEqual(['none', 'open', { amount: 100, depositor: 'alice', maxOpenClaims: 100, maxOpenAmount: Number.POSITIVE_INFINITY }]);
    expect(p.record).toMatchObject({ action: 'open', amount: 100, from: 'alice', to: 'escrow', at: 5, evidenceDigest: '' });
  });
  it('release: escrow is debited, the depositor credited', () => {
    const p = planner.planRelease(view(head()), { claimId: 'c', now: 6 });
    expect(p.moves).toEqual([{ account: 'escrow', op: 'debit', amount: 250 }, { account: 'alice', op: 'credit', amount: 250 }]);
    expect([p.expect, p.next]).toEqual(['open', 'released']);
  });
  it('slash with a named challenger: escrow debited the whole bond, then the three credits in order', () => {
    const p = planner.planSlashOnRevocation(view(head()), { claimId: 'c', claim, revokedCapId: 'cap', treasury: 'treasury', challengerAccount: 'wt', compensationAccount: 'pool', now: 7 });
    expect(p.moves).toEqual([
      { account: 'escrow', op: 'debit', amount: 250 },
      { account: 'wt', op: 'credit', amount: 125 },
      { account: 'pool', op: 'credit', amount: 100 },
      { account: 'treasury', op: 'credit', amount: 25 },
    ]);
    expect([p.expect, p.next]).toEqual(['open', 'slashed']);
  });
  it('anonymous slash: the whole bond to the treasury and nothing else', () => {
    const p = planner.planSlashOnRevocation(view(head()), { claimId: 'c', claim, revokedCapId: 'cap', treasury: 'treasury', now: 7 });
    expect(p.moves).toEqual([{ account: 'escrow', op: 'debit', amount: 250 }, { account: 'treasury', op: 'credit', amount: 250 }]);
  });
  it('a settle plan names the bond phase it expects and refuses a bond that is not open', () => {
    for (const status of ['released', 'slashed'] as const) {
      expect(() => planner.planRelease(view(head({ status })), { claimId: 'c', now: 1 })).toThrow(`releaseBond: bond c is already ${status} (double-settle refused)`);
    }
    expect(() => planner.planRelease(view(), { claimId: 'c', now: 1 })).toThrow('releaseBond: no bond for c');
  });
});

describe('applyBondMoves: exact arithmetic, whole or nothing', () => {
  const bal = (m: Record<string, number>) => (a: string) => m[a] ?? 0;
  it('applies moves in order on an overlay and returns the changed balances', () => {
    const out = applyBondMoves(bal({ a: 10 }), [{ account: 'a', op: 'debit', amount: 4 }, { account: 'b', op: 'credit', amount: 4 }, { account: 'a', op: 'credit', amount: 0.5 }]);
    expect([...out]).toEqual([['a', 6.5], ['b', 4]]);
    expect([...applyBondMoves(bal({ a: 0.1 }), [{ account: 'a', op: 'credit', amount: 0.2 }])]).toEqual([['a', 0.3]]); // micro-exact, not 0.30000000000000004
  });
  it('an invalid amount names its operation; zero is allowed; an overdraft names its account', () => {
    for (const bad of [Number.NaN, -1, Number.POSITIVE_INFINITY]) {
      expect(() => applyBondMoves(bal({}), [{ account: 'a', op: 'credit', amount: bad }])).toThrow('credit: invalid amount');
      expect(() => applyBondMoves(bal({ a: 5 }), [{ account: 'a', op: 'debit', amount: bad }])).toThrow('debit: invalid amount');
    }
    expect([...applyBondMoves(bal({ a: 5 }), [{ account: 'a', op: 'debit', amount: 0 }])]).toEqual([['a', 5]]);
    expect(() => applyBondMoves(bal({ a: 5 }), [{ account: 'a', op: 'debit', amount: 5.000001 }])).toThrow('debit: insufficient balance for a');
    expect([...applyBondMoves(bal({ a: 5 }), [{ account: 'a', op: 'debit', amount: 5 }])]).toEqual([['a', 0]]);
  });
});

describe('BondLedger applies a plan atomically: the overdraft check runs before any account is touched', () => {
  it('an escrow that cannot cover a release is refused with the library message, no credit lands and the bond stays open', () => {
    const calls: string[] = [];
    let broken = false;
    const accounts: BondAccount = {
      balanceOf: (a) => (broken && a === 'escrow' ? 0 : 1000),
      debit: (a, n) => {
        if (broken) throw new Error('custom debit failure');
        calls.push(`debit ${a} ${n}`);
      },
      credit: (a, n) => {
        calls.push(`credit ${a} ${n}`);
      },
    };
    const L = new BondLedger({ guardianSecret: G.secretKey, accounts });
    L.openBond({ claimId: 'c', amount: 100, depositor: 'alice', at: 1 });
    expect(calls).toEqual(['debit alice 100', 'credit escrow 100']);
    broken = true;
    expect(() => L.releaseBond({ claimId: 'c', at: 2 })).toThrow('debit: insufficient balance for escrow');
    expect(calls).toHaveLength(2);
    expect(L.bondStatus('c')).toBe('open');
  });
  it('an open then a release moves exactly the bond and leaves the status released', () => {
    const accounts = new InMemoryBondAccount({ alice: 500 });
    const L = new BondLedger({ guardianSecret: G.secretKey, accounts });
    L.openBond({ claimId: 'c', amount: 120.5, depositor: 'alice', at: 1 });
    expect([accounts.balanceOf('alice'), accounts.balanceOf('escrow')]).toEqual([379.5, 120.5]);
    L.releaseBond({ claimId: 'c', at: 2 });
    expect([accounts.balanceOf('alice'), accounts.balanceOf('escrow'), L.bondStatus('c')]).toEqual([500, 0, 'released']);
  });
});

describe('ledger helpers: the never-throws catch paths', () => {
  const log = new TransparencyLedger('p');
  for (let i = 0; i < 4; i++) log.appendCommitment(b64u(new TextEncoder().encode(`leaf-${i}-padding-padding-padding`)).slice(0, 43));
  const sth = (size: number, root = log.rootAt(size)): SignedTreeHead => signTreeHead(G.secretKey, { instance_id: 'i', principal: 'p', size, root, prev_root: '', timestamp: 1 });
  it('verifyCheckpointChain: a chain whose elements cannot be read is "head" at index 0, never an exception', () => {
    const hostile = new Proxy([sth(2)], {
      get(t, k, r) {
        if (k === 'length') throw new Error('unreadable');
        return Reflect.get(t, k, r);
      },
    });
    expect(verifyCheckpointChain(hostile as never, encodeKey(G.publicKey))).toEqual({ ok: false, at: 0, reason: 'head' });
  });
  it('detectTreeHeadEquivocation: a head that breaks after it verified is "not evidence", never an exception', () => {
    const a = sth(4);
    const b = sth(4, 'a-different-root-a-different-root-a-different-0');
    const gpk = encodeKey(G.publicKey);
    expect(detectTreeHeadEquivocation(a, b, gpk)).toBe(true);
    let reads = 0;
    let limit = Number.POSITIVE_INFINITY;
    const flaky = { ...a } as SignedTreeHead;
    Object.defineProperty(flaky, 'instance_id', {
      enumerable: true,
      get() {
        reads += 1;
        if (reads > limit) throw new Error('breaks late');
        return a.instance_id;
      },
    });
    expect(verifyTreeHead(flaky, gpk)).toBe(true);
    limit = reads; // every later read throws: the ones the equivocation comparison makes after verification
    reads = 0;
    expect(detectTreeHeadEquivocation(flaky, b, gpk)).toBe(false);
  });
});

describe('beacon acceptor: stored values and sequence zero', () => {
  const issue = (seq: number) => issueLivenessBeacon({ issuerSecret: A.secretKey, instance: 'ins', seq, issuedAt: NOW, validityMs: 120_000 });
  const chk = { issuers: [apk], now: NOW + 1, instance: 'ins' };
  it('sequence zero is a valid sequence number: it verifies, it is accepted once, a second zero is a replay', async () => {
    expect(verifyLivenessBeacon(issue(0), chk)).toEqual({ ok: true });
    const acc = createBeaconAcceptor(createMemoryDurableKv());
    expect(await acc.accept(issue(0), chk)).toEqual({ ok: true });
    expect(await acc.accept(issue(0), chk)).toEqual({ ok: false, reason: 'replayed beacon: seq 0 <= 0' });
    expect(await acc.accept(issue(1), chk)).toEqual({ ok: true });
  });
  it('a stored zero is valid state; a stored negative, fractional, huge, string or null value is refused as unavailable', async () => {
    for (const [stored, expected] of [[0, { ok: true }], [-1, { ok: false, reason: 'beacon state unavailable' }], [1.5, { ok: false, reason: 'beacon state unavailable' }], [2 ** 53, { ok: false, reason: 'beacon state unavailable' }], ['3', { ok: false, reason: 'beacon state unavailable' }], [null, { ok: false, reason: 'beacon state unavailable' }]] as const) {
      const kv = createMemoryDurableKv();
      await kv.set(`beacon-seq/v1/${JSON.stringify(['ins', '*', apk])}`, stored);
      expect(await createBeaconAcceptor(kv).accept(issue(1), chk), JSON.stringify(stored)).toEqual(expected);
    }
  });
  it('the constructor names what it needs', () => {
    expect(() => createBeaconAcceptor(undefined as never)).toThrow('createBeaconAcceptor: a DurableKv is required');
    expect(() => createBeaconAcceptor({} as never)).toThrow(TypeError);
  });
});
