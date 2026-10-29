// Caveat language v2 through the real guard: requirePCA -> verifyPCActn -> decide, with the discharges and narrow block
// presented as headers, and max_uses spent from a replay store after the counter admitted the action.
import { describe, expect, it } from 'vitest';
import { capHash, type Caveat } from './capability';
import { dischargeActionDigest, signDischarge, signNarrow, type DischargePin } from './caveat-lang';
import { b64u as b64uBytes } from './hash';
import { encodeKey, generateKeyPair } from './keys';
import { InMemoryReplayStore } from './replay';
import { memoryPcaStore, requirePCA as requirePCA05 } from './server/require-pca';
import { AUD, NOW, setup } from './server/fixture.test-util';
const requirePCA = (o: Parameters<typeof requirePCA05>[0]): ReturnType<typeof requirePCA05> => requirePCA05({ insecureAllowUnboundOperation: true, multiInstance: false, ...o });
const enc = (v: unknown) => Buffer.from(JSON.stringify(v)).toString('base64url');

const issuer = generateKeyPair();
const PIN: DischargePin = { label: 'risk-team', class: 'human', pk: encodeKey(issuer.publicKey) };
const nd = (o: Partial<Caveat> = {}): Caveat => ({ type: 'needs_discharge', id: 'kyc', issuer: 'risk-team', issuer_class: 'human', bind: 'chain_hop', ttl_ms: 600_000, require: [{ claim: 'kyc_level', op: 'gte', value: 2 }], ...o });
const dis = (cap: string, o: Record<string, unknown> = {}) =>
  signDischarge({ v: 1, kind: 'pca-discharge', caveat_id: 'kyc', issuer: 'risk-team', cap_hash: cap, bind: 'chain_hop', claims: { kyc_level: 3 }, iat: NOW - 1000, not_after: NOW + 1000, nonce: b64uBytes(new Uint8Array(16).fill(5)), ...o } as never, issuer.secretKey);

function world(taskCaveats: Caveat[], extra: Record<string, unknown> = {}) {
  const s = setup({ taskCaveats: taskCaveats as never });
  const guard = requirePCA({
    resolveGrant: async (ref: string) => (ref === s.grant.id ? s.grant : null),
    now: () => NOW,
    audience: AUD,
    context: () => ({ plan: s.plan, planAuthorized: true, risk: s.lowRisk }),
    budgetStore: memoryPcaStore(),
    hooks: { revocation: () => ({ enforced: true, ok: true }) },
    ...extra,
  });
  const p = (counter = 1) => s.mk(s.plan[0]!, { counter });
  const taskHash = (counter = 1) => capHash(p(counter).cap_chain[1]!);
  return { s, guard, p, taskHash };
}

describe('K1 through requirePCA', () => {
  it('a delegated needs_discharge denies without a discharge, naming the caveat', async () => {
    const w = world([nd()], { k1: { pins: [PIN] } });
    const r = await w.guard({ headers: {}, body: { pcactn: w.p() } });
    expect(r.ok).toBe(false);
    expect(!r.ok && r.verdict.checks.delegated_caveats).toBe('fail');
    expect(!r.ok && r.verdict.reasons.join('|')).toContain('no discharge presented');
  });

  it('admits with a discharge presented in PCA-Discharges, bound to the hop that carries the caveat', async () => {
    const w = world([nd()], { k1: { pins: [PIN] } });
    const r = await w.guard({ headers: { 'pca-discharges': enc([dis(w.taskHash())]) }, body: { pcactn: w.p() } });
    expect(r.ok).toBe(true);
  });

  it('refuses a discharge bound to the root hop, a rogue key, an unreadable header and a missing pin', async () => {
    const w = world([nd()], { k1: { pins: [PIN] } });
    const root = capHash(w.s.grant);
    for (const h of [enc([dis(root)]), enc([dis(w.taskHash(), {})].map((d) => ({ ...d, sig: d.sig.replace(/^./, (c) => (c === 'A' ? 'B' : 'A')) }))), '!!!not-base64!!!', enc({ not: 'an array' })]) {
      const r = await w.guard({ headers: { 'pca-discharges': h }, body: { pcactn: w.p() } });
      expect(r.ok).toBe(false);
    }
    const noPins = world([nd()], { k1: { pins: [] } });
    expect((await noPins.guard({ headers: { 'pca-discharges': enc([dis(noPins.taskHash())]) }, body: { pcactn: noPins.p() } })).ok).toBe(false);
    const noK1 = world([nd()]);
    expect((await noK1.guard({ headers: { 'pca-discharges': enc([dis(noK1.taskHash())]) }, body: { pcactn: noK1.p() } })).ok).toBe(false);
  });

  it('a bind-action discharge authorises exactly one PCActn: the verifier computes the action digest itself', async () => {
    const w = world([nd({ bind: 'action' })], { k1: { pins: [PIN] } });
    const p1 = w.p(1);
    const ok = dis(w.taskHash(), { bind: 'action', action_digest: dischargeActionDigest(p1) });
    expect((await w.guard({ headers: { 'pca-discharges': enc([ok]) }, body: { pcactn: p1 } })).ok).toBe(true);
    const p2 = w.p(2);
    const r2 = await w.guard({ headers: { 'pca-discharges': enc([ok]) }, body: { pcactn: p2 } });
    expect(r2.ok).toBe(false);
    expect(!r2.ok && r2.verdict.reasons.join('|')).toContain('bound to another action');
    // a caller-supplied action_digest in k1 is overwritten by the verifier's own
    const forged = world([nd({ bind: 'action' })], { k1: { pins: [PIN], action_digest: dischargeActionDigest(w.p(2)) } });
    const f1 = forged.p(1);
    expect((await forged.guard({ headers: { 'pca-discharges': enc([dis(forged.taskHash(), { bind: 'action', action_digest: dischargeActionDigest(forged.p(2)) })]) }, body: { pcactn: f1 } })).ok).toBe(false);
  });

  it('a sealed leaf hop is fine; derive reads a verified claim', async () => {
    const w = world([{ type: 'sealed' }], { k1: {} });
    expect((await w.guard({ headers: {}, body: { pcactn: w.p() } })).ok).toBe(true);
    const d: Caveat = { type: 'derive', id: 'gate', defs: [{ name: 'kyc', kind: 'claim', caveat_id: 'kyc', claim: 'kyc_level' }], check: { op: 'gte', a: { ref: 'kyc' }, b: { const: 3 } } };
    const w2 = world([nd(), d], { k1: { pins: [PIN] } });
    expect((await w2.guard({ headers: { 'pca-discharges': enc([dis(w2.taskHash())]) }, body: { pcactn: w2.p() } })).ok).toBe(true);
    expect((await w2.guard({ headers: { 'pca-discharges': enc([dis(w2.taskHash(), { claims: { kyc_level: 2 } })]) }, body: { pcactn: w2.p(2) } })).ok).toBe(false);
  });

  it('spiffe_bound compares the SPIFFE ID the guard was given', async () => {
    const id = 'spiffe://acme.test/ns/prod/runtime';
    const yes = world([{ type: 'spiffe_bound', spiffe_id: id }], { k1: { spiffe_id: id } });
    expect((await yes.guard({ headers: {}, body: { pcactn: yes.p() } })).ok).toBe(true);
    const no = world([{ type: 'spiffe_bound', spiffe_id: id }], { k1: { spiffe_id: 'spiffe://acme.test/ns/prod/other' } });
    expect((await no.guard({ headers: {}, body: { pcactn: no.p() } })).ok).toBe(false);
  });

  it('a narrow block in PCA-Narrow adds a restriction the leaf holder chose', async () => {
    const wk = world([], { k1: {} });
    const mine = signNarrow({ v: 1, kind: 'pca-narrow', cap_hash: wk.taskHash(), holder: wk.s.aPub, caveats: [{ type: 'expires', at: NOW + 500 }], iat: NOW - 1, not_after: NOW + 1000, nonce: b64uBytes(new Uint8Array(16).fill(1)) }, wk.s.agentSecret);
    expect((await wk.guard({ headers: { 'pca-narrow': enc(mine) }, body: { pcactn: wk.p() } })).ok).toBe(true);
    const wk2 = world([], { k1: {} });
    const tight = signNarrow({ v: 1, kind: 'pca-narrow', cap_hash: wk2.taskHash(), holder: wk2.s.aPub, caveats: [{ type: 'expires', at: NOW }], iat: NOW - 1, not_after: NOW + 1000, nonce: b64uBytes(new Uint8Array(16).fill(1)) }, wk2.s.agentSecret);
    const r = await wk2.guard({ headers: { 'pca-narrow': enc(tight) }, body: { pcactn: wk2.p() } });
    expect(r.ok).toBe(false);
    expect(!r.ok && r.verdict.checks.delegated_caveats).toBe('fail');
  });

  it('max_uses is spent after the counter admits the action, from the guard usesStore', async () => {
    const until = NOW + 100_000;
    const store = new InMemoryReplayStore();
    const w = world([{ type: 'max_uses', id: 'u', n: 2, until }], { k1: {}, usesStore: store });
    expect((await w.guard({ headers: {}, body: { pcactn: w.p(1) } })).ok).toBe(true);
    expect((await w.guard({ headers: {}, body: { pcactn: w.p(2) } })).ok).toBe(true);
    const third = await w.guard({ headers: {}, body: { pcactn: w.p(3) } });
    expect(third.ok).toBe(false);
    expect(!third.ok && third.verdict.checks.max_uses).toBe('fail');
    expect(!third.ok && third.verdict.reasons.join('|')).toContain("max_uses 'u' is exhausted");
    // a replayed counter never reaches the store: replaying counter 1 burns nothing
    const w2 = world([{ type: 'max_uses', id: 'u', n: 1, until }], { k1: {}, usesStore: new InMemoryReplayStore() });
    expect((await w2.guard({ headers: {}, body: { pcactn: w2.p(1) } })).ok).toBe(true);
    const replay = await w2.guard({ headers: {}, body: { pcactn: w2.p(1) } });
    expect(replay.ok).toBe(false);
    expect(!replay.ok && replay.verdict.checks.max_uses).toBeUndefined();
  });

  it('max_uses without a usesStore is refused (fail closed)', async () => {
    const w = world([{ type: 'max_uses', id: 'u', n: 2, until: NOW + 100_000 }], { k1: {} });
    const r = await w.guard({ headers: {}, body: { pcactn: w.p() } });
    expect(r.ok).toBe(false);
    expect(!r.ok && r.verdict.reasons.join('|')).toContain('no usesStore');
  });

  it('a K1 caveat with no K1 configuration at all is refused, never skipped', async () => {
    for (const c of [nd(), { type: 'derive', id: 'd', defs: [], check: { const: true } }, { type: 'spiffe_bound', spiffe_id: 'spiffe://a.test/x' }] as Caveat[]) {
      const w = world([c]);
      const r = await w.guard({ headers: {}, body: { pcactn: w.p() } });
      expect(r.ok).toBe(false);
      expect(!r.ok && r.verdict.reasons.join('|')).toContain('not configured');
    }
    for (const c of [{ type: 'sealed' }, { type: 'derive', id: 'd', defs: [], check: { const: true } }] as Caveat[]) {
      const w = world([c], { k1: {} }); // configured with nothing but `{}`: these two need no input
      expect((await w.guard({ headers: {}, body: { pcactn: w.p() } })).ok).toBe(true);
    }
  });
});
