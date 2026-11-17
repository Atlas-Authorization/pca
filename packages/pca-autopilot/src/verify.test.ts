import { describe, expect, it } from 'vitest';
import { b64u, generateKeyPair, readEnvelope } from '@atlasauth/pca';
import { ingestText } from './ingest';
import { amend, tighten } from './continuous';
import { summarize } from './review';
import { approvalChallenge, issueGrant, reportIntact, signApproval, verifyApproval } from './signoff';
import { propose } from './synth';
import { verifyProposal } from './verify';
import { DAY, NOW, benign, jsonl, row } from './test-support/fixtures';

const set = (rows: string[]) => ingestText(jsonl(rows));

describe('verifyProposal', () => {
  it('replays every included trace through the real verifier and passes a faithful proposal', async () => {
    const s = set(benign());
    const p = propose(s, { now: NOW });
    const r = await verifyProposal(p, s);
    expect(r.replay.total).toBe(6);
    expect(r.replay.failures).toEqual([]);
    expect(r.replay.ok).toBe(true);
    expect(r.ok).toBe(true);
    expect(reportIntact(r)).toBe(true);
  });

  it('is deterministic: the same proposal and traces give a byte-identical report', async () => {
    const s = set(benign());
    const p = propose(s, { now: NOW });
    expect((await verifyProposal(p, s)).digest).toBe((await verifyProposal(p, s)).digest);
  });

  it('fails when a trace is not admitted (a proposal narrowed after the fact is caught by the digest, not trusted)', async () => {
    const s = set(benign());
    const p = propose(s, { now: NOW });
    const narrowed = { ...p, policy: { ...p.policy, predicates: [{ verb: 'gmail.draft', resource: '/drafts/1' }] } };
    const r = await verifyProposal(narrowed, s);
    expect(r.intact).toBe(false);
    expect(r.ok).toBe(false);
  });

  it('fails when the traces are not the ones the proposal was built from', async () => {
    const p = propose(set(benign()), { now: NOW });
    const other = set([...benign(), row(40)]);
    expect((await verifyProposal(p, other)).basisMatches).toBe(false);
    expect((await verifyProposal(p, other)).ok).toBe(false);
  });

  it('reports, per trace, an observed action the policy does not admit (the check is not a rubber stamp)', async () => {
    const base = propose(set(benign()), { now: NOW });
    const obs = set([...benign(), row(70, { resource: '/other/1' }), ...Array.from({ length: 3 }, (_, i) => row(100 + i, { resource: '/mail/x', outcome: 'deny' }))]);
    const a = amend(base, obs, { now: NOW });
    const r = await verifyProposal(a, obs);
    expect(r.replay.ok).toBe(false);
    expect(r.ok).toBe(false);
    expect(r.replay.failures.map((f) => f.resource)).toEqual(['/other/1']);
  });

  it('reports excess authority: generalization, the margin and the rate, not just a pass', async () => {
    const s = set(benign());
    const r = await verifyProposal(propose(s, { now: NOW }), s);
    const text = r.excess.summary.join('\n');
    expect(text).toMatch(/every resource under that parent/);
    expect(text).toMatch(/20% margin/);
    expect(text).toMatch(/per 3600s/);
    // the analyzer probes a trailing-* rule with 'parent/' and 'parent/x': a resource nobody used is admitted
    expect(r.excess.witnesses.some((w) => w.kinds.includes('off-scope') && w.resource.startsWith('/drafts/'))).toBe(true);
  });

  it('diffs against the policy in force and says when the proposal is wider', async () => {
    const s = set(benign());
    const p = propose(s, { now: NOW });
    const existing = { predicates: [{ verb: 'gmail.draft', resource: '/drafts/1' }], caveats: [] };
    const r = await verifyProposal(p, s, { existing });
    expect(r.diff).toBeDefined();
    expect(r.diff!.widens).toBe(true);
    const text = summarize(p, r);
    expect(text).toMatch(/COMPARED WITH THE POLICY IN FORCE/);
  });

  it('lints the policy and never reports a lint crash as a pass', async () => {
    const s = set([...benign(), row(30, { verb: 'gmail.delete', resource: '/drafts/1', params: {} })]);
    const id = propose(s, { now: NOW }).heldBack[0]!.id;
    const p = propose(s, { now: NOW, confirmed: [id] });
    const r = await verifyProposal(p, s);
    expect(r.lint.some((f) => f.rule === 'internal-error')).toBe(false);
  });
});

describe('sign-off: a proposal is not authority until a pinned reviewer signs this exact proposal and report', () => {
  const setup = async (o: { confirmed?: boolean } = {}) => {
    const s = set([...benign(), row(30, { verb: 'gmail.delete', resource: '/drafts/1', params: {} })]);
    const held = propose(s, { now: NOW }).heldBack[0]!.id;
    const p = propose(s, { now: NOW, ...(o.confirmed ? { confirmed: [held] } : {}) });
    const report = await verifyProposal(p, s);
    const reviewer = generateKeyPair();
    return { s, p, report, reviewer, pub: b64u(reviewer.publicKey), held };
  };

  it('a signed approval verifies; the grant carries exactly the proposal and nothing else', async () => {
    const { p, report, reviewer, pub } = await setup();
    const a = signApproval(reviewer.secretKey, p, report, { at: NOW });
    expect(verifyApproval(a, p, report, { principals: [pub], now: NOW + 1000 })).toEqual({ ok: true, principal: pub, method: 'key' });
    const holder = generateKeyPair();
    const g = issueGrant(p, report, a, { principalSecret: reviewer.secretKey, holder: b64u(holder.publicKey), goal: 'draft mail', principals: [pub], now: NOW + 1000 });
    const env = readEnvelope(g.grant)!;
    expect(env.predicates).toEqual(p.policy.predicates);
    expect(env.caveats).toEqual(p.policy.caveats);
    expect(env.risk_policy).toEqual(p.riskPolicy);
    expect(g.approvedBy).toBe(pub);
  });

  it('refuses to sign or issue for a proposal or report that did not verify or was edited', async () => {
    const { p, report, reviewer, pub } = await setup();
    const bad = { ...report, ok: false };
    expect(() => signApproval(reviewer.secretKey, p, bad, { at: NOW })).toThrow(/not for this proposal|did not verify/);
    expect(() => signApproval(reviewer.secretKey, { ...p, margin: 9 }, report, { at: NOW })).toThrow(/modified/);
    const failedReport = await verifyProposal({ ...p, margin: 9 }, set(benign()));
    expect(() => signApproval(reviewer.secretKey, p, failedReport, { at: NOW })).toThrow();
    const a = signApproval(reviewer.secretKey, p, report, { at: NOW });
    expect(() => issueGrant({ ...p, margin: 9 }, report, a, { principalSecret: reviewer.secretKey, holder: pub, goal: 'g', principals: [pub], now: NOW })).toThrow(/grant not issued/);
  });

  it('refuses an unpinned signer, an expired or future approval, another proposal, and a swapped confirmation list', async () => {
    const { s, p, report, reviewer, pub, held } = await setup();
    const a = signApproval(reviewer.secretKey, p, report, { at: NOW, ttlMs: 60_000 });
    const ok = (x: unknown, pr = p, rep = report, now = NOW + 1000, principals = [pub]) => verifyApproval(x, pr, rep, { principals, now }).ok;
    expect(ok(a)).toBe(true);
    expect(ok(a, p, report, NOW + 61_000)).toBe(false);
    expect(ok(a, p, report, NOW - 1)).toBe(false);
    expect(ok(a, p, report, NOW + 1000, [b64u(generateKeyPair().publicKey)])).toBe(false);
    const p2 = propose(s, { now: NOW, margin: 0.5 });
    expect(ok(a, p2, await verifyProposal(p2, s))).toBe(false);
    expect(ok({ ...a, confirmed: [held] })).toBe(false);
    expect(ok({ ...a, expires_at: a.expires_at + 3_000_000 })).toBe(false); // the signature covers the window
    expect(ok({ ...a, principal: pub, sig: a.sig.replace(/^./, (c) => (c === 'A' ? 'B' : 'A')) })).toBe(false);
    expect(ok(null)).toBe(false);
    expect(ok('approved')).toBe(false);
  });

  it('a confirmed sensitive action must be repeated, exactly, in the approval', async () => {
    const { p, report, reviewer, pub, held } = await setup({ confirmed: true });
    expect(p.confirmedSensitive).toEqual([held]);
    const a = signApproval(reviewer.secretKey, p, report, { at: NOW });
    expect(a.confirmed).toEqual([held]);
    expect(verifyApproval(a, p, report, { principals: [pub], now: NOW + 1 }).ok).toBe(true);
    const forged = signApproval(reviewer.secretKey, p, report, { at: NOW, confirmed: [] });
    expect(verifyApproval(forged, p, report, { principals: [pub], now: NOW + 1 }).ok).toBe(false);
  });

  it('will not mint a grant from a proposal that has already expired', async () => {
    const { p, report, reviewer, pub } = await setup();
    const later = NOW + 31 * DAY;
    const a = signApproval(reviewer.secretKey, p, report, { at: later });
    expect(() => issueGrant(p, report, a, { principalSecret: reviewer.secretKey, holder: pub, goal: 'g', principals: [pub], now: later + 1 })).toThrow(/expired/);
  });

  it('the passkey challenge binds the proposal, the report, the confirmations and the expiry', async () => {
    const { p, report } = await setup();
    const c = approvalChallenge(p, report, [], 1000);
    expect(c).toHaveLength(32);
    expect(Buffer.from(approvalChallenge(p, report, [], 1000)).equals(Buffer.from(c))).toBe(true);
    expect(Buffer.from(approvalChallenge(p, report, [], 1001)).equals(Buffer.from(c))).toBe(false);
    expect(Buffer.from(approvalChallenge(p, report, ['x'], 1000)).equals(Buffer.from(c))).toBe(false);
  });

  it('a passkey approval without registered credentials is refused', async () => {
    const { p, report, pub } = await setup();
    const a = { v: 1, kind: 'pca-autopilot-approval', method: 'passkey', proposal_digest: p.digest, report_digest: report.digest, confirmed: [], principal: pub, at: NOW, expires_at: NOW + 60_000, assertion: { authenticatorData: '', clientDataJSON: '', signature: '' } };
    expect(verifyApproval(a, p, report, { principals: [pub], now: NOW + 1 }).ok).toBe(false);
  });
});

describe('continuous mode', () => {
  const base = () => {
    const s = set(benign());
    return { s, p: propose(s, { now: NOW }) };
  };
  const denied = (resource: string, n: number, o: Record<string, unknown> = {}) => Array.from({ length: n }, (_, i) => row(100 + i, { resource, outcome: 'deny', ...o }));

  it('amends by the minimum for denied-but-legitimate actions, and the amendment verifies and needs its own review', async () => {
    const { p } = base();
    const obs = set([...benign(), ...denied('/mail/x', 3)]);
    const a = amend(p, obs, { now: NOW });
    expect(a.amends).toBe(p.digest);
    expect(a.digest).not.toBe(p.digest);
    expect(a.policy.predicates.map((x) => x.resource)).toEqual(['/drafts/*', '/mail/x']);
    expect(a.admitDenied).toHaveLength(1);
    expect(a.policy.caveats.filter((c) => c.type !== 'rate')).toEqual(p.policy.caveats.filter((c) => c.type !== 'rate'));
    expect(a.policy.caveats.find((c) => c.type === 'rate')!.max).toBe(11); // 9 actions in the window, plus the margin
    const r = await verifyProposal(a, obs);
    expect(r.replay.total).toBe(9);
    expect(r.ok).toBe(true);
  });

  it('does not amend for a denial seen too few times, or one that is already admitted', () => {
    const { p } = base();
    expect(() => amend(p, set([...benign(), ...denied('/mail/x', 2)]), { now: NOW })).toThrow(/no denied-but-legitimate/);
    expect(() => amend(p, set([...benign(), ...denied('/drafts/77', 5)]), { now: NOW })).toThrow(/no denied-but-legitimate/);
  });

  it('a sensitive denied action is held, and admitted only when its id is confirmed', () => {
    const { p } = base();
    const obs = set([...benign(), ...denied('/mail/x', 3), ...denied('/drafts/1', 5, { verb: 'gmail.delete', params: {} })]);
    const a = amend(p, obs, { now: NOW });
    expect(a.policy.predicates.map((x) => x.verb)).not.toContain('gmail.delete');
    const held = a.heldBack.find((h) => h.verb === 'gmail.delete')!;
    expect(held.reasons).toContain('dangerous-verb');
    const b = amend(p, obs, { now: NOW, confirmed: [held.id] });
    expect(b.confirmedSensitive).toEqual([held.id]);
    expect(b.policy.predicates.map((x) => x.verb)).toContain('gmail.delete');
    expect(() => amend(p, obs, { now: NOW, confirmed: ['0123456789abcdef'] })).toThrow(/not a denied sensitive/);
  });

  it('widens a covering rule instead of adding a duplicate, only as far as the new values need', () => {
    const { p } = base();
    const obs = set([...benign(), ...Array.from({ length: 3 }, (_, i) => row(100 + i, { resource: '/drafts/new', outcome: 'deny', params: { recipients: 9 } }))]);
    const a = amend(p, obs, { now: NOW });
    expect(a.policy.predicates).toHaveLength(1);
    expect(a.policy.predicates[0]!.where).toContainEqual({ field: 'action.params.recipients', op: 'lte', value: 11 });
  });

  it('tightens: drops authority unused for N days and shrinks caps to what was used', () => {
    const s0 = set([...benign(), row(40, { verb: 'docs.read', resource: '/docs/1', params: {} })]);
    const p = propose(s0, { now: NOW });
    expect(p.policy.predicates).toHaveLength(2);
    const recent = Array.from({ length: 4 }, (_, i) => row(0, { at: NOW - 5 * DAY + i * 1000, resource: `/drafts/${i}`, params: { recipients: 1 + (i % 2) } }));
    const old = row(0, { at: NOW - 60 * DAY, verb: 'docs.read', resource: '/docs/1', params: {} });
    const obs = set([old, ...recent]);
    const t = tighten(p, obs, { unusedDays: 30, now: NOW, observedFrom: NOW - 90 * DAY });
    expect(t.amends).toBe(p.digest);
    expect(t.policy.predicates.map((x) => x.verb)).toEqual(['gmail.draft']);
    expect(t.policy.predicates[0]!.where).toContainEqual({ field: 'action.params.recipients', op: 'lte', value: 3 });
    expect(t.notes.join()).toMatch(/tightening: 1 rule\(s\) unused for 30 day/);
  });

  it('refuses to call authority unused over a window the observation does not cover, or when nothing was used', () => {
    const { p } = base();
    const obs = set([row(0, { at: NOW - 2 * DAY })]);
    expect(() => tighten(p, obs, { unusedDays: 30, now: NOW })).toThrow(/does not cover/);
    expect(() => tighten(p, set([row(0, { at: NOW - 60 * DAY })]), { unusedDays: 30, now: NOW, observedFrom: NOW - 90 * DAY })).toThrow(/no authority was used/);
    expect(() => tighten(p, obs, { unusedDays: -1, now: NOW })).toThrow(RangeError);
  });
});
