/**
 * Three ways to keep an allow on a short leash:
 *   1. obligations   an allow that carries duties; an enforcement point that cannot do them turns the allow into a deny
 *   2. leases        a time-boxed grant that must be renewed, has a hard cap, and dies when revoked
 *   3. break glass   a sealed emergency grant: small budget, loud on every use, reviewed afterwards
 *
 * Run it:  npm run obligations-leases-break-glass      (exits nonzero if any outcome is not the expected one)
 */
import { b64u, collectObligations, generateKeyPair, mergeObligations, obligationOutcome, pepObligationGate, publicKeyOf } from '@atlasauth/pca';
import {
  BreakGlassRegistry, LeaseRegistry, checkLease, memoryLeaseKv, renewLease, signBreakGlass, signBreakGlassReview, signLease, signLeaseRevocation,
  type BgUseDecision, type LeaseDecision,
} from '@atlasauth/pca-grants';
import { expectOutcome, finish } from './check.js';

const T0 = 1_800_000_000_000; // a fixed clock, so every run prints the same thing
const MIN = 60_000;
const HOUR = 60 * MIN;
const idOf = (secret: Uint8Array): string => b64u(publicKeyOf(secret));

// ---- 1. obligations ---------------------------------------------------------------------------------------------------

const rules = [
  { id: 'big', when: { field: 'action.params.amount', op: 'gt', value: 100 }, obligations: [{ kind: 'notify', params: { to: 'finance' } }] },
  { id: 'pii', when: { field: 'env.contains_pii', op: 'eq', value: true }, obligations: [{ kind: 'redact', params: { fields: ['ssn'] } }] },
];
const kinds = (r: { ok: boolean; obligations?: Array<{ kind: string }> }): string[] => (r.ok ? (r.obligations ?? []).map((o) => o.kind) : ['refused']);

expectOutcome('small, no PII: no duties', kinds(collectObligations(rules, { action: { params: { amount: 5 } }, env: { contains_pii: false } })), []);
const collected = collectObligations(rules, { action: { params: { amount: 500 } }, env: { contains_pii: true } });
expectOutcome('large, PII: two duties', kinds(collected), ['notify', 'redact']);

const merged = mergeObligations(collected.ok ? collected.obligations : [], [{ kind: 'require_receipt', due: T0 + MIN }]);
if (!merged.ok) throw new Error(merged.reason);
const duties = merged.obligations;

const all = ['notify', 'redact', 'require_receipt'];
const full = pepObligationGate('allow', false, duties, all);
expectOutcome('a point that does all three: allow, three duties', [full.decision, full.perform.length], ['allow', 3]);
const partial = pepObligationGate('allow', false, duties, ['notify']);
expectOutcome('a point that only notifies: deny', [partial.decision, partial.unsupported], ['deny', ['redact', 'require_receipt']]);
expectOutcome('a deny stays a deny', pepObligationGate('deny', false, duties, all).decision, 'deny');
expectOutcome('an unanswered escalate stays escalate', pepObligationGate('escalate', false, duties, all).decision, 'escalate');

const receiptIdx = duties.findIndex((o) => o.kind === 'require_receipt');
const overdue = (fulfilled: number[], now: number): unknown => {
  const o = obligationOutcome(duties, fulfilled, now);
  return [o.outcome, o.overdue.map((i) => duties[i]?.kind)];
};
expectOutcome('before the due time: ok', overdue([], T0 + 30_000), ['ok', []]);
expectOutcome('past the due time, no receipt: escalate', overdue([], T0 + MIN + 1), ['escalate', ['require_receipt']]);
expectOutcome('past the due time, receipt reported: ok', overdue([receiptIdx], T0 + MIN + 1), ['ok', []]);

// ---- 2. leases --------------------------------------------------------------------------------------------------------

const authority = generateKeyPair();
const registry = new LeaseRegistry({ authorities: [idOf(authority.secretKey)] }, memoryLeaseKv());
const show = (d: LeaseDecision): string => (d.decision === 'allow' ? 'allow' : `deny:${d.code}`);

const issue = {
  lease_id: 'db-ro-1', path: 'db/prod/ro', grant_ref: 'grant-1', holder: 'agent-a', requester: 'owner-a', approvers: ['alice'],
  justification_digest: 'reason-1', seq: 1, issued_at: T0, renewed_at: T0, expires_at: T0 + HOUR, max_ttl: 4 * HOUR,
};
const lease = signLease(authority.secretKey, issue);
const accepted = await registry.accept(lease);
expectOutcome('issue a one-hour lease', accepted, { ok: true, replaced: true, seq: 1 });
expectOutcome('use it inside the hour', show(await checkLease(lease, registry, T0 + 5 * MIN)), 'allow');
expectOutcome('use it after the hour', show(await checkLease(lease, registry, T0 + HOUR + 1)), 'deny:expired');

const selfApproved = signLease(authority.secretKey, { ...issue, lease_id: 'db-ro-2', approvers: ['agent-a'] });
const sod = await registry.accept(selfApproved);
expectOutcome('the holder approving its own lease', sod.ok ? 'accepted' : sod.code, 'sod');

const r2 = await renewLease(authority.secretKey, registry, 'db-ro-1', { now: T0 + 30 * MIN, increment: HOUR, justification_digest: 'reason-2' });
if (!r2.ok) throw new Error(`renewal failed: ${r2.code}`);
expectOutcome('renew with a new reason: expiry moves', r2.record.expires_at - T0, 90 * MIN);
expectOutcome('the old record is superseded', show(await checkLease(lease, registry, T0 + 31 * MIN)), 'deny:superseded');
const replay = await renewLease(authority.secretKey, registry, 'db-ro-1', { now: T0 + 40 * MIN, increment: HOUR, justification_digest: 'reason-2' });
expectOutcome('renew with the same reason again', replay.ok ? 'renewed' : replay.code, 'stale_justification');
const r3 = await renewLease(authority.secretKey, registry, 'db-ro-1', { now: T0 + 80 * MIN, increment: 10 * HOUR, justification_digest: 'reason-3' });
if (!r3.ok) throw new Error(`renewal failed: ${r3.code}`);
expectOutcome('ask for ten more hours: capped at the 4 hour max', r3.record.expires_at - T0, 4 * HOUR);

expectOutcome('the newest record is alive', show(await checkLease(r3.record, registry, T0 + 85 * MIN)), 'allow');
const revocation = signLeaseRevocation(authority.secretKey, { target: 'prefix', value: 'db/prod', revoked_at: T0 + 90 * MIN });
expectOutcome('revoke everything under db/prod', await registry.revoke(revocation), { ok: true, revoked: 1 });
expectOutcome('the lease is dead at once', show(await checkLease(r3.record, registry, T0 + 91 * MIN)), 'deny:revoked');
const afterRevoke = await renewLease(authority.secretKey, registry, 'db-ro-1', { now: T0 + 92 * MIN, increment: HOUR, justification_digest: 'reason-4' });
expectOutcome('a revoked lease cannot be renewed', afterRevoke.ok ? 'renewed' : afterRevoke.code, 'revoked');

// ---- 3. break glass ---------------------------------------------------------------------------------------------------

const reviewer = generateKeyPair();
const bg = new BreakGlassRegistry({ authorities: [idOf(authority.secretKey)], reviewers: [idOf(reviewer.secretKey)] }, memoryLeaseKv());
const useShow = (d: BgUseDecision): string => (d.decision === 'allow' ? `allow, ${d.remaining} left` : `deny:${d.code}`);
const emergency = (id: string, holder: string) =>
  signBreakGlass(authority.secretKey, { id, holder, grant_ref: 'grant-oncall', reason_digest: 'reason-digest', max_uses: 2, issued_at: T0, expires_at: T0 + HOUR, review_within: 30 * MIN, notify_to: 'oncall-channel' });

expectOutcome('register an emergency grant', await bg.accept(emergency('bg-1', 'agent-a'), T0), { ok: true, replaced: true });
const use = (id: string, holder: string, n: number, notified: boolean, now = T0 + n * 1000) => bg.use({ id, holder, action_digest: `action-${n}`, now, notified });
expectOutcome('use it without telling the on-call channel', useShow(await use('bg-1', 'agent-a', 1, false)), 'deny:not_notified');
expectOutcome('use 1, notified', useShow(await use('bg-1', 'agent-a', 1, true)), 'allow, 1 left');
expectOutcome('use 2, notified', useShow(await use('bg-1', 'agent-a', 2, true)), 'allow, 0 left');
expectOutcome('use 3 is over the budget', useShow(await use('bg-1', 'agent-a', 3, true)), 'deny:budget_exhausted');
expectOutcome('every use is numbered in the log', (await bg.uses('agent-a', 'bg-1')).map((u) => u.n), [1, 2]);

expectOutcome('no review within 30 minutes: the holder is frozen', await bg.frozen('agent-a', T0 + 31 * MIN), true);
const late = signBreakGlassReview(reviewer.secretKey, { id: 'bg-1', outcome: 'justified', notes_digest: 'notes-1', at: T0 + 40 * MIN });
expectOutcome('a late, signed review lifts the freeze', await bg.review(late, 'agent-a', T0 + 41 * MIN), { ok: true, replaced: true });
expectOutcome('the holder is free again', await bg.frozen('agent-a', T0 + 42 * MIN), false);

await bg.accept(emergency('bg-2', 'agent-b'), T0);
await use('bg-2', 'agent-b', 1, true);
const bad = signBreakGlassReview(reviewer.secretKey, { id: 'bg-2', outcome: 'unjustified', notes_digest: 'notes-2', at: T0 + 10 * MIN });
expectOutcome('an unjustified review', await bg.review(bad, 'agent-b', T0 + 10 * MIN), { ok: true, replaced: true });
expectOutcome('the holder is frozen for good', await bg.frozen('agent-b', T0 + 20 * MIN), true);
expectOutcome('and cannot use the grant again', useShow(await use('bg-2', 'agent-b', 2, true, T0 + 20 * MIN)), 'deny:holder_frozen');

finish();
