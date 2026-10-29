import { certify, decideClauses, type ClauseOptions, type ForbidCertificate, type PolicyClause } from '../forbid-certificate';
import { hashCanonical } from '../hash';
import type { ActionContext } from '../predicates';

/**
 * Shared vectors for the forbid-wins certificate (conformance/forbid-certificate-vectors.json). Two tables:
 *  - `decide`: a clause list and an action, with the decision, winner, shadowed list, per-clause values and the digest of the
 *    whole certificate. Replayed by every verifier that implements the predicate DSL.
 *  - `table`: a certificate and whether its own table entails its decision. It needs no evaluator, so every verifier can run it.
 */

const act = (verb: string, resource: string, params?: Record<string, unknown>): ActionContext => ({ action: { verb, resource, ...(params ? { params } : {}) } });

export const CLAUSES: PolicyClause[] = [
  { id: 'p-small', kind: 'permit', signer: 'user', when: { verb: 'pay.send', where: [{ field: 'action.params.amount', op: 'lte', value: 100 }] } },
  { id: 'p-vip', kind: 'permit', signer: 'user', when: { verb: 'pay.send', resource: '/vip/*' } },
  { id: 'f-blocked', kind: 'forbid', signer: 'org', when: { verb: 'pay.send', resource: '/blocked/*' } },
  { id: 'f-large', kind: 'forbid', signer: 'user', when: { verb: 'pay.send', where: [{ field: 'action.params.amount', op: 'gt', value: 5000 }] } },
  { id: 'e-review', kind: 'escalate', signer: 'org', when: { verb: 'pay.send', where: [{ field: 'action.params.amount', op: 'gt', value: 80 }] } },
];

const CASES: Array<{ name: string; ctx: ActionContext; opts?: ClauseOptions }> = [
  { name: 'small payment is allowed by the first matching permit', ctx: act('pay.send', '/acct/1', { amount: 10 }) },
  { name: 'over the review line the decision is capped at escalate', ctx: act('pay.send', '/acct/1', { amount: 90 }) },
  { name: 'a forbid beats every permit', ctx: act('pay.send', '/vip/1', { amount: 6000 }) },
  { name: 'two forbids: the more authoritative signer is named', ctx: act('pay.send', '/blocked/x', { amount: 6000 }), opts: { precedence: ['org', 'user'] } },
  { name: 'two forbids: precedence reversed names the other', ctx: act('pay.send', '/blocked/x', { amount: 6000 }), opts: { precedence: ['user', 'org'] } },
  { name: 'two forbids with no precedence: ties break by id', ctx: act('pay.send', '/blocked/x', { amount: 6000 }) },
  { name: 'a forbid that cannot be decided still applies (veto polarity)', ctx: act('pay.send', '/vip/2') },
  { name: 'no permit matches: default deny, nothing to name', ctx: act('pay.refund', '/acct/1', { amount: 1 }) },
  { name: 'a permit from an untrusted signer is ignored', ctx: act('pay.send', '/vip/3', { amount: 10 }), opts: { permitSigners: ['org'] } },
  { name: 'allowed with a shadowed second permit', ctx: act('pay.send', '/vip/3', { amount: 10 }) },
  { name: 'malformed action fails closed', ctx: { action: { verb: 5 as unknown as string, resource: '/x' } } },
];

function tamper(c: ForbidCertificate, f: (x: ForbidCertificate) => void): ForbidCertificate {
  const x = structuredClone(c);
  f(x);
  return x;
}

export function buildForbidCertificateVectors(): unknown {
  const decide = CASES.map((c) => {
    const d = decideClauses(CLAUSES, c.ctx, c.opts);
    const cert = certify(CLAUSES, c.ctx, c.opts);
    return { name: c.name, clauses: CLAUSES, action: c.ctx, ...(c.opts ? { options: c.opts } : {}), expect: { decision: d.decision, winner: d.witness.winner, shadowed: d.witness.shadowed, values: d.values, certificate_digest: hashCanonical(cert) } };
  });
  const base = certify(CLAUSES, act('pay.send', '/blocked/x', { amount: 6000 }), { precedence: ['org', 'user'] });
  const allow = certify(CLAUSES, act('pay.send', '/acct/1', { amount: 10 }));
  const esc = certify(CLAUSES, act('pay.send', '/acct/1', { amount: 90 }));
  const none = certify(CLAUSES, act('pay.refund', '/acct/1', { amount: 1 }));
  const opts = { precedence: ['org', 'user'] };
  const table: Array<{ name: string; certificate: ForbidCertificate; options?: ClauseOptions; expect: boolean }> = [
    { name: 'forbid certificate is consistent', certificate: base, options: opts, expect: true },
    { name: 'allow certificate is consistent', certificate: allow, expect: true },
    { name: 'escalate certificate is consistent', certificate: esc, expect: true },
    { name: 'default-deny certificate is consistent', certificate: none, expect: true },
    { name: 'allow claimed while a forbid matched', certificate: tamper(base, (x) => { x.decision = 'allow'; }), options: opts, expect: false },
    { name: 'forbid certificate naming a permit as the winner', certificate: tamper(base, (x) => { x.winner = { kind: 'permit', id: 'p-vip' }; }), options: opts, expect: false },
    { name: 'forbid certificate naming the less authoritative forbid', certificate: tamper(base, (x) => { x.winner = { kind: 'forbid', id: 'f-large' }; }), options: opts, expect: false },
    { name: 'a matched forbid dropped from the shadowed list', certificate: tamper(base, (x) => { x.shadowed = x.shadowed.filter((id) => id !== 'f-large'); }), options: opts, expect: false },
    { name: 'a forbid row flipped to false hides the veto', certificate: tamper(base, (x) => { for (const r of x.clauses) if (r.kind === 'forbid') r.value = 'false'; }), options: opts, expect: false },
    { name: 'escalate claimed as allow', certificate: tamper(esc, (x) => { x.decision = 'allow'; }), expect: false },
    { name: 'allow claimed as escalate', certificate: tamper(allow, (x) => { x.decision = 'escalate'; }), expect: false },
    { name: 'deny claimed for a plain allow', certificate: tamper(allow, (x) => { x.decision = 'deny'; }), expect: false },
    { name: 'unknown clause value', certificate: tamper(allow, (x) => { x.clauses[0]!.value = 'maybe' as never; }), expect: false },
    { name: 'unknown clause kind', certificate: tamper(allow, (x) => { x.clauses[0]!.kind = 'allow' as never; }), expect: false },
    { name: 'wrong version', certificate: tamper(allow, (x) => { (x as { v: number }).v = 2; }), expect: false },
    { name: 'malformed certificate (no table) is consistent', certificate: certify(CLAUSES, { action: {} } as never), expect: true },
    { name: 'malformed certificate that carries a table row', certificate: tamper(certify(CLAUSES, { action: {} } as never), (x) => { x.clauses = [{ id: 'p-small', kind: 'permit', value: 'true' }]; }), expect: false },
    { name: 'malformed certificate claiming allow', certificate: tamper(certify(CLAUSES, { action: {} } as never), (x) => { x.decision = 'allow'; }), expect: false },
    { name: 'unknown value of an unknown (veto-polarity) forbid still denies', certificate: tamper(base, (x) => { for (const r of x.clauses) if (r.kind === 'forbid' && r.value === 'true') r.value = 'unknown'; }), options: opts, expect: true },
  ];
  return {
    version: 1,
    note: 'Generated by scripts/gen-conformance-forbid-certificate.ts from the TypeScript reference. `decide`: replay with the clause evaluator; `table`: certificateConsistent, no evaluator needed.',
    decide,
    table: table.map((t) => ({ ...t, expect: { consistent: t.expect } })),
  };
}
