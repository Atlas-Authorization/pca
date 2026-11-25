import { certify, checkForbidCertificate, clausesError, decideClauses, MAX_CLAUSES, type ClauseOptions, type ForbidCertificate, type PolicyClause } from '../forbid-certificate';
import { sha256, utf8 } from '../hash';
import { encodeKey, publicKeyOf } from '../keys';
import type { ActionContext } from '../predicates';
import { checkAndAdvance, checkProhibitions, constitutionId, emptyState, proveSafety, signSafetyEvidence, tickState, validateConstitution, verifySignedSafetyEvidence, type Constitution, type Invariant, type MonitorState } from '../prohibitions';
import { CLAUSES } from './forbid-certificate-vectors';

/**
 * Shared vectors for the prohibition plane (conformance/prohibition-vectors.json), generated from the TypeScript reference.
 *  - `clauses`: clausesError on malformed forbid/permit/escalate lists, and the decision they force (always a deny naming `malformed`).
 *  - `check`: checkForbidCertificate with the exact reason it returns.
 *  - `constitution`: validateConstitution problems and checkProhibitions results (no state needed beyond the genesis state).
 *  - `evidence`: verifySignedSafetyEvidence over signed evidence with malformed `evaluated` rows and odd invariants (deterministic Ed25519; the key is derived from a public test seed). `signed` + `expected` are the two arguments.
 *  - `monitor`: step sequences through tickState + checkAndAdvance (stateful invariants: cap, rate, never_after, require_prior).
 */
const NOW = 1_700_000_000_000;
const PRINCIPAL = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const act = (verb: string, resource = '/r', params?: Record<string, unknown>): ActionContext => ({ action: { verb, resource, ...(params ? { params } : {}) } });
const W = (verb: string, extra: Record<string, unknown> = {}) => ({ verb, ...extra });
const con = (invariants: Invariant[]): Constitution => ({ version: 1, principal: PRINCIPAL, invariants });

function tamper(c: ForbidCertificate, f: (x: ForbidCertificate) => void): ForbidCertificate {
  const x = structuredClone(c);
  f(x);
  return x;
}

export function buildProhibitionVectors(): unknown {
  const p = (id: string, extra: Partial<PolicyClause> = {}): PolicyClause => ({ id, kind: 'permit', when: { verb: 'v' }, ...extra });
  const clauseCases: Array<{ name: string; clauses: unknown; action?: ActionContext; options?: ClauseOptions }> = [
    { name: 'empty list is well formed: default deny naming nothing', clauses: [] },
    { name: 'not an array', clauses: { id: 'a' } },
    { name: 'clause not an object', clauses: [5] },
    { name: 'missing id', clauses: [{ kind: 'permit', when: { verb: 'v' } }] },
    { name: 'empty id', clauses: [p('')] },
    { name: 'id of 129 characters', clauses: [p('a'.repeat(129))] },
    { name: 'id of 128 characters is fine', clauses: [p('a'.repeat(128))] },
    { name: 'duplicate id', clauses: [p('a'), p('a')] },
    { name: 'unknown kind', clauses: [{ id: 'a', kind: 'allow', when: { verb: 'v' } }] },
    { name: 'kind is not a string', clauses: [{ id: 'a', kind: 7, when: { verb: 'v' } }] },
    { name: 'signer not a string', clauses: [p('a', { signer: 5 as never })] },
    { name: 'signer of 257 characters', clauses: [p('a', { signer: 's'.repeat(257) })] },
    { name: 'signer of 256 characters is fine', clauses: [p('a', { signer: 's'.repeat(256) })] },
    { name: 'when is not an object', clauses: [{ id: 'a', kind: 'permit', when: 'v' }] },
    { name: 'when is an array', clauses: [{ id: 'a', kind: 'permit', when: [] }] },
    { name: `${MAX_CLAUSES} clauses are fine`, clauses: Array.from({ length: MAX_CLAUSES }, (_, i) => p(`c${i}`)) },
    { name: `${MAX_CLAUSES + 1} clauses are refused`, clauses: Array.from({ length: MAX_CLAUSES + 1 }, (_, i) => p(`c${i}`)) },
    { name: 'a malformed action denies even a well formed policy', clauses: CLAUSES, action: { action: {} } as never },
    { name: 'a null action denies', clauses: CLAUSES, action: null as never },
    { name: 'an unknown clause kind denies with winner malformed and no table', clauses: [p('a'), { id: 'b', kind: 'eventually', when: { verb: 'v' } }], action: act('v') },
  ];
  const clauses = clauseCases.map((c) => {
    const ctx = c.action === undefined ? act('v', '/x') : c.action;
    const d = decideClauses(c.clauses as PolicyClause[], ctx, c.options);
    return { name: c.name, clauses: c.clauses, action: ctx, ...(c.options ? { options: c.options } : {}), expect: { error: clausesError(c.clauses), decision: d.decision, winner: d.witness.winner, shadowed: d.witness.shadowed, values: d.values } };
  });

  const ctx = act('pay.send', '/blocked/x', { amount: 6000 });
  const opts: ClauseOptions = { precedence: ['org', 'user'] };
  const good = certify(CLAUSES, ctx, opts);
  const malformedCert = certify(CLAUSES, { action: {} } as never);
  const checkCases: Array<{ name: string; certificate: ForbidCertificate; clauses: unknown; action: ActionContext; options?: ClauseOptions }> = [
    { name: 'a recomputed certificate is accepted', certificate: good, clauses: CLAUSES, action: ctx, options: opts },
    { name: 'malformed clauses are refused before anything else', certificate: good, clauses: [{ id: 'a', kind: 'eventually', when: {} }], action: ctx, options: opts },
    { name: 'a table that does not entail its decision', certificate: tamper(good, (x) => { x.decision = 'allow'; }), clauses: CLAUSES, action: ctx, options: opts },
    { name: 'a consistent certificate for another action', certificate: certify(CLAUSES, act('pay.send', '/acct/1', { amount: 10 })), clauses: CLAUSES, action: ctx, options: opts },
    { name: 'a consistent certificate for another policy', certificate: certify([CLAUSES[0]!], ctx, opts), clauses: CLAUSES, action: ctx, options: opts },
    { name: 'a consistent certificate under other precedence', certificate: certify(CLAUSES, ctx, { precedence: ['user', 'org'] }), clauses: CLAUSES, action: ctx, options: opts },
    { name: 'a malformed-action certificate is accepted for the malformed action', certificate: malformedCert, clauses: CLAUSES, action: { action: {} } as never },
    { name: 'a malformed-action certificate does not vouch for a good action', certificate: malformedCert, clauses: CLAUSES, action: ctx, options: opts },
    { name: 'a certificate that is not an object', certificate: null as never, clauses: CLAUSES, action: ctx, options: opts },
    { name: 'a certificate with the wrong version', certificate: tamper(good, (x) => { (x as { v: number }).v = 2; }), clauses: CLAUSES, action: ctx, options: opts },
    { name: 'a forbid row hidden as false', certificate: tamper(good, (x) => { for (const r of x.clauses) if (r.kind === 'forbid') r.value = 'false'; }), clauses: CLAUSES, action: ctx, options: opts },
  ];
  const check = checkCases.map((c) => ({ name: c.name, certificate: c.certificate, clauses: c.clauses, action: c.action, ...(c.options ? { options: c.options } : {}), expect: checkForbidCertificate(c.certificate, c.clauses as PolicyClause[], c.action, c.options) }));

  const genesis = emptyState(NOW);
  const never = (id: string): Invariant => ({ id, kind: 'never', when: W('delete') });
  const constitutionCases: Array<{ name: string; constitution: unknown; action: ActionContext; state?: MonitorState }> = [
    { name: 'no invariants: nothing violated', constitution: con([]), action: act('read') },
    { name: 'never: a matching action violates', constitution: con([never('no-delete')]), action: act('delete') },
    { name: 'never: a non-matching action passes', constitution: con([never('no-delete')]), action: act('read') },
    { name: 'never carries its description as the reason', constitution: con([{ ...never('no-delete'), description: 'deletes are banned' }]), action: act('delete') },
    { name: 'never: an unresolvable where condition counts as matched (veto applies)', constitution: con([{ id: 'n', kind: 'never', when: W('pay', { where: [{ field: 'action.params.amount', op: 'gt', value: 100 }] }) }]), action: act('pay') },
    { name: 'never: a resolvable where condition that misses passes', constitution: con([{ id: 'n', kind: 'never', when: W('pay', { where: [{ field: 'action.params.amount', op: 'gt', value: 100 }] }) }]), action: act('pay', '/r', { amount: 5 }) },
    { name: 'never_unless: forbidden without the exception', constitution: con([{ id: 'nu', kind: 'never_unless', when: W('wire'), unless: [{ field: 'action.params.approved', op: 'eq', value: true }] }]), action: act('wire') },
    { name: 'never_unless: allowed when the exception holds', constitution: con([{ id: 'nu', kind: 'never_unless', when: W('wire'), unless: [{ field: 'action.params.approved', op: 'eq', value: true }] }]), action: act('wire', '/r', { approved: true }) },
    { name: 'require_approval_over: at the threshold needs no approval', constitution: con([{ id: 'ra', kind: 'require_approval_over', when: W('pay'), amount: 'action.params.amount', threshold: 100, approved: [{ field: 'action.params.approved', op: 'eq', value: true }] }]), action: act('pay', '/r', { amount: 100 }) },
    { name: 'require_approval_over: above the threshold needs approval', constitution: con([{ id: 'ra', kind: 'require_approval_over', when: W('pay'), amount: 'action.params.amount', threshold: 100, approved: [{ field: 'action.params.approved', op: 'eq', value: true }] }]), action: act('pay', '/r', { amount: 101 }) },
    { name: 'require_approval_over: a missing amount counts as over', constitution: con([{ id: 'ra', kind: 'require_approval_over', when: W('pay'), amount: 'action.params.amount', threshold: 100, approved: [{ field: 'action.params.approved', op: 'eq', value: true }] }]), action: act('pay') },
    { name: 'require_approval_over: a negative amount counts as over', constitution: con([{ id: 'ra', kind: 'require_approval_over', when: W('pay'), amount: 'action.params.amount', threshold: 100, approved: [{ field: 'action.params.approved', op: 'eq', value: true }] }]), action: act('pay', '/r', { amount: -1 }) },
    { name: 'cap: a missing amount fails closed', constitution: con([{ id: 'c', kind: 'cap', when: W('pay'), amount: 'action.params.amount', max: 100 }]), action: act('pay') },
    { name: 'cap: exactly the maximum passes', constitution: con([{ id: 'c', kind: 'cap', when: W('pay'), amount: 'action.params.amount', max: 100 }]), action: act('pay', '/r', { amount: 100 }) },
    { name: 'cap: one over the maximum is violated with the arithmetic in the reason', constitution: con([{ id: 'c', kind: 'cap', when: W('pay'), amount: 'action.params.amount', max: 100 }]), action: act('pay', '/r', { amount: 101 }) },
    { name: 'rate: the first action is within the limit', constitution: con([{ id: 'r', kind: 'rate', when: W('call'), max: 1, window_secs: 60 }]), action: act('call') },
    { name: 'require_prior: forbidden before the prior', constitution: con([{ id: 'rp', kind: 'require_prior', when: W('deploy'), prior: W('review') }]), action: act('deploy') },
    { name: 'never_after: allowed while the trigger is not latched', constitution: con([{ id: 'na', kind: 'never_after', after: W('export'), forbid: W('delete') }]), action: act('delete') },
    { name: 'every invariant is evaluated: two violations are both listed', constitution: con([never('a'), { id: 'b', kind: 'never', when: W('delete') }]), action: act('delete') },
    { name: 'constitution: not an object', constitution: null, action: act('read') },
    { name: 'constitution: wrong version', constitution: { version: 2, principal: PRINCIPAL, invariants: [] }, action: act('read') },
    { name: 'constitution: no principal', constitution: { version: 1, invariants: [] }, action: act('read') },
    { name: 'constitution: invariants not an array', constitution: { version: 1, principal: PRINCIPAL, invariants: {} }, action: act('read') },
    { name: 'constitution: duplicate invariant id', constitution: con([never('a'), never('a')]), action: act('read') },
    { name: 'constitution: forbidden id __proto__', constitution: con([never('__proto__')]), action: act('read') },
    { name: 'constitution: unknown invariant kind', constitution: con([{ id: 'x', kind: 'eventually', when: W('v') } as never]), action: act('read') },
    { name: 'constitution: cap with a non-numeric max', constitution: con([{ id: 'c', kind: 'cap', when: W('pay'), amount: 'action.params.amount', max: 'big' as never }]), action: act('read') },
    { name: 'action: malformed', constitution: con([never('a')]), action: { action: { verb: 5, resource: '/r' } } as never },
    { name: 'action: null', constitution: con([never('a')]), action: null as never },
    { name: 'state: negative seq', constitution: con([never('a')]), action: act('read'), state: { ...genesis, seq: -1 } },
    { name: 'state: genesis with a parent', constitution: con([never('a')]), action: act('read'), state: { ...genesis, parent: 'x' } },
    { name: 'state: seq above zero without a parent link', constitution: con([never('a')]), action: act('read'), state: { ...genesis, seq: 3, parent: null } },
    { name: 'state: now is not a number', constitution: con([never('a')]), action: act('read'), state: { ...genesis, now: 'soon' as never } },
  ];
  const constitution = constitutionCases.map((c) => {
    const st = c.state ?? genesis;
    return { name: c.name, constitution: c.constitution, action: c.action, state: st, expect: { problems: validateConstitution(c.constitution), result: checkProhibitions(c.action, c.constitution as Constitution, st) } };
  });

  type Step = { action: ActionContext; now?: number };
  const scenarios: Array<{ name: string; constitution: Constitution; steps: Step[] }> = [
    { name: 'cap: spend accumulates inside the window and is refused over the maximum', constitution: con([{ id: 'cap', kind: 'cap', when: W('pay'), amount: 'action.params.amount', max: 100, window_secs: 60 }]), steps: [{ action: act('pay', '/r', { amount: 60 }) }, { action: act('pay', '/r', { amount: 40 }), now: NOW + 1000 }, { action: act('pay', '/r', { amount: 1 }), now: NOW + 2000 }, { action: act('pay', '/r', { amount: 1 }), now: NOW + 61_001 }] },
    { name: 'rate: the second call inside the window is refused, then the window rolls', constitution: con([{ id: 'rate', kind: 'rate', when: W('call'), max: 1, window_secs: 10 }]), steps: [{ action: act('call') }, { action: act('call'), now: NOW + 1000 }, { action: act('call'), now: NOW + 11_000 }] },
    { name: 'require_prior: the prior unlocks the guarded action', constitution: con([{ id: 'rp', kind: 'require_prior', when: W('deploy'), prior: W('review') }]), steps: [{ action: act('deploy') }, { action: act('review') }, { action: act('deploy') }] },
    { name: 'never_after: the trigger latches the ban', constitution: con([{ id: 'na', kind: 'never_after', after: W('export'), forbid: W('delete') }]), steps: [{ action: act('delete') }, { action: act('export') }, { action: act('delete') }] },
    { name: 'a clock that goes backwards is refused', constitution: con([never('a')]), steps: [{ action: act('read') }, { action: act('read'), now: NOW - 1 }] },
  ];
  const monitor = scenarios.map((s) => {
    let st: MonitorState = emptyState(NOW);
    const steps = s.steps.map((step) => {
      let cur = st;
      if (step.now !== undefined) {
        const t = tickState(st, step.now);
        if (!t.ok) return { action: step.action, now: step.now, expect: { allow: false, decidedBy: 'clock', reason: t.reason } };
        cur = t.state;
      }
      const r = checkAndAdvance(true, step.action, s.constitution, cur);
      if (r.allow) st = r.next;
      else st = cur;
      return { action: step.action, ...(step.now !== undefined ? { now: step.now } : {}), expect: { allow: r.allow, decidedBy: r.decidedBy, violated: r.prohibition.violated, seq: r.next.seq } };
    });
    return { name: s.name, constitution: s.constitution, genesis_now: NOW, steps };
  });

  const SEED = sha256(utf8('atlas-pca/conformance/prohibition-vectors/evidence-signer'));
  const SIGNER = encodeKey(publicKeyOf(SEED));
  const evCon = con([{ id: 'n', kind: 'never', when: W('x') }]);
  const evAct = act('y');
  const real = proveSafety(evAct, evCon, genesis);
  const bound = { signer: SIGNER, actionDigest: real.action_digest, stateDigest: real.state_digest };
  const full = { signer: SIGNER, action: evAct, constitution: evCon, state: genesis };
  const signEv = (ev: unknown) => signSafetyEvidence(ev as never, SEED, SIGNER);
  const withInv = (inv: unknown[]) => ({ ...evCon, invariants: inv }) as unknown as Constitution;
  const evidenceCases: Array<{ name: string; signed: unknown; expected: Record<string, unknown> }> = [
    { name: 'a valid signed admit verifies', signed: signEv(real), expected: full },
    { name: 'a row without an id is not coverage of the invariant', signed: signEv({ ...real, evaluated: [{ result: 'pass' }] }), expected: { ...bound, constitution: evCon } },
    { name: 'a string row makes the claimed ok verdict inconsistent', signed: signEv({ ...real, evaluated: ['x'] }), expected: { ...bound, constitution: evCon } },
    { name: 'a null row makes the claimed ok verdict inconsistent', signed: signEv({ ...real, evaluated: [null] }), expected: { ...bound, constitution: evCon } },
    { name: 'a string row under a not-ok verdict is accepted without requireOk', signed: signEv({ ...real, ok: false, violated: ['v'], evaluated: ['x'] }), expected: { ...bound, constitution: evCon, requireOk: false } },
    { name: 'a string row under a not-ok verdict does not reproduce against the full inputs', signed: signEv({ ...real, ok: false, violated: ['v'], evaluated: ['x'] }), expected: { ...full, requireOk: false } },
    { name: 'a string row claiming ok is inconsistent against the full inputs', signed: signEv({ ...real, evaluated: ['x'] }), expected: full },
    { name: 'a row without an id does not reproduce against the full inputs', signed: signEv({ ...real, evaluated: [{ result: 'pass' }] }), expected: full },
    { name: 'a non-string evaluated row id is malformed evidence', signed: signEv({ ...real, evaluated: [{ id: 5, result: 'pass' }] }), expected: { ...bound, constitution: evCon } },
    { name: 'an invariant with an empty id is a malformed constitution: refused', signed: signEv({ ...real, constitution: constitutionId(withInv([{ id: '', kind: 'never', when: W('x') }])), evaluated: [{ result: 'pass' }] }), expected: { ...bound, constitution: withInv([{ id: '', kind: 'never', when: W('x') }]) } },
    { name: 'a numeric invariant is a malformed constitution: refused, an id-less row does not cover it', signed: signEv({ ...real, constitution: constitutionId(withInv([5])), evaluated: [{ result: 'pass' }] }), expected: { ...bound, constitution: withInv([5]) } },
    { name: 'a null invariant is a malformed constitution: refused', signed: signEv({ ...real, constitution: constitutionId(withInv([null])), evaluated: [{ result: 'pass', id: 'n' }] }), expected: { ...bound, constitution: withInv([null]) } },
    { name: 'a string invariant is a malformed constitution: refused', signed: signEv({ ...real, constitution: constitutionId(withInv(['q'])), evaluated: [{ result: 'pass', id: 'n' }] }), expected: { ...bound, constitution: withInv(['q']) } },
  ];
  const evidence = evidenceCases.map((c) => ({ name: c.name, signed: c.signed, expected: c.expected, expect: verifySignedSafetyEvidence(c.signed as never, c.expected as never) }));

  return {
    version: 1,
    note: 'Generated by scripts/gen-conformance-prohibition.ts from the TypeScript reference. `clauses`: forbid-wins clause-list validation and the decision it forces; `check`: checkForbidCertificate and its exact reason; `constitution`: validateConstitution + checkProhibitions from the genesis state (or the malformed state given); `monitor`: step sequences through tickState (when a step carries `now`) then checkAndAdvance(permitted=true) from the genesis state at genesis_now; a refused step leaves the state as it was (a tick that was accepted stays). Chain digests are not compared. `evidence`: verifySignedSafetyEvidence(signed, expected) outcomes, including malformed evaluated rows and non-object invariants; the signing key is derived from a public test seed only to make signatures reproducible.',
    clauses,
    check,
    constitution,
    monitor,
    evidence,
  };
}
