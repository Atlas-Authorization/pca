/** Mutation-kill tests for the SIEM exporters: exact field values for OCSF / CEF / ECS, every fallback, severity, override and sink branch. */
import { describe, expect, it, vi } from 'vitest';
import { pcactnDigest } from '@atlasauth/pca';
import {
  type PcaDecisionRecord,
  type SiemSink,
  consoleSink,
  exportBatch,
  exportDecision,
  formatDecision,
  httpSink,
  toCef,
  toEcs,
  toOcsfEvent,
} from './index';

const K = (c: string, n = 20) => c.repeat(n); // 20-char keys: long enough to be abbreviated (>13)
const PRINCIPAL = K('P');
const MID = K('M');
const LEAF = K('L');
const NOW = 1_800_000_000_000;

function cap(issuer: string, holder: string, caveats: unknown[] = []): unknown {
  return { issuer, holder, caveats };
}

function pcactn(over: Record<string, unknown> = {}): any {
  const o: Record<string, unknown> = {
    ver: 3,
    alg: 'ml-dsa-65',
    sig: 'SIGSIG',
    nonce: 'nonce-1',
    counter: 7,
    iat: 1_700_000_000_000,
    exp: 1_700_000_060_000,
    grant_ref: 'grant-xyz',
    caution: 0.25,
    bond_ref: 'bond-1',
    action: { verb: 'stripe.refund', resource: 'charge/ch_1', params_digest: 'pd-1', reversibility_class: 'reversible' },
    plan: { root: 'plan-root-1' },
    cap_chain: [cap(PRINCIPAL, MID, [1, 2]), cap(MID, MID, [1, 2, 3]), cap(MID, LEAF, [1, 2, 3, 4, 5])],
    ...over,
  };
  for (const k of Object.keys(o)) if (o[k] === undefined) delete o[k]; // pcactnDigest rejects undefined members
  return o;
}

const PASS = { wire: 'pass', leaf_signature: 'pass', threshold: 'pass' } as any;
const verifyOk = (checks: any = PASS): any => ({ allow: true, checks });
const rec = (over: Partial<PcaDecisionRecord> & Record<string, unknown> = {}): PcaDecisionRecord =>
  ({ pcactn: pcactn(), verify: verifyOk(), now: NOW, ...over }) as PcaDecisionRecord;

const admit = (extra: any = {}): any => ({ admit: true, releaseGuardianShare: false, reasons: ['auto ok'], r: 0.5, requiredThreshold: { t: 1, proof: 'agent' }, ...extra });

describe('shortKey / chain string', () => {
  it('abbreviates keys longer than 13 chars, keeps <= 13 verbatim, (none) for empty/non-string', () => {
    const k13 = 'A'.repeat(13);
    const k14 = 'B'.repeat(14);
    const e1 = toEcs(rec({ pcactn: pcactn({ cap_chain: [cap(k13, k13)] }) }));
    expect(e1.user.name).toBe(k13);
    expect(e1.user.effective.name).toBe(k13);
    const e2 = toEcs(rec({ pcactn: pcactn({ cap_chain: [cap(k14, k14)] }) }));
    expect(e2.user.name).toBe('B'.repeat(12) + '…');
    expect(e2.user.effective.name).toBe('B'.repeat(12) + '…');
    const e3 = toEcs(rec({ pcactn: pcactn({ cap_chain: [] }) }));
    expect(e3.user.name).toBe('(none)');
    expect(e3.user.effective.name).toBe('(none)');
    expect(e3.user.effective.id).toBe('(none)');
    const e4 = toEcs(rec({ pcactn: pcactn({ cap_chain: [cap('', 5 as any)] }) }));
    expect(e4.user.name).toBe('(none)');
    expect(e4.user.effective.name).toBe('(none)');
  });
  it('chain string: abbreviated principal then each holder joined with " -> "; unknown principal placeholder', () => {
    const a = (PRINCIPAL.slice(0, 12) + '…');
    const m = (MID.slice(0, 12) + '…');
    const l = (LEAF.slice(0, 12) + '…');
    expect(toEcs(rec()).pca['delegation']).toMatchObject({ chain: `${a} -> ${m} -> ${m} -> ${l}` });
    const none = toEcs(rec({ pcactn: pcactn({ cap_chain: [] }) }));
    expect(none.pca['delegation']).toEqual({ depth: 0, chain: '(principal?)', hops: [] });
    const nop = toEcs(rec({ pcactn: pcactn({ cap_chain: [cap('', 'h')] }) }));
    expect((nop.pca['delegation'] as any).chain).toBe('(principal?) -> h');
  });
});

describe('hops / delegation chain', () => {
  it('computes isRoot, addedCaveats diffs, depth, and skips holes', () => {
    const e = toEcs(rec());
    expect(e.pca['delegation']).toMatchObject({
      depth: 2,
      hops: [
        { index: 0, isRoot: true, issuer: PRINCIPAL, holder: MID, addedCaveats: 2 },
        { index: 1, isRoot: false, issuer: MID, holder: MID, addedCaveats: 1 },
        { index: 2, isRoot: false, issuer: MID, holder: LEAF, addedCaveats: 2 },
      ],
    });
  });
  it('addedCaveats is clamped at 0 when a child has fewer caveats; missing caveat arrays count as 0', () => {
    const e = toEcs(rec({ pcactn: pcactn({ cap_chain: [cap('a', 'b', [1, 2, 3]), cap('b', 'c', [1]), { issuer: 'c', holder: 'd' }, cap('d', 'e', [1, 2])] }) }));
    const hops = (e.pca['delegation'] as any).hops;
    expect(hops.map((h: any) => h.addedCaveats)).toEqual([3, 0, 0, 2]);
    const e2 = toEcs(rec({ pcactn: pcactn({ cap_chain: [{ issuer: 'a', holder: 'b' }, cap('b', 'c', [1, 2])] }) }));
    expect((e2.pca['delegation'] as any).hops.map((h: any) => h.addedCaveats)).toEqual([0, 2]);
  });
  it('a hole in the chain is skipped (index keeps the array position); missing issuer/holder are (none)', () => {
    const chain: any[] = [cap('a', 'b'), undefined, { caveats: [] }];
    const e = toEcs(rec({ pcactn: pcactn({ cap_chain: chain }) }));
    expect((e.pca['delegation'] as any).hops).toEqual([
      { index: 0, isRoot: true, issuer: 'a', holder: 'b', addedCaveats: 0 },
      { index: 2, isRoot: false, issuer: '(none)', holder: '(none)', addedCaveats: 0 },
    ]);
    expect((e.pca['delegation'] as any).depth).toBe(1);
    expect(e.user.id).toBe('(none)');
  });
  it('a non-array cap_chain / missing pcactn are treated as an empty chain', () => {
    expect((toEcs(rec({ pcactn: pcactn({ cap_chain: 'nope' }) })).pca['delegation'] as any).hops).toEqual([]);
    const e = toEcs({ verify: verifyOk(), now: NOW } as any);
    expect((e.pca['delegation'] as any).hops).toEqual([]);
    expect(e.event.action).toBe('(unknown verb)');
  });
  it('OCSF unmapped delegation_chain uses snake_case fields', () => {
    const o = toOcsfEvent(rec());
    expect(o.unmapped['delegation_depth']).toBe(2);
    expect(o.unmapped['delegation_chain']).toEqual([
      { index: 0, is_root: true, issuer: PRINCIPAL, holder: MID, added_caveats: 2 },
      { index: 1, is_root: false, issuer: MID, holder: MID, added_caveats: 1 },
      { index: 2, is_root: false, issuer: MID, holder: LEAF, added_caveats: 2 },
    ]);
  });
});

describe('outcome resolution', () => {
  it('missing verify record is a deny (proof failed verification)', () => {
    const o = toOcsfEvent({ pcactn: pcactn(), now: NOW } as any);
    expect(o.status_detail).toBe('proof failed verification');
    expect(o.unmapped['checks']).toEqual({});
    expect(o.action_id).toBe(2);
  });
  it('verify.allow false: deny with verify.reason, else the default; ignores a permissive decision', () => {
    const o = toOcsfEvent(rec({ verify: { allow: false, reason: 'bad sig', checks: {} } as any, decision: admit() }));
    expect(o.status_detail).toBe('bad sig');
    expect(o.status).toBe('Failure');
    expect(o.metadata.labels).toEqual(['pca', 'outcome:deny', 'suite:ml-dsa-65']);
    const o2 = toOcsfEvent(rec({ verify: { allow: false, reason: '', checks: {} } as any }));
    expect(o2.status_detail).toBe('proof failed verification');
    const o3 = toOcsfEvent(rec({ verify: { allow: 'yes', checks: {} } as any }));
    expect(o3.action).toBe('Denied');
  });
  it('allow with no decision', () => {
    const o = toOcsfEvent(rec());
    expect(o.status_detail).toBe('proof verified; no policy decision supplied');
    expect(o.status).toBe('Success');
    expect(o.status_id).toBe(1);
    expect(o.action).toBe('Allowed');
    expect(o.action_id).toBe(1);
  });
  it('admit uses first reason, else the default', () => {
    expect(toOcsfEvent(rec({ decision: admit() })).status_detail).toBe('auto ok');
    expect(toOcsfEvent(rec({ decision: admit({ reasons: [] }) })).status_detail).toBe('auto-admitted within policy and budget');
    expect(toOcsfEvent(rec({ decision: admit({ reasons: [''] }) })).status_detail).toBe('auto-admitted within policy and budget');
    expect(toOcsfEvent(rec({ decision: admit({ reasons: [7] }) })).status_detail).toBe('auto-admitted within policy and budget');
    expect(toOcsfEvent(rec({ decision: admit({ reasons: 'abc' }) })).status_detail).toBe('auto-admitted within policy and budget');
    expect(toOcsfEvent(rec({ decision: admit({ reasons: undefined }) })).status_detail).toBe('auto-admitted within policy and budget');
  });
  it('step-up requires releaseGuardianShare without admit', () => {
    const d: any = { admit: false, releaseGuardianShare: true, reasons: ['need cosign'], requiredThreshold: { t: 2, proof: 'principal' } };
    const o = toOcsfEvent(rec({ decision: d }));
    expect(o.activity_id).toBe(3);
    expect(o.activity_name).toBe('Step-Up');
    expect(o.type_uid).toBe(300303);
    expect(o.type_name).toBe('Authorize Session: Step-Up');
    expect(o.action_id).toBe(99);
    expect(o.action).toBe('Other');
    expect(o.status_id).toBe(99);
    expect(o.status).toBe('Other');
    expect(o.status_detail).toBe('step-up / co-signature required: need cosign');
    expect(toOcsfEvent(rec({ decision: { ...d, reasons: [] } })).status_detail).toBe('step-up / co-signature required: policy satisfied but a co-signature is required');
  });
  it('deny from policy: first reason, else default-deny text', () => {
    const d: any = { admit: false, releaseGuardianShare: false, reasons: ['over budget'] };
    const o = toOcsfEvent(rec({ decision: d }));
    expect(o.activity_id).toBe(2);
    expect(o.activity_name).toBe('Deny');
    expect(o.type_uid).toBe(300302);
    expect(o.type_name).toBe('Authorize Session: Deny');
    expect(o.status_id).toBe(2);
    expect(o.status).toBe('Failure');
    expect(o.status_detail).toBe('over budget');
    expect(toOcsfEvent(rec({ decision: { ...d, reasons: [] } })).status_detail).toBe('policy did not release authority (default-deny)');
    expect(toOcsfEvent(rec({ decision: { admit: false, releaseGuardianShare: false } as any })).status_detail).toBe('policy did not release authority (default-deny)');
  });
});

describe('severity', () => {
  const deny = (checks: any, extra: any = {}) => toOcsfEvent(rec({ verify: { allow: false, reason: 'r', checks } as any, ...extra }));
  it('deny: High when any security check failed, Medium otherwise', () => {
    for (const k of ['wire', 'version', 'audience', 'validity', 'cap_chain', 'plan_inclusion', 'leaf_signature', 'counter']) {
      const o = deny({ [k]: 'fail' });
      expect([o.severity_id, o.severity]).toEqual([4, 'High']);
    }
    expect([deny({ wire: 'pass', policy: 'fail', threshold: 'fail' }).severity_id, deny({}).severity]).toEqual([3, 'Medium']);
    expect(deny({ wire: 'pass' }).severity).toBe('Medium');
  });
  it('step-up is Medium even with tier 1; allow scales with tier', () => {
    const su: any = { admit: false, releaseGuardianShare: true, reasons: [], requiredThreshold: { t: 1 } };
    expect(toOcsfEvent(rec({ decision: su })).severity).toBe('Medium');
    const t = (tier: any) => toOcsfEvent(rec({ decision: admit({ requiredThreshold: { t: tier, proof: 'agent' } }) }));
    expect([t(3).severity_id, t(3).severity]).toEqual([3, 'Medium']);
    expect([t(2).severity_id, t(2).severity]).toEqual([2, 'Low']);
    expect([t(1).severity_id, t(1).severity]).toEqual([1, 'Informational']);
    expect(toOcsfEvent(rec()).severity).toBe('Informational');
  });
  it('CEF severity numbers per level', () => {
    const sev = (line: string) => line.split('|')[6];
    expect(sev(toCef(rec()))).toBe('1');
    expect(sev(toCef(rec({ decision: admit({ requiredThreshold: { t: 2 } }) })))).toBe('3');
    expect(sev(toCef(rec({ decision: admit({ requiredThreshold: { t: 3 } }) })))).toBe('5');
    expect(sev(toCef(rec({ verify: { allow: false, checks: { wire: 'fail' } } as any })))).toBe('8');
    expect(sev(toCef(rec({ verify: { allow: false, checks: {} } as any })))).toBe('5');
    expect(toEcs(rec({ verify: { allow: false, checks: { counter: 'fail' } } as any })).event.severity).toBe(8);
  });
});

describe('human override (threshold shares)', () => {
  const shares = [
    { role: 'principal', publicKey: 'PK1' },
    { role: 'guardian', publicKey: 'GK1' },
    { role: 'agent', publicKey: 'AK1' },
    { role: 'guardian', publicKey: 7 },
    { role: 'principal', publicKey: 9 },
    { role: 9, publicKey: 'ZZ' },
    null,
  ];
  it('verified shares produce approvers, guardians and roles', () => {
    const o = toOcsfEvent(rec({ pcactn: pcactn({ threshold: { shares } }) }));
    expect(o.unmapped['human_override']).toEqual({ human_approved: true, approvers: ['PK1'], guardian_cosigners: ['GK1'], roles: ['principal', 'guardian', 'agent', 'guardian', 'principal'] });
    expect(o.message).toContain('; human-signed step-up). ');
    const e = toEcs(rec({ pcactn: pcactn({ threshold: { shares } }) }));
    expect((e.pca['human_override'] as any)).toEqual({ human_approved: true, approvers: ['PK1'], guardian_cosigners: ['GK1'], roles: ['principal', 'guardian', 'agent', 'guardian', 'principal'] });
    expect(e.related.user).toEqual([LEAF, PRINCIPAL, 'PK1']);
    expect(toCef(rec({ pcactn: pcactn({ threshold: { shares } }) }))).toContain(' flexString1=true ');
  });
  it('guardian-only shares are not a human approval', () => {
    const o = toOcsfEvent(rec({ pcactn: pcactn({ threshold: { shares: [{ role: 'guardian', publicKey: 'G' }] } }) }));
    expect(o.unmapped['human_override']).toBeUndefined();
    expect(o.message).not.toContain('human-signed');
    expect(toCef(rec({ pcactn: pcactn({ threshold: { shares: [{ role: 'guardian', publicKey: 'G' }] } }) }))).toContain(' flexString1=false ');
  });
  it('unverified shares never reach related identities', () => {
    const e = toEcs(rec({ pcactn: pcactn({ threshold: { shares } }), verify: verifyOk({ wire: 'pass', threshold: 'fail' }) }));
    expect(e.related.user).toEqual([LEAF, PRINCIPAL]);
  });
  it('identical proof digest and signature are listed once', () => {
    const bad: any = { ...pcactn(), nonce: undefined, sig: '(undigestible)' };
    expect(toEcs({ pcactn: bad, verify: verifyOk(), now: NOW } as any).related.hash).toEqual(['(undigestible)']);
  });
  it('shares are ignored unless checks.threshold passed', () => {
    for (const t of ['fail', 'skip', undefined]) {
      const o = toOcsfEvent(rec({ pcactn: pcactn({ threshold: { shares } }), verify: verifyOk({ wire: 'pass', leaf_signature: 'pass', threshold: t }) }));
      expect(o.unmapped['human_override']).toBeUndefined();
    }
  });
  it('a non-array shares list / missing threshold is empty', () => {
    expect(toOcsfEvent(rec({ pcactn: pcactn({ threshold: { shares: 'x' } }) })).unmapped['human_override']).toBeUndefined();
    expect(toOcsfEvent(rec({ pcactn: pcactn({ threshold: undefined }) })).unmapped['human_override']).toBeUndefined();
    expect(toOcsfEvent(rec({ pcactn: pcactn({ threshold: { shares: [] } }) })).unmapped['human_override']).toBeUndefined();
  });
});

describe('OCSF event exact shape', () => {
  it('full golden event for an admitted action', () => {
    const p = pcactn();
    const digest = pcactnDigest(p);
    const d = admit({ r: 0.5, requiredThreshold: { t: 2, proof: 'agent' } });
    const o = toOcsfEvent(rec({ pcactn: p, decision: d, session: 'sess-1' }));
    const A = (PRINCIPAL.slice(0, 12) + '…');
    const L = (LEAF.slice(0, 12) + '…');
    const M = (MID.slice(0, 12) + '…');
    expect(o).toEqual({
      activity_id: 1,
      activity_name: 'Allow',
      category_uid: 3,
      category_name: 'Identity & Access Management',
      class_uid: 3003,
      class_name: 'Authorize Session',
      type_uid: 300301,
      type_name: 'Authorize Session: Allow',
      action_id: 1,
      action: 'Allowed',
      severity_id: 2,
      severity: 'Low',
      status_id: 1,
      status: 'Success',
      status_detail: 'auto ok',
      time: 1_700_000_000_000,
      actor: {
        user: { type_id: 99, type: 'Agent', uid: LEAF, name: L },
        invoked_by: PRINCIPAL,
        session: { uid: 'sess-1', issuer: PRINCIPAL },
        app_name: 'PCA',
      },
      user: { type_id: 1, type: 'User', uid: PRINCIPAL, name: A },
      resources: [{ type: 'pca.resource', name: 'charge/ch_1', uid: 'charge/ch_1' }],
      api: { operation: 'stripe.refund', service: { name: 'PCA' } },
      metadata: { version: '1.1.0', product: { name: 'PCA', vendor_name: 'Atlas', version: '1.1.0' }, logged_time: NOW, uid: digest, labels: ['pca', 'outcome:allow', 'suite:ml-dsa-65'] },
      observables: [
        { name: 'actor.user.uid', type: 'User Name', type_id: 4, value: LEAF },
        { name: 'pca.proof.digest', type: 'Hash', type_id: 8, value: digest },
        { name: 'resources.uid', type: 'Resource UID', type_id: 10, value: 'charge/ch_1' },
      ],
      count: 1,
      message: `Agent ${L} ALLOWED to stripe.refund on charge/ch_1 (3-hop chain rooted at principal ${A}; cryptographically verifiable proof). auto ok`,
      unmapped: {
        proof_digest: digest,
        leaf_signature: 'SIGSIG',
        signature_suite: 'ml-dsa-65',
        cryptographically_verifiable: true,
        plan_root: 'plan-root-1',
        params_digest: 'pd-1',
        grant_ref: 'grant-xyz',
        counter: 7,
        nonce: 'nonce-1',
        reversibility_class: 'reversible',
        risk_score: 0.5,
        risk_tier: 2,
        required_proof: 'agent',
        caution: 0.25,
        bond_ref: 'bond-1',
        delegation_depth: 2,
        delegation_chain: [
          { index: 0, is_root: true, issuer: PRINCIPAL, holder: MID, added_caveats: 2 },
          { index: 1, is_root: false, issuer: MID, holder: MID, added_caveats: 1 },
          { index: 2, is_root: false, issuer: MID, holder: LEAF, added_caveats: 2 },
        ],
        checks: PASS,
      },
    });
    void M;
  });
  it('deny narrative and session default to the grant ref; step-up narrative word', () => {
    const a = toOcsfEvent(rec({ verify: { allow: false, reason: 'nope', checks: {} } as any }));
    expect(a.actor.session.uid).toBe('grant-xyz');
    expect(a.message).toContain(' DENIED to stripe.refund on charge/ch_1 (3-hop chain rooted at principal ');
    expect(a.message).toContain('; proof not cryptographically verifiable). nope');
    expect(toOcsfEvent(rec({ session: '' })).actor.session.uid).toBe('grant-xyz');
    const s = toOcsfEvent(rec({ decision: { admit: false, releaseGuardianShare: true, reasons: [] } as any }));
    expect(s.message).toContain(' STEP-UP to ');
  });
  it('cryptographicallyVerifiable needs BOTH wire and leaf_signature to pass', () => {
    const f = (checks: any) => toOcsfEvent(rec({ verify: verifyOk(checks) })).unmapped['cryptographically_verifiable'];
    expect(f({ wire: 'pass', leaf_signature: 'pass' })).toBe(true);
    expect(f({ wire: 'pass', leaf_signature: 'fail' })).toBe(false);
    expect(f({ wire: 'fail', leaf_signature: 'pass' })).toBe(false);
    expect(f({})).toBe(false);
  });
  it('fallback values for an empty / garbage PCActn', () => {
    const o = toOcsfEvent({ pcactn: {}, verify: verifyOk({}), now: NOW } as any);
    expect(o.time).toBe(NOW);
    expect(o.resources).toEqual([{ type: 'pca.resource', name: '(unknown resource)', uid: '(unknown resource)' }]);
    expect(o.api.operation).toBe('(unknown verb)');
    expect(o.metadata.labels).toEqual(['pca', 'outcome:allow', 'suite:ed25519']);
    expect(o.actor.user).toEqual({ type_id: 99, type: 'Agent', uid: '(none)', name: '(none)' });
    expect(o.actor.invoked_by).toBe('(none)');
    expect(o.user).toEqual({ type_id: 1, type: 'User', uid: '(none)', name: '(none)' });
    expect(o.actor.session).toEqual({ uid: '(none)', issuer: undefined });
    expect(o.unmapped).toEqual({
      proof_digest: o.metadata.uid,
      leaf_signature: '(unsigned)',
      signature_suite: 'ed25519',
      cryptographically_verifiable: false,
      plan_root: '(none)',
      params_digest: '(none)',
      grant_ref: '(none)',
      counter: -1,
      reversibility_class: '(unknown)',
      delegation_depth: 0,
      delegation_chain: [],
      checks: {},
    });
    expect(Object.keys(o.unmapped)).not.toContain('nonce');
    expect(Object.keys(o.unmapped)).not.toContain('risk_score');
  });
  it('time falls back to now when iat is not finite; now defaults to Date.now()', () => {
    expect(toOcsfEvent(rec({ pcactn: pcactn({ iat: Infinity }) })).time).toBe(NOW);
    expect(toOcsfEvent(rec({ pcactn: pcactn({ iat: '5' }) })).time).toBe(NOW);
    const spy = vi.spyOn(Date, 'now').mockReturnValue(4242);
    try {
      expect(toOcsfEvent(rec({ now: undefined })).metadata.logged_time).toBe(4242);
      expect(toOcsfEvent(rec({ now: NaN })).metadata.logged_time).toBe(4242);
      expect(toOcsfEvent(rec({ now: 0 })).metadata.logged_time).toBe(0);
      expect(toOcsfEvent(rec({ now: '9' as any })).metadata.logged_time).toBe(4242);
    } finally {
      spy.mockRestore();
    }
  });
  it('an undigestible PCActn yields the placeholder digest', () => {
    const circular: any = pcactn();
    circular.self = circular;
    const bad: any = { ...pcactn(), nonce: undefined };
    const o = toOcsfEvent({ pcactn: bad, verify: verifyOk(), now: NOW } as any);
    expect(o.metadata.uid).toBe('(undigestible)');
    expect(o.unmapped['proof_digest']).toBe('(undigestible)');
    expect(toCef({ pcactn: bad, verify: verifyOk(), now: NOW } as any)).toContain(' cs1=(undigestible) ');
  });
  it('numeric optional fields: non-finite values are dropped', () => {
    const o = toOcsfEvent(rec({ pcactn: pcactn({ caution: NaN, nonce: 5, bond_ref: 5 }), decision: admit({ r: Infinity, requiredThreshold: { t: 1 } }) }));
    for (const k of ['caution', 'nonce', 'bond_ref', 'risk_score', 'required_proof']) expect(Object.keys(o.unmapped)).not.toContain(k);
    expect(o.unmapped['risk_tier']).toBe(1);
    const o2 = toOcsfEvent(rec({ decision: admit({ r: 0 }) }));
    expect(o2.unmapped['risk_score']).toBe(0);
    const o3 = toOcsfEvent(rec({ pcactn: pcactn({ counter: 0, caution: 0, nonce: '', bond_ref: '' }) }));
    expect(o3.unmapped['counter']).toBe(0);
    expect(o3.unmapped['caution']).toBe(0);
    expect(o3.unmapped['nonce']).toBe('');
    expect(o3.unmapped['bond_ref']).toBe('');
  });
});

describe('CEF', () => {
  it('exact line for an admitted action', () => {
    const p = pcactn();
    const digest = pcactnDigest(p);
    const line = toCef(rec({ pcactn: p, decision: admit({ r: 0.5, requiredThreshold: { t: 2, proof: 'agent' } }) }));
    const A = (PRINCIPAL.slice(0, 12) + '…');
    const M = (MID.slice(0, 12) + '…');
    const L = (LEAF.slice(0, 12) + '…');
    const name = 'PCA authorization allow: stripe.refund on charge/ch_1';
    const ext = [
      'act=allow', 'outcome=allow', `suser=${PRINCIPAL}`, `suid=${PRINCIPAL}`, `duser=${LEAF}`, `duid=${LEAF}`,
      'destinationServiceName=stripe.refund', `rt=${NOW}`, 'start=1700000000000', 'end=1700000060000', 'externalId=nonce-1',
      'request=charge/ch_1', 'requestMethod=stripe.refund',
      'cs1Label=pcaProofDigest', `cs1=${digest}`,
      'cs2Label=pcaDelegationChain', `cs2=${A} -> ${M} -> ${M} -> ${L}`,
      'cs3Label=pcaProofStrength', 'cs3=agent',
      'cs4Label=pcaSignatureSuite', 'cs4=ml-dsa-65',
      'cs5Label=pcaVerifyChecks', 'cs5=wire:pass;leaf_signature:pass;threshold:pass',
      'cs6Label=pcaGrantRef', 'cs6=grant-xyz',
      'cn1Label=pcaRiskScore', 'cn1=0.5', 'cn2Label=pcaDelegationDepth', 'cn2=2', 'cn3Label=pcaRiskTier', 'cn3=2',
      'flexString1Label=pcaHumanApproved', 'flexString1=false', 'cat=authorization', 'msg=auto ok',
    ].join(' ');
    expect(line).toBe(`CEF:0|Atlas|PCA|3|pca-authz-allow|${name}|3|${ext}`);
  });
  it('defaults: version 2, externalId counter, n/a proof strength, empty cn values', () => {
    const line = toCef({ pcactn: { action: { verb: 'v', resource: 'r' } }, verify: verifyOk({}), now: 5 } as any);
    expect(line.startsWith('CEF:0|Atlas|PCA|2|pca-authz-allow|PCA authorization allow: v on r|1|')).toBe(true);
    expect(line).toContain(' externalId=-1 ');
    expect(line).toContain(' cs3=n/a ');
    expect(line).toContain(' cs5Label=pcaVerifyChecks cs5= ');
    expect(line).toContain(' cn1Label=pcaRiskScore cn1= cn2Label=pcaDelegationDepth cn2=0 cn3Label=pcaRiskTier cn3= ');
    expect(line).toContain(' suser=(none) suid=(none) duser=(none) duid=(none) ');
    expect(line).toContain(' cs2=(principal?) ');
    expect(line).toContain(' rt=5 start=5 end=5 ');
    expect(line).toContain(' cs4=ed25519 ');
    expect(line).toContain(' cs6=(none) ');
    expect(toCef({ verify: verifyOk({}), now: 5 } as any).startsWith('CEF:0|Atlas|PCA|2|')).toBe(true);
    expect(toCef(rec({ pcactn: pcactn({ ver: 'x' }) })).split('|')[3]).toBe('2');
    expect(toCef(rec({ pcactn: pcactn({ ver: 0 }) })).split('|')[3]).toBe('0');
  });
  it('risk score 0 and tier values are rendered, not blanked', () => {
    const line = toCef(rec({ decision: admit({ r: 0, requiredThreshold: { t: 3, proof: 'x' } }) }));
    expect(line).toContain(' cn1=0 ');
    expect(line).toContain(' cn3=3 ');
  });
  it('header escaping: backslash, pipe, CR/LF runs collapse to one space; extension escapes \\, =, newlines', () => {
    const line = toCef(rec({ pcactn: pcactn({ action: { verb: 'a|b\\c\r\n\nd', resource: 'x' } }) }));
    const hdr = line.split(/(?<!\\)\|/);
    expect(hdr[5]).toBe('PCA authorization allow: a\\|b\\\\c d on x');
    const ext = toCef(rec({ pcactn: pcactn({ action: { verb: 'a=b\\c\nd\r\ne\rf', resource: 'x' } }) }));
    expect(ext).toContain(' destinationServiceName=a\\=b\\\\c\\nd\\ne\\nf ');
    expect(ext).toContain(' requestMethod=a\\=b\\\\c\\nd\\ne\\nf ');
  });
  it('missing nonce falls back to the counter; the msg carries the reason', () => {
    const line = toCef(rec({ pcactn: pcactn({ nonce: undefined, counter: 12 }), verify: { allow: false, reason: 'x=y', checks: { wire: 'fail' } } as any }));
    expect(line).toContain(' externalId=12 ');
    expect(line.endsWith(' msg=x\\=y')).toBe(true);
    expect(line).toContain(' cs5=wire:fail ');
  });
});

describe('ECS', () => {
  it('exact event for a denial', () => {
    const p = pcactn({ nonce: undefined, bond_ref: undefined, caution: undefined });
    const digest = pcactnDigest(p);
    const e = toEcs({ pcactn: p, verify: { allow: false, reason: 'bad', checks: { leaf_signature: 'fail' } }, now: NOW } as any);
    const A = (PRINCIPAL.slice(0, 12) + '…');
    const M = (MID.slice(0, 12) + '…');
    const L = (LEAF.slice(0, 12) + '…');
    expect(e).toEqual({
      '@timestamp': '2023-11-14T22:13:20.000Z',
      'ecs.version': '8.11.0',
      event: { kind: 'event', category: ['iam'], type: ['denied'], action: 'stripe.refund', outcome: 'failure', module: 'pca', dataset: 'pca.authorization', provider: 'pca', id: digest, severity: 8, reason: 'bad' },
      user: { id: LEAF, name: L, roles: ['agent'], effective: { id: PRINCIPAL, name: A } },
      service: { name: 'pca', type: 'authorization' },
      related: { user: [LEAF, PRINCIPAL], hash: [digest, 'SIGSIG'] },
      message: `Agent ${L} DENIED to stripe.refund on charge/ch_1 (3-hop chain rooted at principal ${A}; proof not cryptographically verifiable). bad`,
      pca: {
        outcome: 'deny',
        proof: { digest, leaf_signature: 'SIGSIG', signature_suite: 'ml-dsa-65', cryptographically_verifiable: false, plan_root: 'plan-root-1', params_digest: 'pd-1' },
        risk: {},
        delegation: {
          depth: 2,
          chain: `${A} -> ${M} -> ${M} -> ${L}`,
          hops: [
            { index: 0, isRoot: true, issuer: PRINCIPAL, holder: MID, addedCaveats: 2 },
            { index: 1, isRoot: false, issuer: MID, holder: MID, addedCaveats: 1 },
            { index: 2, isRoot: false, issuer: MID, holder: LEAF, addedCaveats: 2 },
          ],
        },
        grant_ref: 'grant-xyz',
        counter: 7,
        reversibility_class: 'reversible',
        checks: { leaf_signature: 'fail' },
      },
    });
    expect(Object.keys(e.event)).not.toContain('risk_score');
  });
  it('event types / outcomes per disposition and risk_score including 0', () => {
    expect(toEcs(rec()).event).toMatchObject({ type: ['allowed'], outcome: 'success' });
    expect(toEcs(rec({ decision: { admit: false, releaseGuardianShare: true } as any })).event).toMatchObject({ type: ['info'], outcome: 'unknown' });
    expect(toEcs(rec({ decision: admit({ r: 0 }) })).event.risk_score).toBe(0);
    expect(toEcs(rec({ decision: admit({ r: 0.75 }) })).pca['risk']).toEqual({ score: 0.75, tier: 1, required_proof: 'agent' , caution: 0.25 });
  });
  it('related users and hashes are de-duplicated', () => {
    const same = toEcs(rec({ pcactn: pcactn({ cap_chain: [cap('SAME', 'SAME')], sig: 'X' }) }));
    expect(same.related.user).toEqual(['SAME']);
    const hash = toEcs(rec({ pcactn: pcactn({ cap_chain: [cap('a', 'b')] }) })).related.hash;
    expect(hash).toHaveLength(2);
    const e = toEcs(rec({ pcactn: pcactn({ cap_chain: [cap('P', 'P')], threshold: { shares: [{ role: 'principal', publicKey: 'P' }, { role: 'principal', publicKey: 'Q' }] } }) }));
    expect(e.related.user).toEqual(['P', 'Q']);
    const e2 = toEcs(rec({ pcactn: pcactn({ cap_chain: [cap('', 'h')], threshold: { shares: [{ role: 'principal', publicKey: 'h' }] } }) }));
    expect(e2.related.user).toEqual(['h']);
  });
  it('the timestamp falls back to epoch for a non-finite or out-of-range time', () => {
    expect(toEcs(rec({ pcactn: pcactn({ iat: 8.64e15 + 1 }) }))['@timestamp']).toBe('1970-01-01T00:00:00.000Z');
    expect(toEcs(rec({ pcactn: pcactn({ iat: 0 }) }))['@timestamp']).toBe('1970-01-01T00:00:00.000Z');
    expect(toEcs(rec({ pcactn: pcactn({ iat: 1000 }) }))['@timestamp']).toBe('1970-01-01T00:00:01.000Z');
  });
});

describe('sinks and export', () => {
  const ok = { ok: true, status: 200 };
  it('formatDecision serialises per format', () => {
    const r = rec();
    expect(formatDecision(r, 'cef')).toEqual({ format: 'cef', line: toCef(r) });
    const o = formatDecision(r, 'ocsf');
    expect(o.object).toEqual(toOcsfEvent(r));
    expect(o.line).toBe(JSON.stringify(toOcsfEvent(r)));
    const e = formatDecision(r, 'ecs');
    expect(e.object).toEqual(toEcs(r));
    expect(e.line).toBe(JSON.stringify(toEcs(r)));
  });
  it('httpSink: name, content types, header merge, body join, status text', async () => {
    const calls: any[] = [];
    const fetch = async (url: string, init: any) => (calls.push([url, init]), ok);
    const evs = [{ format: 'cef' as const, line: 'a' }, { format: 'cef' as const, line: 'b' }];
    expect(httpSink('u', { format: 'ocsf', fetch }).name).toBe('http:ocsf');
    expect(httpSink('u', { format: 'ecs', fetch, name: 'N' }).name).toBe('N');
    expect(httpSink('u', { format: 'cef', fetch }).format).toBe('cef');
    expect(await httpSink('http://x', { format: 'cef', fetch, headers: { Authorization: 'Splunk t' } }).deliver(evs)).toEqual({ ok: true });
    expect(calls[0]).toEqual(['http://x', { method: 'POST', headers: { 'content-type': 'text/plain; charset=utf-8', Authorization: 'Splunk t' }, body: 'a\nb' }]);
    await httpSink('u', { format: 'ocsf', fetch }).deliver(evs);
    expect(calls[1][1].headers).toEqual({ 'content-type': 'application/x-ndjson' });
    await httpSink('u', { format: 'ecs', fetch }).deliver(evs);
    expect(calls[2][1].headers).toEqual({ 'content-type': 'application/x-ndjson' });
    await httpSink('u', { format: 'ecs', fetch, contentType: 'x/y', headers: { 'content-type': 'z/z' } }).deliver(evs);
    expect(calls[3][1].headers).toEqual({ 'content-type': 'z/z' });
    await httpSink('u', { format: 'ecs', fetch, contentType: 'x/y' }).deliver(evs);
    expect(calls[4][1].headers).toEqual({ 'content-type': 'x/y' });
    await httpSink('u', { format: 'ecs', fetch }).deliver([]);
    expect(calls[5][1].body).toBe('');
  });
  it('httpSink failures never throw: status with and without text, thrown Error / non-Error, no fetch', async () => {
    const ev = [{ format: 'cef' as const, line: 'a' }];
    expect(await httpSink('u', { format: 'cef', fetch: async () => ({ ok: false, status: 503, statusText: 'Down' }) }).deliver(ev)).toEqual({ ok: false, error: 'HTTP 503 Down' });
    expect(await httpSink('u', { format: 'cef', fetch: async () => ({ ok: false, status: 500 }) }).deliver(ev)).toEqual({ ok: false, error: 'HTTP 500' });
    expect(await httpSink('u', { format: 'cef', fetch: async () => ({ ok: false, status: 500, statusText: '' }) }).deliver(ev)).toEqual({ ok: false, error: 'HTTP 500' });
    expect(await httpSink('u', { format: 'cef', fetch: async () => { throw new Error('boom'); } }).deliver(ev)).toEqual({ ok: false, error: 'boom' });
    expect(await httpSink('u', { format: 'cef', fetch: async () => { throw 'str'; } }).deliver(ev)).toEqual({ ok: false, error: 'str' });
  });
  it('httpSink defaults to globalThis.fetch; reports when none exists', async () => {
    const g = globalThis as any;
    const orig = g.fetch;
    const seen: any[] = [];
    try {
      g.fetch = async (u: string, i: any) => (seen.push([u, i.body]), { ok: true, status: 200 });
      expect(await httpSink('http://g', { format: 'cef' }).deliver([{ format: 'cef', line: 'L' }])).toEqual({ ok: true });
      expect(seen).toEqual([['http://g', 'L']]);
      g.fetch = 'not a function';
      expect(await httpSink('http://g', { format: 'cef' }).deliver([])).toEqual({ ok: false, error: 'no fetch implementation available (pass options.fetch)' });
      g.fetch = undefined;
      expect(await httpSink('http://g', { format: 'cef' }).deliver([])).toEqual({ ok: false, error: 'no fetch implementation available (pass options.fetch)' });
    } finally {
      g.fetch = orig;
    }
  });
  it('consoleSink: defaults, names, line per event, logger errors caught', () => {
    const lines: string[] = [];
    const s = consoleSink({ logger: (l) => lines.push(l) });
    expect(s.format).toBe('ocsf');
    expect(s.name).toBe('console:ocsf');
    expect(s.deliver([{ format: 'cef', line: 'x' }, { format: 'cef', line: 'y' }])).toEqual({ ok: true });
    expect(lines).toEqual(['x', 'y']);
    const c = consoleSink({ format: 'cef', name: 'mine' });
    expect([c.format, c.name]).toEqual(['cef', 'mine']);
    const log = vi.spyOn(console, 'log').mockImplementation(() => undefined);
    try {
      expect(consoleSink().deliver([{ format: 'cef', line: 'zz' }])).toEqual({ ok: true });
      expect(log).toHaveBeenCalledWith('zz');
    } finally {
      log.mockRestore();
    }
    expect(consoleSink({ logger: () => { throw new Error('lg'); } }).deliver([{ format: 'cef', line: 'q' }])).toEqual({ ok: false, error: 'lg' });
    expect(consoleSink({ logger: () => { throw 'plain'; } }).deliver([{ format: 'cef', line: 'q' }])).toEqual({ ok: false, error: 'plain' });
  });
  it('exportBatch: success, delivery failure details, thrown sink, onError isolation', async () => {
    const good: SiemSink = { name: 'g', format: 'cef', deliver: (e) => (expect(e).toHaveLength(2), { ok: true }) };
    expect(await exportBatch([rec(), rec()], good)).toEqual({ ok: true, delivered: 2, format: 'cef' });
    expect(await exportDecision(rec(), { name: 'g', format: 'ecs', deliver: () => ({ ok: true }) })).toEqual({ ok: true, delivered: 1, format: 'ecs' });

    const errs: any[] = [];
    const bad: SiemSink = { name: 'bad', format: 'ocsf', deliver: () => ({ ok: false, error: 'rejected' }) };
    expect(await exportBatch([rec(), rec(), rec()], bad, { onError: (e, c) => errs.push([e.message, c]) })).toEqual({ ok: false, delivered: 0, format: 'ocsf', error: 'rejected' });
    expect(errs).toEqual([['rejected', { sink: 'bad', count: 3 }]]);
    const noMsg: SiemSink = { name: 'nm', format: 'ocsf', deliver: () => ({ ok: false }) };
    expect((await exportBatch([rec()], noMsg)).error).toBe('sink reported a delivery failure');
    // no options / throwing onError never escapes
    expect((await exportBatch([rec()], bad, undefined)).ok).toBe(false);
    expect((await exportBatch([rec()], bad, {})).ok).toBe(false);
    expect((await exportBatch([rec()], bad, { onError: () => { throw new Error('x'); } })).error).toBe('rejected');

    const errs2: any[] = [];
    const thrower: SiemSink = { name: 'th', format: 'cef', deliver: async () => { throw new Error('net'); } };
    expect(await exportBatch([rec(), rec()], thrower, { onError: (e, c) => errs2.push([e.message, c]) })).toEqual({ ok: false, delivered: 0, format: 'cef', error: 'net' });
    expect(errs2).toEqual([['net', { sink: 'th', count: 2 }]]);
    const strThrower: SiemSink = { name: 'st', format: 'cef', deliver: () => { throw 'oops'; } };
    expect((await exportBatch([rec()], strThrower)).error).toBe('oops');
    // a sink without a name is labelled '(unknown sink)'; a formatting failure keeps count 0
    const errs3: any[] = [];
    const r = await exportBatch([rec()], { format: 'cef', deliver: () => { throw new Error('nn'); } } as any, { onError: (e, c) => errs3.push([e.message, c]) });
    expect(r.ok).toBe(false);
    expect(errs3).toEqual([['nn', { sink: '(unknown sink)', count: 1 }]]);
    const errs4: any[] = [];
    await exportBatch([{ pcactn: pcactn(), verify: verifyOk(), now: NOW }, null as any], { name: 'f', format: 'ocsf', deliver: () => ({ ok: true }) }, { onError: (e, c) => errs4.push(c) });
    expect(errs4).toEqual([{ sink: 'f', count: 0 }]);
  });
});
