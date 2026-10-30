import { describe, expect, it } from 'vitest';
import { memoryLeaseKv } from './lease';
import { b64u, publicKeyOf } from '@atlasauth/pca';
import {
  LEASE_DOMAIN, LEASE_REVOKE_DOMAIN, LeaseRegistry, ShadowLog, checkLease, leaseCap, leaseResourceHandler, leaseManagementMetadata, pathUnder, promoteShadow, promotionGate,
  renewLease, runShadow, signLease, signLeaseRevocation, sodError, verifyLease, verifyLeaseRevocation, verifyShadowDiff, signWideningExplanation, signPromotionApproval, signDomainBody as signBody,
  type Lease, type NewLease,
} from './index';
import { bundleDigest, type PolicyBundleBody } from './bundle';

const SK = new Uint8Array(32).fill(31);
const AUTH = b64u(publicKeyOf(SK));
const T0 = 1_800_000_000_000;
const base: NewLease = { lease_id: 'L', path: 'a/b', grant_ref: 'g', holder: 'h', requester: 'r', approvers: ['x'], justification_digest: 'j', seq: 1, issued_at: T0, renewed_at: T0, expires_at: T0 + 100, max_ttl: 1000 };
const forge = (over: Record<string, unknown>) => {
  const body = { v: 1, ...base, authority: AUTH, ...over };
  return { ...body, sig: signBody(LEASE_DOMAIN, body, SK) };
};

describe('lease record shape: every field is checked (exact verify results)', () => {
  it('the baseline forge verifies', () => expect(verifyLease(forge({}))).toBe(true));
  const bad: [string, Record<string, unknown>][] = [
    ['v', { v: 2 }], ['empty lease_id', { lease_id: '' }], ['long lease_id', { lease_id: 'a'.repeat(129) }], ['empty grant_ref', { grant_ref: '' }], ['long grant_ref', { grant_ref: 'a'.repeat(257) }],
    ['empty holder', { holder: '' }], ['long holder', { holder: 'a'.repeat(129) }], ['empty requester', { requester: '' }], ['empty authority', { authority: '' }],
    ['empty justification', { justification_digest: '' }], ['long justification', { justification_digest: 'a'.repeat(129) }],
    ['path not a string', { path: 5 }], ['path uppercase', { path: 'A/b' }], ['path trailing slash', { path: 'a/b/' }], ['path empty segment', { path: 'a//b' }], ['path of nine segments', { path: 'a/b/c/d/e/f/g/h/i' }], ['path segment of 65', { path: 'a'.repeat(65) }], ['empty path', { path: '' }],
    ['seq 0', { seq: 0 }], ['seq fraction', { seq: 1.5 }], ['seq string', { seq: '1' }], ['issued_at fraction', { issued_at: 1.5 }], ['renewed_at before issued_at', { renewed_at: T0 - 1 }],
    ['expires_at equal renewed_at', { expires_at: T0 }], ['expires_at before renewed_at', { expires_at: T0 - 1 }], ['max_ttl 0', { max_ttl: 0 }], ['max_ttl fraction', { max_ttl: 1.5 }],
    ['seq 1 renewed later than issued', { renewed_at: T0 + 1 }], ['approvers not an array', { approvers: 'x' }], ['17 approvers', { approvers: Array.from({ length: 17 }, (_, i) => `a${i}`) }], ['empty approver', { approvers: [''] }], ['numeric approver', { approvers: [5] }],
  ];
  it.each(bad)('%s is refused', (_n, over) => expect(verifyLease(forge(over))).toBe(false));
  it('16 approvers, a 128-char id and a 64-char segment are the limits that pass', () => {
    expect(verifyLease(forge({ approvers: Array.from({ length: 16 }, (_, i) => `a${i}`) }))).toBe(true);
    expect(verifyLease(forge({ lease_id: 'a'.repeat(128) }))).toBe(true);
    expect(verifyLease(forge({ path: 'a'.repeat(64) }))).toBe(true);
    expect(verifyLease(forge({ path: 'a/b/c/d/e/f/g/h' }))).toBe(true);
    expect(verifyLease(forge({ seq: 2, renewed_at: T0 + 1, expires_at: T0 + 2 }))).toBe(true);
  });
  it('a lease past its cap verifies as a record but is refused by the registry', async () => {
    const over = forge({ expires_at: T0 + 1001 });
    expect(verifyLease(over)).toBe(true);
    expect(await new LeaseRegistry({ authorities: [AUTH] }, memoryLeaseKv()).accept(over)).toEqual({ ok: false, code: 'over_max_ttl' });
    expect(leaseCap(over as Lease)).toBe(T0 + 1000);
  });
  it('the signature domain matters', () => {
    const body = { v: 1, ...base, authority: AUTH };
    expect(verifyLease({ ...body, sig: signBody(LEASE_REVOKE_DOMAIN, body, SK) })).toBe(false);
    expect(verifyLease({ ...body })).toBe(false);
    expect(verifyLease({ ...body, sig: 5 })).toBe(false);
  });
});

describe('revocation shape', () => {
  const rb = (over: Record<string, unknown>) => { const body = { v: 1, target: 'lease', value: 'L', revoked_at: T0, authority: AUTH, ...over }; return { ...body, sig: signBody(LEASE_REVOKE_DOMAIN, body, SK) }; };
  it.each([['v', { v: 2 }], ['target', { target: 'tree' }], ['empty value', { value: '' }], ['long value', { value: 'a'.repeat(257) }], ['revoked_at fraction', { revoked_at: 1.5 }], ['empty authority', { authority: '' }], ['prefix with uppercase', { target: 'prefix', value: 'A' }], ['prefix with trailing slash', { target: 'prefix', value: 'a/' }]] as const)('%s is refused', (_n, over) => expect(verifyLeaseRevocation(rb(over))).toBe(false));
  it('accepts each target', () => {
    expect(verifyLeaseRevocation(rb({}))).toBe(true);
    expect(verifyLeaseRevocation(rb({ target: 'grant', value: 'Any Grant Ref/1' }))).toBe(true);
    expect(verifyLeaseRevocation(rb({ target: 'prefix', value: 'a/b' }))).toBe(true);
    expect(() => signLeaseRevocation(SK, { target: 'prefix', value: 'A', revoked_at: 1 })).toThrow('malformed');
  });
});

describe('separation of duties: exact reasons and order', () => {
  const l = { requester: 'r', holder: 'h' };
  it('checks in order', () => {
    expect(sodError({ ...l, approvers: ['a', 'a'] })).toBe('an approver is listed twice');
    expect(sodError({ ...l, approvers: ['r', 'r'] })).toBe('the requester may not approve their own request');
    expect(sodError({ ...l, approvers: ['h'] })).toBe('the holder may not approve its own lease');
    expect(sodError({ ...l, approvers: ['a'] }, {}, ['a'])).toBe("an approver appears in the holder's delegation chain");
    expect(sodError({ ...l, approvers: ['a'] }, { eligibleApprovers: ['b'] })).toBe('an approver is not eligible');
    expect(sodError({ ...l, approvers: ['a'] }, { eligibleApprovers: ['a'] })).toBeNull();
    expect(sodError({ ...l, approvers: ['a', 'b'] }, { minApprovals: 2 })).toBeNull();
    expect(sodError({ ...l, approvers: ['a'] }, { minApprovals: 2 })).toBe('1 approver(s), need 2');
    expect(sodError({ ...l, approvers: [] })).toBe('0 approver(s), need 1');
    expect(sodError({ ...l, approvers: ['a'] }, { minApprovals: 1.5 })).toBe('minApprovals must be a positive integer');
    expect(sodError({ ...l, approvers: ['a'] }, { minApprovals: -1 })).toBe('minApprovals must be a positive integer');
  });
  it('pathUnder', () => {
    expect(pathUnder('a/b', 'a')).toBe(true);
    expect(pathUnder('ab', 'a')).toBe(false);
    expect(pathUnder('a', 'a/b')).toBe(false);
  });
});

describe('registry renewal identity: each field is compared', () => {
  const second = (over: Partial<NewLease>) => signLease(SK, { ...base, seq: 2, renewed_at: T0 + 10, expires_at: T0 + 200, justification_digest: 'j2', ...over });
  it.each([['path', { path: 'a/c' }], ['grant_ref', { grant_ref: 'g2' }], ['holder', { holder: 'h2' }], ['requester', { requester: 'r2' }], ['max_ttl', { max_ttl: 2000 }], ['issued_at', { issued_at: T0 - 1 }]] as const)('%s', async (_n, over) => {
    const reg = new LeaseRegistry({ authorities: [AUTH] }, memoryLeaseKv());
    await reg.accept(signLease(SK, base));
    expect(await reg.accept(second(over))).toEqual({ ok: false, code: 'renewal_mismatch' });
  });
  it('a renewal by another pinned authority is a mismatch', async () => {
    const SK2 = new Uint8Array(32).fill(32);
    const reg = new LeaseRegistry({ authorities: [AUTH, b64u(publicKeyOf(SK2))] }, memoryLeaseKv());
    await reg.accept(signLease(SK, base));
    expect(await reg.accept(signLease(SK2, { ...base, seq: 2, renewed_at: T0 + 10, expires_at: T0 + 200, justification_digest: 'j2' }))).toEqual({ ok: false, code: 'renewal_mismatch' });
  });
  it('seq equal and identical is a no-op, a skipped seq is bad_seq, the renewal boundary is exact', async () => {
    const reg = new LeaseRegistry({ authorities: [AUTH] }, memoryLeaseKv());
    const first = signLease(SK, base);
    await reg.accept(first);
    expect(await reg.accept(first)).toEqual({ ok: true, replaced: false, seq: 1 });
    expect(await reg.accept(second({ seq: 3 }))).toMatchObject({ ok: false, code: 'bad_seq', reason: 'renewals advance seq by exactly 1' });
    expect(await reg.accept(second({ renewed_at: T0 + 100, expires_at: T0 + 300 }))).toMatchObject({ code: 'expired_lease', reason: 'an expired lease cannot be renewed' });
    expect(await reg.accept(second({ renewed_at: T0 + 99, expires_at: T0 + 300 }))).toEqual({ ok: true, replaced: true, seq: 2 });
  });
  it('renewed_at going backwards is not extending, expires_at equal is not extending', async () => {
    const reg = new LeaseRegistry({ authorities: [AUTH] }, memoryLeaseKv());
    await reg.accept(signLease(SK, { ...base, seq: 1 }));
    await reg.accept(second({ renewed_at: T0 + 50, expires_at: T0 + 200 }));
    expect(await reg.accept(signLease(SK, { ...base, seq: 3, renewed_at: T0 + 49, expires_at: T0 + 300, justification_digest: 'j3' }))).toEqual({ ok: false, code: 'not_extending' });
    expect(await reg.accept(signLease(SK, { ...base, seq: 3, renewed_at: T0 + 60, expires_at: T0 + 200, justification_digest: 'j3' }))).toEqual({ ok: false, code: 'not_extending' });
  });
  it('freshJustification false allows a replay, true (the default) does not', async () => {
    for (const [policy, ok] of [[{ freshJustification: false }, true], [{ freshJustification: true }, false], [{}, false]] as const) {
      const reg = new LeaseRegistry({ authorities: [AUTH], ...policy }, memoryLeaseKv());
      await reg.accept(signLease(SK, base));
      expect((await reg.accept(second({ justification_digest: 'j' }))).ok).toBe(ok);
    }
  });
  it('a record is refused for an unknown authority before SoD, and SoD before the cap', async () => {
    const reg = new LeaseRegistry({ authorities: ['someone-else'] }, memoryLeaseKv());
    expect(await reg.accept(signLease(SK, base))).toEqual({ ok: false, code: 'unknown_authority' });
    const reg2 = new LeaseRegistry({ authorities: [AUTH] }, memoryLeaseKv());
    expect(await reg2.accept(forge({ approvers: [], expires_at: T0 + 5000 }))).toMatchObject({ code: 'sod' });
    expect(await reg2.accept(null)).toEqual({ ok: false, code: 'bad_record' });
  });
  it('revoke refuses bad and unpinned records and reports store errors', async () => {
    const reg = new LeaseRegistry({ authorities: ['other'] }, memoryLeaseKv());
    expect(await reg.revoke(signLeaseRevocation(SK, { target: 'lease', value: 'L', revoked_at: 1 }))).toEqual({ ok: false, code: 'unknown_authority' });
    expect(await reg.revoke({})).toEqual({ ok: false, code: 'bad_record' });
    const down = new LeaseRegistry({ authorities: [AUTH] }, { get: async () => { throw new Error('x'); }, update: async () => { throw new Error('x'); } });
    expect(await down.revoke(signLeaseRevocation(SK, { target: 'lease', value: 'L', revoked_at: 1 }))).toEqual({ ok: false, code: 'store_unreachable' });
    expect(await down.revoke(signLeaseRevocation(SK, { target: 'prefix', value: 'a', revoked_at: 1 }))).toEqual({ ok: false, code: 'store_unreachable' });
    await expect(down.get('L')).rejects.toThrow();
    await expect(new LeaseRegistry({ authorities: [AUTH] }, memoryLeaseKv()).shardRevocations(16)).rejects.toThrow('no such shard');
    await expect(new LeaseRegistry({ authorities: [AUTH] }, memoryLeaseKv()).shardRevocations(-1)).rejects.toThrow('no such shard');
    expect(new LeaseRegistry({ authorities: [AUTH] }, memoryLeaseKv(), { shards: 4 }).shardCount).toBe(4);
  });
});

describe('checkLease and renewLease edges', () => {
  it('bad clocks and unsigned records', async () => {
    const reg = new LeaseRegistry({ authorities: [AUTH] }, memoryLeaseKv());
    const l = signLease(SK, base);
    await reg.accept(l);
    expect(await checkLease(l, reg, -1)).toEqual({ decision: 'deny', code: 'bad_input' });
    expect(await checkLease(l, reg, Number.NaN)).toEqual({ decision: 'deny', code: 'bad_input' });
    expect(await checkLease({ ...l, holder: 'z' }, reg, T0)).toEqual({ decision: 'deny', code: 'bad_record' });
    expect(await checkLease(l, reg, T0 + 99)).toEqual({ decision: 'allow', lease_id: 'L', expires_at: T0 + 100 });
    expect(await checkLease(l, reg, T0 + 100)).toEqual({ decision: 'deny', code: 'expired', lease_id: 'L' });
  });
  it('renewLease validates its input and maps a lease at its cap', async () => {
    const reg = new LeaseRegistry({ authorities: [AUTH] }, memoryLeaseKv());
    await reg.accept(signLease(SK, base));
    for (const bad of [{ now: 1.5, increment: 10 }, { now: T0, increment: 0 }, { now: T0, increment: 1.5 }, { now: -1, increment: 1 }]) {
      expect(await renewLease(SK, reg, 'L', { ...bad, justification_digest: 'x' })).toEqual({ ok: false, code: 'bad_input' });
    }
    expect(await renewLease(SK, reg, 'L', { now: T0 + 1, increment: 200, justification_digest: 'j2' })).toMatchObject({ ok: true, record: { expires_at: T0 + 201, seq: 2 } });
    expect(await renewLease(SK, reg, 'L', { now: T0 + 150, increment: 100000, justification_digest: 'j3', approvers: ['y'] })).toMatchObject({ ok: true, record: { expires_at: T0 + 1000, approvers: ['y'], seq: 3 } });
    expect(await renewLease(SK, reg, 'L', { now: T0 + 2000, increment: 5, justification_digest: 'j4' })).toEqual({ ok: false, code: 'expired_lease' });
  });
});

describe('hosted routes: every status', () => {
  const mk = (now = T0 + 10) => {
    const reg = new LeaseRegistry({ authorities: [AUTH] }, memoryLeaseKv());
    return { reg, h: leaseResourceHandler(reg, { authenticate: (r) => (r.query?.as === 'admin' ? { admin: true } : r.query?.as === 'agent' ? { principal: 'h' } : r.query?.as === 'nobody' ? {} : null), now: () => now }) };
  };
  it('maps every accept code to its status', async () => {
    const { reg, h } = mk();
    const post = (lease: unknown, chain?: unknown) => h({ method: 'POST', path: '/pca/leases', query: { as: 'admin' }, body: { lease, ...(chain ? { chain } : {}) } });
    await reg.accept(signLease(SK, base));
    const second = (over: Partial<NewLease>) => signLease(SK, { ...base, seq: 2, renewed_at: T0 + 10, expires_at: T0 + 200, justification_digest: 'j2', ...over });
    expect((await post({})).status).toBe(400);
    expect((await post(signLease(SK, { ...base, lease_id: 'M', seq: 2 }))).status).toBe(409);
    expect((await post(second({ holder: 'z' }))).status).toBe(422);
    expect((await post(second({ justification_digest: 'j' }))).status).toBe(422);
    expect((await post(second({ renewed_at: T0 + 500, expires_at: T0 + 700 }))).status).toBe(409);
    expect((await post(signLease(SK, { ...base, lease_id: 'N', approvers: ['r'] }))).status).toBe(403);
    expect((await post(signLease(SK, { ...base, lease_id: 'O' }), ['x'])).status).toBe(403);
    expect((await post(signLease(SK, { ...base, lease_id: 'P' }), 'not-an-array')).status).toBe(201);
    expect((await h({ method: 'POST', path: '/pca/leases', query: { as: 'nobody' }, body: {} })).status).toBe(401);
    expect((await h({ method: 'GET', path: '/pca/leases', query: { as: 'admin' } })).status).toBe(404);
    expect((await h({ method: 'GET', path: '/pca/leases/nope', query: { as: 'admin' } })).status).toBe(404);
    expect((await h({ method: 'POST', path: '/pca/leases/nope/check', query: { as: 'admin' }, body: {} })).status).toBe(404);
    expect((await h({ method: 'DELETE', path: '/pca/leases/L', query: { as: 'admin' } })).status).toBe(404);
    expect((await h({ method: 'POST', path: '/pca/leases/revoke', query: { as: 'admin' }, body: { revocation: {} } })).status).toBe(400);
    expect((await h({ method: 'POST', path: '/pca/leases/revoke', query: { as: 'admin' }, body: { revocation: signLeaseRevocation(new Uint8Array(32).fill(9), { target: 'lease', value: 'L', revoked_at: 1 }) } })).status).toBe(403);
    expect((await h({ method: 'GET', path: '/pca/leases/L', query: { as: 'agent' } })).body).toMatchObject({ lease: { lease_id: 'L' }, history: [{ seq: 1 }] });
    expect(leaseManagementMetadata('https://x')).toEqual({ leases: { leases_endpoint: 'https://x/pca/leases', revoke_targets: ['lease', 'prefix', 'grant'] } });
  });
  it('the check route uses the server clock, not the body', async () => {
    const { reg, h } = mk(T0 + 500);
    const l = signLease(SK, base);
    await reg.accept(l);
    const r = await h({ method: 'POST', path: '/pca/leases/L/check', query: { as: 'admin' }, body: { lease: l, now: T0 } });
    expect(r).toMatchObject({ status: 403, body: { code: 'expired' } });
  });
});

// ---- shadow -----------------------------------------------------------------------------------------------------------------
describe('shadow: exact records and gate order', () => {
  const LOGK = new Uint8Array(32).fill(41);
  const PK = new Uint8Array(32).fill(42);
  const P = b64u(publicKeyOf(PK));
  const dec = (i: { n: number }) => (i.n < 5 ? 'allow' : 'deny') as 'allow' | 'deny';
  const observeOne = (log: ShadowLog, n: number, cand: (i: { n: number }) => 'allow' | 'deny' | 'escalate', at = 7) => {
    const r = runShadow({ n }, dec, [{ digest: 'C', decide: cand }]);
    return log.observe({ enforced_digest: 'E', action_digest: `a${n}`, enforced: r.decision, outcome: r.shadow[0]!, at });
  };
  it('a diff carries exactly its fields and verifies only unchanged', () => {
    const log = new ShadowLog(LOGK);
    const d = observeOne(log, 7, () => 'allow')!;
    expect({ ...d, sig: undefined }).toEqual({ v: 1, shadow_digest: 'C', enforced_digest: 'E', action_digest: 'a7', enforced: 'deny', shadow: 'allow', widening: true, at: 7, signer: log.signer, sig: undefined });
    expect(verifyShadowDiff(d)).toBe(true);
    for (const o of [{ v: 2 }, { shadow_digest: '' }, { enforced_digest: '' }, { action_digest: '' }, { enforced: 'x' }, { shadow: 'x' }, { widening: false }, { widening: 'yes' }, { at: 1.5 }, { signer: '' }, { enforced: 'allow' }]) {
      expect(verifyShadowDiff({ ...d, ...o })).toBe(false);
    }
    expect(verifyShadowDiff(null)).toBe(false);
  });
  it('an unchanged answer records no diff but counts', () => {
    const log = new ShadowLog(LOGK);
    expect(observeOne(log, 1, () => 'allow')).toBeUndefined();
    expect(log.stats('C')).toEqual({ total: 1, diverged: 0, widened: 0, tightened: 0, errors: 0 });
  });
  it('gate options are checked and the first failing rule wins', () => {
    const log = new ShadowLog(LOGK);
    for (const n of [7, 8, 9]) observeOne(log, n, () => 'allow');
    const o = { shadow_digest: 'C', enforced_digest: 'E', minSamples: 3, principals: [P], surface: 'wider' as const };
    expect(promotionGate(log, { ...o, shadow_digest: '' })).toMatchObject({ code: 'bad_input' });
    expect(promotionGate(log, { ...o, enforced_digest: '' })).toMatchObject({ code: 'bad_input' });
    expect(promotionGate(log, { ...o, minSamples: 1.5 })).toMatchObject({ code: 'bad_input' });
    expect(promotionGate(log, { ...o, principals: 'x' as never })).toMatchObject({ code: 'bad_input' });
    expect(promotionGate(log, { ...o, minSamples: 4 })).toMatchObject({ code: 'too_few_samples' });
    expect(promotionGate(log, o)).toMatchObject({ code: 'unexplained_widening', unexplained: ['a7', 'a8', 'a9'] });
    const ex = [7, 8, 9].map((n) => signWideningExplanation(PK, { shadow_digest: 'C', action_digest: `a${n}`, reason_digest: 'r' }));
    expect(promotionGate(log, { ...o, explanations: ex })).toMatchObject({ code: 'advisory_wider' });
    const ap = signPromotionApproval(PK, { shadow_digest: 'C', enforced_digest: 'E', at: 1 });
    expect(promotionGate(log, { ...o, explanations: ex, approval: ap })).toEqual({ ok: true, samples: 3, widenings: 3, surface: 'wider' });
    for (const surface of ['narrower', 'equal'] as const) expect(promotionGate(log, { ...o, surface, explanations: ex })).toMatchObject({ ok: true, surface });
    // an explanation from an unpinned key does not count; a bad explanation member does not count
    expect(promotionGate(log, { ...o, explanations: ex, principals: ['other'], surface: 'narrower' })).toMatchObject({ code: 'unexplained_widening' });
    expect(promotionGate(log, { ...o, explanations: [{ ...ex[0]!, reason_digest: '' }, ex[1]!, ex[2]!], surface: 'narrower' })).toMatchObject({ code: 'unexplained_widening', unexplained: ['a7'] });
  });
  it('a missing diff (count mismatch) is bad_diff', () => {
    const log = new ShadowLog(LOGK);
    for (const n of [7, 8, 9]) observeOne(log, n, () => 'escalate');
    const forged = Object.create(log) as ShadowLog;
    forged.diffs = () => log.diffs('C').slice(1);
    expect(promotionGate(forged, { shadow_digest: 'C', enforced_digest: 'E', minSamples: 1, principals: [P], surface: 'narrower' })).toMatchObject({ code: 'bad_diff' });
  });
  it('promoteShadow keeps the candidate content and drops its signatures, shadow list and prev', () => {
    const cand: PolicyBundleBody = { v: 1, kind: 'pca-policy-bundle', revision: 7, prev: 'old', grants: ['g'], schema_digest: 's', constitution_digest: 'c', template_digests: ['t'], flow_rules_digest: 'f', min_verifier_version: '0.9.0', shadow: ['zz'], issued_at: 5 };
    const enf: PolicyBundleBody = { v: 1, kind: 'pca-policy-bundle', revision: 3, prev: 'p', grants: [], template_digests: [], min_verifier_version: '0.5.0', shadow: [bundleDigest(cand)], issued_at: 1 };
    const next = promoteShadow(enf, { ...cand, sigs: [] } as never, { ok: true, samples: 1, widenings: 0, surface: 'equal' }, 99);
    expect(next).toEqual({ v: 1, kind: 'pca-policy-bundle', grants: ['g'], schema_digest: 's', constitution_digest: 'c', template_digests: ['t'], flow_rules_digest: 'f', min_verifier_version: '0.9.0', revision: 4, prev: bundleDigest(enf), issued_at: 99 });
  });
});
