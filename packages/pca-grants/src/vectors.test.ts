import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { b64u, publicKeyOf } from '@atlasauth/pca';
import {
  DecisionLog, GRANT_AMEND_DOMAIN, GRANT_REVOKE_DOMAIN, NEED_APPROVE_DOMAIN, WindowReadAccumulator, amendMessage, assembleBundle, authorityDigest, bundleDigest, checkFreshAt,
  compareAuthority, freshAtDigest, grantRevokeMessage, listAuthorized, listBind, needApproveMessage, nextBatch, objectsDigest, recordCommit, signBundle, signDomainBody, signFreshAt,
  verifyAmendment, verifyBatch, verifyBundle, verifyFreshAt, verifyListCursor, verifyListReceipt, verifyLogHead, verifyNeedApproval, verifyRecordInclusion, verifyRevokeSignature,
  type Authority, type FreshAtState, type GrantFacts, type Need, type PolicyBundleBody,
} from './index';

/**
 * Shared K3 conformance vectors (packages/pca/conformance/k3-vectors.json), in the `primitives` shape of decision-vectors.json:
 * every entry is `{name, input, expect}` for one pure function. Ed25519 is deterministic and the seeds are fixed, so the file is
 * reproducible; this test REGENERATES it and fails on drift (UPDATE_K3_VECTORS=1 rewrites it). Native verifiers replay every entry.
 */
const FILE = join(__dirname, '..', '..', 'pca', 'conformance', 'k3-vectors.json');
const seed = (n: number): Uint8Array => new Uint8Array(32).fill(n);
const pk = (s: Uint8Array): string => b64u(publicKeyOf(s));
type Entry = { name: string; input: unknown; expect: unknown };
const E = (name: string, input: unknown, expect: unknown): Entry => ({ name, input, expect });

async function build() {
  const [s1, s2, s3] = [seed(1), seed(2), seed(3)];
  const primitives: Record<string, Entry[]> = {};

  // ---- fresh_at -------------------------------------------------------------------------------------------------------
  const S: FreshAtState = { revocation_epoch: 5, ledger_tree_size: 100, budget_version: 7, policy_revision: 3, policy_digest: 'pd3' };
  const tok = signFreshAt(s1, 'inst_1', S, 1000);
  primitives.fresh_at_verify = [
    E('valid', { signer: pk(s1), token: tok }, { valid: true }),
    E('other signer', { signer: pk(s2), token: tok }, { valid: false }),
    E('tampered counter', { signer: pk(s1), token: { ...tok, revocation_epoch: 4 } }, { valid: false }),
    E('tampered scope', { signer: pk(s1), token: { ...tok, scope: 'inst_2' } }, { valid: false }),
    E('not an object', { signer: pk(s1), token: 'x' }, { valid: false }),
  ];
  primitives.fresh_at_digest = [E('digest', { token: tok }, { digest: freshAtDigest(tok) }), E('digest differs by issued_at', { token: { ...tok, issued_at: 1001 } }, { digest: freshAtDigest({ ...tok, issued_at: 1001 }) })];
  const fcase = (name: string, local: FreshAtState, o: { scope?: string; now?: number; maxTokenAgeMs?: number; signer?: string }, token: unknown = tok) => {
    const options = { signer: o.signer ?? pk(s1), scope: o.scope ?? 'inst_1', now: o.now ?? 1000, ...(o.maxTokenAgeMs !== undefined ? { maxTokenAgeMs: o.maxTokenAgeMs } : {}) };
    return E(name, { token, local, options }, checkFreshAt(token, local, options));
  };
  primitives.fresh_at_check = [
    fcase('equal state is ok', S, {}),
    fcase('newer state is ok', { ...S, ledger_tree_size: 101, budget_version: 9 }, {}),
    fcase('stale revocation epoch escalates', { ...S, revocation_epoch: 4 }, {}),
    fcase('two counters behind', { ...S, revocation_epoch: 4, budget_version: 6 }, {}),
    fcase('lower policy revision is stale', { ...S, policy_revision: 2, policy_digest: 'pd2' }, {}),
    fcase('wrong scope denied', S, { scope: 'inst_2' }),
    fcase('policy fork denied', { ...S, policy_digest: 'other' }, {}),
    fcase('token from the future denied', S, { now: 1000 - 60_001 }),
    fcase('future skew boundary is ok', S, { now: 1000 - 60_000 }),
    fcase('token too old denied', S, { now: 11_001, maxTokenAgeMs: 10_000 }),
    fcase('age boundary is ok', S, { now: 11_000, maxTokenAgeMs: 10_000 }),
    fcase('wrong signer denied', S, { signer: pk(s2) }),
    fcase('forged signature denied', S, {}, { ...tok, sig: tok.sig.slice(1) + 'A' }),
    fcase('missing token denied', S, {}, null),
  ];

  // ---- policy bundles ---------------------------------------------------------------------------------------------------
  const body = (over: Partial<PolicyBundleBody> = {}): PolicyBundleBody => ({ v: 1, kind: 'pca-policy-bundle', revision: 1, grants: ['g1'], template_digests: [], min_verifier_version: '0.5.0', issued_at: 1, ...over });
  const b1 = body();
  const bun1 = assembleBundle(b1, [signBundle(b1, s1), signBundle(b1, s2)]);
  const b2 = body({ revision: 2, prev: bundleDigest(bun1), grants: ['g1', 'g2'], schema_digest: 'sd', template_digests: ['t1', 't2'] });
  const bun2 = assembleBundle(b2, [signBundle(b2, s1), signBundle(b2, s3)]);
  const b3 = body({ min_verifier_version: '0.6.0' });
  const bun3 = assembleBundle(b3, [signBundle(b3, s1), signBundle(b3, s2)]);
  const pins = [pk(s1), pk(s2), pk(s3)];
  const bcase = (name: string, bundle: unknown, o: { threshold?: number; verifierVersion?: string; last?: { revision: number; digest: string }; signers?: string[] }) => {
    const options = { signers: o.signers ?? pins, threshold: o.threshold ?? 2, verifierVersion: o.verifierVersion ?? '0.5.0', ...(o.last ? { last: o.last } : {}) };
    return E(name, { bundle, options }, verifyBundle(bundle, options));
  };
  primitives.bundle_digest = [E('revision 1', { bundle: bun1 }, { digest: bundleDigest(bun1) }), E('revision 2 (the digest ignores the signatures)', { bundle: { ...bun2, sigs: [] } }, { digest: bundleDigest(bun2) })];
  primitives.bundle_verify = [
    bcase('2-of-3 accepted', bun1, {}),
    bcase('below threshold', bun1, { threshold: 3 }),
    bcase('signers not pinned', bun1, { signers: [pk(s3)] }),
    bcase('same signer twice does not count', assembleBundle(b1, [signBundle(b1, s1), signBundle(b1, s1)]), {}),
    bcase('a signature over other content does not count', assembleBundle(b1, [signBundle(b1, s1), signBundle(body({ grants: ['evil'] }), s2)]), {}),
    bcase('chains to the previous revision', bun2, { last: { revision: 1, digest: bundleDigest(bun1) } }),
    bcase('rollback', bun1, { last: { revision: 2, digest: bundleDigest(bun2) } }),
    bcase('broken chain', bun2, { last: { revision: 1, digest: 'not-the-digest' } }),
    bcase('same revision different content', bun1, { last: { revision: 1, digest: 'other' } }),
    bcase('verifier too old', bun3, {}),
    bcase('verifier version boundary is ok', bun3, { verifierVersion: '0.6.0' }),
    bcase('an unparseable verifier version is too old (fail closed)', bun1, { verifierVersion: 'v1' }),
    bcase('malformed: revision 2 without prev', { ...bun1, revision: 2 }, {}),
    bcase('malformed: not an object', null, {}),
    bcase('malformed: bad min_verifier_version', { ...bun1, min_verifier_version: 'v1' }, {}),
  ];

  // ---- decision log -------------------------------------------------------------------------------------------------------
  const log = new DecisionLog(s1, ['pii']);
  const recs = [
    log.append({ bundle_revision: 1, bundle_digest: bundleDigest(bun1), action_digest: 'a1', decision: 'deny', witness: 'clause:7', at: 5 }),
    log.append({ bundle_revision: 1, bundle_digest: bundleDigest(bun1), action_digest: 'a2', decision: 'allow', at: 6, detail: { email: 'x@y.z', n: 1 }, classes: { email: 'pii' } }),
    log.append({ bundle_revision: 2, bundle_digest: bundleDigest(bun2), action_digest: 'a3', decision: 'escalate', at: 7, fresh_at: freshAtDigest(tok), assurance: 'high' }),
  ];
  const head = log.head(9);
  const head2 = log.head(10);
  primitives.log_commit = recs.map((r) => E(`record ${r.seq}`, { record: r }, { commit: recordCommit(r) }));
  primitives.log_head_verify = [
    E('valid head', { head, signer: pk(s1) }, { valid: true }),
    E('other signer', { head, signer: pk(s2) }, { valid: false }),
    E('tampered size', { head: { ...head, size: 2 }, signer: pk(s1) }, { valid: false }),
    E('tampered root', { head: { ...head, root: head.last_commit }, signer: pk(s1) }, { valid: false }),
  ];
  primitives.log_inclusion = [
    ...recs.map((r) => E(`record ${r.seq} is in the log`, { record: r, proof: log.proof(r.seq), head, signer: pk(s1) }, { valid: verifyRecordInclusion(r, log.proof(r.seq), head, pk(s1)) })),
    E('an edited record is not', { record: { ...recs[0]!, decision: 'allow' }, proof: log.proof(0), head, signer: pk(s1) }, { valid: false }),
    E('a proof for another record is not', { record: recs[0], proof: log.proof(1), head, signer: pk(s1) }, { valid: false }),
    E('a head by another signer is not', { record: recs[0], proof: log.proof(0), head, signer: pk(s2) }, { valid: false }),
  ];
  const b0 = nextBatch(log, 0, 2, 11);
  const bAll = nextBatch(log, 0, 10, 12);
  const bTail = nextBatch(log, 2, 10, 13);
  const st0 = { next: 0, lastCommit: '' };
  const st2 = { next: 2, lastCommit: recordCommit(recs[1]!) };
  const bcheck = (name: string, batch: unknown, state: { next: number; lastCommit: string }, signer = pk(s1)) => E(name, { batch, state, signer }, verifyBatch(batch as never, state, signer));
  primitives.log_batch_verify = [
    bcheck('first two records', b0, st0),
    bcheck('the whole log', bAll, st0),
    bcheck('the tail continues from the receiver state', bTail, st2),
    bcheck('a replayed batch (gap or replay)', b0, st2),
    bcheck('a gap', nextBatch(log, 2, 10, 13), st0),
    bcheck('a head by another signer', bAll, st0, pk(s2)),
    bcheck('an edited record breaks the chain', { ...bAll, records: bAll.records.map((r, i) => (i === 1 ? { ...r, decision: 'deny' } : r)) }, st0),
    bcheck('a truncated tail against the head', { ...bAll, records: bAll.records.slice(0, 2), head: head2 }, st0),
    bcheck('a batch longer than the head', { ...bAll, head: { ...head2, size: 2 } }, st0),
  ];

  // ---- list receipts and cursors -------------------------------------------------------------------------------------------
  const ALL = Array.from({ length: 6 }, (_, i) => `doc:${i}`);
  const listArgs = {
    subject: 'agent:a', resourceType: 'doc', permits: (o: string) => Number(o.slice(4)) % 2 === 0, filterId: 'f1', policyDigest: 'pd', freshAtDigest: freshAtDigest(tok),
    reads: new WindowReadAccumulator(100, 1000), now: 1000, signingSecret: s1,
  };
  const pageOf = (objs: string[]) => ({ page: async ({ cursor, limit }: { cursor?: string; limit: number }) => { const st = cursor === undefined ? 0 : Number(cursor); return { objects: objs.slice(st, st + limit), ...(st + limit < objs.length ? { next: String(st + limit) } : {}) }; } });
  const full = await listAuthorized({ ...listArgs, page: { limit: 10 }, candidates: { page: async () => ({ objects: ALL }) } });
  const first = await listAuthorized({ ...listArgs, page: { limit: 2 }, candidates: pageOf(ALL) });
  const signer = pk(s1);
  primitives.list_objects_digest = [E('digest of the returned ids', { objects: full.objects }, { digest: objectsDigest(full.objects) })];
  primitives.list_receipt_verify = [
    E('valid with objects', { receipt: full.receipt, signer, objects: full.objects }, { valid: true }),
    E('valid without objects', { receipt: full.receipt, signer }, { valid: true }),
    E('different objects', { receipt: full.receipt, signer, objects: [...full.objects.slice(1), 'doc:99'] }, { valid: false }),
    E('fewer objects', { receipt: full.receipt, signer, objects: full.objects.slice(1) }, { valid: false }),
    E('tampered policy digest', { receipt: { ...full.receipt, policy_digest: 'x' }, signer }, { valid: false }),
    E('other signer', { receipt: full.receipt, signer: pk(s2) }, { valid: false }),
  ];
  const bindIn = { subject: 'agent:a', resourceType: 'doc', filterId: 'f1', policyDigest: 'pd', limit: 2 };
  const cur = first.next_cursor!;
  const ccase = (name: string, cursor: unknown, sgn: string, bind?: typeof bindIn) => E(name, { cursor, signer: sgn, ...(bind ? { bind } : {}) }, verifyListCursor(cursor, sgn, bind));
  primitives.list_bind = [E('bind digest', { bind: bindIn }, { digest: listBind(bindIn) }), E('with a relation', { bind: { ...bindIn, relation: { relation: 'viewer' } } }, { digest: listBind({ ...bindIn, relation: { relation: 'viewer' } }) })];
  primitives.list_cursor_verify = [
    ccase('valid, no bind check', cur, signer),
    ccase('valid and bound to its inputs', cur, signer, bindIn),
    ccase('another subject', cur, signer, { ...bindIn, subject: 'agent:b' }),
    ccase('another filter', cur, signer, { ...bindIn, filterId: 'f2' }),
    ccase('another policy', cur, signer, { ...bindIn, policyDigest: 'p2' }),
    ccase('another type', cur, signer, { ...bindIn, resourceType: 'img' }),
    ccase('another limit', cur, signer, { ...bindIn, limit: 3 }),
    ccase('another signer', cur, pk(s2)),
    ccase('forged signature', cur.replace(/.$/, (c) => (c === 'A' ? 'B' : 'A')), signer),
    ccase('garbage', 'garbage', signer),
    ccase('not a string', 7, signer),
  ];

  // ---- authority + grant management -----------------------------------------------------------------------------------------
  const A: Authority = { verbs: ['read', 'pay'], resources: ['acct/1/*'], limits: { 'money.usd': 100 }, expires_at: 10_000 };
  primitives.authority_digest = [
    E('digest', { authority: A }, { digest: authorityDigest(A) }),
    E('verb and resource order do not matter', { authority: { ...A, verbs: ['pay', 'read'] } }, { digest: authorityDigest(A) }),
  ];
  const cmp = (name: string, n: Authority) => E(name, { old: A, new: n }, { order: compareAuthority(A, n) });
  primitives.authority_compare = [
    cmp('equal', A), cmp('narrower verbs', { ...A, verbs: ['read'] }), cmp('wider verbs', { ...A, verbs: ['read', 'pay', 'delete'] }), cmp('lower ceiling', { ...A, limits: { 'money.usd': 50 } }),
    cmp('higher ceiling', { ...A, limits: { 'money.usd': 500 } }), cmp('dropped ceiling', { ...A, limits: {} }), cmp('dropped expiry', { ...A, expires_at: undefined }), cmp('sooner expiry', { ...A, expires_at: 5000 }),
    cmp('narrower resource', { ...A, resources: ['acct/1/x'] }), cmp('wider resource', { ...A, resources: ['acct/*'] }), cmp('incomparable', { ...A, verbs: ['read', 'x'], limits: { 'money.usd': 1 } }),
  ];

  const principal = seed(10);
  const holder = seed(11);
  const stranger = seed(12);
  const G: GrantFacts = { id: 'g_0', rev: 1, principal: pk(principal), agent: pk(holder), status: 'active', authority: A };
  const signAmend = (g: { id: string; rev: number }, action: 'narrow' | 'merge' | 'replace', a: Authority, k: Uint8Array) => signDomainBody(GRANT_AMEND_DOMAIN, amendMessage(g, action, a), k);
  const acase = (name: string, grant: GrantFacts, request: unknown, stepUpOk: boolean) => {
    const r = verifyAmendment(grant, request, stepUpOk);
    return E(name, { grant, request, step_up_ok: stepUpOk }, r.ok ? { ok: true, widens: r.widens, next_digest: authorityDigest(r.next) } : { ok: false, code: r.code });
  };
  const less: Authority = { ...A, verbs: ['read'] };
  const wider: Authority = { ...A, verbs: ['read', 'pay', 'delete'] };
  const delta: Authority = { verbs: ['delete'], resources: ['acct/2/*'], limits: { 'money.usd': 300 }, expires_at: 20_000 };
  primitives.amend_verify = [
    acase('narrow by the holder', G, { action: 'narrow', authority: less, sig: signAmend(G, 'narrow', less, holder), signed_by: 'holder' }, false),
    acase('narrow by the principal', G, { action: 'narrow', authority: less, sig: signAmend(G, 'narrow', less, principal), signed_by: 'principal' }, false),
    acase('narrow that changes nothing', G, { action: 'narrow', authority: A, sig: signAmend(G, 'narrow', A, holder), signed_by: 'holder' }, false),
    acase('narrow that widens', G, { action: 'narrow', authority: wider, sig: signAmend(G, 'narrow', wider, principal), signed_by: 'principal' }, true),
    acase('unsigned', G, { action: 'narrow', authority: less }, false),
    acase('signed by a stranger', G, { action: 'narrow', authority: less, sig: signAmend(G, 'narrow', less, stranger), signed_by: 'holder' }, false),
    acase('a signature for the previous revision cannot be replayed', { ...G, rev: 2 }, { action: 'narrow', authority: less, sig: signAmend(G, 'narrow', less, holder), signed_by: 'holder' }, false),
    acase('a signature for another action', G, { action: 'replace', authority: less, sig: signAmend(G, 'narrow', less, holder), signed_by: 'holder' }, false),
    acase('replace that widens, holder signature', G, { action: 'replace', authority: wider, sig: signAmend(G, 'replace', wider, holder), signed_by: 'holder', step_up_ref: 's' }, true),
    acase('replace that widens, principal signature, no step-up', G, { action: 'replace', authority: wider, sig: signAmend(G, 'replace', wider, principal), signed_by: 'principal' }, false),
    acase('replace that widens, principal signature and step-up', G, { action: 'replace', authority: wider, sig: signAmend(G, 'replace', wider, principal), signed_by: 'principal', step_up_ref: 's' }, true),
    acase('merge unions authority and keeps omitted ceilings', G, { action: 'merge', authority: delta, sig: signAmend(G, 'merge', delta, principal), signed_by: 'principal', step_up_ref: 's' }, true),
    acase('replace to something narrower is in place', G, { action: 'replace', authority: less, sig: signAmend(G, 'replace', less, holder), signed_by: 'holder' }, false),
    acase('grant not active', { ...G, status: 'revoked' }, { action: 'narrow', authority: less, sig: signAmend(G, 'narrow', less, holder), signed_by: 'holder' }, false),
    acase('unknown action', G, { action: 'bogus', authority: less }, false),
    acase('malformed authority', G, { action: 'narrow', authority: { verbs: 'read', resources: [] } }, false),
  ];

  const rcase = (name: string, root: { id: string; principal: string }, scope: unknown, sig: unknown) => E(name, { root, scope, sig }, (() => { const r = verifyRevokeSignature(root, scope, sig); return r.ok ? { ok: true, scope: r.scope } : { ok: false, code: r.code }; })());
  const rsig = (scope: 'grant' | 'agent' | 'subtree', k: Uint8Array = principal) => signDomainBody(GRANT_REVOKE_DOMAIN, grantRevokeMessage('g_0', scope), k);
  const root = { id: 'g_0', principal: pk(principal) };
  primitives.revoke_verify = [
    rcase('grant scope', root, 'grant', rsig('grant')),
    rcase('subtree scope', root, 'subtree', rsig('subtree')),
    rcase('a grant-scope signature does not authorise subtree', root, 'subtree', rsig('grant')),
    rcase('a stranger', root, 'grant', rsig('grant', stranger)),
    rcase('another grant id', { id: 'g_9', principal: pk(principal) }, 'grant', rsig('grant')),
    rcase('unknown scope', root, 'galaxy', rsig('grant')),
    rcase('no signature', root, 'grant', undefined),
  ];

  const need: Need = { verb: 'pay', resource: 'acct/9/*', limits: { 'money.usd': 400 }, adjustable: true };
  const nr = { id: 'n_1', grant_id: 'g_0', needs: [need], status: 'pending' as const };
  const nsig = (approved: Need[], k: Uint8Array = principal, rev = 1) => signDomainBody(NEED_APPROVE_DOMAIN, needApproveMessage(nr, rev, approved), k);
  const ncase = (name: string, req: typeof nr, approved: Need[], sig: unknown, stepUpOk: boolean) => {
    const r = verifyNeedApproval(req, G, approved, sig, stepUpOk);
    return E(name, { need_request: req, grant: G, approved, sig, step_up_ok: stepUpOk }, r.ok ? { ok: true, authority_digest: authorityDigest(r.authority) } : { ok: false, code: r.code });
  };
  const lowered: Need[] = [{ ...need, limits: { 'money.usd': 250 } }];
  const raised: Need[] = [{ ...need, limits: { 'money.usd': 401 } }];
  const fixed: Need = { ...need, adjustable: false };
  primitives.need_approve_verify = [
    ncase('approve as asked', nr, [need], nsig([need]), true),
    ncase('approve a lowered amount of an adjustable need', nr, lowered, nsig(lowered), true),
    ncase('a raised amount', nr, raised, nsig(raised), true),
    ncase('a changed target', nr, [{ ...need, resource: 'acct/*' }], nsig([{ ...need, resource: 'acct/*' }]), true),
    ncase('lowering a non-adjustable need', { ...nr, needs: [fixed] }, lowered, nsig(lowered), true),
    ncase('wrong count', nr, [need, need], nsig([need, need]), true),
    ncase('signed by a stranger', nr, [need], nsig([need], stranger), true),
    ncase('signed for another revision', nr, [need], nsig([need], principal, 2), true),
    ncase('no step-up', nr, [need], nsig([need]), false),
    ncase('already approved', { ...nr, status: 'approved' as never }, [need], nsig([need]), true),
    ncase('a limit that was not asked for', nr, [{ ...need, limits: { 'gold.oz': 1 } }], nsig([{ ...need, limits: { 'gold.oz': 1 } }]), true),
  ];

  return {
    about: 'PCA K3 operational-plane conformance vectors (fixed Ed25519 seeds: byte value N repeated 32 times; seeds 1-3 log/bundle/token signers, 10 principal, 11 holder, 12 stranger). Regenerated and drift-checked by packages/pca-grants vectors.test.ts.',
    format: 1,
    primitives,
  };
}

describe('K3 conformance vectors', () => {
  it('the committed file is exactly what the reference produces, and the headline outcomes are the documented ones', async () => {
    const v = await build();
    const text = `${JSON.stringify(v, null, 1)}\n`;
    if (process.env.UPDATE_K3_VECTORS === '1') writeFileSync(FILE, text);
    expect(readFileSync(FILE, 'utf8')).toBe(text);
    const p = v.primitives;
    const decisions = (p.fresh_at_check as Array<{ expect: { decision: string } }>).map((c) => c.expect.decision);
    expect(decisions).toEqual(['ok', 'ok', 'escalate', 'escalate', 'escalate', 'deny', 'deny', 'deny', 'ok', 'deny', 'ok', 'deny', 'deny', 'deny']);
    expect((p.bundle_verify as Array<{ expect: { ok: boolean } }>).map((c) => c.expect.ok)).toEqual([true, false, false, false, false, true, false, false, false, false, true, false, false, false, false]);
    expect((p.amend_verify as Array<{ expect: { code?: string; ok: boolean } }>).map((c) => (c.expect.ok ? 'ok' : c.expect.code))).toEqual([
      'ok', 'ok', 'not_narrower', 'not_narrower', 'signature_required', 'bad_signature', 'bad_signature', 'bad_signature', 'signature_required', 'step_up_required', 'ok', 'ok', 'ok', 'not_active', 'bad_request', 'bad_request',
    ]);
    expect((p.need_approve_verify as Array<{ expect: { code?: string; ok: boolean } }>).map((c) => (c.expect.ok ? 'ok' : c.expect.code))).toEqual([
      'ok', 'ok', 'need_not_lowered_only', 'need_not_lowered_only', 'need_not_adjustable', 'need_not_lowered_only', 'bad_signature', 'bad_signature', 'step_up_required', 'conflict', 'need_not_lowered_only',
    ]);
    expect(verifyFreshAt(p.fresh_at_verify![0]!.input && (p.fresh_at_verify![0]!.input as { token: unknown }).token, pk(seed(1)))).toBe(true);
    expect(verifyLogHead((p.log_head_verify![0]!.input as { head: unknown }).head, pk(seed(1)))).toBe(true);
    expect(verifyListReceipt((p.list_receipt_verify![0]!.input as { receipt: unknown }).receipt, pk(seed(1)))).toBe(true);
  });
});
