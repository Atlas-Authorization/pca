import { beforeAll, describe, expect, it } from 'vitest';
import { DEFAULT_CATALOG, buildCatalog, defineAction } from './catalog';
import { generateKeyPair } from './keys';
import { b64u } from './hash';
import {
  MAX_NL_APPROVAL_TTL_MS,
  MAX_NL_OUTPUT_BYTES,
  agentFromApprovedNL,
  catalogDigest,
  draftDigest,
  draftDigestV2,
  approveDraftLegacyV1,
  draftBinding,
  approveDraft,
  draftPolicyFromNL,
  loadApprovedPolicy,
  type DraftPolicy,
  type NLApproval,
} from './nl';

const reviewer = generateKeyPair();
const rpk = b64u(reviewer.publicKey);
const NOW = 1_700_000_000_000;
const model = (o: object) => () => JSON.stringify(o);
const good = { permissions: { stripe: ['refund'] }, limits: { refund: '$200/day' } };
const mk = async (o: object = good) => draftPolicyFromNL({ instruction: 'x', complete: model(o) });

describe('draftPolicyFromNL', () => {
  it('yields an unapproved draft with a digest', async () => {
    const d = await mk();
    expect(d.status).toBe('draft');
    expect(d.analyzerOk).toBe(true);
    expect(d.digest).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });
  it('digest is stable and changes with limits', async () => {
    expect((await mk()).digest).toBe((await mk()).digest);
    expect((await mk({ ...good, limits: { refund: '$900/day' } })).digest).not.toBe((await mk()).digest);
  });
  it('model output that is empty/garbage gives analyzerOk=false', async () => {
    expect((await mk({})).analyzerOk).toBe(false);
    expect((await draftPolicyFromNL({ instruction: 'x', complete: () => 'garbage' })).analyzerOk).toBe(false);
  });
  it('unknown verbs are reported and block approval', async () => {
    const d = await mk({ permissions: { stripe: ['refund', 'teleport'] } });
    expect(d.unknownVerbs).toEqual(['stripe.teleport']);
    expect(() => approveDraft(d, reviewer.secretKey)).toThrow('approveDraft: the draft proposed verbs that are not in the catalog');
  });
  it('oversize model output throws', async () => {
    await expect(draftPolicyFromNL({ instruction: 'x', complete: () => 'x'.repeat(MAX_NL_OUTPUT_BYTES + 1) })).rejects.toThrow(
      `draftPolicyFromNL: model output exceeds ${MAX_NL_OUTPUT_BYTES} bytes or is not a string`,
    );
  });
  it('non-string model output throws', async () => {
    await expect(draftPolicyFromNL({ instruction: 'x', complete: () => 5 as unknown as string })).rejects.toThrow(/not a string/);
  });
});

describe('approveDraft', () => {
  it('rejects bad ttl', async () => {
    const d = await mk();
    for (const ttlMs of [0, -1, NaN, MAX_NL_APPROVAL_TTL_MS + 1]) expect(() => approveDraft(d, reviewer.secretKey, { now: NOW, ttlMs })).toThrow('approveDraft: invalid time or ttl');
    expect(() => approveDraft(d, reviewer.secretKey, { now: NaN })).toThrow('approveDraft: invalid time or ttl');
  });
});

describe('loadApprovedPolicy: missing X gives Y', () => {
  let draft!: DraftPolicy;
  let ok!: NLApproval;
  let emptyDraft!: DraftPolicy;
  beforeAll(async () => {
    draft = await mk();
    ok = approveDraft(draft, reviewer.secretKey, { now: NOW });
    emptyDraft = await mk({});
  });
  const load = (d: DraftPolicy, a: NLApproval, o: Partial<Parameters<typeof loadApprovedPolicy>[2]> = {}) => loadApprovedPolicy(d, a, { reviewers: [rpk], now: NOW + 1000, ...o });
  const other = generateKeyPair();

  it('a hand-built draft with an error lint is refused by the loader even though signed', () => {
    const cd = catalogDigest(DEFAULT_CATALOG);
    const permissions = { stripe: ['refund'] };
    const limits = { gmail_send: '$5/day' }; // matches no granted action => limit-unmatched (error)
    const hand: DraftPolicy = { ...draft, permissions, limits, catalog_digest: cd, digest: draftDigestV2(permissions, limits, cd, draft.binding), analyzerOk: true };
    expect(load(hand, approveDraft(hand, reviewer.secretKey, { now: NOW }))).toEqual({ ok: false, reason: 'analyzer_error' });
  });
  it('valid approval loads exactly the drafted policy', () => {
    expect(load(draft, ok)).toEqual({ ok: true, permissions: draft.permissions, limits: draft.limits, reviewer: rpk, instruction: 'x', legacy_unbound_instruction: false });
  });
  const rows = (): Array<[string, () => ReturnType<typeof load>, string]> => [
    ['no reviewers pinned', () => load(draft, ok, { reviewers: [] }), 'no_reviewers_pinned'],
    ['reviewers missing', () => load(draft, ok, { reviewers: undefined as never }), 'no_reviewers_pinned'],
    ['unpinned reviewer', () => load(draft, approveDraft(draft, other.secretKey, { now: NOW })), 'reviewer_not_pinned'],
    ['not a draft', () => load({ ...draft, status: 'approved' as never }, ok), 'not_a_draft'],
    ['null draft', () => load(null as never, ok), 'not_a_draft'],
    ['tampered permissions', () => load({ ...draft, permissions: { stripe: ['refund'], gmail: ['send'] } }, ok), 'tampered_draft'],
    ['tampered limits', () => load({ ...draft, limits: { refund: '$9999/day' } }, ok), 'tampered_draft'],
    ['other catalog', () => load(draft, ok, { catalog: buildCatalog([defineAction({ connector: 'bank', action: 'peek', reversibility: 'reversible', blastRadius: 0.1, description: 'Look.' })]) }), 'catalog_mismatch'],
    ['empty permissions', () => load(emptyDraft, ok), 'empty_permissions'],
    ['approval for another draft', () => load(draft, { ...ok, digest: 'AAAA' }), 'digest_mismatch'],
    ['approval for another catalog', () => load(draft, { ...ok, catalog_digest: 'AAAA' }), 'digest_mismatch'],
    ['malformed approval', () => load(draft, { ...ok, expires_at: 'soon' as never }), 'malformed_approval'],
    ['null approval', () => load(draft, null as never), 'malformed_approval'],
    ['wrong version', () => load(draft, { ...ok, v: 3 as never }), 'malformed_approval'],
    ['expired (at the boundary)', () => load(draft, ok, { now: ok.expires_at }), 'expired'],
    ['not yet valid', () => load(draft, ok, { now: NOW - 1 }), 'not_yet_valid'],
    ['ttl beyond max', () => load(draft, { ...ok, expires_at: ok.approved_at + MAX_NL_APPROVAL_TTL_MS + 1 }), 'ttl_too_long'],
    ['ttl zero', () => load(draft, { ...ok, expires_at: ok.approved_at }), 'ttl_too_long'],
    ['forged signature', () => load(draft, { ...ok, sig: approveDraft(draft, other.secretKey, { now: NOW }).sig }), 'bad_signature'],
    ['signed field changed', () => load(draft, { ...ok, expires_at: ok.expires_at + 1 }), 'bad_signature'],
  ];
  it('every refusal row gives its exact reason', () => {
    for (const [name, f, reason] of rows()) expect([name, f()]).toEqual([name, { ok: false, reason }]);
  });

  it('unknown verb smuggled into a re-digested draft is refused', async () => {
    const d = await mk();
    const evil = { ...d, permissions: { stripe: ['teleport'] } };
    // even with a self-consistent digest the loader re-grounds against the catalog
    const re = await draftPolicyFromNL({ instruction: 'x', complete: model({ permissions: { stripe: ['refund'] } }) });
    expect(load({ ...evil, digest: re.digest }, ok).ok).toBe(false);
  });
  it('listed unknownVerbs on a draft is refused', () => {
    expect(load({ ...draft, unknownVerbs: ['x.y'] }, ok)).toEqual({ ok: false, reason: 'unknown_verbs' });
  });
});

describe('agentFromApprovedNL', () => {
  it('throws with the reason when refused', async () => {
    const d = await mk();
    const a = approveDraft(d, reviewer.secretKey, { now: NOW });
    expect(() => agentFromApprovedNL({ draft: d, approval: a, reviewers: [], principal: generateKeyPair(), goal: 'g' })).toThrow('agentFromApprovedNL: no_reviewers_pinned');
  });
});

describe('approval v2 binds the instruction, model and prompt (W4)', () => {
  const load = (d: DraftPolicy, a: NLApproval) => loadApprovedPolicy(d, a, { reviewers: [rpk], now: NOW + 1000 });
  it('the same content under another instruction is another draft and another digest', async () => {
    const a = await draftPolicyFromNL({ instruction: 'refund duplicate charge ch_9', complete: model(good) });
    const b = await draftPolicyFromNL({ instruction: 'refund every charge', complete: model(good) });
    expect(a.digest).not.toBe(b.digest);
    expect(a.binding.instruction_digest).not.toBe(b.binding.instruction_digest);
  });
  it('a reviewer-signed draft cannot be re-pointed at another instruction', async () => {
    const d = await mk();
    const approval = approveDraft(d, reviewer.secretKey, { now: NOW });
    expect(load({ ...d, instruction: 'something else entirely' }, approval)).toEqual({ ok: false, reason: 'tampered_draft' });
    // even with the binding re-computed for the new instruction, the signed digest no longer matches
    const evil = { ...d, instruction: 'y', binding: draftBinding('y', DEFAULT_CATALOG) };
    expect(load({ ...evil, digest: draftDigestV2(evil.permissions, evil.limits, evil.catalog_digest, evil.binding) }, approval)).toEqual({ ok: false, reason: 'digest_mismatch' });
  });
  it('the model id is pinned: another model is another digest, and a tampered model id is refused', async () => {
    const a = await draftPolicyFromNL({ instruction: 'x', complete: model(good), model: 'm-1' });
    const b = await draftPolicyFromNL({ instruction: 'x', complete: model(good), model: 'm-2' });
    expect(a.digest).not.toBe(b.digest);
    const approval = approveDraft(a, reviewer.secretKey, { now: NOW });
    expect(load(a, approval).ok).toBe(true);
    expect(load({ ...a, binding: { ...a.binding, model: 'm-2' } }, approval)).toEqual({ ok: false, reason: 'tampered_draft' });
  });
  it('the prompt is pinned: a tampered prompt digest, or another catalog prompt, is refused', async () => {
    const d = await mk();
    const approval = approveDraft(d, reviewer.secretKey, { now: NOW });
    expect(load({ ...d, binding: { ...d.binding, prompt_digest: 'AAAA' } }, approval)).toEqual({ ok: false, reason: 'tampered_draft' });
    expect(load({ ...d, binding: { ...d.binding, instruction_digest: 'AAAA' } }, approval)).toEqual({ ok: false, reason: 'tampered_draft' });
  });
  it('agentFromApprovedNL refuses a goal text other than the approved instruction', async () => {
    const d = await mk();
    const approval = approveDraft(d, reviewer.secretKey, { now: NOW });
    const req = { draft: d, approval, reviewers: [rpk], now: NOW + 1000, principal: generateKeyPair() };
    expect(() => agentFromApprovedNL({ ...req, goal: 'refund everything' })).toThrow('agentFromApprovedNL: goal_mismatch');
    const r = agentFromApprovedNL({ ...req, goal: d.instruction });
    expect(r.legacy_unbound_instruction).toBe(false);
  });
});

describe('legacy (v1) approvals still load for one release, flagged', () => {
  const load = (d: DraftPolicy, a: NLApproval) => loadApprovedPolicy(d, a, { reviewers: [rpk], now: NOW + 1000 });
  it('a v1 approval of a current draft loads with legacy_unbound_instruction and any goal text', async () => {
    const d = await mk();
    const v1 = approveDraftLegacyV1(d, reviewer.secretKey, { now: NOW });
    expect(v1.v).toBe(1);
    const r = load(d, v1);
    expect(r).toMatchObject({ ok: true, legacy_unbound_instruction: true });
    const a = agentFromApprovedNL({ draft: d, approval: v1, reviewers: [rpk], now: NOW + 1000, principal: generateKeyPair(), goal: 'any goal text at all' });
    expect(a.legacy_unbound_instruction).toBe(true);
  });
  it('a pre-0.5 draft (no binding, v1 digest) loads only with a v1 approval', async () => {
    const d = await mk();
    const { binding: _drop, ...rest } = d;
    const old = { ...rest, digest: draftDigest(d.permissions, d.limits, d.catalog_digest) } as unknown as DraftPolicy;
    expect(load(old, approveDraftLegacyV1(d, reviewer.secretKey, { now: NOW }))).toMatchObject({ ok: true, legacy_unbound_instruction: true });
    expect(load(old, approveDraft(d, reviewer.secretKey, { now: NOW }))).toEqual({ ok: false, reason: 'digest_mismatch' });
    expect(load({ ...old, digest: 'AAAA' }, approveDraftLegacyV1(d, reviewer.secretKey, { now: NOW }))).toEqual({ ok: false, reason: 'tampered_draft' });
  });
  it('a v1 approval signed over another content is refused', async () => {
    const d = await mk();
    const other = await mk({ permissions: { stripe: ['refund'] }, limits: { refund: '$900/day' } });
    expect(load(d, approveDraftLegacyV1(other, reviewer.secretKey, { now: NOW }))).toEqual({ ok: false, reason: 'digest_mismatch' });
  });
  it('a v1 approval does not verify as a v2 approval (domain separated)', async () => {
    const d = await mk();
    const v1 = approveDraftLegacyV1(d, reviewer.secretKey, { now: NOW });
    expect(load(d, { ...v1, v: 2 })).toEqual({ ok: false, reason: 'digest_mismatch' });
  });
});
