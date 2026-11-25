/**
 * Mutation kills for the 0.5.0 flagship gate survivors in nl.ts: alias and foreign-spec grounding in parseNLPolicy (a
 * catalog without resolve, a resolve that answers another connector's spec, alias limit keys), the exact catalog digest
 * (sorted rows, stable ties), the exact draft binding and draft digests (sorted actions), draft lints under an injected
 * catalog, the output-size boundary, the analyzer's error lint, the approval signing message (domain per version, read
 * independently), the TTL boundaries, and every loadApprovedPolicy refusal with a later check placed so that only the
 * intended guard can produce the expected reason.
 */
import { describe, expect, it } from 'vitest';
import { buildCatalog, defineAction, DEFAULT_CATALOG, type ActionSpec, type Catalog } from './catalog';
import { canonicalBytesLenient, b64u, hashCanonicalLenient, utf8 } from './hash';
import { generateKeyPair, verifyB64u } from './keys';
import {
  approveDraft,
  approveDraftLegacyV1,
  catalogDigest,
  draftBinding,
  draftDigest,
  draftDigestV2,
  draftPolicyFromNL,
  loadApprovedPolicy,
  MAX_NL_APPROVAL_TTL_MS,
  MAX_NL_OUTPUT_BYTES,
  NL_APPROVAL_DOMAIN,
  NL_APPROVAL_DOMAIN_V2,
  nlPrompt,
  parseNLPolicy,
  type DraftPolicy,
  type NLApproval,
} from './nl';

/** Run f, capturing its value or its error message, so a mutant that throws fails an assertion, not the runner. */
const settle = <T>(f: () => T) => {
  try {
    return { ok: true as const, value: f() };
  } catch (e) {
    return { ok: false as const, error: (e as Error)?.message };
  }
};

const peek = defineAction({ connector: 'bank', action: 'peek', reversibility: 'reversible', blastRadius: 0.1, description: 'Look.' });
const wire = defineAction({ connector: 'bank', action: 'wire', reversibility: 'irreversible', blastRadius: 0.9, description: 'Wire money.', amountField: 'amt' });
const CAT = buildCatalog([wire, peek]); // definition order is NOT verb order
/** A spec whose verb names another connector than its own (defineAction lets the verb be overridden). */
const foreign = defineAction({ connector: 'a', action: 'b', verb: 'x.y', reversibility: 'reversible', blastRadius: 0.1, description: 'd' });
const XCAT = buildCatalog([foreign]);

const reviewer = generateKeyPair();
const rpk = b64u(reviewer.publicKey);
const NOW = 1_700_000_000_000;
const mk = (o: object, catalog: Catalog = CAT, instruction = 'i', model?: string) =>
  draftPolicyFromNL({ instruction, complete: () => JSON.stringify(o), catalog, ...(model !== undefined ? { model } : {}) });
const load = (d: DraftPolicy, a: NLApproval, o: { now?: number; reviewers?: string[] } = {}) => loadApprovedPolicy(d, a, { reviewers: [rpk], catalog: CAT, now: NOW + 1000, ...o });
const fail = (reason: string) => ({ ok: false, reason });
/** Re-digest a hand-edited (non-legacy) draft so the digest check passes and the next guard decides. */
const redigest = (d: DraftPolicy, permissions: unknown, limits: unknown = d.limits): DraftPolicy =>
  ({ ...d, permissions, limits, digest: draftDigestV2(permissions as never, limits as never, d.catalog_digest, d.binding) }) as DraftPolicy;

describe('parseNLPolicy grounding', () => {
  it('an alias is stored canonically (catalog.get misses, resolve answers)', () => {
    expect(parseNLPolicy('{"permissions":{"stripe":["reimburse"]},"limits":{"reimburse":"$5/day"}}')).toEqual({
      permissions: { stripe: ['refund'] },
      limits: { reimburse: '$5/day' }, // an alias of a granted action is a granted limit name
      unknownVerbs: [],
      droppedLimits: [],
    });
  });
  it('a catalog without resolve: a miss is an unknown verb, not a throw', () => {
    const noResolve: Catalog = { get: (v) => CAT.get(v), forConnector: (c) => CAT.forConnector(c), all: () => CAT.all() };
    expect(settle(() => parseNLPolicy('{"permissions":{"bank":["nope","peek"]}}', noResolve))).toEqual({
      ok: true,
      value: { permissions: { bank: ['peek'] }, limits: {}, unknownVerbs: ['bank.nope'], droppedLimits: [] },
    });
  });
  it('a spec whose connector differs from the proposed one keeps the proposed action name', () => {
    expect(parseNLPolicy('{"permissions":{"x":["y"]}}', XCAT).permissions).toEqual({ x: ['y'] });
  });
  it('a resolve that answers another connector\'s spec: the proposed action is granted and get() misses safely', () => {
    const odd: Catalog = { get: (v) => XCAT.get(v), forConnector: (c) => XCAT.forConnector(c), all: () => XCAT.all(), resolve: () => foreign };
    expect(settle(() => parseNLPolicy('{"permissions":{"q":["r"]},"limits":{"r":"5/day","q.r":"6/day"}}', odd))).toEqual({
      ok: true,
      value: { permissions: { q: ['r'] }, limits: { r: '5/day', 'q.r': '6/day' }, unknownVerbs: [], droppedLimits: [] },
    });
  });
  it('a granted action without aliases adds no other limit name', () => {
    expect(parseNLPolicy('{"permissions":{"bank":["peek"]},"limits":{"Stryker was here":"5/day","peek":"5/day"}}', CAT)).toEqual({
      permissions: { bank: ['peek'] },
      limits: { peek: '5/day' },
      unknownVerbs: [],
      droppedLimits: ['Stryker was here'],
    });
  });
});

describe('catalogDigest', () => {
  const expected = (rows: unknown[]) => hashCanonicalLenient({ v: 1, rows });
  const asCatalog = (specs: ActionSpec[]): Catalog => ({ get: () => undefined, forConnector: () => [], all: () => specs });
  const spec = (verb: string, reversibility: ActionSpec['reversibility'] = 'reversible') => ({ ...peek, verb, reversibility });
  it('rows are [verb, reversibility, amountField|null] sorted by verb', () => {
    expect(catalogDigest(CAT)).toBe(expected([['bank.peek', 'reversible', null], ['bank.wire', 'irreversible', 'amt']]));
  });
  it('sorting holds for any input order', () => {
    const rows = [['a.a', 'reversible', null], ['b.b', 'reversible', null], ['c.c', 'reversible', null], ['d.d', 'reversible', null]];
    for (const order of [['c.c', 'a.a', 'd.d', 'b.b'], ['d.d', 'c.c', 'b.b', 'a.a'], ['a.a', 'b.b', 'c.c', 'd.d'], ['b.b', 'd.d', 'a.a', 'c.c']]) {
      expect([order, catalogDigest(asCatalog(order.map((v) => spec(v))))]).toEqual([order, expected(rows)]);
    }
  });
  it('rows with the same verb keep their input order (the comparator answers 0 for a tie)', () => {
    const tie = asCatalog([spec('z.z', 'reversible'), spec('z.z', 'irreversible')]);
    expect(catalogDigest(tie)).toBe(expected([['z.z', 'reversible', null], ['z.z', 'irreversible', null]]));
  });
});

describe('draft binding and digests', () => {
  it('draftBinding hashes the instruction and the exact prompt under their own domains', () => {
    expect(draftBinding('i', CAT, 'm')).toEqual({
      instruction_digest: hashCanonicalLenient({ d: 'atlas-pca/nl-instruction/v1', text: 'i' }),
      model: 'm',
      prompt_digest: hashCanonicalLenient({ d: 'atlas-pca/nl-prompt/v1', text: nlPrompt('i', CAT) }),
    });
  });
  const b = { instruction_digest: 'I', model: null, prompt_digest: 'P' };
  it('draftDigestV2 signs the actions sorted', () => {
    expect(draftDigestV2({ bank: ['wire', 'peek'] }, {}, 'C', b)).toBe(
      hashCanonicalLenient({ v: 2, permissions: { bank: ['peek', 'wire'] }, limits: {}, catalog_digest: 'C', instruction_digest: 'I', model: null, prompt_digest: 'P' }),
    );
  });
  it('draftDigest (v1) signs the actions sorted', () => {
    expect(draftDigest({ bank: ['wire', 'peek'] }, {}, 'C')).toBe(hashCanonicalLenient({ v: 1, permissions: { bank: ['peek', 'wire'] }, limits: {}, catalog_digest: 'C' }));
  });
});

describe('draftPolicyFromNL', () => {
  it('lints are computed against the injected catalog (no "uncatalogued" note for a catalogued verb)', async () => {
    const d = await mk({ permissions: { bank: ['peek'] } });
    expect(d.lints).toEqual([]);
    expect(d.analyzerOk).toBe(true);
  });
  it('empty permissions give no lints at all', async () => {
    expect((await mk({})).lints).toEqual([]);
  });
  it('model output of exactly MAX_NL_OUTPUT_BYTES is accepted', async () => {
    const raw = '{}'.padEnd(MAX_NL_OUTPUT_BYTES, ' ');
    const r = await draftPolicyFromNL({ instruction: 'i', complete: () => raw, catalog: CAT }).then((v) => v.status, (e: Error) => e.message);
    expect(r).toBe('draft');
  });
  it('an error-level lint makes analyzerOk false', async () => {
    // the limit key 'y' is granted by NL grounding (the proposed action name) but not by the compiled spec (action 'b')
    const d = await mk({ permissions: { x: ['y'] }, limits: { y: '5/day' } }, XCAT);
    expect(d.lints).toEqual([{ level: 'error', code: 'limit-unmatched', message: "limit for 'y' matches no granted action" }]);
    expect(d.analyzerOk).toBe(false);
  });
});

describe('approval message and TTL', () => {
  const msg = (domain: string, a: NLApproval) => {
    const pre = utf8(domain);
    const body = canonicalBytesLenient({ v: a.v, digest: a.digest, catalog_digest: a.catalog_digest, reviewer: a.reviewer, approved_at: a.approved_at, expires_at: a.expires_at });
    const m = new Uint8Array(pre.length + body.length);
    m.set(pre);
    m.set(body, pre.length);
    return m;
  };
  it('a v2 approval signs the v2 domain followed by the canonical body', async () => {
    const a = approveDraft(await mk({ permissions: { bank: ['peek'] } }), reviewer.secretKey, { now: NOW });
    expect(verifyB64u(rpk, msg(NL_APPROVAL_DOMAIN_V2, a), a.sig)).toBe(true);
    expect(verifyB64u(rpk, msg(NL_APPROVAL_DOMAIN, a), a.sig)).toBe(false);
  });
  it('a v1 approval signs the v1 domain', async () => {
    const a = approveDraftLegacyV1(await mk({ permissions: { bank: ['peek'] } }), reviewer.secretKey, { now: NOW });
    expect(verifyB64u(rpk, msg(NL_APPROVAL_DOMAIN, a), a.sig)).toBe(true);
    expect(verifyB64u(rpk, msg(NL_APPROVAL_DOMAIN_V2, a), a.sig)).toBe(false);
  });
  it('a ttl of exactly MAX_NL_APPROVAL_TTL_MS is allowed when signing and when loading', async () => {
    const d = await mk({ permissions: { bank: ['peek'] } });
    const a = settle(() => approveDraft(d, reviewer.secretKey, { now: NOW, ttlMs: MAX_NL_APPROVAL_TTL_MS }));
    expect(a.ok && a.value.expires_at - a.value.approved_at).toBe(MAX_NL_APPROVAL_TTL_MS);
    if (a.ok) expect(load(d, a.value)).toMatchObject({ ok: true });
  });
});

describe('loadApprovedPolicy refusals', () => {
  const good = () => mk({ permissions: { bank: ['peek'] } });
  const signed = async () => {
    const d = await good();
    return { d, a: approveDraft(d, reviewer.secretKey, { now: NOW }) };
  };
  it('non-object or null permissions / limits are not a draft', async () => {
    const { d, a } = await signed();
    expect(load({ ...d, permissions: 'bank' as never }, a)).toEqual(fail('not_a_draft'));
    expect(load({ ...d, permissions: null as never }, a)).toEqual(fail('not_a_draft'));
    expect(load({ ...d, limits: 'x' as never }, a)).toEqual(fail('not_a_draft'));
    expect(load({ ...d, limits: null as never }, a)).toEqual(fail('not_a_draft'));
  });
  it('a non-string instruction is not a draft', async () => {
    const { d, a } = await signed();
    expect(load({ ...d, instruction: 5 as never }, a)).toEqual(fail('not_a_draft'));
  });
  it('a null or non-object binding is not a draft', async () => {
    const { d, a } = await signed();
    expect(load({ ...d, binding: null as never }, a)).toEqual(fail('not_a_draft'));
    expect(load({ ...d, binding: 'b' as never }, a)).toEqual(fail('not_a_draft'));
  });
  it('a non-string model id in the binding is tampering, even under a digest recomputed over it', async () => {
    const { d } = await signed();
    // the approval is deliberately absent: a mutant that let the draft through would end at malformed_approval
    const over5 = { ...d.binding, model: 5 } as never;
    expect(load({ ...d, binding: over5, digest: draftDigestV2(d.permissions, d.limits, d.catalog_digest, over5) }, undefined as never)).toEqual(fail('tampered_draft'));
    const nullModel = { ...d, binding: { ...d.binding, model: 7 }, digest: draftDigestV2(d.permissions, d.limits, d.catalog_digest, { ...d.binding, model: null }) } as never;
    expect(load(nullModel, undefined as never)).toEqual(fail('tampered_draft'));
  });
  it('every action is re-grounded, whatever the draft digest says', async () => {
    const { d, a } = await signed();
    const cases: Array<[string, unknown]> = [
      ['not an array', { bank: 'peek' }],
      ['unknown verb', { bank: ['teleport'] }],
      ['known then unknown', { bank: ['peek', 'teleport'] }],
      ['non-string that stringifies to a known action', { bank: [['peek']] }],
    ];
    for (const [name, permissions] of cases) expect([name, load(redigest(d, permissions), a)]).toEqual([name, fail('unknown_verbs')]);
  });
  it('a non-string signature, reviewer, digest or catalog digest is a malformed approval before any later check', async () => {
    const { d, a } = await signed();
    // each field alone, with the approval ALSO expired: a mutant that skipped the type check would answer a later reason
    const late = { now: a.expires_at };
    for (const k of ['sig', 'reviewer', 'digest', 'catalog_digest'] as const) {
      expect([k, load(d, { ...a, [k]: 5 } as never, late)]).toEqual([k, fail('malformed_approval')]);
    }
  });
  it('a fractional or NaN timestamp is a malformed approval', async () => {
    const { d, a } = await signed();
    expect(load(d, { ...a, approved_at: a.approved_at + 0.5 })).toEqual(fail('malformed_approval'));
    expect(load(d, { ...a, expires_at: NaN })).toEqual(fail('malformed_approval'));
  });
  it('a binding-less (pre-0.5) draft is refused under a v2 approval even when that approval signed its digest', async () => {
    const d = await good();
    const { binding: _drop, ...rest } = d;
    const old = { ...rest, digest: draftDigest(d.permissions, d.limits, d.catalog_digest) } as unknown as DraftPolicy;
    const v2 = approveDraft(old, reviewer.secretKey, { now: NOW }); // a v2 body over the v1 digest
    expect(v2.v).toBe(2);
    expect(load(old, v2)).toEqual(fail('digest_mismatch'));
  });
  it('an exception anywhere inside is a malformed approval, never a throw or an undefined result', async () => {
    const { d, a } = await signed();
    const boom = Object.defineProperty({ ...a }, 'v', { get: () => { throw new Error('boom'); } }) as NLApproval;
    expect(settle(() => load(d, boom))).toEqual({ ok: true, value: fail('malformed_approval') });
  });
});

describe('the built-in catalog is untouched by these probes', () => {
  it('stripe.refund still resolves its aliases', () => {
    expect(DEFAULT_CATALOG.resolve?.('stripe', 'reimburse')?.verb).toBe('stripe.refund');
  });
});
