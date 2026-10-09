/**
 * T-045 (visually identical Unicode identifiers). The library intentionally does NOT normalize, case-fold or strip
 * anything: an identifier is its exact UTF-16/UTF-8 code units. These tests prove that byte-different identifiers are
 * NEVER treated as equal at any point where a decision is made, in BOTH directions (a grant for the variant does not
 * authorize the base form; a grant for the base form does not authorize the variant), and that the exact form is still
 * allowed. Integrators who want normalization must apply it BEFORE authorizing (documented residual).
 */
import { describe, expect, it } from 'vitest';
import { envelopeCaveatEvaluator, evaluateCaveats, evaluatePredicates, predicateMatches, type ActionContext, type Predicate } from './predicates';
import { hashCanonical } from './hash';
import { paramsDigest, commitPlan, type PlanNode } from './merkle';
import { strictParse } from './strict-json';
import { encodePCActn } from './pcactn';
import { verifyPCActn } from './server/verify';
import { AUD, NOW, setup } from './server/fixture.test-util';

/** A base identifier plus every kind of "looks the same" variant. All of them are byte-different from the base. */
const BASE = 'caf\u00e9-payments'; // NFC: precomposed e-acute
interface Variant {
  name: string;
  value: string;
}
const VARIANTS: Variant[] = [
  { name: 'NFD (decomposed e + combining acute)', value: BASE.normalize('NFD') },
  { name: 'Cyrillic a homoglyph', value: BASE.replace('a', '\u0430') },
  { name: 'Cyrillic o homoglyph', value: BASE.replace('a', '\u0430').replace('p', '\u0440') },
  { name: 'zero-width space', value: BASE.replace('-', '\u200b-') },
  { name: 'zero-width joiner', value: `${BASE}\u200d` },
  { name: 'zero-width no-break space / BOM', value: `\ufeff${BASE}` },
  { name: 'soft hyphen', value: BASE.replace('pay', 'pa\u00ady') },
  { name: 'right-to-left override', value: `\u202e${BASE}` },
  { name: 'fullwidth letters', value: BASE.replace('payments', '\uff50\uff41\uff59ments') },
  { name: 'compatibility ligature', value: BASE.replace('ts', '\ufb06') },
  { name: 'trailing no-break space', value: `${BASE}\u00a0` },
  { name: 'Greek question mark / look-alike punctuation', value: BASE.replace('-', '\u2010') },
  { name: 'case difference', value: BASE.toUpperCase() },
  { name: 'astral math-alphanumeric letter', value: BASE.replace('c', '\u{1d41c}') },
  { name: 'tag characters', value: `${BASE}\u{e0041}` },
];

const ctxOf = (verb: string, resource: string, params?: Record<string, unknown>): ActionContext => ({ action: { verb, resource, ...(params ? { params } : {}) } });

describe('T-045: the variants really are byte-different from the base (guards the test data)', () => {
  it('every variant differs from BASE in its UTF-8 bytes and none of them is a no-op', () => {
    const enc = (s: string) => Buffer.from(s, 'utf8').toString('hex');
    const seen = new Set<string>([enc(BASE)]);
    for (const v of VARIANTS) {
      expect(enc(v.value), v.name).not.toBe(enc(BASE));
      seen.add(enc(v.value));
    }
    expect(BASE.normalize('NFD')).not.toBe(BASE);
    expect(BASE.normalize('NFC')).toBe(BASE);
    expect(seen.size).toBeGreaterThanOrEqual(VARIANTS.length - 1); // at most one accidental collision between variants
  });
});

describe('T-045: verb matching is byte-exact', () => {
  it('a predicate for the exact verb allows it and denies every variant', () => {
    const p: Predicate[] = [{ verb: BASE }];
    expect(evaluatePredicates(p, ctxOf(BASE, 'r')).allowed).toBe(true);
    for (const v of VARIANTS) {
      const r = evaluatePredicates(p, ctxOf(v.value, 'r'));
      expect(r.allowed, v.name).toBe(false);
      expect(r.reason, v.name).toBe(`no predicate permits ${v.value} on r`);
    }
  });
  it('the reverse direction: a predicate for a variant denies the base form', () => {
    for (const v of VARIANTS) {
      expect(evaluatePredicates([{ verb: v.value }], ctxOf(v.value, 'r')).allowed, `${v.name} exact`).toBe(true);
      expect(evaluatePredicates([{ verb: v.value }], ctxOf(BASE, 'r')).allowed, `${v.name} base`).toBe(false);
    }
  });
  it('array verbs and the wildcard: only the listed exact strings (and "*") match', () => {
    expect(evaluatePredicates([{ verb: [BASE.normalize('NFD'), 'other'] }], ctxOf(BASE, 'r')).allowed).toBe(false);
    expect(evaluatePredicates([{ verb: [BASE, 'other'] }], ctxOf(BASE, 'r')).allowed).toBe(true);
    expect(evaluatePredicates([{ verb: '*' }], ctxOf(VARIANTS[0]!.value, 'r')).allowed).toBe(true); // explicit wildcard is explicit
  });
});

describe('T-045: resource matching is byte-exact (exact, prefix, glob, regex)', () => {
  const RES = `/acct/${BASE}/items`;
  const resVariants = VARIANTS.map((v) => ({ name: v.name, value: `/acct/${v.value}/items` }));
  it('exact resource: allows itself, denies every variant (both directions)', () => {
    expect(predicateMatches({ verb: 'v', resource: RES }, ctxOf('v', RES))).toBe(true);
    for (const v of resVariants) {
      expect(predicateMatches({ verb: 'v', resource: RES }, ctxOf('v', v.value)), `${v.name} requested`).toBe(false);
      expect(predicateMatches({ verb: 'v', resource: v.value }, ctxOf('v', RES)), `${v.name} granted`).toBe(false);
      expect(predicateMatches({ verb: 'v', resource: v.value }, ctxOf('v', v.value)), `${v.name} self`).toBe(true);
    }
  });
  it('trailing-* prefix patterns compare the prefix by code units: a variant prefix never covers the base and vice versa', () => {
    const pat = `/acct/${BASE}/*`;
    expect(predicateMatches({ verb: 'v', resource: pat }, ctxOf('v', `/acct/${BASE}/x`))).toBe(true);
    for (const v of VARIANTS) {
      expect(predicateMatches({ verb: 'v', resource: pat }, ctxOf('v', `/acct/${v.value}/x`)), v.name).toBe(false);
      expect(predicateMatches({ verb: 'v', resource: `/acct/${v.value}/*` }, ctxOf('v', `/acct/${BASE}/x`)), `${v.name} (variant grant)`).toBe(false);
    }
  });
  it('regex resources (re:) do not fold or normalize: a literal pattern matches only its own bytes', () => {
    const re = `re:/acct/${BASE.replace('-', '\\-')}/items`;
    expect(predicateMatches({ verb: 'v', resource: re }, ctxOf('v', RES))).toBe(true);
    for (const v of resVariants) expect(predicateMatches({ verb: 'v', resource: re }, ctxOf('v', v.value)), v.name).toBe(false);
  });
  it('a regex "." does not make NFC and NFD equal: NFD is two code units where NFC is one', () => {
    const nfc = 'caf\u00e9';
    const nfd = nfc.normalize('NFD');
    expect(nfd.length).toBe(nfc.length + 1);
    expect(predicateMatches({ verb: 'v', resource: 're:caf.' }, ctxOf('v', nfc))).toBe(true);
    expect(predicateMatches({ verb: 'v', resource: 're:caf.' }, ctxOf('v', nfd))).toBe(false);
    expect(predicateMatches({ verb: 'v', resource: 're:caf.+' }, ctxOf('v', nfd))).toBe(true); // explicit author intent is honoured
  });
});

describe('T-045: condition operands (where) compare exact values', () => {
  const field = 'action.params.account';
  const run = (op: 'eq' | 'ne' | 'in' | 'nin' | 'prefix' | 'like', value: unknown, actual: string) =>
    predicateMatches({ verb: 'v', where: [{ field, op, value }] }, ctxOf('v', 'r', { account: actual }));
  it('eq / in allow only the identical string and deny each variant; ne / nin are the exact mirror', () => {
    expect(run('eq', BASE, BASE)).toBe(true);
    expect(run('in', [BASE, 'x'], BASE)).toBe(true);
    expect(run('ne', BASE, BASE)).toBe(false);
    expect(run('nin', [BASE], BASE)).toBe(false);
    for (const v of VARIANTS) {
      expect(run('eq', BASE, v.value), `eq ${v.name}`).toBe(false);
      expect(run('eq', v.value, BASE), `eq(rev) ${v.name}`).toBe(false);
      expect(run('in', [BASE, 'x'], v.value), `in ${v.name}`).toBe(false);
      expect(run('ne', BASE, v.value), `ne ${v.name}`).toBe(true); // different bytes => genuinely "not equal"
      expect(run('nin', [BASE], v.value), `nin ${v.name}`).toBe(true);
    }
  });
  it('prefix and like (glob) are code-unit comparisons', () => {
    expect(run('prefix', 'caf\u00e9', BASE)).toBe(true);
    expect(run('prefix', 'caf\u00e9', BASE.normalize('NFD'))).toBe(false);
    expect(run('prefix', BASE.normalize('NFD'), BASE)).toBe(false);
    expect(run('like', `${BASE}*`, `${BASE}-x`)).toBe(true);
    expect(run('like', BASE, BASE)).toBe(true);
    for (const v of VARIANTS) {
      expect(run('like', BASE, v.value), `${v.name} requested`).toBe(false);
      expect(run('like', v.value, BASE), `${v.name} granted`).toBe(false);
    }
    expect(run('like', 'caf?-payments', BASE.normalize('NFD'))).toBe(false); // ? is one code unit
  });
  it('is_a type/tag tests are exact: a homoglyph type name is a different type', () => {
    const t = 'Acc\u043eunt'; // Cyrillic o inside "Account"
    const isA = (operand: string, v: unknown) => predicateMatches({ verb: 'v', where: [{ field: 'subject.thing', op: 'is_a', value: operand }] }, { ...ctxOf('v', 'r'), subject: { thing: v } });
    expect(isA('Account', 'Account::1')).toBe(true);
    expect(isA('Account', `${t}::1`)).toBe(false);
    expect(isA('Account', { type: t })).toBe(false);
    expect(isA('Account', { tags: [t] })).toBe(false);
    expect(isA(t, 'Account::1')).toBe(false);
  });
  it('member_of group membership is exact: a homoglyph group id is not the group', () => {
    const adj = { alice: ['admins'], admins: [] };
    const member = (who: string, group: string) =>
      predicateMatches({ verb: 'v', where: [{ field: 'subject.id', op: 'member_of', collection: 'env.groups', value: group }] }, { ...ctxOf('v', 'r'), subject: { id: who }, env: { groups: adj } });
    expect(member('alice', 'admins')).toBe(true);
    expect(member('alice', 'adm\u0456ns')).toBe(false); // Cyrillic i
    expect(member('al\u0456ce', 'admins')).toBe(false);
    expect(member('alice', 'admins\u200b')).toBe(false);
  });
  it('ordering ops see different strings as different (no fold): equal-looking NFC/NFD are strictly ordered, never "equal"', () => {
    const cmp = (op: 'lt' | 'gt' | 'lte' | 'gte', a: string, b: string) => predicateMatches({ verb: 'v', where: [{ field, op, value: b }] }, ctxOf('v', 'r', { account: a }));
    const nfc = 'caf\u00e9';
    const nfd = nfc.normalize('NFD');
    expect(cmp('lte', nfc, nfd) && cmp('gte', nfc, nfd)).toBe(false); // would be true only if they compared equal
    expect(cmp('lt', nfd, nfc) !== cmp('gt', nfd, nfc)).toBe(true);
  });
});

describe('T-045: caveat type matching is exact', () => {
  const ctx = { now: NOW };
  it('the real "expires" caveat is evaluated; look-alike type names are unknown caveats and FAIL CLOSED', () => {
    expect(envelopeCaveatEvaluator({ type: 'expires', at: NOW + 1000 }, ctx)).toBe(true);
    const lookalikes = ['expіres', 'expires\u200b', '\u200bexpires', 'EXPIRES', 'expires ', 'exp\u0131res', '\uff45xpires', 'expires\u0301'];
    for (const type of lookalikes) {
      expect(type).not.toBe('expires');
      expect(envelopeCaveatEvaluator({ type, at: NOW + 1000 }, ctx), JSON.stringify(type)).toBe(false);
      expect(evaluateCaveats([{ type, at: NOW + 1000 }], ctx), JSON.stringify(type)).toEqual({ ok: false, failed: [type] });
    }
  });
  it('reversibility classes in the reversibility_max caveat compare exactly', () => {
    expect(envelopeCaveatEvaluator({ type: 'reversibility_max', class: 'irreversible' }, { now: NOW, reversibilityClass: 'reversible' })).toBe(true);
    for (const cls of ['irreversibl\u0435', 'irreversible\u200b', 'Irreversible']) {
      expect(envelopeCaveatEvaluator({ type: 'reversibility_max', class: cls }, { now: NOW, reversibilityClass: 'reversible' }), cls).toBe(false);
      expect(envelopeCaveatEvaluator({ type: 'reversibility_max', class: 'irreversible' }, { now: NOW, reversibilityClass: cls }), `ctx ${cls}`).toBe(false);
    }
  });
});

describe('T-045: audience binding is byte-exact (full verifier)', () => {
  const AUD_NFC = 'rs-caf\u00e9';
  const verdictFor = async (signedAud: string, verifierAud: string) => {
    const s = setup();
    const a = s.mk(s.plan[0]!, { extra: { aud: signedAud } });
    return verifyPCActn(a, { grant: s.grant, now: NOW, audience: verifierAud, context: { plan: s.plan, risk: s.lowRisk, params: {} } });
  };
  it('the identical audience passes the audience check', async () => {
    const v = await verdictFor(AUD_NFC, AUD_NFC);
    expect(v.checks.audience).toBe('pass');
    expect(v.allow).toBe(true);
  });
  it('a verifier audience that is any byte-different look-alike of the signed audience FAILS the audience check and denies', async () => {
    const variants = [AUD_NFC.normalize('NFD'), AUD_NFC.replace('r', '\u0433'), `${AUD_NFC}\u200b`, `\ufeff${AUD_NFC}`, AUD_NFC.toUpperCase(), `${AUD_NFC}\u00a0`];
    for (const bad of variants) {
      const v = await verdictFor(AUD_NFC, bad);
      expect(v.checks.audience, JSON.stringify(bad)).toBe('fail');
      expect(v.allow, JSON.stringify(bad)).toBe(false);
    }
  });
  it('the reverse: an action signed for a look-alike audience is refused by the genuine verifier', async () => {
    for (const signed of [AUD_NFC.normalize('NFD'), AUD_NFC.replace('r', '\u0433'), `${AUD_NFC}\u200b`]) {
      const v = await verdictFor(signed, AUD_NFC);
      expect(v.checks.audience, JSON.stringify(signed)).toBe('fail');
      expect(v.allow).toBe(false);
    }
  });
  it('a signed-in-AUD action is not accepted by a verifier whose id merely renders the same ("rs-test" vs Cyrillic es)', async () => {
    const v = await verdictFor(AUD, 'r\u0455-test');
    expect(v.checks.audience).toBe('fail');
    expect(v.allow).toBe(false);
  });
});

describe('T-045: digests and commitments bind the exact bytes', () => {
  it('params digests, canonical hashes and plan roots all differ between every pair of byte-different identifiers', () => {
    const all = [BASE, ...VARIANTS.map((v) => v.value)];
    const digests = new Set(all.map((x) => paramsDigest({ account: x })));
    expect(digests.size).toBe(new Set(all).size);
    expect(hashCanonical(BASE)).not.toBe(hashCanonical(BASE.normalize('NFD')));
    const root = (resource: string) => {
      const n: PlanNode = { id: 'n1', verb: 'v', resource, params_digest: paramsDigest({}), reversibility_class: 'reversible' };
      return commitPlan([n]).root;
    };
    const roots = new Set(all.map(root));
    expect(roots.size).toBe(new Set(all).size);
  });
  it('the strict wire parser and the encoder preserve exact code units: nothing is normalized in transit', () => {
    for (const v of [BASE, ...VARIANTS.map((x) => x.value)]) {
      const text = JSON.stringify({ r: v });
      const back = strictParse(text) as { r: string };
      expect(back.r).toBe(v);
      expect(Buffer.from(back.r, 'utf8').equals(Buffer.from(v, 'utf8'))).toBe(true);
    }
    const s = setup();
    const a = s.mk(s.plan[0]!, { extra: { aud: BASE.normalize('NFD') } });
    expect(encodePCActn(a)).toContain(BASE.normalize('NFD'));
    expect(encodePCActn(a)).not.toContain(BASE);
  });
  it('a PCActn whose signed resource is NFD does not verify against a plan committing the NFC resource (inclusion fails)', async () => {
    const s = setup();
    const a = s.mk(s.plan[0]!, { tweak: (x) => { x.resource = 'session:caf\u00e9'.normalize('NFD'); } });
    const v = await verifyPCActn(a, { grant: s.grant, now: NOW, audience: AUD, context: { plan: s.plan, risk: s.lowRisk, params: {} } });
    expect(v.allow).toBe(false);
    expect(v.checks.plan_inclusion).toBe('fail');
  });
});
