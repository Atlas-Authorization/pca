import { describe, expect, it } from 'vitest';
import { b64u } from './hash';
import { publicKeyOf } from './keys';
import {
  createLink,
  instantiateTemplate,
  resolveLink,
  signTemplate,
  signTighten,
  templateDefError,
  templateDigest,
  tightenOverlayError,
  verifyLinkedPolicy,
  verifyTemplate,
  verifyTighten,
  type TemplateDef,
  type TemplateRegistry,
} from './policy-link';

const SECRET = new Uint8Array(32).fill(7);
const PUB = b64u(publicKeyOf(SECRET));
const OTHER_PUB = b64u(publicKeyOf(new Uint8Array(32).fill(9)));

const BASE = { v: 1, kind: 'pca-policy-template', id: 't', version: '1', slots: { a: { type: 'string' } }, body: { predicates: [{ verb: { $slot: 'a' } }] } };
const mk = (over: Record<string, unknown> = {}): TemplateDef => ({ ...BASE, ...over }) as unknown as TemplateDef;
/** A one-slot template whose body is the given predicate list. */
const withBody = (slot: Record<string, unknown>, predicates: unknown[], caveats?: unknown[]): TemplateDef => mk({ slots: { s: slot }, body: { predicates, ...(caveats ? { caveats } : {}) } });
const slotOf = (extra: Record<string, unknown> = {}) => ({ $slot: 's', ...extra });
const valueTpl = (slot: Record<string, unknown>, extra: Record<string, unknown> = {}) => withBody(slot, [{ verb: 'x', where: [{ field: 'f', op: 'eq', value: slotOf(extra) }] }]);
const whereValue = (r: ReturnType<typeof instantiateTemplate>): unknown => (r.ok ? (r.policy.predicates[0] as unknown as { where: Array<{ value: unknown }> }).where[0]!.value : r);
const DEF_ERR = (tpl: unknown) => templateDefError(tpl);

describe('template definition errors', () => {
  it('top-level members', () => {
    expect(DEF_ERR(mk())).toBeNull();
    expect(DEF_ERR(mk({ kind: 'x' }))).toBe('template v / kind mismatch');
    expect(DEF_ERR(mk({ v: 2 }))).toBe('template v / kind mismatch');
    expect(DEF_ERR(mk({ id: ['a'] }))).toBe('template id must match ^[a-z][a-z0-9_]{0,63}$');
    expect(DEF_ERR(mk({ id: 5 }))).toBe('template id must match ^[a-z][a-z0-9_]{0,63}$');
    expect(DEF_ERR(mk({ id: 'A' }))).toBe('template id must match ^[a-z][a-z0-9_]{0,63}$');
    const VERSION = 'template version must be a string of 1..64 characters';
    expect(DEF_ERR(mk({ version: 5 }))).toBe(VERSION);
    expect(DEF_ERR(mk({ version: '' }))).toBe(VERSION);
    expect(DEF_ERR(mk({ version: 'v'.repeat(65) }))).toBe(VERSION);
    expect(DEF_ERR(mk({ version: 'v'.repeat(64) }))).toBeNull();
  });
  it('slots container and count', () => {
    for (const slots of [null, [], 'x', 5]) expect(DEF_ERR(mk({ slots }))).toBe('slots must be an object');
    const many = (n: number) => {
      const names = Array.from({ length: n }, (_, i) => `s${i}`);
      return mk({ slots: Object.fromEntries(names.map((s) => [s, { type: 'string' }])), body: { predicates: [{ verb: 'x', where: names.map((s) => ({ field: 'f', op: 'eq', value: { $slot: s } })) }] } });
    };
    expect(DEF_ERR(many(32))).toBeNull();
    expect(DEF_ERR(many(33))).toBe('more than 32 slots');
  });
  it('each slot declaration', () => {
    expect(DEF_ERR(mk({ slots: { a: null } }))).toBe("slot 'a' must be an object");
    expect(DEF_ERR(mk({ slots: { a: 'x' } }))).toBe("slot 'a' must be an object");
    expect(DEF_ERR(mk({ slots: { a: { type: 'float' } } }))).toBe("slot 'a'.type must be string, integer or set");
    expect(DEF_ERR(mk({ slots: { a: { type: 'set' } } }))).toBe("set slot 'a' needs a closed values list");
    const VALUES = "slot 'a'.values must be a list of strings";
    expect(DEF_ERR(mk({ slots: { a: { type: 'string', values: 'abc' } } }))).toBe(VALUES);
    expect(DEF_ERR(mk({ slots: { a: { type: 'string', values: ['x', 5] } } }))).toBe(VALUES);
    expect(DEF_ERR(mk({ slots: { a: { type: 'string', values: [5] } } }))).toBe(VALUES);
    expect(DEF_ERR(mk({ slots: { a: { type: 'string', values: Array.from({ length: 65 }, (_, i) => `m${i}`) } } }))).toBe(VALUES);
    expect(DEF_ERR(mk({ slots: { a: { type: 'string', values: Array.from({ length: 64 }, (_, i) => `m${i}`) } } }))).toBeNull();
  });
  it('integer bounds are checked for integer slots only', () => {
    expect(DEF_ERR(mk({ slots: { a: { type: 'integer', min: 1.5 } } }))).toBe("slot 'a'.min must be a safe integer");
    expect(DEF_ERR(mk({ slots: { a: { type: 'integer', max: 1.5 } } }))).toBe("slot 'a'.max must be a safe integer");
    expect(DEF_ERR(mk({ slots: { a: { type: 'integer', min: 1, max: 9 } } }))).toBeNull();
    expect(DEF_ERR(mk({ slots: { a: { type: 'string', min: 1.5, max: -0 } } }))).toBeNull();
  });
  it('body', () => {
    expect(DEF_ERR(mk({ body: null }))).toBe('body.predicates must be an array');
    expect(DEF_ERR(mk({ body: { predicates: 'x' } }))).toBe('body.predicates must be an array');
    expect(DEF_ERR(mk({ slots: {}, body: { predicates: [], caveats: 'x' } }))).toBe('body.caveats must be an array');
    expect(DEF_ERR(mk({ slots: {}, body: { predicates: [], caveats: [] } }))).toBeNull();
  });
  it('forbidden keys anywhere in the body, and placeholder members', () => {
    expect(DEF_ERR(mk({ slots: {}, body: { predicates: [{ verb: 'x', constructor: 1 }] } }))).toBe("body has the forbidden key 'constructor'");
    expect(DEF_ERR(mk({ slots: {}, body: { predicates: [{ verb: 'x', prototype: 1 }] } }))).toBe("body has the forbidden key 'prototype'");
    expect(DEF_ERR(mk({ slots: {}, body: { predicates: [{ verb: 'x', where: [{ nested: { prototype: 1 } }] }] } }))).toBe("body has the forbidden key 'prototype'");
    expect(DEF_ERR(mk({ body: { predicates: [{ verb: { $slot: ['a'] } }] } }))).toBe("placeholder names undeclared slot 'a'");
    expect(DEF_ERR(mk({ body: { predicates: [{ verb: { $slot: 'a', pre: 5 } }] } }))).toBe('placeholder pre must be a string');
    expect(DEF_ERR(mk({ body: { predicates: [{ verb: { $slot: 'a', post: 5 } }] } }))).toBe('placeholder post must be a string');
    expect(DEF_ERR(mk({ body: { predicates: [{ verb: { $slot: 'a', pre: '/', post: '/*' } }] } }))).toBeNull();
  });
});

describe('verifyTemplate and verifyTighten', () => {
  const tpl = mk();
  const signed = signTemplate(tpl, SECRET, PUB);
  const overlay = { v: 1, kind: 'pca-template-tighten', template_id: 't', version_digest: templateDigest(tpl), add_where: [{ field: 'f', op: 'eq', value: 1 }] } as const;
  const sov = signTighten(overlay as never, SECRET, PUB);
  it('template', () => {
    expect(verifyTemplate(signed, [PUB])).toEqual({ ok: true });
    expect(verifyTemplate(null as never, [PUB])).toEqual({ ok: false, reason: 'template must be an object' });
    expect(verifyTemplate({ ...signed, def: mk({ kind: 'x' }) }, [PUB])).toEqual({ ok: false, reason: 'template v / kind mismatch' });
    expect(verifyTemplate(signed, [OTHER_PUB])).toEqual({ ok: false, reason: 'template signer is not trusted' });
    expect(verifyTemplate({ ...signed, sig: 5 as never }, [PUB])).toEqual({ ok: false, reason: 'bad template signature' });
    expect(verifyTemplate({ ...signed, sig: sov.sig }, [PUB])).toEqual({ ok: false, reason: 'bad template signature' });
    expect(verifyTemplate(signed, undefined as never)).toEqual({ ok: false, reason: 'template verification error (fail closed)' });
  });
  it('overlay', () => {
    expect(verifyTighten(sov, [PUB])).toEqual({ ok: true });
    expect(verifyTighten(null as never, [PUB])).toEqual({ ok: false, reason: 'overlay must be an object' });
    expect(verifyTighten({ ...sov, overlay: { ...overlay, kind: 'x' } as never }, [PUB])).toEqual({ ok: false, reason: 'overlay v / kind mismatch' });
    expect(verifyTighten(sov, [OTHER_PUB])).toEqual({ ok: false, reason: 'overlay signer is not trusted' });
    expect(verifyTighten({ ...sov, sig: 5 as never }, [PUB])).toEqual({ ok: false, reason: 'bad overlay signature' });
    expect(verifyTighten({ ...sov, sig: signed.sig }, [PUB])).toEqual({ ok: false, reason: 'bad overlay signature' });
    expect(verifyTighten(sov, undefined as never)).toEqual({ ok: false, reason: 'overlay verification error (fail closed)' });
  });
});

describe('tighten overlay errors', () => {
  const OV = { v: 1, kind: 'pca-template-tighten', template_id: 't', version_digest: 'd' };
  const ov = (over: Record<string, unknown>) => tightenOverlayError({ ...OV, ...over });
  it('exact reasons', () => {
    expect(ov({})).toBeNull();
    expect(tightenOverlayError('x')).toBe('overlay must be an object');
    expect(ov({ v: 2 })).toBe('overlay v / kind mismatch');
    expect(ov({ kind: 'x' })).toBe('overlay v / kind mismatch');
    expect(ov({ template_id: ['t'] })).toBe('overlay template_id invalid');
    expect(ov({ template_id: 5 })).toBe('overlay template_id invalid');
    expect(ov({ template_id: 'T' })).toBe('overlay template_id invalid');
    expect(ov({ version_digest: 5 })).toBe('overlay version_digest invalid');
    expect(ov({ version_digest: '' })).toBe('overlay version_digest invalid');
    for (const add_where of ['x', [5], [null], [1, {}]]) expect(ov({ add_where })).toBe('overlay add_where must be a list of conditions');
    expect(ov({ add_where: [{}] })).toBeNull();
    for (const add_caveats of ['x', [{}], [{ type: 5 }], [{ type: 'a' }, {}], [null]]) expect(ov({ add_caveats })).toBe('overlay add_caveats must be a list of caveats');
    expect(ov({ add_caveats: [{ type: 'a' }] })).toBeNull();
  });
});

describe('instantiateTemplate', () => {
  it('refuses a malformed definition and non-object slots with the exact reason', () => {
    expect(instantiateTemplate(mk({ kind: 'x' }), { a: 'v' })).toEqual({ ok: false, reason: 'template v / kind mismatch' });
    expect(instantiateTemplate(mk(), null as never)).toEqual({ ok: false, reason: 'slots must be an object' });
    expect(instantiateTemplate(mk(), { a: 'v', b: 1 })).toEqual({ ok: false, reason: "slot 'b' is not declared by the template" });
    expect(instantiateTemplate(mk(), {})).toEqual({ ok: false, reason: "slot 'a' is not filled" });
    expect(instantiateTemplate(mk(), { a: 'v' })).toEqual({ ok: true, policy: { predicates: [{ verb: 'v' }], caveats: [] } });
  });
  it('a non-error failure fails closed with the fixed reason', () => {
    const slots = { get a(): never { throw 'nope'; } };
    expect(instantiateTemplate(mk(), slots as never)).toEqual({ ok: false, reason: 'instantiation error (fail closed)' });
  });
  it('string slots: 1..256 characters', () => {
    const MSG = "slot 'a' must be a string of 1..256 characters";
    expect(instantiateTemplate(mk(), { a: '' })).toEqual({ ok: false, reason: MSG });
    expect(instantiateTemplate(mk(), { a: 5 })).toEqual({ ok: false, reason: MSG });
    expect(instantiateTemplate(mk(), { a: 'x'.repeat(257) })).toEqual({ ok: false, reason: MSG });
    expect(instantiateTemplate(mk(), { a: 'x'.repeat(256) }).ok).toBe(true);
    expect(instantiateTemplate(mk({ slots: { a: { type: 'string', values: ['p', 'q'] } } }), { a: 'z' })).toEqual({ ok: false, reason: "slot 'a' is outside its closed value set" });
    expect(instantiateTemplate(mk({ slots: { a: { type: 'string', values: ['p', 'q'] } } }), { a: 'q' }).ok).toBe(true);
  });
  it('integer slots: inclusive bounds, optional on either side', () => {
    const bounded = mk({ slots: { a: { type: 'integer', min: 1, max: 10 } } });
    expect(instantiateTemplate(bounded, { a: 1 }).ok).toBe(true);
    expect(instantiateTemplate(bounded, { a: 10 }).ok).toBe(true);
    expect(instantiateTemplate(bounded, { a: 0 })).toEqual({ ok: false, reason: "slot 'a' is below its minimum" });
    expect(instantiateTemplate(bounded, { a: 11 })).toEqual({ ok: false, reason: "slot 'a' is above its maximum" });
    expect(instantiateTemplate(bounded, { a: 1.5 })).toEqual({ ok: false, reason: "slot 'a' must be a safe integer" });
    const open = mk({ slots: { a: { type: 'integer' } } });
    expect(instantiateTemplate(open, { a: -5 }).ok).toBe(true);
    expect(instantiateTemplate(open, { a: 2 ** 40 }).ok).toBe(true);
  });
  it('set slots: at most 64 members, strings only, closed domain', () => {
    const V64 = Array.from({ length: 64 }, (_, i) => `m${i}`);
    const tpl = withBody({ type: 'set', values: V64 }, [{ verb: slotOf() }]);
    const MSG = "slot 's' must be a non-empty list of strings";
    expect(instantiateTemplate(tpl, { s: V64 })).toEqual({ ok: true, policy: { predicates: [{ verb: V64 }], caveats: [] } });
    expect(instantiateTemplate(tpl, { s: [...V64, 'm64'] })).toEqual({ ok: false, reason: MSG });
    expect(instantiateTemplate(tpl, { s: [] })).toEqual({ ok: false, reason: MSG });
    expect(instantiateTemplate(tpl, { s: 'm1' })).toEqual({ ok: false, reason: MSG });
    expect(instantiateTemplate(tpl, { s: ['m1', 5] })).toEqual({ ok: false, reason: MSG });
    expect(instantiateTemplate(tpl, { s: ['m1', 'm1'] })).toEqual({ ok: false, reason: "slot 's' has duplicate members" });
    expect(instantiateTemplate(tpl, { s: ['m1', 'zz'] })).toEqual({ ok: false, reason: "slot 's' has a member outside its closed set" });
  });
});

describe('instantiateTemplate: where a slot value lands', () => {
  const VR = "slot 's' would inject a wildcard or regex matcher into a verb or resource";
  it('a verb or resource position refuses wildcards and regex matchers, other kinds pass', () => {
    const verb = withBody({ type: 'string' }, [{ verb: slotOf() }]);
    expect(instantiateTemplate(verb, { s: 're:abc' })).toEqual({ ok: false, reason: VR });
    expect(instantiateTemplate(verb, { s: 'a*' })).toEqual({ ok: false, reason: VR });
    expect(instantiateTemplate(verb, { s: 'more:' })).toEqual({ ok: true, policy: { predicates: [{ verb: 'more:' }], caveats: [] } });
    const resource = withBody({ type: 'string' }, [{ verb: 'x', resource: slotOf() }]);
    expect(instantiateTemplate(resource, { s: 're:abc' })).toEqual({ ok: false, reason: VR });
    const int = withBody({ type: 'integer' }, [{ verb: slotOf() }]);
    expect(instantiateTemplate(int, { s: 5 })).toEqual({ ok: true, policy: { predicates: [{ verb: 5 }], caveats: [] } });
    const set = withBody({ type: 'set', values: ['p', 'q*', 're:z'] }, [{ verb: slotOf() }]);
    expect(instantiateTemplate(set, { s: ['p', 'q*'] })).toEqual({ ok: false, reason: VR });
    expect(instantiateTemplate(set, { s: ['p', 're:z'] })).toEqual({ ok: false, reason: VR });
  });
  it('any other position takes the value as is', () => {
    const t = valueTpl({ type: 'string' });
    expect(whereValue(instantiateTemplate(t, { s: 'a*' }))).toBe('a*');
    expect(whereValue(instantiateTemplate(t, { s: 're:a' }))).toBe('re:a');
  });
  it('affixes splice into a string', () => {
    const t = (extra: Record<string, unknown>) => valueTpl({ type: 'string' }, extra);
    expect(whereValue(instantiateTemplate(t({ pre: '/p/' }), { s: 'abc' }))).toBe('/p/abc');
    expect(whereValue(instantiateTemplate(t({ post: '/x' }), { s: 'abc' }))).toBe('abc/x');
    expect(whereValue(instantiateTemplate(t({ pre: '/p/', post: '/x' }), { s: 'abc' }))).toBe('/p/abc/x');
    expect(whereValue(instantiateTemplate(t({ pre: '' , post: '' }), { s: 'abc' }))).toBe('abc');
  });
  it('a spliced value may not be a non-string, carry a wildcard or a NUL', () => {
    const MSG = "slot 's' cannot be spliced into a string (wildcard or non-string)";
    const str = (extra: Record<string, unknown>) => valueTpl({ type: 'string' }, extra);
    expect(instantiateTemplate(valueTpl({ type: 'integer' }, { pre: '/p/' }), { s: 5 })).toEqual({ ok: false, reason: MSG });
    expect(instantiateTemplate(valueTpl({ type: 'set', values: ['p'] }, { post: '/' }), { s: ['p'] })).toEqual({ ok: false, reason: MSG });
    expect(instantiateTemplate(str({ pre: '/p/' }), { s: 'a*' })).toEqual({ ok: false, reason: MSG });
    expect(instantiateTemplate(str({ post: '/x' }), { s: '*' })).toEqual({ ok: false, reason: MSG });
    expect(instantiateTemplate(str({ post: '/x' }), { s: 'a\u0000b' })).toEqual({ ok: false, reason: MSG });
  });
  it('a value spliced with no prefix may not begin a regex matcher; an author prefix may', () => {
    const REGEX = "slot 's' would inject a regex matcher";
    expect(instantiateTemplate(valueTpl({ type: 'string' }, { post: '/x' }), { s: 're:a' })).toEqual({ ok: false, reason: REGEX });
    expect(whereValue(instantiateTemplate(valueTpl({ type: 'string' }, { post: '/x' }), { s: 'are:a' }))).toBe('are:a/x');
    expect(whereValue(instantiateTemplate(valueTpl({ type: 'string' }, { pre: '/p/' }), { s: 're:a' }))).toBe('/p/re:a');
    expect(whereValue(instantiateTemplate(valueTpl({ type: 'string' }, { pre: 're:' }), { s: 'abc' }))).toBe('re:abc');
    expect(whereValue(instantiateTemplate(valueTpl({ type: 'string' }, { pre: 're:', post: '$' }), { s: 'abc' }))).toBe('re:abc$');
  });
});

describe('resolveLink and verifyLinkedPolicy', () => {
  const tpl = mk();
  const digest = templateDigest(tpl);
  const reg = (over: Partial<TemplateRegistry> = {}): TemplateRegistry => ({ templates: { [digest]: signTemplate(tpl, SECRET, PUB) }, trusted: [PUB], ...over });
  const ref = createLink(tpl, { a: 'mail.send' });
  const tighten = (over: Record<string, unknown>, secret = SECRET, pub = PUB) => signTighten({ v: 1, kind: 'pca-template-tighten', template_id: 't', version_digest: digest, ...over } as never, secret, pub);
  const COND = { field: 'env.tier', op: 'ne', value: 'frozen' };
  it('a plain link', () => {
    expect(resolveLink(ref, reg())).toEqual({ ok: true, policy: { predicates: [{ verb: 'mail.send' }], caveats: [] }, overlays: 0 });
  });
  it('a malformed reference is refused with its reason', () => {
    expect(resolveLink({ ...ref, template_id: 'X' }, reg())).toEqual({ ok: false, reason: 'template_ref.template_id invalid' });
    expect(resolveLink(null as never, reg())).toEqual({ ok: false, reason: 'template_ref must be an object' });
  });
  it('an overlay adding only caveats leaves the conditions empty and the caveats added', () => {
    const o = tighten({ add_caveats: [{ type: 'rate', max: 1, per_secs: 60 }] });
    expect(resolveLink(ref, reg({ overlays: [o] }))).toEqual({ ok: true, policy: { predicates: [{ verb: 'mail.send', where: [] }], caveats: [{ type: 'rate', max: 1, per_secs: 60 }] }, overlays: 1 });
  });
  it('an overlay adding only conditions adds nothing to the caveats', () => {
    const o = tighten({ add_where: [COND] });
    expect(resolveLink(ref, reg({ overlays: [o] }))).toEqual({ ok: true, policy: { predicates: [{ verb: 'mail.send', where: [COND] }], caveats: [] }, overlays: 1 });
  });
  it('an overlay for another template or another version is skipped, a null entry is ignored', () => {
    const otherTemplate = tighten({ template_id: 'other', add_where: [COND] });
    const otherVersion = tighten({ version_digest: 'd', add_where: [COND] });
    expect(resolveLink(ref, reg({ overlays: [otherTemplate, otherVersion, null as never] }))).toEqual({ ok: true, policy: { predicates: [{ verb: 'mail.send' }], caveats: [] }, overlays: 0 });
  });
  it('an overlay for this version that does not verify is a refusal', () => {
    expect(resolveLink(ref, reg({ overlays: [tighten({ add_where: [COND] }, new Uint8Array(32).fill(9), OTHER_PUB)] }))).toEqual({ ok: false, reason: 'overlay signer is not trusted' });
  });
  it('a grant must hold exactly the policy the link denotes', () => {
    const env = { template_ref: ref, predicates: [{ verb: 'mail.send' }] as never, caveats: [] };
    expect(verifyLinkedPolicy(env, reg())).toEqual({ ok: true, template: digest });
    expect(verifyLinkedPolicy({ ...env, predicates: [{ verb: 'mail.draft' }] as never }, reg())).toEqual({ ok: false, reason: 'grant policy differs from the linked template instantiation' });
    expect(verifyLinkedPolicy({ ...env, caveats: [{ type: 'rate', max: 1, per_secs: 60 }] as never }, reg())).toEqual({ ok: false, reason: 'grant policy differs from the linked template instantiation' });
  });
});
