import { describe, expect, it } from 'vitest';
import { approvalRenderDigest } from '@atlasauth/pca';
import { BUILTIN_DEFS, action, compensationShape, defDigest, mayBeReversible, p, reversibilityFor, undoEngine, type ActionDef, type ActionSpec } from '../src';
import { TEST_PINS, confirmed } from './reviewed';

const R = 'acme.draft:dr_*';
const create = (x: Partial<ActionSpec> = {}): ActionDef =>
  action('acme.draft.create', { title: 'Create a draft', description: 'Saves a draft.', effects: ['create'], resource: R, params: { box: p.text(40), body: p.message(500) }, reversibility: 'reversible', compensates: 'acme.draft.delete', since: '0.1.0', ...x });
const del = (x: Partial<ActionSpec> = {}): ActionDef =>
  action('acme.draft.delete', { title: 'Delete a draft', description: 'Deletes a draft.', effects: ['delete'], resource: R, params: { box: p.text(40), draft: p.id('acme.draft') }, since: '0.1.0', ...x });
const op = (params: Record<string, unknown> = { box: 'inbox', body: 'hello', idempotency_key: 'k1' }, verb = 'acme.draft.create') => ({ verb, resource: 'acme.draft:dr_1', params });

describe('reversibilityFor / mayBeReversible', () => {
  const vd = (map: Record<string, 'reversible' | 'rate_limited' | 'irreversible'>, dflt?: 'reversible' | 'irreversible') =>
    create({ params: { box: p.text(40), body: p.message(500), mode: p.enum(['draft', 'final']) }, reversibility: { by: 'mode', map, ...(dflt ? { default: dflt } : {}) } });
  it('a fixed class is itself; a value-dependent one maps the value, an unmapped or absent value takes the default, else irreversible', () => {
    expect(reversibilityFor(create(), {})).toBe('reversible');
    expect(reversibilityFor(create({ reversibility: 'rate_limited' }), {})).toBe('rate_limited');
    const d = vd({ draft: 'reversible', final: 'irreversible' });
    expect(reversibilityFor(d, { mode: 'draft' })).toBe('reversible');
    expect(reversibilityFor(d, { mode: 'final' })).toBe('irreversible');
    expect(reversibilityFor(d, { mode: 'other' })).toBe('irreversible');
    expect(reversibilityFor(d, {})).toBe('irreversible');
    expect(reversibilityFor(d, { mode: { toString: () => 'draft' } })).toBe('irreversible');
    expect(reversibilityFor(d, { mode: ['draft'] })).toBe('irreversible');
    expect(reversibilityFor(vd({ final: 'irreversible' }, 'reversible'), { mode: 'x' })).toBe('reversible');
    // own properties only: a prototype key is not a mapping
    expect(reversibilityFor(d, { mode: 'constructor' })).toBe('irreversible');
  });
  it('mayBeReversible: any reversible value (fixed, mapped or default)', () => {
    expect(mayBeReversible({ reversibility: 'reversible' })).toBe(true);
    expect(mayBeReversible({ reversibility: 'irreversible' })).toBe(false);
    expect(mayBeReversible({ reversibility: undefined })).toBe(false);
    expect(mayBeReversible({ reversibility: { by: 'm', map: { a: 'irreversible', b: 'reversible' } } })).toBe(true);
    expect(mayBeReversible({ reversibility: { by: 'm', map: { a: 'irreversible' }, default: 'reversible' } })).toBe(true);
    expect(mayBeReversible({ reversibility: { by: 'm', map: { a: 'rate_limited' }, default: 'irreversible' } })).toBe(false);
  });
});

describe('compensationShape: can the compensating action undo the original without the agent?', () => {
  it('copies same-name same-type params and fills one resource-id target from the result', () => {
    expect(compensationShape(create(), del())).toEqual({ ok: true, shape: { copied: ['box'], target: 'draft' } });
  });
  it('a same-name param of another type is not copied (and so must be derivable some other way)', () => {
    expect(compensationShape(create(), del({ params: { box: p.bool(), draft: p.id('acme.draft') } }))).toMatchObject({ ok: false, reason: expect.stringContaining("'box'") });
    expect(compensationShape(create(), del({ params: { box: p.optional(p.bool()), draft: p.id('acme.draft') } }))).toEqual({ ok: true, shape: { copied: [], target: 'draft' } });
  });
  it('refuses a read-only compensator, another resource type, an underivable required param, or two targets', () => {
    expect(compensationShape(create(), action('acme.draft.get', { title: 'Read a draft', effects: ['read'], resource: R, params: { draft: p.id('acme.draft') } }))).toMatchObject({ ok: false, reason: expect.stringContaining('only reads') });
    expect(compensationShape(create(), del({ resource: 'acme.note:nt_*', params: { note: p.id('acme.note') } }))).toMatchObject({ ok: false, reason: expect.stringContaining('acts on acme.note') });
    expect(compensationShape(create(), del({ params: { box: p.text(40), draft: p.id('acme.draft'), reason: p.text(50) } }))).toMatchObject({ ok: false, reason: expect.stringContaining("'reason'") });
    expect(compensationShape(create(), del({ params: { a: p.id('acme.draft'), b: p.id('acme.draft') } }))).toMatchObject({ ok: false, reason: expect.stringContaining("'b'") });
  });
  it('optional params never block; the compensator\'s own idempotency key is the attempt key, not copied', () => {
    expect(compensationShape(create(), del({ params: { box: p.text(40), draft: p.id('acme.draft'), reason: { ...p.text(50), required: false } } }))).toEqual({ ok: true, shape: { copied: ['box'], target: 'draft' } });
    const keyed = del({ effects: ['delete', 'create'] });
    expect(keyed.params.idempotency_key).toBeDefined();
    const s = compensationShape(create(), keyed);
    expect(s.ok && s.shape.copied).toEqual(['box']);
  });
});

describe('undoEngine: reversibility counts only when CONFIRMED', () => {
  const engine = (defs: ActionDef[]) => undoEngine({ defs, pins: TEST_PINS });
  it('a confirmed reversible create with a confirmed compensator yields the derived plan and the render', () => {
    const c = confirmed(create());
    const d = confirmed(del());
    const plan = engine([c, d]).plan(op(), { operationId: 'x' });
    expect(plan).toBeTruthy();
    expect(plan!.def_digest).toBe(defDigest(c));
    expect(plan!.compensation).toEqual({ verb: 'acme.draft.delete', params: { box: 'inbox' }, def_digest: defDigest(d), target_param: 'draft' });
    expect(plan!.render).toBeDefined();
    expect(plan!.render_digest).toBe(approvalRenderDigest(plan!.render!));
  });
  const none: [string, () => ActionDef[], ReturnType<typeof op>?][] = [
    ['an unconfirmed original (claims are not confirmation)', () => [create(), confirmed(del())]],
    ['an unconfirmed compensator', () => [confirmed(create()), del()]],
    ['no compensator in the defs', () => [confirmed(create())]],
    ['no compensates at all', () => [confirmed(create({ compensates: undefined })), confirmed(del())]],
    ['declared rate_limited', () => [confirmed(create({ reversibility: 'rate_limited' })), confirmed(del())]],
    ['declared irreversible', () => [confirmed(create({ reversibility: 'irreversible' })), confirmed(del())]],
    ['a read-only original', () => [confirmed(action('acme.draft.create', { title: 'Read drafts', effects: ['read'], resource: R, params: { box: p.text(40) }, reversibility: 'reversible', compensates: 'acme.draft.delete' })), confirmed(del())]],
    ['a value-dependent class with an irreversible value (the worst case counts)', () => [confirmed(create({ params: { box: p.text(40), body: p.message(500), mode: p.enum(['draft', 'final']) }, reversibility: { by: 'mode', map: { draft: 'reversible', final: 'irreversible' } } })), confirmed(del())], op({ box: 'inbox', body: 'x', mode: 'draft', idempotency_key: 'k' })],
    ['a compensator it cannot derive', () => [confirmed(create()), confirmed(del({ params: { box: p.text(40), draft: p.id('acme.draft'), reason: p.text(50) } }))]],
    ['a call missing a param the compensator copies', () => [confirmed(create({ params: { box: { ...p.text(40), required: false }, body: p.message(500) } })), confirmed(del())], op({ body: 'x', idempotency_key: 'k' })],
    ['an alias (only the exact verb confers reversibility)', () => [confirmed(create({ aliases: ['make_draft'] })), confirmed(del())], op(undefined, 'make_draft')],
    ['an unknown verb', () => [confirmed(create()), confirmed(del())], op(undefined, 'acme.draft.publish')],
  ];
  for (const [name, defs, o] of none) {
    it(`no plan: ${name}`, () => {
      expect(engine(defs()).plan(o ?? op(), { operationId: 'x' })).toBeNull();
    });
  }
  it('no pins: nothing is confirmed, nothing is undoable; pins of another reviewer: same', () => {
    const defs = [confirmed(create()), confirmed(del())];
    expect(undoEngine({ defs, pins: undefined }).plan(op(), { operationId: 'x' })).toBeNull();
    expect(undoEngine({ defs, pins: { keys: [{ kid: 'other', pk: 'A'.repeat(43), roles: ['reviewer'] }] } }).plan(op(), { operationId: 'x' })).toBeNull();
  });
  it('a signed def that was edited after review is not confirmed', () => {
    const c = confirmed(create());
    const edited = { ...c, title: 'Create a draft quietly' };
    expect(engine([edited, confirmed(del())]).plan(op(), { operationId: 'x' })).toBeNull();
  });
  it('never throws, whatever it is handed', () => {
    const e = engine([confirmed(create()), confirmed(del())]);
    for (const bad of [null, undefined, {}, { verb: 1 }, { verb: 'acme.draft.create', params: null }, { verb: 'acme.draft.create', params: 'x' }]) {
      expect(() => e.plan(bad as never, { operationId: 'x' })).not.toThrow();
    }
  });
  it('the built-in gmail.draft, once confirmed, is undone by gmail.delete with the created message as the target', () => {
    const draft = BUILTIN_DEFS.find((d) => d.verb === 'gmail.draft')!;
    const gdel = BUILTIN_DEFS.find((d) => d.verb === 'gmail.delete')!;
    const plan = engine([confirmed(draft), confirmed(gdel)]).plan({ verb: 'gmail.draft', resource: 'gmail.message:m_1', params: { to: 'a@example.com', subject: 's', body: 'b' } }, { operationId: 'x' });
    expect(plan?.compensation).toMatchObject({ verb: 'gmail.delete', params: {}, target_param: 'message' });
    // a parameter the definition does not declare cannot be shown completely, so it gets no window either
    expect(engine([confirmed(draft), confirmed(gdel)]).plan({ verb: 'gmail.draft', resource: 'gmail.message:m_1', params: { to: 'a@example.com', subject: 's', body: 'b', idempotency_key: 'k' } }, { operationId: 'x' })).toBeNull();
    // not confirmed by a pinned reviewer it is not undoable: an approval is still asked
    expect(engine([draft, gdel]).plan({ verb: 'gmail.draft', resource: 'gmail.message:m_1', params: { to: 'a@example.com', subject: 's', body: 'b' } }, { operationId: 'x' })).toBeNull();
  });
});
