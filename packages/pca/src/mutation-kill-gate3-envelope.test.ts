/**
 * Mutation kills for the 0.5.0 flagship gate survivors in envelope.ts (mintGrant's units / tighten / actions /
 * model_polarity checks and the optional members it copies into the signed envelope) and envelope-rules.ts (the name and
 * parameter-path patterns at their anchors and length bounds, the 64-entry units bound, template_ref field checks).
 */
import { describe, expect, it } from 'vitest';
import { mintGrant, readEnvelope, type Envelope } from './envelope';
import { PARAM_PATH_RE, templateRefError, tightenListError, unitTagsError } from './envelope-rules';
import { encodeKey, generateKeyPair } from './keys';
import { DEFAULT_RISK_POLICY } from './risk';

const P = generateKeyPair();
const A = generateKeyPair();
const env = (over: Record<string, unknown> = {}): Omit<Envelope, 'goal_commit'> =>
  ({ predicates: [], caveats: [], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY, ...over }) as never;
const mint = (e: Omit<Envelope, 'goal_commit'>) =>
  mintGrant({ principalSecret: P.secretKey, principalPublic: encodeKey(P.publicKey), holder: encodeKey(A.publicKey), envelope: e, goal: 'g', salt: 's' });
const PIN = { pack: { ns: 'shop', root: 'A'.repeat(43) }, on_new_action: 'deny' };
const DIG = 'd'.repeat(43);

describe('mintGrant: member checks', () => {
  it('malformed units are refused with the validator message', () => {
    expect(() => mint(env({ units: 5 }))).toThrow(new Error('mintGrant: units must be an object'));
    expect(() => mint(env({ units: { x: { kind: 'usd' } } }))).toThrow(new Error("mintGrant: units key 'x' must be an action.params.<name> path"));
  });
  it('malformed tighten is refused with the validator message', () => {
    expect(() => mint(env({ tighten: {} }))).toThrow(new Error('mintGrant: tighten must be an array'));
  });
  it('a malformed actions pin is refused with the validator message', () => {
    expect(() => mint(env({ actions: {} }))).toThrow(new Error('mintGrant: actions.pack must be {ns, root}'));
    expect(() => mint(env({ actions: 5 }))).toThrow(new Error('mintGrant: actions must be an object'));
  });
  it("model_polarity other than 'legacy' is refused; 'legacy' is accepted", () => {
    const m = new Error("mintGrant: model_polarity must be 'legacy' when present");
    for (const p of ['strict', '', 'LEGACY', 5]) expect(() => mint(env({ model_polarity: p }))).toThrow(m);
    expect(() => mint(env({ model_polarity: 'legacy' }))).not.toThrow();
  });
});

describe('mintGrant: optional members reach the signed envelope', () => {
  it('model_polarity is copied exactly when given', () => {
    expect(readEnvelope(mint(env({ model_polarity: 'legacy' })).grant)!.model_polarity).toBe('legacy');
    expect('model_polarity' in readEnvelope(mint(env()).grant)!).toBe(false);
  });
  it('actions is copied exactly when given', () => {
    expect(readEnvelope(mint(env({ actions: PIN })).grant)!.actions).toEqual(PIN);
    expect('actions' in readEnvelope(mint(env()).grant)!).toBe(false);
  });
  it('valid units, tighten and template_ref are copied too', () => {
    const units = { 'action.params.amount': { kind: 'money', currency: 'USD', exponent: 2 } };
    const tighten = [{ id: 'big', when: { field: 'action.params.amount', op: 'gt', value: 5 }, signal: 'deny' }];
    const template_ref = { template_id: 'tpl', version_digest: DIG, slots: {} };
    const e = readEnvelope(mint(env({ units, tighten, template_ref })).grant)!;
    expect(e.units).toEqual(units);
    expect(e.tighten).toEqual(tighten);
    expect(e.template_ref).toEqual(template_ref);
  });
});

describe('envelope-rules: the name pattern ^[a-z][a-z0-9_]{0,63}$', () => {
  const idOk = (id: unknown) => tightenListError([{ id, when: {}, signal: 'deny' }]) === null;
  const tplOk = (template_id: unknown) => templateRefError({ template_id, version_digest: DIG, slots: {} }) === null;
  it('accepts one letter, letters + digits + underscore, and exactly 64 characters', () => {
    for (const ok of [idOk, tplOk]) {
      expect(ok('a')).toBe(true);
      expect(ok('ab')).toBe(true);
      expect(ok('abc_9')).toBe(true);
      expect(ok('a'.repeat(64))).toBe(true);
    }
  });
  it('refuses 65 characters, a non-letter first character, junk before or after, and a non-string', () => {
    for (const ok of [idOk, tplOk]) {
      expect(ok('a'.repeat(65))).toBe(false);
      expect(ok('9ab')).toBe(false);
      expect(ok('_ab')).toBe(false);
      expect(ok('Xab')).toBe(false);
      expect(ok('-ab')).toBe(false);
      expect(ok('ab-')).toBe(false);
      expect(ok('ab\n')).toBe(false);
      expect(ok('ab X')).toBe(false);
      expect(ok('')).toBe(false);
      // String(['abc']) is 'abc': only the type check refuses an array
      expect(ok(['abc'])).toBe(false);
    }
  });
  it('the tighten id error names the pattern', () => {
    expect(tightenListError([{ id: ['abc'], when: {}, signal: 'deny' }])).toBe('tighten[0].id must match ^[a-z][a-z0-9_]{0,63}$');
    expect(templateRefError({ template_id: 'Xab', version_digest: DIG, slots: {} })).toBe('template_ref.template_id invalid');
  });
});

describe('envelope-rules: the parameter-path pattern and the units bound', () => {
  const tag = { kind: 'k' };
  it('anchored at both ends, 1..64 name characters', () => {
    expect(PARAM_PATH_RE.test('action.params.a')).toBe(true);
    expect(PARAM_PATH_RE.test(`action.params.${'a'.repeat(64)}`)).toBe(true);
    expect(PARAM_PATH_RE.test(`action.params.${'a'.repeat(65)}`)).toBe(false);
    expect(PARAM_PATH_RE.test('xaction.params.a')).toBe(false);
    expect(PARAM_PATH_RE.test('a.action.params.a')).toBe(false);
    expect(PARAM_PATH_RE.test('action.params.a!')).toBe(false);
    expect(PARAM_PATH_RE.test('action.params.a.b')).toBe(false);
    expect(unitTagsError({ 'xaction.params.a': tag })).toBe("units key 'xaction.params.a' must be an action.params.<name> path");
    expect(unitTagsError({ 'action.params.a!': tag })).toBe("units key 'action.params.a!' must be an action.params.<name> path");
  });
  it('exactly 64 entries are accepted, 65 are refused', () => {
    const n = (k: number) => Object.fromEntries(Array.from({ length: k }, (_, i) => [`action.params.p${i}`, tag]));
    expect(unitTagsError(n(64))).toBeNull();
    expect(unitTagsError(n(65))).toBe('units has more than 64 entries');
  });
});

describe('envelope-rules: templateRefError digests', () => {
  const ref = (o: Record<string, unknown>) => templateRefError({ template_id: 'tpl', ...o });
  const VD = 'template_ref.version_digest invalid';
  it('version_digest is a string of 1..128 characters', () => {
    expect(ref({ version_digest: 'x', slots: {} })).toBeNull();
    expect(ref({ version_digest: 'x'.repeat(128), slots: {} })).toBeNull();
    expect(ref({ version_digest: 'x'.repeat(129), slots: {} })).toBe(VD);
    expect(ref({ version_digest: '', slots: {} })).toBe(VD);
    expect(ref({ version_digest: 5, slots: {} })).toBe(VD);
    expect(ref({ version_digest: ['x'], slots: {} })).toBe(VD);
    expect(ref({ slots: {} })).toBe(VD);
  });
  it('bind_params_digest is a string of 1..128 characters', () => {
    const BD = 'template_ref.bind_params_digest invalid';
    expect(ref({ version_digest: 'x', bind_params_digest: 'y' })).toBeNull();
    expect(ref({ version_digest: 'x', bind_params_digest: 'y'.repeat(128) })).toBeNull();
    expect(ref({ version_digest: 'x', bind_params_digest: 'y'.repeat(129) })).toBe(BD);
    expect(ref({ version_digest: 'x', bind_params_digest: '' })).toBe(BD);
    expect(ref({ version_digest: 'x', bind_params_digest: ['y'] })).toBe(BD);
    expect(ref({ version_digest: 'x', bind_params_digest: 5 })).toBe(BD);
  });
});
