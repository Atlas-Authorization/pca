import { describe, expect, it } from 'vitest';
import { generateKeyPair, encodeKey } from '@atlasauth/pca';
import { signerOf } from './sig';
import { BlueprintRegistry, MemoryBlueprintStore, checkBlueprints, groupKill, signBlueprint, verifyBlueprint, type BlueprintStore, type NewBlueprint } from './blueprint';

const NOW = 1_800_000_000_000;
const operator = generateKeyPair();
const OP = signerOf(operator.secretKey);
const bpKey = generateKeyPair();
const BP = encodeKey(bpKey.publicKey);
const base: NewBlueprint = { id: 'bot', key: BP, ceiling: [], epoch: 1, status: 'active', issued_at: NOW };
const mk = (over: Record<string, unknown> = {}) => signBlueprint(operator.secretKey, { ...base, ...over } as never);
const MALFORMED = new RangeError('signBlueprint: a malformed blueprint');
const chain = [{ issuer: 'root', holder: BP }, { issuer: BP, holder: 'inst' }];
const regWith = async (bp = mk(), store: BlueprintStore = new MemoryBlueprintStore()) => {
  const reg = new BlueprintRegistry([OP], store);
  expect((await reg.accept(bp)).ok).toBe(true);
  return reg;
};

describe('blueprint record shape', () => {
  it('accepts the edge values', () => {
    expect(() => mk({ max_depth: 1, expires_at: 0, epoch: 0 })).not.toThrow();
    expect(() => mk({ ceiling: Array.from({ length: 32 }, () => ({ type: 'reversibility_max', class: 'reversible' })) })).not.toThrow();
    expect(() => mk({ runtime_pins: [{ model_id: 'm' }, { operator: 'o', spiffe_id: 's' }] })).not.toThrow();
  });
  it.each([
    ['wrong version', { v: 2 }],
    ['empty id', { id: '' }],
    ['overlong id', { id: 'x'.repeat(129) }],
    ['empty key', { key: '' }],
    ['negative epoch', { epoch: -1 }],
    ['fractional issued_at', { issued_at: 1.5 }],
    ['unknown status', { status: 'paused' }],
    ['zero max_depth', { max_depth: 0 }],
    ['fractional expires_at', { expires_at: 1.5 }],
    ['negative expires_at', { expires_at: -1 }],
    ['empty pin list', { runtime_pins: [] }],
    ['seventeen pins', { runtime_pins: Array.from({ length: 17 }, () => ({ model_id: 'm' })) }],
    ['an empty pin', { runtime_pins: [{ model_id: 'm' }, {}] }],
    ['a pin with an unknown member', { runtime_pins: [{ model_id: 'm', bogus: 'x' }] }],
    ['a pin with an empty value', { runtime_pins: [{ model_id: '' }] }],
    ['ceiling not an array', { ceiling: undefined }],
    ['thirty-three ceiling entries', { ceiling: Array.from({ length: 33 }, () => ({ type: 'reversibility_max' })) }],
    ['a non-object ceiling entry', { ceiling: [5] }],
    ['a null ceiling entry', { ceiling: [null] }],
    ['a ceiling entry with a non-string type', { ceiling: [{ type: 5 }] }],
  ])('signing refuses %s', (_n, over) => {
    expect(() => mk(over)).toThrow(MALFORMED);
  });
  it('verify never accepts a non-record', () => {
    for (const x of [null, undefined, 5, {}, mk() && { ...mk(), id: '' }]) expect(verifyBlueprint(x)).toBe(false);
    expect(verifyBlueprint(mk())).toBe(true);
  });
});

describe('MemoryBlueprintStore', () => {
  it('returns copies, not the stored object', async () => {
    const s = new MemoryBlueprintStore();
    await s.put(mk());
    const got = await s.get(BP);
    got!.id = 'changed';
    expect((await s.get(BP))!.id).toBe('bot');
    expect(await s.get('missing')).toBeUndefined();
  });
});

describe('BlueprintRegistry construction', () => {
  const msg = 'BlueprintRegistry: a durable BlueprintStore is required (MemoryBlueprintStore is for tests and single-process use)';
  it('needs get, put and maxEpoch', () => {
    const ok = new MemoryBlueprintStore();
    const bind = (k: 'get' | 'put' | 'maxEpoch') => ({ get: ok.get.bind(ok), put: ok.put.bind(ok), maxEpoch: ok.maxEpoch.bind(ok), [k]: undefined });
    for (const k of ['get', 'put', 'maxEpoch'] as const) expect(() => new BlueprintRegistry([OP], bind(k) as never), k).toThrow(new TypeError(msg));
    expect(() => new BlueprintRegistry([OP], undefined as never)).toThrow(new TypeError(msg));
    expect(() => new BlueprintRegistry([OP], ok)).not.toThrow();
  });
});

describe('checkBlueprints input and store handling', () => {
  const reg = () => regWith();
  it('a chain with one malformed hop is bad input', async () => {
    const r = await reg();
    const o = { now: NOW, mode: 'any' as const };
    const bad = { decision: 'deny', code: 'bad_input' };
    expect(await checkBlueprints([chain[0]!, { issuer: 'a' } as never], r, o)).toEqual(bad);
    expect(await checkBlueprints([chain[0]!, { holder: 'a' } as never], r, o)).toEqual(bad);
    expect(await checkBlueprints([chain[0]!, { issuer: '', holder: 'a' }], r, o)).toEqual(bad);
    expect(await checkBlueprints([chain[0]!, null as never], r, o)).toEqual(bad);
    expect(await checkBlueprints(chain, r, undefined as never)).toEqual(bad);
  });
  it('the registry epoch is not consulted without minEpoch', async () => {
    const store = new MemoryBlueprintStore();
    store.maxEpoch = async () => {
      throw new Error('offline');
    };
    const r = await regWith(mk(), store);
    expect(await checkBlueprints(chain, r, { now: NOW, mode: 'any' })).toEqual({ decision: 'allow', governed: ['bot'] });
    expect(await checkBlueprints(chain, r, { now: NOW, mode: 'any', minEpoch: 1 })).toEqual({ decision: 'deny', code: 'store_unreachable' });
  });
  it('the ceiling sees the action as given', async () => {
    // an action-dependent ceiling (the reversibility class comes from caveatContext, not from the action)
    const r = await regWith(mk({ ceiling: [{ type: 'predicates', allow: [{ verb: 'v', resource: 'r' }] }] }));
    const action = { verb: 'v', resource: 'r' };
    expect(await checkBlueprints(chain, r, { now: NOW, mode: 'require', action })).toEqual({ decision: 'allow', governed: ['bot'] });
    const other = await checkBlueprints(chain, r, { now: NOW, mode: 'require', action: { verb: 'w', resource: 'r' } });
    expect(other).toMatchObject({ decision: 'deny', code: 'ceiling_violated', blueprint: 'bot' });
  });
  it('a violated ceiling with no failure list reports an empty one', async () => {
    const r = await regWith(mk({ ceiling: [{ type: 'reversibility_max', class: 'reversible' }] }));
    const d = await checkBlueprints(chain, r, { now: NOW, mode: 'require', evaluateCeiling: () => ({ ok: false }) });
    expect(d).toEqual({ decision: 'deny', code: 'ceiling_violated', blueprint: 'bot', failed: [] });
  });
});

describe('groupKill', () => {
  it('returns the registry refusal and changes nothing', async () => {
    const r = await regWith();
    const other = generateKeyPair();
    const res = await groupKill(other.secretKey, r, BP, { now: NOW + 1 });
    expect(res).toEqual({ ok: false, code: 'unknown_operator' });
    expect((await r.get(BP))!.status).toBe('active');
  });
  it('without a fresh-at advancer the result carries no freshAt member', async () => {
    const r = await regWith();
    const res = await groupKill(operator.secretKey, r, BP, { now: NOW + 1 });
    expect(res.ok).toBe(true);
    expect(Object.keys(res).sort()).toEqual(['ok', 'record']);
  });
});
