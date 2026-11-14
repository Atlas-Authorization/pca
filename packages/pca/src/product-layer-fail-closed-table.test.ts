import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { type ActionSpec, assertCatalogPinned, buildCatalog, catalogDigest, defineAction, extendCatalog, resolveAction } from './catalog';
import { EMPTY_FREEZE, freezeAgent, isFrozen, unfreezeAgent } from './console';
import { type DlpPolicy, defaultDlpPolicy, evaluateDlp } from './dlp';
import { recommendPolicy } from './budget-forecast';
import { FileMeshWitnessStore } from './durable-mesh-witness';

const spec = (over: Partial<ActionSpec> = {}): ActionSpec => ({ connector: 'acme', action: 'send', verb: 'acme.send', reversibility: 'reversible', blastRadius: 0.5, description: 'd', ...over });

describe('evaluateDlp: missing or malformed X gives exact result', () => {
  const pii = defaultDlpPolicy({ piiResource: 'customer:*' });
  it.each<[string, unknown, { verb: string; resource: string; taint: number }, unknown]>([
    ['policy null', null, { verb: 'x', resource: 'customer:1', taint: 0 }, { outcome: 'deny', reason: 'malformed DLP policy' }],
    ['classes not an array', { classes: {} }, { verb: 'x', resource: 'customer:1', taint: 0 }, { outcome: 'deny', reason: 'malformed DLP policy' }],
    [
      'class ceiling is a string',
      { classes: [{ name: 'c', resource: '*', maxTaintForAuto: '1' }] },
      { verb: 'x', resource: 'r', taint: 0 },
      { outcome: 'deny', class: 'c', reason: 'malformed DLP policy: ceilings must be numbers' },
    ],
    [
      'default ceiling is NaN',
      { classes: [], defaultMaxTaintForAuto: Number.NaN },
      { verb: 'x', resource: 'r', taint: 0 },
      { outcome: 'deny', reason: 'malformed DLP policy: ceilings must be numbers' },
    ],
    ['NaN taint against a hard ceiling is a hard deny', pii, { verb: 'x', resource: 'customer:1', taint: Number.NaN }, { outcome: 'deny', class: 'pii', reason: "taint Infinity exceeds hard ceiling 2 for 'pii'" }],
    ['no ceiling at all allows even an unknown taint', { classes: [] }, { verb: 'x', resource: 'r', taint: Number.NaN }, { outcome: 'allow' }],
  ])('%s', (_n, policy, ctx, want) => {
    expect(evaluateDlp(policy as DlpPolicy, ctx)).toEqual(want);
  });
  it('a taint smuggled in as a string is treated as maximally tainted (never beats the ceiling)', () => {
    expect(evaluateDlp({ classes: [], defaultMaxTaintForAuto: 5 }, { verb: 'x', resource: 'r', taint: '0' as unknown as number }).outcome).toBe('step_up');
  });
});

describe('FileMeshWitnessStore: a damaged file is never an empty start', () => {
  const dir = mkdtempSync(join(tmpdir(), 'pca-mesh-witness-'));
  const f = (n: string): string => join(dir, n);
  it('a missing file is a first run', () => expect(new FileMeshWitnessStore(f('absent.json')).load()).toBeUndefined());
  it.each<[string, string, string]>([
    ['not JSON', 'not json', 'the state file is not valid JSON; refusing to start empty'],
    ['JSON null', 'null', 'the state file has an unexpected shape; refusing to start empty'],
    ['wrong version', '{"v":2,"state":{},"digest":"x"}', 'the state file has an unexpected shape; refusing to start empty'],
    ['no digest', '{"v":1,"state":{}}', 'the state file has an unexpected shape; refusing to start empty'],
    ['state not an object', '{"v":1,"state":5,"digest":"x"}', 'the state file has an unexpected shape; refusing to start empty'],
    ['digest does not match', '{"v":1,"state":{"a":1},"digest":"x"}', 'the state file fails its digest; refusing to start empty'],
  ])('%s', (name, body, msg) => {
    const p = f(`${name.replace(/\W/g, '_')}.json`);
    writeFileSync(p, body);
    expect(() => new FileMeshWitnessStore(p).load()).toThrow(`FileMeshWitnessStore: ${msg}`);
  });
  it('a saved state loads back exactly and leaves no temporary file', () => {
    const p = f('ok.json');
    const s = new FileMeshWitnessStore(p);
    s.save({ a: 1 } as never);
    expect(s.load()).toEqual({ a: 1 });
    expect(existsSync(`${p}.tmp`)).toBe(false);
    expect(JSON.parse(readFileSync(p, 'utf8')).v).toBe(1);
    rmSync(dir, { recursive: true, force: true });
  });
});

describe('catalog: unknown, malformed and downgrading input', () => {
  it.each<[string, Partial<ActionSpec>, string]>([
    ['no connector', { connector: '' }, 'defineAction: connector and action are required'],
    ['connector with a dot', { connector: 'a.b' }, 'defineAction: connector must not contain whitespace or a dot'],
    ['connector with a space', { connector: 'a b' }, 'defineAction: connector must not contain whitespace or a dot'],
    ['empty amountField', { amountField: '' }, 'defineAction: amountField must be a non-empty string'],
    ['unknown reversibility', { reversibility: 'sometimes' as never }, "defineAction: bad reversibility 'sometimes'"],
    ['blast radius above 1', { blastRadius: 2 }, 'defineAction: blastRadius must be in [0,1]'],
    ['blast radius NaN', { blastRadius: Number.NaN }, 'defineAction: blastRadius must be in [0,1]'],
  ])('defineAction refuses %s', (_n, over, msg) => {
    const { verb: _v, ...rest } = spec(over);
    expect(() => defineAction(rest)).toThrow(msg);
  });
  it('an unknown verb resolves to the most dangerous spec and says it is not catalogued', () => {
    expect(resolveAction(buildCatalog([]), 'zz.do.it')).toEqual({
      spec: { connector: 'zz', action: 'do.it', verb: 'zz.do.it', reversibility: 'irreversible', blastRadius: 1, description: '(uncatalogued) zz.do.it' },
      catalogued: false,
    });
  });
  it('an ambiguous alias resolves to nothing', () => {
    const c = buildCatalog([spec({ verb: 'acme.a', action: 'a', aliases: ['go'] }), spec({ verb: 'acme.b', action: 'b', aliases: ['go'] })]);
    expect(c.resolve!('acme', 'go')).toBeUndefined();
  });
  it('a pin mismatch throws; the matching digest passes', () => {
    const c = buildCatalog([spec()]);
    expect(() => assertCatalogPinned(c, 'deadbeef')).toThrow('catalog does not match the pinned digest');
    expect(() => assertCatalogPinned(c, catalogDigest(c))).not.toThrow();
  });
  it('extending cannot relabel an existing verb as less cautious', () => {
    const base = buildCatalog([spec({ reversibility: 'irreversible', blastRadius: 0.9 })]);
    expect(() => extendCatalog(base, [spec({ reversibility: 'reversible', blastRadius: 0.9 })])).toThrow("extendCatalog: 'acme.send' would be less cautious than the existing entry");
    expect(() => extendCatalog(base, [spec({ reversibility: 'irreversible', blastRadius: 0.1 })])).toThrow("extendCatalog: 'acme.send' would be less cautious than the existing entry");
  });
});

describe('console freeze: no identifiable agent or a malformed set is frozen', () => {
  it.each<[string, unknown, unknown, boolean]>([
    ['empty agent', EMPTY_FREEZE, '', true],
    ['non-string agent', EMPTY_FREEZE, 7, true],
    ['null set', null, 'a', true],
    ['frozen not an array', { frozen: 'a' }, 'a', true],
    ['unfrozen agent in a good set', EMPTY_FREEZE, 'a', false],
  ])('%s', (_n, set, agent, want) => {
    expect(isFrozen(set as never, agent as never)).toBe(want);
  });
  it('freezing needs a non-empty agent, is idempotent and sorted; unfreezing removes only that agent', () => {
    expect(() => freezeAgent(EMPTY_FREEZE, '')).toThrow('freezeAgent: agent must be a non-empty string');
    const s = freezeAgent(freezeAgent(EMPTY_FREEZE, 'b'), 'a');
    expect(s).toEqual({ frozen: ['a', 'b'] });
    expect(freezeAgent(s, 'a')).toBe(s);
    expect(unfreezeAgent(s, 'a')).toEqual({ frozen: ['b'] });
  });
});

describe('recommendPolicy: bad numbers throw, out-of-range numbers are clamped', () => {
  it.each<[string, () => unknown, string]>([
    ['kappa 0', () => recommendPolicy(10, 0.5, { kappa: 0 }), 'recommendPolicy: kappa must be a positive finite number'],
    ['kappa Infinity', () => recommendPolicy(10, 0.5, { kappa: Infinity }), 'recommendPolicy: kappa must be a positive finite number'],
    ['NaN target', () => recommendPolicy(Number.NaN, 0.5), 'recommendPolicy: targetActions and perActionRisk must be finite numbers'],
    ['Infinite risk', () => recommendPolicy(3, Infinity), 'recommendPolicy: targetActions and perActionRisk must be finite numbers'],
  ])('%s', (_n, fn, msg) => expect(fn).toThrow(msg));
  it('risk above 1 clamps to 1 and a negative target clamps to 0', () => {
    expect(recommendPolicy(4, 2)).toMatchObject({ kappa: 1, bMax: 4, autonomousBound: 4 });
    expect(recommendPolicy(-3, 0.5)).toMatchObject({ bMax: 0, autonomousBound: 0 });
  });
});
