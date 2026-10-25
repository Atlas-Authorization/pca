/* eslint-disable @typescript-eslint/no-explicit-any */
// Mutation-kill tests for src/ext-policyvm.ts (the glue around the proved Policy-VM core): value-model conversion and its
// unsupported-input errors, exact rationals, the regex / tool_schema oracles (laziness, failure = fail closed), long strings.
import { describe, expect, it } from 'vitest';
import { PolicyVmUnsupported, createPolicyVm, ratToDouble, requiredThresholdVerified, toRat, toValue } from '../src/ext-policyvm';

const ctx = { action: { verb: 'read', resource: '/a/1', params: { s: 'abc', n: 2 } } };
const leaf = (op: string, value: unknown, field = 'action.params.s') => ({ field, op, value });
const plainVm = () => createPolicyVm({ safeRegex: () => true, regexFullMatch: (src, subj) => new RegExp(`^(?:${src})$`).test(subj) });

describe('PolicyVmUnsupported and the value model', () => {
  it('error message and name', () => {
    const e = new PolicyVmUnsupported('why');
    expect(e.message).toBe('pca-verified-core/policyvm: unsupported input (why)');
    expect(e.name).toBe('PolicyVmUnsupported');
    expect(e).toBeInstanceOf(Error);
  });
  it('functions, bigints and symbols are opaque function values (not objects)', () => {
    for (const x of [() => 1, function named() {}, 10n, Symbol('s')]) expect(toValue(x).is_VFn).toBe(true);
    expect(toValue(undefined).is_VUndef).toBe(true);
    expect(toValue(null).is_VNull).toBe(true);
    expect(toValue(Number.NaN).is_VNonFinite).toBe(true);
    // inside a context: a function-valued field is present but not a string / object
    expect(plainVm().evaluateConditionTri(leaf('exists', true, 'action.params.f'), { action: { params: { f: () => 1 } } })).toBe('true');
  });
  it('cyclic values, sparse arrays, non-enumerable and accessor properties are refused with their reason', () => {
    const msg = (x: unknown) => { try { toValue(x); return 'ok'; } catch (e) { return `${(e as Error).name}: ${(e as Error).message}`; } };
    const cyc: any = { a: 1 };
    cyc.self = cyc;
    expect(msg(cyc)).toBe('PolicyVmUnsupported: pca-verified-core/policyvm: unsupported input (cyclic value)');
    const cycArr: any[] = [];
    cycArr.push({ back: cycArr });
    expect(msg(cycArr)).toBe('PolicyVmUnsupported: pca-verified-core/policyvm: unsupported input (cyclic value)');
    // eslint-disable-next-line no-sparse-arrays
    expect(msg([1, , 3])).toBe('PolicyVmUnsupported: pca-verified-core/policyvm: unsupported input (sparse array)');
    const ne = {};
    Object.defineProperty(ne, 'hidden', { value: 1, enumerable: false });
    expect(msg(ne)).toBe('PolicyVmUnsupported: pca-verified-core/policyvm: unsupported input (non-enumerable own property)');
    expect(msg({ get g() { return 1; } })).toBe('PolicyVmUnsupported: pca-verified-core/policyvm: unsupported input (accessor property)');
    // a shared (non-cyclic) reference is fine, and the cycle guard leaves no residue
    const shared = { k: 1 };
    expect(msg({ x: shared, y: shared, z: [shared, shared] })).toBe('ok');
    expect(msg([shared, [shared]])).toBe('ok');
  });
});

describe('exact rationals', () => {
  const nd = (x: number) => { const q = toRat(x); return `${q.num.toFixed()}/${q.den.toFixed()}`; };
  it('lowest terms with a power-of-two denominator; integers over 1; zero is +0', () => {
    expect(nd(1.5)).toBe('3/2');
    expect(nd(-0.75)).toBe('-3/4');
    expect(nd(0.1)).toBe('3602879701896397/36028797018963968');
    expect(nd(5e-324)).toBe(`1/${(2n ** 1074n).toString()}`);
    expect(nd(6)).toBe('6/1');
    expect(nd(-7)).toBe('-7/1');
    expect(nd(2 ** 60)).toBe(`${(2n ** 60n).toString()}/1`);
    expect(nd(0)).toBe('0/1');
    expect(toRat(-0).num.isNegative()).toBe(false);
    expect(toRat(0.5).den.toFixed()).toBe('2');
    for (const x of [1.5, -0.75, 0.1, 5e-324, 6, 2 ** 60, 1.7976931348623157e308, -123.456]) expect(ratToDouble(toRat(x))).toBe(x);
  });
});

describe('oracles', () => {
  it('matches: the regex oracle decides; null / undefined is unknown, true / false decide; non-boolean truthy is false', () => {
    const mk = (r: unknown) => createPolicyVm({ safeRegex: () => true, regexFullMatch: () => r as any });
    expect(mk(true).evaluateConditionTri(leaf('matches', 'a.c'), ctx)).toBe('true');
    expect(mk(false).evaluateConditionTri(leaf('matches', 'a.c'), ctx)).toBe('false');
    expect(mk(null).evaluateConditionTri(leaf('matches', 'a.c'), ctx)).toBe('unknown');
    expect(mk(undefined).evaluateConditionTri(leaf('matches', 'a.c'), ctx)).toBe('unknown');
    expect(mk('yes').evaluateConditionTri(leaf('matches', 'a.c'), ctx)).toBe('false');
  });
  it('a throwing oracle fails closed (unsafe source / unknown match)', () => {
    const throwsSafe = createPolicyVm({ safeRegex: () => { throw new Error('x'); }, regexFullMatch: () => true });
    expect(throwsSafe.evaluateConditionTri(leaf('matches', 'a.c'), ctx)).toBe('unknown');
    expect(throwsSafe.predicateMatches({ verb: 'read', resource: 're:/a/.*' }, ctx)).toBe(false);
    const throwsFull = createPolicyVm({ safeRegex: () => true, regexFullMatch: () => { throw new Error('x'); } });
    expect(throwsFull.evaluateConditionTri(leaf('matches', 'a.c'), ctx)).toBe('unknown');
    expect(throwsFull.predicateMatches({ verb: 'read', resource: 're:/a/.*' }, ctx)).toBe(false);
    expect(plainVm().predicateMatches({ verb: 'read', resource: 're:/a/.*' }, ctx)).toBe(true);
  });
  it('the oracles receive the exact JS strings', () => {
    const seen: string[] = [];
    const vm = createPolicyVm({ safeRegex: (s) => { seen.push(`safe:${s}`); return true; }, regexFullMatch: (s, t) => { seen.push(`full:${s}|${t}`); return true; } });
    vm.evaluateConditionTri(leaf('matches', 'é\u{1F600}.'), { action: { params: { s: 'x\u{1F600}y' } } });
    expect(seen).toEqual(['safe:é\u{1F600}.', 'full:é\u{1F600}.|x\u{1F600}y']);
  });
  it('tool_schema: no oracle => false; the oracle gets the ORIGINAL caveat and context objects; only `true` passes; a throw is false', () => {
    const cv = { type: 'tool_schema', schema: { k: 1 } };
    const c = { action: { verb: 'call' } };
    expect(plainVm().agentNativeCaveatEvaluator(cv, c)).toBe(false);
    let got: unknown[] = [];
    const vm = (r: () => unknown) => createPolicyVm({ safeRegex: () => true, regexFullMatch: () => true, toolSchema: (a, b) => { got = [a, b]; return r() as boolean; } });
    expect(vm(() => true).agentNativeCaveatEvaluator(cv, c)).toBe(true);
    expect(got[0]).toBe(cv);
    expect(got[1]).toBe(c);
    expect(vm(() => false).agentNativeCaveatEvaluator(cv, c)).toBe(false);
    expect(vm(() => 'true').agentNativeCaveatEvaluator(cv, c)).toBe(false);
    expect(vm(() => 1).agentNativeCaveatEvaluator(cv, c)).toBe(false);
    expect(vm(() => { throw new Error('boom'); }).agentNativeCaveatEvaluator(cv, c)).toBe(false);
    expect(vm(() => true).evaluateCaveats([cv], c, 'agent')).toEqual({ ok: true, failed: [] });
    expect(vm(() => false).evaluateCaveats([cv], c, 'agent')).toEqual({ ok: false, failed: ['tool_schema'] });
    // the envelope evaluator (the default) never consults the tool oracle
    expect(vm(() => true).evaluateCaveats([cv], c).ok).toBe(vm(() => true).envelopeCaveatEvaluator(cv, c));
  });
});

describe('long strings and thresholds', () => {
  it('failed caveat names longer than the 4096-unit chunk come back intact', () => {
    for (const n of [4095, 4096, 4097, 9000]) {
      const name = 'q'.repeat(n - 1) + 'Z';
      const r = plainVm().evaluateCaveats([{ type: name }], ctx);
      expect(r.ok).toBe(false);
      expect(r.failed).toEqual([name]);
    }
  });
  it('requiredThresholdVerified refuses a non-finite theta (either one)', () => {
    for (const [a, b] of [[Number.NaN, 0.5], [0.3, Number.NaN], [Number.POSITIVE_INFINITY, 0.5], [0.3, Number.NEGATIVE_INFINITY]]) {
      expect(() => requiredThresholdVerified(0.5, a!, b!, false)).toThrow(new PolicyVmUnsupported('non-finite theta'));
    }
    expect(() => requiredThresholdVerified(0.5, 0.3, 0.6, false)).not.toThrow();
  });
});

describe('envelope caveats and plain conditions decide true as well as false', () => {
  it('a satisfied expires caveat passes through every entry point', () => {
    const vm = plainVm();
    const cv = { type: 'expires', at: 2000 };
    expect(vm.envelopeCaveatEvaluator(cv, { now: 1000 })).toBe(true);
    expect(vm.envelopeCaveatEvaluator(cv, { now: 2000 })).toBe(false);
    expect(vm.evaluateCaveats([cv], { now: 1000 })).toEqual({ ok: true, failed: [] });
    expect(vm.evaluateCaveats([cv], { now: 3000 })).toEqual({ ok: false, failed: ['expires'] });
    expect(vm.evaluateCaveats([cv], { now: 1000 }, 'agent')).toEqual({ ok: true, failed: [] });
    expect(vm.agentNativeCaveatEvaluator(cv, { now: 1000 })).toBe(true);
  });
  it('evaluateCondition is exactly tri === true', () => {
    const vm = plainVm();
    expect(vm.evaluateCondition(leaf('eq', 'abc'), ctx)).toBe(true);
    expect(vm.evaluateCondition(leaf('eq', 'x'), ctx)).toBe(false);
    expect(vm.evaluateCondition(leaf('lt', 'x', 'action.params.missing'), ctx)).toBe(false);
  });
});

describe('rootCaveats', () => {
  it('a non-array is returned untouched (same value, no conversion attempted)', () => {
    const vm = plainVm();
    const o = { not: 'an array' };
    expect(vm.rootCaveats(o as never)).toBe(o);
    for (const x of [undefined, null, 5, 'x']) expect(vm.rootCaveats(x as never)).toBe(x);
  });
  it('an array yields a subsequence of the ORIGINAL caveat objects (identity preserved, order kept); the empty array stays empty', () => {
    const vm = plainVm();
    const cav = [{ type: 'expires', at: 1 }, { type: 'budget', limit: 5 }, { type: 'expires', at: 2 }, { type: 'x' }];
    const out = vm.rootCaveats(cav as never) as unknown[];
    expect(Array.isArray(out)).toBe(true);
    let at = -1;
    for (const c of out) {
      const idx = cav.indexOf(c as never);
      expect(idx).toBeGreaterThan(at);
      at = idx;
    }
    expect(vm.rootCaveats([] as never)).toEqual([]);
  });
});
