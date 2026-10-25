/**
 * r13 g1: zk.ts pure helpers, exact outcomes: the canonical Groth16 envelope gate (every structural branch, both curves),
 * commitmentField, policyVmStructHash, the action/plan/policy quantizers (every refusal message), decodePolicyVmPublic and
 * the public-context pinning (policyVmContextMatches / pins / windows / bounds).
 */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  POLICYVM_PUBLIC_SIGNAL,
  POLICYVM_PUBLIC_SIGNAL_COUNT,
  commitmentField,
  decodePolicyVmPublic,
  isCanonicalGroth16Envelope,
  policyVmCommitmentFromAction,
  policyVmContextMatches,
  policyVmStructHash,
  quantizeActionStruct,
  quantizePlanStruct,
  quantizePolicyStruct,
  quantizePolicyVmInputs,
  type QuantizablePolicy,
} from './zk';
import { b64u } from './hash';

// Outcome capture: a mutant that throws where a value is expected (or returns where a refusal is expected) fails an
// explicit toEqual assertion instead of an uncaught error.
type Outcome = { ok: true; value: unknown } | { ok: false; error: { name: string; message: string } };
const caught = (e: unknown): Outcome => ({
  ok: false,
  error: e instanceof Error ? { name: e.constructor.name, message: e.message } : { name: typeof e, message: String(e) },
});
const settle = (f: () => unknown): Outcome => {
  try {
    return { ok: true, value: f() };
  } catch (e) {
    return caught(e);
  }
};
const settleAsync = async (f: () => unknown): Promise<Outcome> => {
  try {
    return { ok: true, value: await f() };
  } catch (e) {
    return caught(e);
  }
};
const ok = (value: unknown): Outcome => ({ ok: true, value });
const refused = (message: string, name = 'Error'): Outcome => ({ ok: false, error: { name, message } });

type Env = { system: string; circuit: string; proof: Record<string, unknown> & { pi_a: unknown; pi_b: unknown; pi_c: unknown }; publicSignals: unknown[] } & Record<string, unknown>;
// fixtures read by literal path (not via the zk.ts path helpers, which are mutated too)
const bn = JSON.parse(readFileSync(`${__dirname}/../circuits/policyvm_sample_proof.json`, 'utf8')) as Env;
const bls = JSON.parse(readFileSync(`${__dirname}/../circuits/policyvm_bls12381_sample_proof.json`, 'utf8')) as Env;
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x)) as T;
const FR = { bn254: 21888242871839275222246405745257275088548364400416034343698204186575808495617n, bls: 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n };
const FQ_BN = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;

describe('isCanonicalGroth16Envelope: every structural branch', () => {
  for (const [curve, sample, fr] of [['bn254', bn, FR.bn254], ['bls12-381', bls, FR.bls]] as const) {
    const g = (f: (e: Env) => void): Env => {
      const c = clone(sample);
      f(c);
      return c;
    };
    const no = (e: unknown) => expect(settle(() => isCanonicalGroth16Envelope(e, curve))).toEqual(ok(false));

    it(`${curve}: the sample is canonical`, () => {
      expect(settle(() => isCanonicalGroth16Envelope(sample, curve))).toEqual(ok(true));
    });
    it(`${curve}: non-objects, arrays and functions are refused`, () => {
      for (const e of [null, undefined, 0, 'x', [], [sample]]) no(e);
      no(Object.assign(() => undefined, clone(sample)));
    });
    it(`${curve}: envelope keys must be exactly the four`, () => {
      no(g((e) => { e.zzz = 1; }));
      no(g((e) => { e.aaa = 1; }));
      no(g((e) => { delete e.circuit; }));
      no(g((e) => { e.circuitX = e.circuit; delete e.circuit; })); // same count, one name differs
      no({ a: 1, b: 2, c: 3, d: 4 });
    });
    it(`${curve}: public signals must be an array of canonical decimals below r`, () => {
      no(g((e) => { e.publicSignals = 'x'; }));
      no(g((e) => { e.publicSignals[0] = [String(e.publicSignals[0])]; })); // array that stringifies canonically
      no(g((e) => { e.publicSignals[0] = 5; }));
      no(g((e) => { e.publicSignals[0] = fr.toString(); }));
      expect(settle(() => isCanonicalGroth16Envelope(g((e) => { e.publicSignals[0] = (fr - 1n).toString(); }), curve))).toEqual(ok(true));
      expect(settle(() => isCanonicalGroth16Envelope(g((e) => { e.publicSignals = []; }), curve))).toEqual(ok(true));
    });
    it(`${curve}: the proof must be a plain object with exactly the five keys`, () => {
      no(g((e) => { (e as Record<string, unknown>).proof = null; }));
      no(g((e) => { (e as Record<string, unknown>).proof = 'pi'; }));
      no(g((e) => { (e as Record<string, unknown>).proof = [e.proof]; }));
      no(g((e) => { (e as Record<string, unknown>).proof = Object.assign(() => undefined, clone(sample.proof)); }));
      no(g((e) => { e.proof.zzz = 1; }));
      no(g((e) => { e.proof.pi_d = e.proof.pi_c; delete e.proof.pi_c; }));
    });
    it(`${curve}: protocol and curve tags`, () => {
      no(g((e) => { e.proof.protocol = 'plonk'; }));
      no(g((e) => { e.proof.curve = curve === 'bn254' ? 'bls12381' : 'bn128'; }));
      no(g((e) => { e.proof.curve = 'x'; }));
    });
    it(`${curve}: G1 points are 3-arrays of canonical coordinates with z == "1"`, () => {
      for (const k of ['pi_a', 'pi_c'] as const) {
        no(g((e) => { e.proof[k] = Object.assign({}, e.proof[k]); }));
        no(g((e) => { (e.proof[k] as string[]).push('1'); }));
        no(g((e) => { (e.proof[k] as string[])[2] = '0'; }));
        no(g((e) => { (e.proof[k] as string[])[1] = '0' + (e.proof[k] as string[])[1]; }));
      }
    });
    it(`${curve}: the G2 point is [[x0,x1],[y0,y1],["1","0"]]`, () => {
      const b = (f: (pb: unknown[]) => void) => g((e) => f(e.proof.pi_b as unknown[]));
      no(g((e) => { e.proof.pi_b = Object.assign({}, e.proof.pi_b); }));
      no(b((pb) => pb.push(['1', '0'])));
      no(b((pb) => pb.pop()));
      for (const r of [0, 1]) {
        no(b((pb) => { pb[r] = Object.assign({}, pb[r]); }));
        no(b((pb) => { (pb[r] as string[]).push('1'); }));
        no(b((pb) => { (pb[r] as string[])[0] = '0' + (pb[r] as string[])[0]; }));
        no(b((pb) => { (pb[r] as string[])[1] = '0' + (pb[r] as string[])[1]; }));
      }
      no(b((pb) => { pb[2] = Object.assign({}, pb[2]); }));
      no(b((pb) => { pb[2] = ['1', '0', '0']; }));
      no(b((pb) => { pb[2] = ['0', '0']; }));
      no(b((pb) => { pb[2] = ['1', '1']; }));
      no(b((pb) => { pb[2] = '10'; }));
    });
  }

  it('the field bounds are per curve', () => {
    // a BLS coordinate is above the BN254 base field: canonical for BLS only
    const big = (bls.proof.pi_a as string[]).map(BigInt).find((x) => x > FQ_BN);
    expect(big).toBeDefined();
    // a BN254 public signal in [r_bn254, r_bls) is canonical for BLS, not for BN254
    const e = clone(bls);
    e.publicSignals[0] = FR.bn254.toString();
    expect(settle(() => isCanonicalGroth16Envelope(e, 'bls12-381'))).toEqual(ok(true));
    const e2 = clone(bn);
    e2.publicSignals[0] = FR.bn254.toString();
    expect(settle(() => isCanonicalGroth16Envelope(e2, 'bn254'))).toEqual(ok(false));
  });
});

describe('commitmentField', () => {
  it('is the big-endian integer mod the BN254 scalar field, as a decimal string', () => {
    const ff = new Uint8Array(32).fill(0xff);
    expect(settle(() => commitmentField(b64u(ff)))).toEqual(ok(((1n << 256n) - 1n) % FR.bn254 + ''));
    expect(settle(() => commitmentField(b64u(Uint8Array.of(1, 2))))).toEqual(ok('258'));
    expect(settle(() => commitmentField(''))).toEqual(ok('0'));
  });
});

describe('policyVmStructHash', () => {
  const ref = (fields: bigint[]) => {
    const buf = Buffer.alloc(fields.length * 8);
    fields.forEach((f, i) => buf.writeBigUInt64BE(f, i * 8));
    const d = createHash('sha256').update(buf).digest('hex');
    return { hi: BigInt('0x' + d.slice(0, 32)).toString(), lo: BigInt('0x' + d.slice(32)).toString() };
  };
  it('serializes each field as a 64-bit big-endian uint (top byte included)', () => {
    const fields = [(1n << 64n) - 1n, 0x0102030405060708n, 0n, 1n << 63n];
    expect(settle(() => policyVmStructHash(fields))).toEqual(ok(ref(fields)));
    expect(settle(() => policyVmStructHash(['5', 6, 7n]))).toEqual(ok(ref([5n, 6n, 7n])));
  });
  it('refuses a field outside [0, 2^64) with the exact message', () => {
    for (const f of [-1n, 1n << 64n, -1]) expect(() => policyVmStructHash([f])).toThrow(new Error('policyVmStructHash: field out of uint64 range'));
  });
});

describe('quantizers: exact codes and refusals', () => {
  const contentAddress = (domain: string, value: string): bigint =>
    BigInt('0x' + createHash('sha256').update(`atlas-pca/policyvm-quantize/${domain}:${value}`).digest('hex').slice(0, 16));
  const POL: QuantizablePolicy = {
    weights: { alpha: 1, beta: 2, gamma: 3, delta: 4, epsilon: 5, zeta: 6 },
    theta1: 7, theta2: 8, kappa: 9, budgetB: 10,
    policyVerb: 'v', policyResource: 'r', policyParamBound: 11,
    expiresAt: 12, notBefore: 13, maxBlast: 14, maxDepth: 15, revMax: 'rate_limited', rateMax: 16, allocParent: 17,
  };

  it('content-addresses uncatalogued strings per domain (top 8 sha256 bytes)', () => {
    expect(settle(() => quantizeActionStruct({ verb: 'a', resource: 'b' }))).toEqual(ok([contentAddress('verb', 'a'), contentAddress('resource', 'b'), 0n, 0n]));
    expect(settle(() => quantizePlanStruct({ verb: 'a', resource: 'b', semanticDist: 3, planSalt: 4n }))).toEqual(ok([contentAddress('verb', 'a'), contentAddress('resource', 'b'), 3n, 4n]));
  });

  it('uses only OWN catalog entries (an inherited name is content-addressed)', () => {
    expect(settle(() => quantizeActionStruct({ verb: 'toString', resource: 'x' }, { verbCodes: {} })[0])).toEqual(ok(contentAddress('verb', 'toString')));
    expect(settle(() => quantizeActionStruct({ verb: 'v', resource: 'x' }, { verbCodes: { v: 9n }, resourceCodes: { x: 8 } }))).toEqual(ok([9n, 8n, 0n, 0n]));
  });

  it('strict catalog: only `strictCatalog === true` is strict; a miss names the domain and value', () => {
    expect(() => quantizeActionStruct({ verb: 'v', resource: 'x' }, { strictCatalog: true, verbCodes: { v: 1 } })).toThrow(
      new Error('policyvm quantize: resource "x" is not in the catalog (strict)'),
    );
    expect(() => quantizeActionStruct({ verb: 'v', resource: 'x' }, { strictCatalog: true })).toThrow(new Error('policyvm quantize: verb "v" is not in the catalog (strict)'));
    expect(settle(() => quantizeActionStruct({ verb: 'v', resource: 'x' }, { strictCatalog: true, verbCodes: { v: 1 }, resourceCodes: { x: 2 } }))).toEqual(ok([1n, 2n, 0n, 0n]));
    expect(settle(() => quantizeActionStruct({ verb: 'v', resource: 'x' }, { strictCatalog: 'true' as unknown as boolean })[0])).toEqual(ok(contentAddress('verb', 'v')));
    expect(() => quantizePlanStruct({ verb: 'v', resource: 'x', semanticDist: 0, planSalt: 0 }, { strictCatalog: true })).toThrow(new Error('policyvm quantize: verb "v" is not in the catalog (strict)'));
    expect(settle(() => quantizePlanStruct({ verb: 'v', resource: 'x', semanticDist: 0, planSalt: 0 }, { strictCatalog: 1 as unknown as boolean })[0])).toEqual(ok(contentAddress('verb', 'v')));
    expect(() => quantizePolicyStruct(POL, { strictCatalog: true })).toThrow(new Error('policyvm quantize: verb "v" is not in the catalog (strict)'));
    expect(settle(() => quantizePolicyStruct(POL, { strictCatalog: 1 as unknown as boolean })[10])).toEqual(ok(contentAddress('verb', 'v')));
  });

  it('a catalog code out of the uint64 domain names the domain', () => {
    expect(() => quantizeActionStruct({ verb: 'v', resource: 'x' }, { verbCodes: { v: -1 } })).toThrow(new Error('policyvm quantize: verb code is not a uint64'));
    expect(() => quantizeActionStruct({ verb: 'v', resource: 'x' }, { resourceCodes: { x: 1.5 } })).toThrow(new Error('policyvm quantize: resource code is not a uint64'));
    expect(() => quantizeActionStruct({ verb: 'v', resource: 'x' }, { verbCodes: { v: 1n << 64n } })).toThrow(new Error('policyvm quantize: verb code is not a uint64'));
    expect(settle(() => quantizeActionStruct({ verb: 'v', resource: 'x' }, { verbCodes: { v: (1n << 64n) - 1n }, resourceCodes: { x: 0 } }))).toEqual(ok([(1n << 64n) - 1n, 0n, 0n, 0n]));
  });

  it('non-string verb / resource and a missing action are refused', () => {
    expect(() => quantizeActionStruct({ verb: 1 as unknown as string, resource: 'x' })).toThrow(new Error('policyvm quantize: verb must be a string'));
    expect(() => quantizeActionStruct({ verb: 'v', resource: null as unknown as string })).toThrow(new Error('policyvm quantize: resource must be a string'));
    for (const a of [null, undefined, 'v', 5]) {
      expect(() => quantizeActionStruct(a as never)).toThrow(new Error('policyvm quantize: action is missing'));
    }
  });

  it('reversibility: default reversible, each class index, unknown refused', () => {
    expect(settle(() => quantizeActionStruct({ verb: 'v', resource: 'x' })[2])).toEqual(ok(0n));
    expect(settle(() => quantizeActionStruct({ verb: 'v', resource: 'x', reversibility_class: 'reversible' })[2])).toEqual(ok(0n));
    expect(settle(() => quantizeActionStruct({ verb: 'v', resource: 'x', reversibility_class: 'rate_limited' })[2])).toEqual(ok(1n));
    expect(settle(() => quantizeActionStruct({ verb: 'v', resource: 'x', reversibility_class: 'irreversible' })[2])).toEqual(ok(2n));
    expect(() => quantizeActionStruct({ verb: 'v', resource: 'x', reversibility_class: 'x' })).toThrow(new Error('policyvm quantize: unknown reversibility class "x"'));
    expect(() => quantizePolicyStruct({ ...POL, revMax: 'nope' })).toThrow(new Error('policyvm quantize: unknown revMax class "nope"'));
  });

  it('param scalar: unset field/params/value are 0; numbers, bigints and digit strings; exact refusals', () => {
    const qf = (params: Record<string, unknown> | undefined, field: string | undefined) => quantizeActionStruct({ verb: 'v', resource: 'x', params }, { paramScalarField: field })[3];
    const q = (params: Record<string, unknown> | undefined) => qf(params, 'n');
    const bad = (params: Record<string, unknown>, msg: string) => expect(() => q(params)).toThrow(new Error(msg));
    expect(settle(() => qf({ n: 5 }, undefined))).toEqual(ok(0n));
    expect(settle(() => qf({ n: 5 }, ''))).toEqual(ok(0n));
    expect(settle(() => quantizeActionStruct({ verb: 'v', resource: 'x', params: { n: 5 } })[3])).toEqual(ok(0n));
    // no / empty field name: the params are not read at all (not even a key named 'undefined' or '')
    expect(settle(() => quantizeActionStruct({ verb: 'v', resource: 'x', params: { undefined: 5, '': 6 } })[3])).toEqual(ok(0n));
    expect(settle(() => qf({ undefined: 5, '': 6 }, ''))).toEqual(ok(0n));
    expect(settle(() => q(undefined))).toEqual(ok(0n));
    expect(settle(() => q({}))).toEqual(ok(0n));
    expect(settle(() => q({ n: null }))).toEqual(ok(0n));
    expect(settle(() => q({ n: 0 }))).toEqual(ok(0n));
    expect(settle(() => q({ n: 5 }))).toEqual(ok(5n));
    expect(settle(() => q({ n: 6n }))).toEqual(ok(6n));
    expect(settle(() => q({ n: '0' }))).toEqual(ok(0n));
    expect(settle(() => q({ n: '123' }))).toEqual(ok(123n));
    expect(settle(() => q({ n: '18446744073709551615' }))).toEqual(ok((1n << 64n) - 1n));
    bad({ n: -1n }, 'policyvm quantize: paramScalar is not a uint64');
    bad({ n: 1n << 64n }, 'policyvm quantize: paramScalar is not a uint64');
    bad({ n: '18446744073709551616' }, 'policyvm quantize: paramScalar is not a uint64');
    bad({ n: 2 ** 64 }, 'policyvm quantize: paramScalar is not a uint64');
    bad({ n: -1 }, 'policyvm quantize: paramScalar must be a non-negative integer');
    bad({ n: 1.5 }, 'policyvm quantize: paramScalar must be a non-negative integer');
    bad({ n: Number.NaN }, 'policyvm quantize: paramScalar must be a non-negative integer');
    for (const v of ['12a', 'a12', '', '-1', '1 2', true, ['12'], { a: 1 }]) bad({ n: v }, 'policyvm quantize: paramScalar is not a non-negative integer');
  });

  it('plan and policy structs: exact layout and the field name in every refusal', () => {
    expect(settle(() => quantizePlanStruct({ verb: 'v', resource: 'x', semanticDist: 1, planSalt: 2 }, { verbCodes: { v: 3 }, resourceCodes: { x: 4 } }))).toEqual(ok([3n, 4n, 1n, 2n]));
    expect(() => quantizePlanStruct({ verb: 'v', resource: 'x', semanticDist: -1, planSalt: 2 })).toThrow(new Error('policyvm quantize: semanticDist is not a uint64'));
    expect(() => quantizePlanStruct({ verb: 'v', resource: 'x', semanticDist: 1, planSalt: 0.5 })).toThrow(new Error('policyvm quantize: planSalt is not a uint64'));
    expect(() => quantizePlanStruct({ verb: 2 as unknown as string, resource: 'x', semanticDist: 1, planSalt: 1 })).toThrow(new Error('policyvm quantize: verb must be a string'));
    expect(() => quantizePlanStruct({ verb: 'v', resource: 2 as unknown as string, semanticDist: 1, planSalt: 1 })).toThrow(new Error('policyvm quantize: resource must be a string'));
    const opts = { verbCodes: { v: 100 }, resourceCodes: { r: 200 } };
    expect(settle(() => quantizePolicyStruct(POL, opts))).toEqual(ok([1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 9n, 10n, 100n, 200n, 11n, 12n, 13n, 14n, 15n, 1n, 16n, 17n]));
    const names: Array<[string, (p: QuantizablePolicy) => QuantizablePolicy]> = [
      ['wAlpha', (p) => ({ ...p, weights: { ...p.weights, alpha: -1 } })],
      ['wBeta', (p) => ({ ...p, weights: { ...p.weights, beta: -1 } })],
      ['wGamma', (p) => ({ ...p, weights: { ...p.weights, gamma: -1 } })],
      ['wDelta', (p) => ({ ...p, weights: { ...p.weights, delta: -1 } })],
      ['wEpsilon', (p) => ({ ...p, weights: { ...p.weights, epsilon: -1 } })],
      ['wZeta', (p) => ({ ...p, weights: { ...p.weights, zeta: -1 } })],
      ['theta1', (p) => ({ ...p, theta1: -1 })],
      ['theta2', (p) => ({ ...p, theta2: -1 })],
      ['kappa', (p) => ({ ...p, kappa: -1 })],
      ['budgetB', (p) => ({ ...p, budgetB: -1 })],
      ['policyParamBound', (p) => ({ ...p, policyParamBound: -1 })],
      ['expiresAt', (p) => ({ ...p, expiresAt: -1 })],
      ['notBefore', (p) => ({ ...p, notBefore: -1 })],
      ['maxBlast', (p) => ({ ...p, maxBlast: -1 })],
      ['maxDepth', (p) => ({ ...p, maxDepth: -1 })],
      ['rateMax', (p) => ({ ...p, rateMax: -1 })],
      ['allocParent', (p) => ({ ...p, allocParent: -1 })],
    ];
    for (const [name, f] of names) expect(() => quantizePolicyStruct(f(POL), opts)).toThrow(new Error(`policyvm quantize: ${name} is not a uint64`));
    expect(() => quantizePolicyStruct({ ...POL, policyVerb: 1 as unknown as string })).toThrow(new Error('policyvm quantize: verb must be a string'));
    expect(() => quantizePolicyStruct({ ...POL, policyResource: 1 as unknown as string })).toThrow(new Error('policyvm quantize: resource must be a string'));
  });

  it('quantizePolicyVmInputs carries only the parts supplied; policyVmCommitmentFromAction hashes the action struct', () => {
    const action = { verb: 'v', resource: 'x' };
    expect(settle(() => Object.keys(quantizePolicyVmInputs({ action })))).toEqual(ok(['action']));
    expect(settle(() => quantizePolicyVmInputs({ action }).action)).toEqual(ok(quantizeActionStruct(action)));
    const plan = { verb: 'v', resource: 'x', semanticDist: 1, planSalt: 2 };
    const all = quantizePolicyVmInputs({ action, plan, policy: POL }, { verbCodes: { v: 1 } });
    expect(all).toEqual({ action: [1n, contentAddress('resource', 'x'), 0n, 0n], plan: [1n, contentAddress('resource', 'x'), 1n, 2n], policy: quantizePolicyStruct(POL, { verbCodes: { v: 1 } }) });
    expect(settle(() => Object.keys(quantizePolicyVmInputs({ action, policy: POL })))).toEqual(ok(['action', 'policy']));
    expect(settle(() => policyVmCommitmentFromAction(action, { verbCodes: { v: 1 } }))).toEqual(ok(policyVmStructHash([1n, contentAddress('resource', 'x'), 0n, 0n])));
  });
});

describe('decodePolicyVmPublic', () => {
  it('maps every index', () => {
    const ps = Array.from({ length: POLICYVM_PUBLIC_SIGNAL_COUNT }, (_, i) => `s${i}`);
    expect(settle(() => decodePolicyVmPublic(ps))).toEqual(ok({
      actionHash: { hi: 's0', lo: 's1' }, policyHash: { hi: 's2', lo: 's3' }, planHash: { hi: 's4', lo: 's5' },
      r: 's6', t: 's7', admit: 's8', allow: 's9', now: 's10', blast: 's11', delegationDepth: 's12', recentCount: 's13', allocChild: 's14',
    }));
    expect(POLICYVM_PUBLIC_SIGNAL_COUNT).toBe(15);
  });
});

describe('policyVmContextMatches: pins, windows, bounds', () => {
  const P = POLICYVM_PUBLIC_SIGNAL;
  // sample context: now=1000000000 blast=0 delegationDepth=0 recentCount=0 allocChild=500000 r=0 t=1 admit=1
  const base = () => [...(bn.publicSignals as string[])];
  const m = (e: unknown, ps = base()) => policyVmContextMatches(ps, e as never);

  it('no expectation: true; an empty expectation: true', () => {
    expect(settle(() => m(undefined))).toEqual(ok(true));
    expect(settle(() => m({}))).toEqual(ok(true));
    expect(settle(() => m(() => ({})))).toEqual(ok(true));
  });

  it('a non-object expectation (or a provider returning one) is false; a throwing provider is false', () => {
    for (const e of [null, 5, 'x', true]) {
      expect(settle(() => m(e))).toEqual(ok(false));
      expect(settle(() => m(() => e))).toEqual(ok(false));
    }
    expect(settle(() => m(() => { throw new Error('x'); }))).toEqual(ok(false));
  });

  it('every context signal must be a canonical decimal below 2^64 (checked even without pins)', () => {
    for (const idx of [P.now, P.blast, P.delegationDepth, P.recentCount, P.allocChild]) {
      const max = base();
      max[idx] = ((1n << 64n) - 1n).toString();
      expect(settle(() => m(undefined, max))).toEqual(ok(true));
      for (const v of [(1n << 64n).toString(), '01', 'x1', '1x', '', '-1']) {
        const ps = base();
        ps[idx] = v;
        expect(settle(() => m(undefined, ps))).toEqual(ok(false));
      }
      const short = base();
      short[idx] = undefined as unknown as string;
      expect(settle(() => m(undefined, short))).toEqual(ok(false));
      const num = base() as unknown[];
      num[idx] = 5;
      expect(settle(() => m(undefined, num as string[]))).toEqual(ok(false));
    }
  });

  it('each pinned key is checked against its own index (exact match passes, off-by-one fails)', () => {
    const vals: Record<string, number> = { now: 1_000_000_000, blast: 0, delegationDepth: 0, recentCount: 0, allocChild: 500_000, r: 0, t: 1 };
    for (const [k, v] of Object.entries(vals)) {
      expect(settle(() => m({ [k]: v }))).toEqual(ok(true));
      expect(settle(() => m({ [k]: v + 1 }))).toEqual(ok(false));
      expect(settle(() => m({ [k]: String(v) }))).toEqual(ok(true));
      expect(settle(() => m({ [k]: BigInt(v) }))).toEqual(ok(true));
    }
  });

  it('exact pins: a non-canonical proof signal never matches; unsafe or fractional numbers never match', () => {
    const ps = base();
    ps[P.r] = '07';
    expect(settle(() => m({ r: 7 }, ps))).toEqual(ok(false));
    ps[P.r] = '7x';
    expect(settle(() => m({ r: 7 }, ps))).toEqual(ok(false));
    ps[P.r] = 'x7';
    expect(settle(() => m({ r: 7 }, ps))).toEqual(ok(false));
    ps[P.r] = '70';
    expect(settle(() => m({ r: 70 }, ps))).toEqual(ok(true));
    ps[P.r] = '123';
    expect(settle(() => m({ r: 123 }, ps))).toEqual(ok(true));
    const big = base();
    big[P.now] = (2n ** 60n).toString();
    expect(settle(() => m({ now: 2 ** 60 }, big))).toEqual(ok(false)); // not a safe integer
    expect(settle(() => m({ now: 2n ** 60n }, big))).toEqual(ok(true));
    expect(settle(() => m({ now: (2n ** 60n).toString() }, big))).toEqual(ok(true));
    expect(settle(() => m({ r: 0.5 }))).toEqual(ok(false));
    expect(settle(() => m({ r: 'zero' }))).toEqual(ok(false));
    const noT = base();
    noT[P.t] = undefined as unknown as string;
    expect(settle(() => m({ t: 1 }, noT))).toEqual(ok(false));
  });

  it('window pins are inclusive at both ends and need min <= max with integer bounds', () => {
    const now = 1_000_000_000;
    expect(settle(() => m({ now: { min: now, max: now } }))).toEqual(ok(true));
    expect(settle(() => m({ now: { min: now - 1, max: now + 1 } }))).toEqual(ok(true));
    expect(settle(() => m({ now: { min: now + 1, max: now + 2 } }))).toEqual(ok(false));
    expect(settle(() => m({ now: { min: now - 2, max: now - 1 } }))).toEqual(ok(false));
    expect(settle(() => m({ now: { min: now + 1, max: now - 1 } }))).toEqual(ok(false));
    expect(settle(() => m({ now: { min: 'a', max: now } }))).toEqual(ok(false));
    expect(settle(() => m({ now: { min: now, max: 'b' } }))).toEqual(ok(false));
    expect(settle(() => m({ now: { min: 1.5, max: now } }))).toEqual(ok(false));
    expect(settle(() => m({ now: { min: String(now), max: BigInt(now) } }))).toEqual(ok(true));
    // a window on a non-canonical (unchecked) signal
    const ps = base();
    ps[P.r] = '05';
    expect(settle(() => m({ r: { min: 0, max: 10 } }, ps))).toEqual(ok(false));
  });

  it('requireAdmit / requireTier1 only bite when set, and only on a non-"1" signal', () => {
    const a0 = base();
    a0[P.admit] = '0';
    expect(settle(() => m({ requireAdmit: false }, a0))).toEqual(ok(true));
    expect(settle(() => m({ requireAdmit: true }, a0))).toEqual(ok(false));
    expect(settle(() => m({ requireAdmit: true }))).toEqual(ok(true));
    const t2 = base();
    t2[P.t] = '2';
    expect(settle(() => m({ requireTier1: false }, t2))).toEqual(ok(true));
    expect(settle(() => m({ requireTier1: true }, t2))).toEqual(ok(false));
    expect(settle(() => m({ requireTier1: true }))).toEqual(ok(true));
    expect(settle(() => m({ requireAdmit: true, requireTier1: true }))).toEqual(ok(true));
  });
});
