/**
 * Configuration snapshots. Every verifier factory validates its policy at construction; afterwards it must enforce
 * exactly what it was built with. These tests wrap the caller's configuration (arrays and plain objects, recursively)
 * in recording proxies, arm them once the verifier is BUILT, and require that using the verifier never reads the
 * caller's data again. A verifier that kept a reference would read it (and a caller emptying an allowlist later would
 * change what it enforces: an empty optional gate is "not gated").
 */
import { describe, expect, it } from 'vitest';
import { snapshotConfig } from './config-snapshot';
import { createAzureMaaVerifier } from './attest-azure-maa';
import { createGcpConfidentialSpaceVerifier } from './attest-gcp-confidential-space';
import { createIntelDcapVerifier } from './attest-intel-dcap';
import { createNvidiaSpdmVerifier } from './attest-nvidia-spdm';
import { createAmdSnpVerifier } from './attest-amd-snp';
import { createPufVerifier } from './attest-puf';
import { createPqSoftwareVerifier } from './attest-pq-software';
import { createAttestationVerifier, createMultiRootVerifier } from './attestation';
import { createZkVerifier } from './zk';
import { createSemanticVerifier } from './semantic-threshold';
import { createRevocationChecker } from './revocation';
import { createThresholdVerifier } from './threshold';
import { createMaaKeyTrust } from './attest-maa-keys';
import { requirePCA } from './server/require-pca';

/** Deep recording proxy over arrays and plain objects (functions and class instances are left alone). */
function recorder<T>(value: T): { value: T; arm: () => void; reads: string[] } {
  const reads: string[] = [];
  let armed = false;
  const cache = new WeakMap<object, unknown>();
  const wrap = (v: unknown, path: string): unknown => {
    if (v === null || typeof v !== 'object') return v;
    const proto = Object.getPrototypeOf(v);
    if (!Array.isArray(v) && proto !== Object.prototype && proto !== null) return v;
    if (cache.has(v)) return cache.get(v);
    const p = new Proxy(v as object, {
      get(t, k, r) {
        if (armed) reads.push(`${path}.${String(k)}`);
        return wrap(Reflect.get(t, k, r), `${path}.${String(k)}`);
      },
      has(t, k) {
        if (armed) reads.push(`${path} has ${String(k)}`);
        return Reflect.has(t, k);
      },
      ownKeys(t) {
        if (armed) reads.push(`${path} keys`);
        return Reflect.ownKeys(t);
      },
    });
    cache.set(v, p);
    return p;
  };
  return { value: wrap(value, 'opts') as T, arm: () => { armed = true; }, reads };
}

class FixedVerifier {
  async verify() { return { ok: false, reason: 'fixed' }; }
}
class NullStore {
  async get() { return undefined; }
  async put() { return undefined; }
  async consume() { return true; }
}

const HEX96 = 'ab'.repeat(48);
const INPUT = { document: {}, ctx: {}, nowMs: 1, expected: { holderPub: 'h', grantRef: 'g', epoch: 1, nonce: 'n' } } as never;
const CTX = { pcactn: { action: { verb: 'v', resource: 'r' }, grant_ref: 'g', attestation: {} }, grant: {} } as never;
const swallow = async (f: () => unknown) => { try { await f(); } catch { /* only the reads matter */ } };

const CASES: [string, () => { build: (o: never) => unknown; opts: unknown; use: (v: never) => Promise<unknown> }][] = [
  ['createAzureMaaVerifier', () => ({ build: createAzureMaaVerifier, opts: { trustedIssuers: ['https://x.attest.azure.net'], trustAnchors: { rootSpkiSha256: ['aa'.repeat(32)] }, policy: { tdxMrtds: [HEX96], tdxRtmrs: [HEX96], sevSnpMeasurements: [HEX96], sevSnpHostData: ['aa'], sevSnpMinTcb: { snp: 1 } }, resolveEvidence: () => undefined }, use: (v) => (v as { verify: (i: never) => Promise<unknown> }).verify(INPUT) })],
  ['createGcpConfidentialSpaceVerifier', () => ({ build: createGcpConfidentialSpaceVerifier, opts: { trustedIssuers: ['https://confidentialcomputing.googleapis.com'], trustAnchors: { trustedKeySpki: ['aa'.repeat(32)] }, policy: { imageDigests: ['sha256:' + 'a'.repeat(64)], allowedTeeTypes: ['x'], allowedSwVersions: ['1'] }, resolveEvidence: () => undefined }, use: (v) => (v as { verify: (i: never) => Promise<unknown> }).verify(INPUT) })],
  ['createIntelDcapVerifier', () => ({ build: createIntelDcapVerifier, opts: { binding: 'report-data', policy: { mrtds: [HEX96], mrSeams: [HEX96], fmspcs: ['aa'], rtmrs: [HEX96] }, resolveEvidence: () => undefined }, use: (v) => (v as { verify: (i: never) => Promise<unknown> }).verify(INPUT) })],
  ['createNvidiaSpdmVerifier', () => ({ build: createNvidiaSpdmVerifier, opts: { rootSpkiSha256: ['aa'.repeat(32)], policy: { measurements: { 1: 'aa' }, leafSubjectIncludes: 'x' }, resolveEvidence: () => undefined }, use: (v) => (v as { verify: (i: never) => Promise<unknown> }).verify(INPUT) })],
  ['createAmdSnpVerifier', () => ({ build: createAmdSnpVerifier, opts: { family: 'genoa', binding: 'report-data', policy: { measurements: [HEX96], hostData: ['aa'], chipIds: ['bb'] }, resolveEvidence: () => undefined }, use: (v) => (v as { verify: (i: never) => Promise<unknown> }).verify(INPUT) })],
  ['createPufVerifier', () => ({ build: createPufVerifier, opts: { policy: { measurements: ['m'], weightsMeasurements: ['w'] }, resolveEnrollment: () => undefined, resolveEvidence: () => undefined }, use: (v) => (v as { verify: (i: never) => Promise<unknown> }).verify(INPUT) })],
  ['createPqSoftwareVerifier', () => ({ build: createPqSoftwareVerifier, opts: { trustedPqPublicKeys: ['k'], allowedSuites: ['ml-dsa-65'], policy: { measurements: ['m'], weightsMeasurements: ['w'] }, resolveEvidence: () => undefined }, use: (v) => (v as { verify: (i: never) => Promise<unknown> }).verify(INPUT) })],
  ['createAttestationVerifier', () => ({ build: createAttestationVerifier, opts: { trustedAttestorKeys: ['k'], nonceStore: new NullStore(), hardwareVerifier: new FixedVerifier() }, use: (v) => (v as (c: never) => Promise<unknown>)(CTX) })],
  ['createMultiRootVerifier', () => ({ build: createMultiRootVerifier, opts: { roots: [{ id: 'a', verifier: new FixedVerifier(), required: true }, { id: 'b', verifier: new FixedVerifier() }], threshold: 1 }, use: (v) => (v as { verify: (i: never) => Promise<unknown> }).verify(INPUT) })],
  ['createZkVerifier', () => ({ build: createZkVerifier, opts: { trustedProverKeys: ['k'], policyCommitments: ['c'] }, use: (v) => (v as (c: never) => Promise<unknown>)(CTX) })],
  ['createSemanticVerifier', () => ({ build: createSemanticVerifier, opts: { judgeKeys: ['k'], k: 1, verdicts: () => [], goalCommitment: () => 'g' }, use: async (v) => (v as (c: never) => unknown)(CTX) })],
  ['createRevocationChecker', () => ({ build: createRevocationChecker, opts: { proofFor: () => undefined, ids: () => ['a'], pqPins: { a: 'b' }, guardianPublic: 'g', root: () => 'r' }, use: async (v) => (v as (c: never) => unknown)(CTX) })],
  ['createThresholdVerifier', () => ({ build: createThresholdVerifier, opts: { signerSet: [{ role: 'agent', key: 'k' }, { role: 'human', key: 'h' }], t: 2 }, use: async (v) => (v as (c: never) => unknown)(CTX) })],
  ['createMaaKeyTrust', () => ({ build: createMaaKeyTrust, opts: { policy: { trustedIssuers: ['https://x.attest.azure.net'], pins: ['aa'] }, store: new NullStore(), fetch: async () => { throw new Error('offline'); } }, use: (v) => (v as { getTrustAnchors: (i: string, o: unknown) => Promise<unknown> }).getTrustAnchors('https://x.attest.azure.net', { nowMs: 1 }) })],
  ['requirePCA', () => ({ build: requirePCA, opts: { audience: 'aud', resolveGrant: async () => null, require: ['attestation'], realm: 'r', budgetStore: new NullStore(), insecureAllowUnboundOperation: true, multiInstance: false }, use: (v) => (v as (r: never) => Promise<unknown>)({ method: 'POST', url: '/x', headers: { 'pca-action': 'e30' } } as never) })],
];

describe('verifier factories never read the caller configuration after construction', () => {
  for (const [name, mk] of CASES) {
    it(name, async () => {
      const { build, opts, use } = mk();
      const rec = recorder(opts);
      const v = build(rec.value as never);
      rec.arm();
      await swallow(() => use(v as never));
      await swallow(() => use(v as never));
      expect(rec.reads).toEqual([]);
    });
  }
});

describe('snapshotConfig', () => {
  it('copies and freezes data, keeps behaviour, preserves cycles', () => {
    class K { x = 1; }
    const k = new K();
    const f = () => 1;
    const shared = [1];
    const src: Record<string, unknown> = { a: [1, { b: 'c' }], m: new Map([['x', [1]]]), s: new Set([1]), u: new Uint8Array([1, 2]), d: new Date(5), k, f, s1: shared, s2: shared };
    src.self = src;
    const c = snapshotConfig(src);
    expect(c).not.toBe(src);
    expect(Object.isFrozen(c)).toBe(true);
    expect(Object.isFrozen(c.a)).toBe(true);
    expect(Object.isFrozen((c.a as unknown[])[1])).toBe(true);
    expect(c.k).toBe(k);
    expect(c.f).toBe(f);
    expect(c.self).toBe(c);
    expect(c.s1).toBe(c.s2);
    (src.a as unknown[]).length = 0;
    (src.m as Map<string, unknown>).clear();
    (src.s as Set<number>).clear();
    (src.u as Uint8Array)[0] = 9;
    (src.d as Date).setTime(0);
    expect(c.a).toEqual([1, { b: 'c' }]);
    expect((c.m as Map<string, unknown>).get('x')).toEqual([1]);
    expect((c.s as Set<number>).has(1)).toBe(true);
    expect((c.u as Uint8Array)[0]).toBe(1);
    expect((c.d as Date).getTime()).toBe(5);
    const nul = Object.create(null) as Record<string, unknown>;
    nul.x = [1];
    const cn = snapshotConfig(nul);
    expect(Object.getPrototypeOf(cn)).toBe(null);
    expect(snapshotConfig(5)).toBe(5);
    expect(snapshotConfig(undefined)).toBe(undefined);
  });
  it('keep: listed top-level members stay the caller object; the rest is copied', () => {
    const store = { n: 0, bump() { this.n++; } };
    const c = snapshotConfig({ store, list: ['a'] }, { keep: ['store'] });
    expect(c.store).toBe(store);
    c.store.bump();
    expect(store.n).toBe(1);
    expect(Object.isFrozen(c.list)).toBe(true);
  });
});
