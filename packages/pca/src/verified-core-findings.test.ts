/* eslint-disable @typescript-eslint/no-explicit-any */
// Regression tests for the production findings of the Dafny verified-core extension (docs/pca/security/verified-core.md,
// PoCs in packages/pca-verified-core/test/ext-*.diff.test.ts). Each block is a PoC that used to PASS an attacker input.
import { describe, expect, it } from 'vitest';
import { attenuate, delegate, mintRoot } from './capability';
import { encodeKey, generateKeyPair } from './keys';
import { commitPlan, conditionsDigest, paramsDigest } from './merkle';
import { type PCActn, type PCActnBody, signPCActn, verifyPCActnCore } from './pcactn';
import { b64u, compareUtf8, sha256 } from './hash';
import { createMultiRootVerifier, memoryNonceStore, type HardwareAttestationResult } from './attestation';
import { signAllowlistManifest, verifyAllowlistDurable, verifyAllowlistManifest, type AllowlistIssuerKey, type VerifyAllowlistResult } from './attest-allowlist';
import { anchorAllowlistHead, createAllowlistAnchorLog, verifyAllowlistAnchored, type AnchorTrust } from './attest-allowlist-anchor';
import { EMPTY_TREE_ROOT, TransparencyLedger, ledgerRootOf, verifyLedgerConsistency } from './ledger';
import { InMemoryTrustedInputRegistry, classifyRef, computeTaint, joinLabels, labelRank, taintValue, type TaintLabel } from './taint';
import { envelopeCaveatEvaluator, evaluateConditionTri } from './predicates';

const DAY = 86_400_000;
const NOW = 1_800_000_000_000;

// ------------------------------------------------------------------------------------------------
// (1) Attest
// ------------------------------------------------------------------------------------------------
const OPS = generateKeyPair();
const ISSUER_KEYS: Record<string, AllowlistIssuerKey> = { ops: { alg: 'ed25519', keys: { edPub: b64u(OPS.publicKey) } } };
const ENTRY = { kind: 'tdx-mrtd' as const, value: 'ab'.repeat(48), label: 'boot' };
const sign = (body: { version: number; issuedAt: number; notBefore: number; expiresAt: number; label?: string }) =>
  signAllowlistManifest(
    { version: body.version, issuedAt: body.issuedAt, notBefore: body.notBefore, expiresAt: body.expiresAt, entries: [{ ...ENTRY, label: body.label ?? 'boot' }] },
    { issuer: 'ops', alg: 'ed25519', secrets: { edSecret: OPS.secretKey } },
  );

describe('Attest finding 1: non-finite numeric options fail closed (were fail OPEN)', () => {
  const expired = sign({ version: 1, issuedAt: NOW - 100 * DAY, notBefore: NOW - 100 * DAY, expiresAt: NOW - 50 * DAY });
  const future = sign({ version: 1, issuedAt: NOW, notBefore: NOW + 50 * DAY, expiresAt: NOW + 60 * DAY });
  const base = { issuerKeys: ISSUER_KEYS, nowMs: NOW };

  it('baseline: an expired / not-yet-valid manifest is refused', () => {
    expect(verifyAllowlistManifest(expired, base)).toMatchObject({ ok: false, code: 'expired' });
    expect(verifyAllowlistManifest(future, base)).toMatchObject({ ok: false, code: 'not-yet-valid' });
  });
  it.each([NaN, Infinity, -Infinity, '5', null])('clockSkewMs = %s never verifies an expired or not-yet-valid manifest', (skew) => {
    const o: any = { ...base, clockSkewMs: skew };
    expect(verifyAllowlistManifest(expired, o)).toMatchObject({ ok: false });
    expect(verifyAllowlistManifest(future, o)).toMatchObject({ ok: false });
    // and even a perfectly valid manifest is refused: the option is invalid, not silently ignored
    const good = sign({ version: 1, issuedAt: NOW, notBefore: NOW - DAY, expiresAt: NOW + DAY });
    expect(verifyAllowlistManifest(good, o)).toMatchObject({ ok: false, code: 'malformed' });
  });
  it('a finite skew still works (fractional, zero, negative clamp)', () => {
    const good = sign({ version: 1, issuedAt: NOW, notBefore: NOW - DAY, expiresAt: NOW + DAY });
    for (const s of [0, 0.5, 1000, -5]) expect(verifyAllowlistManifest(good, { ...base, clockSkewMs: s })).toMatchObject({ ok: true });
    expect(verifyAllowlistManifest(expired, { ...base, clockSkewMs: 60 * DAY })).toMatchObject({ ok: true }); // an enormous but finite skew is the caller's choice
  });
  it('NaN maxLifetimeMs / minVersion / lastSeenVersion cannot disable their own check', () => {
    const m = sign({ version: 1, issuedAt: NOW, notBefore: NOW - DAY, expiresAt: NOW + 30 * DAY });
    expect(verifyAllowlistManifest(m, { ...base, maxLifetimeMs: NaN })).toMatchObject({ ok: false, code: 'malformed' });
    expect(verifyAllowlistManifest(m, { ...base, minVersion: NaN })).toMatchObject({ ok: false, code: 'malformed' });
    expect(verifyAllowlistManifest(m, { ...base, lastSeenVersion: NaN })).toMatchObject({ ok: false, code: 'malformed' });
    expect(verifyAllowlistManifest(m, { ...base, lastSeenVersion: 2.5 as any })).toMatchObject({ ok: false, code: 'malformed' });
  });

  describe('anchored head window', () => {
    const guardian = generateKeyPair();
    const trust: AnchorTrust = { logKey: b64u(guardian.publicKey), instanceId: 'inst', principal: 'log' };
    const v = (() => {
      const r = verifyAllowlistManifest(sign({ version: 1, issuedAt: NOW, notBefore: NOW - DAY, expiresAt: NOW + 30 * DAY }), base);
      if (!r.ok) throw new Error('setup');
      return r as Extract<VerifyAllowlistResult, { ok: true }>;
    })();
    const log = createAllowlistAnchorLog({ instanceId: trust.instanceId, principal: trust.principal });
    const evStale = anchorAllowlistHead(log, v, { guardianSecret: guardian.secretKey, nowMs: NOW - 30 * DAY }); // head 30 days old
    const log2 = createAllowlistAnchorLog({ instanceId: trust.instanceId, principal: trust.principal });
    const evFuture = anchorAllowlistHead(log2, v, { guardianSecret: guardian.secretKey, nowMs: NOW + 30 * DAY }); // head 30 days in the future
    it('baseline refuses stale and future heads', () => {
      expect(verifyAllowlistAnchored(v, evStale, { trust, nowMs: NOW })).toMatchObject({ ok: false, code: 'stale-head' });
      expect(verifyAllowlistAnchored(v, evFuture, { trust, nowMs: NOW })).toMatchObject({ ok: false, code: 'stale-head' });
    });
    it.each([NaN, Infinity])('maxHeadAgeMs = %s does not disable the staleness check', (m) => {
      expect(verifyAllowlistAnchored(v, evStale, { trust, nowMs: NOW, maxHeadAgeMs: m })).toMatchObject({ ok: false });
    });
    it.each([NaN, Infinity])('clockSkewMs = %s does not disable the future-head check', (s) => {
      expect(verifyAllowlistAnchored(v, evFuture, { trust, nowMs: NOW, clockSkewMs: s })).toMatchObject({ ok: false });
    });
  });
});

describe('Attest finding 2: verifyAllowlistDurable rejects a same-version different-digest write', () => {
  function memKv(beforeUpdate?: (s: Map<string, unknown>) => void) {
    const store = new Map<string, unknown>();
    return {
      store,
      async get(k: string) { return store.get(k); },
      async set(k: string, v: unknown) { store.set(k, v); },
      async update(k: string, fn: (p: unknown) => unknown) { beforeUpdate?.(store); const n = fn(store.get(k)); if (n !== undefined) store.set(k, n); return store.get(k); },
      async keys() { return [...store.keys()]; },
    };
  }
  const mA = sign({ version: 2, issuedAt: NOW, notBefore: NOW - DAY, expiresAt: NOW + 30 * DAY, label: 'a' });
  const mB = sign({ version: 2, issuedAt: NOW, notBefore: NOW - DAY, expiresAt: NOW + 30 * DAY, label: 'b' });
  const opts = { issuerKeys: ISSUER_KEYS, nowMs: NOW };

  it('a racing writer stored (v2, digest-A) after our read: manifest B at v2 is a conflict and the record is NOT overwritten', async () => {
    const a = await verifyAllowlistDurable(mA, opts, memKv() as never);
    expect(a.ok).toBe(true);
    const digestA = (a as any).digest as string;
    const kv = memKv((s) => {
      if (!s.has('__i')) {
        s.set('__i', 1);
        s.set('allowlist/ops', { version: 2, digest: digestA });
      }
    });
    const res = await verifyAllowlistDurable(mB, opts, kv as never);
    expect(res).toMatchObject({ ok: false, code: 'conflict' });
    expect(kv.store.get('allowlist/ops')).toEqual({ version: 2, digest: digestA });
  });
  it('sequential: v2/A then v2/B is a conflict; v2/A again is accepted (idempotent); v3 advances', async () => {
    const kv = memKv();
    expect((await verifyAllowlistDurable(mA, opts, kv as never)).ok).toBe(true);
    expect(await verifyAllowlistDurable(mB, opts, kv as never)).toMatchObject({ ok: false, code: 'conflict' });
    expect((await verifyAllowlistDurable(mA, opts, kv as never)).ok).toBe(true);
    const m3 = sign({ version: 3, issuedAt: NOW, notBefore: NOW - DAY, expiresAt: NOW + 30 * DAY });
    expect((await verifyAllowlistDurable(m3, opts, kv as never)).ok).toBe(true);
    expect((kv.store.get('allowlist/ops') as any).version).toBe(3);
  });
});

describe('Attest finding 3: memoryNonceStore never re-accepts a consumed nonce', () => {
  it('max = 1: a, b, a  => a is NOT accepted twice (full store refuses, fail closed)', () => {
    const s = memoryNonceStore(1);
    expect(s.consume('a')).toBe(true);
    expect(s.consume('b')).toBe(false); // full of retained nonces: refused rather than evicting 'a'
    expect(s.consume('a')).toBe(false);
  });
  it('max < 1 / non-integer is invalid', () => {
    for (const m of [0, -1, 1.5, NaN, Infinity]) expect(() => memoryNonceStore(m)).toThrow(TypeError);
  });
  it('a consumed nonce is rejected for the whole retention window, however many others were consumed', () => {
    let t = 1000;
    const s = memoryNonceStore(3, { retentionMs: 1000, now: () => t });
    expect(s.consume('a')).toBe(true);
    for (const n of ['b', 'c']) expect(s.consume(n)).toBe(true);
    expect(s.consume('d')).toBe(false); // full
    t += 500;
    expect(s.consume('a')).toBe(false);
    t += 600; // 'a' (t=1000) now aged out of the 1000 ms retention; so did b and c
    expect(s.consume('d')).toBe(true); // room made only from aged-out entries
    expect(s.consume('d')).toBe(false);
  });
  it('replay inside retention is rejected even with a huge stream of other nonces (default capacity)', () => {
    const s = memoryNonceStore();
    expect(s.consume('victim')).toBe(true);
    for (let i = 0; i < 2000; i++) s.consume(`n${i}`);
    expect(s.consume('victim')).toBe(false);
  });
  it('invalid retention is rejected', () => {
    expect(() => memoryNonceStore(10, { retentionMs: 0 })).toThrow(TypeError);
    expect(() => memoryNonceStore(10, { retentionMs: NaN })).toThrow(TypeError);
    expect(() => memoryNonceStore(10, { retentionMs: 2.5 })).toThrow(TypeError); // integer ms only (matches the proved store)
  });
  it('a non-integer clock reading refuses the nonce (fail closed), and does not consume it', () => {
    let t: number = 1000;
    const s = memoryNonceStore(10, { retentionMs: 100, now: () => t });
    for (const bad of [1000.5, NaN, Infinity, -Infinity, 2 ** 53, '7' as unknown as number]) {
      t = bad;
      expect(s.consume('x')).toBe(false);
    }
    t = 1001;
    expect(s.consume('x')).toBe(true); // never recorded by the refused calls
    expect(s.consume('x')).toBe(false);
  });
});

describe('Attest finding 4: a null result from one root is a failed root, not an abort', () => {
  const ident = { model_id: 'm', weights_digest: 'w', runtime_measurement: 'r', operator: 'o', weights_measured: true };
  const good = (): { verify: () => Promise<HardwareAttestationResult> } => ({ verify: async () => ({ ok: true, bound: true, measured: ident }) });
  const nul = (v: unknown) => ({ verify: async () => v as never });

  it('2-of-3 with one null root: the two good roots still carry the verdict', async () => {
    const v = createMultiRootVerifier({ roots: [{ id: 'a', verifier: nul(null) }, { id: 'b', verifier: good() }, { id: 'c', verifier: good() }], threshold: 2 });
    expect(await v.verify({} as never)).toMatchObject({ ok: true, bound: true });
  });
  it('undefined root result is also just a failed root', async () => {
    const v = createMultiRootVerifier({ roots: [{ id: 'a', verifier: nul(undefined) }, { id: 'b', verifier: good() }], threshold: 1 });
    expect(await v.verify({} as never)).toMatchObject({ ok: true });
  });
  it('fail-closed semantics preserved: below threshold and required-root failure still deny', async () => {
    const below = createMultiRootVerifier({ roots: [{ id: 'a', verifier: nul(null) }, { id: 'b', verifier: good() }], threshold: 2 });
    const r1 = await below.verify({} as never);
    expect(r1.ok).toBe(false);
    expect(r1.reason).toMatch(/below threshold \(1\/2/);
    const req = createMultiRootVerifier({ roots: [{ id: 'a', verifier: nul(null), required: true }, { id: 'b', verifier: good() }], threshold: 1 });
    const r2 = await req.verify({} as never);
    expect(r2.ok).toBe(false);
    expect(r2.reason).toMatch(/required attestation root 'a' failed/);
  });
});

// ------------------------------------------------------------------------------------------------
// (2) Merkle
// ------------------------------------------------------------------------------------------------
describe('Merkle: verifyLedgerConsistency (RFC 9162 §2.1.4)', () => {
  const ledgerOf = (n: number): TransparencyLedger => {
    const l = new TransparencyLedger('p');
    for (let i = 0; i < n; i++) l.appendCommitment(`c${i}`);
    return l;
  };
  const rootAt = (n: number): string => ledgerRootOf(Array.from({ length: n }, (_, i) => `c${i}`));

  it('EMPTY_TREE_ROOT is the root of the empty log', () => {
    expect(EMPTY_TREE_ROOT).toBe(b64u(sha256(new Uint8Array(0))));
    expect(ledgerRootOf([])).toBe(EMPTY_TREE_ROOT);
  });
  it('oldSize = 0: oldRoot must be the empty-tree root and the path empty; newRoot is unconstrained for a non-empty tree', () => {
    const p = { oldSize: 0, newSize: 5, path: [] as string[] };
    expect(verifyLedgerConsistency('not-a-root', 'neither', p)).toBe(false); // was: true (any roots)
    expect(verifyLedgerConsistency('', rootAt(5), p)).toBe(false);
    expect(verifyLedgerConsistency(EMPTY_TREE_ROOT, rootAt(5), p)).toBe(true);
    expect(verifyLedgerConsistency(EMPTY_TREE_ROOT, rootAt(5), { ...p, path: [rootAt(1)] })).toBe(false);
    // empty -> empty is the empty tree again
    expect(verifyLedgerConsistency(EMPTY_TREE_ROOT, EMPTY_TREE_ROOT, { oldSize: 0, newSize: 0, path: [] })).toBe(true);
    expect(verifyLedgerConsistency(EMPTY_TREE_ROOT, rootAt(5), { oldSize: 0, newSize: 0, path: [] })).toBe(false);
    expect(verifyLedgerConsistency('x', 'y', { oldSize: 0, newSize: 0, path: [] })).toBe(false);
  });
  it('honest proofs verify for every (m, n) up to 24 and fail for a forged root', () => {
    const led = ledgerOf(24);
    for (let n = 1; n <= 24; n++) {
      for (let m = 0; m <= n; m++) {
        const proof = led.consistencyProof(m, n);
        const oldRoot = m === 0 ? EMPTY_TREE_ROOT : rootAt(m);
        const newRoot = rootAt(n);
        expect(verifyLedgerConsistency(oldRoot, newRoot, proof), `(${m},${n})`).toBe(true);
        if (m > 0) expect(verifyLedgerConsistency(oldRoot, rootAt(n + 1), proof), `forged (${m},${n})`).toBe(false);
      }
    }
  });
  it('2^32 boundary: sizes are not truncated to 32 bits ((3,7) vs (3+2^32, 7+2^32))', () => {
    const led = ledgerOf(7);
    const p = led.consistencyProof(3, 7);
    const old = rootAt(3);
    const nw = rootAt(7);
    expect(verifyLedgerConsistency(old, nw, p)).toBe(true);
    for (const shift of [2 ** 32, 2 ** 31, 2 ** 33, 2 ** 40, 2 ** 52]) {
      expect(verifyLedgerConsistency(old, nw, { ...p, oldSize: 3 + shift, newSize: 7 + shift }), `+${shift}`).toBe(false);
      expect(verifyLedgerConsistency(old, nw, { ...p, oldSize: 3, newSize: 7 + shift }), `new+${shift}`).toBe(false);
      expect(verifyLedgerConsistency(old, nw, { ...p, oldSize: 3 + shift, newSize: 7 }), `old+${shift}`).toBe(false);
    }
    // power-of-two old size (the `first & (first - 1)` branch)
    const p4 = led.consistencyProof(4, 7);
    expect(verifyLedgerConsistency(rootAt(4), nw, p4)).toBe(true);
    expect(verifyLedgerConsistency(rootAt(4), nw, { ...p4, oldSize: 4 + 2 ** 32, newSize: 7 + 2 ** 32 })).toBe(false);
    // 2^32 as an old size is a power of two: it must not be treated like size 0 (32-bit truncation) or size 1
    expect(verifyLedgerConsistency(old, nw, { oldSize: 2 ** 32, newSize: 2 ** 32 + 7, path: p.path })).toBe(false);
    expect(verifyLedgerConsistency(old, nw, { oldSize: 2 ** 32, newSize: 2 ** 32 + 7, path: [] })).toBe(false);
  });
  it('sizes at or above 2^53, non-integers and negatives are refused', () => {
    for (const bad of [2 ** 53, 2 ** 53 + 2, Number.MAX_VALUE, Infinity, NaN, -1, 1.5]) {
      expect(verifyLedgerConsistency(EMPTY_TREE_ROOT, EMPTY_TREE_ROOT, { oldSize: 0, newSize: bad, path: [] })).toBe(false);
      expect(verifyLedgerConsistency('a', 'b', { oldSize: bad, newSize: bad, path: [] })).toBe(false);
    }
  });
  it('an over-long path is refused outright', () => {
    const led = ledgerOf(7);
    const p = led.consistencyProof(3, 7);
    expect(verifyLedgerConsistency(rootAt(3), rootAt(7), { ...p, path: [...p.path, ...new Array(200).fill(p.path[0])] })).toBe(false);
  });
});

// ------------------------------------------------------------------------------------------------
// (3) Taint
// ------------------------------------------------------------------------------------------------
describe('Taint: attacker-controlled label kinds are own-property lookups; computeTaint never throws', () => {
  const INHERITED = ['constructor', '__proto__', 'toString', 'hasOwnProperty', 'valueOf'];
  it.each(INHERITED)('kind %s is not a level: the registry refuses to record it', (k) => {
    const reg = new InMemoryTrustedInputRegistry();
    reg.record('d', { kind: k } as any);
    expect(reg.size).toBe(0);
  });
  it.each(INHERITED)('a custom registry returning kind %s vouches for nothing: worst taint, never NaN', (k) => {
    const ctx = { registry: { lookup: () => ({ kind: k }) as any } };
    const t = computeTaint({ trusted_refs: ['d1'] }, ctx);
    expect(t.valid).toBe(true);
    expect(t.taint).toBe(1);
    expect(Number.isNaN(t.taint)).toBe(false);
    expect(t.label.kind).toBe('agent');
    expect(classifyRef('d1', ctx).kind).toBe('agent');
  });
  it('labelRank / taintValue / joinLabels fail closed on an unknown kind', () => {
    const bad = { kind: 'constructor' } as unknown as TaintLabel;
    expect(labelRank(bad)).toBe(4);
    expect(taintValue(bad)).toBe(1);
    expect(taintValue(joinLabels([{ kind: 'trusted' }, bad]))).toBe(1);
    expect(taintValue({ kind: undefined } as any)).toBe(1);
    expect(taintValue(null as any)).toBe(1);
  });
  it('a throwing registry.lookup does not throw out of computeTaint (invalid, fail closed)', () => {
    const t = computeTaint({ trusted_refs: ['a'] }, { registry: { lookup: () => { throw new Error('boom'); } } });
    expect(t).toMatchObject({ taint: 1, valid: false });
  });
  it('sparse trusted_refs: holes are rejected (no reduce-of-empty TypeError, no silently skipped slot)', () => {
    const ctx = { registry: { lookup: () => undefined } };
    const holes: string[] = new Array(1);
    expect(() => computeTaint({ trusted_refs: holes }, ctx)).not.toThrow();
    expect(computeTaint({ trusted_refs: holes }, ctx)).toMatchObject({ taint: 1, valid: false });
    const mixed = ['a', , 'b'] as string[]; // eslint-disable-line no-sparse-arrays
    expect(computeTaint({ trusted_refs: mixed }, ctx)).toMatchObject({ taint: 1, valid: false });
  });
  it('a hostile provenance getter / registry object cannot make it throw', () => {
    const prov = { get trusted_refs(): unknown { throw new Error('getter'); } };
    expect(() => computeTaint(prov, { registry: { lookup: () => undefined } })).not.toThrow();
    expect(computeTaint(prov, { registry: { lookup: () => undefined } }).valid).toBe(false);
  });
  it('label with an inherited `id` is not read as an id', () => {
    const l = Object.create({ id: 'inherited' }) as any;
    l.kind = 'tool';
    const j = joinLabels([l, { kind: 'tool', id: 'x' }]);
    expect(j).toEqual({ kind: 'tool' });
  });

  describe('enforce.taint gate', () => {
    function build() {
      const P = generateKeyPair();
      const A = generateKeyPair();
      const S = generateKeyPair();
      const grant = mintRoot({ principalSecret: P.secretKey, principalPublic: encodeKey(P.publicKey), holder: encodeKey(A.publicKey), caveats: [{ type: 'ttl', secs: 60 }] });
      const c1 = attenuate(grant, [{ type: 'x' }], A.secretKey);
      const sub = delegate(c1, encodeKey(S.publicKey), [], A.secretKey);
      const nodes = [{ id: 'n1', verb: 'revoke_session', resource: 'sess/1', params_digest: paramsDigest({ a: 1 }), reversibility_class: 'R1', pre: { a: 1 } }];
      const plan = commitPlan(nodes);
      const n = nodes[0]!;
      const body: PCActnBody = {
        ver: 2,
        action: { verb: n.verb, resource: n.resource, params_digest: n.params_digest, reversibility_class: n.reversibility_class },
        grant_ref: grant.id,
        cap_chain: [grant, c1, sub],
        plan: { root: plan.root, inclusion_proof: plan.proofFor(n.id), node_id: n.id, conditions_digest: conditionsDigest(n.pre, undefined) },
        attestation: { quote_digest: 'q', epoch: 1, model_id: 'm', measurement: 'x', operator: 'o' },
        provenance: { causal_hash: 'c', taint_level: 0, trusted_refs: ['ref-x'] },
        freshness: { beacon_ref: 'b', epoch: 1, accumulator_witness: 'w' },
        counter: 7,
        risk_claim: { r: 0.1, inputs: {} },
        aud: 'rs-1',
        iat: NOW,
        exp: NOW + 60_000,
      } as PCActnBody;
      const p: PCActn = signPCActn(body, S.secretKey);
      return { grant, p };
    }
    it('inherited-key label from the registry: gate FAILS at maxTaint 0 (used to pass with NaN taint)', async () => {
      const { grant, p } = build();
      const ctx = { registry: { lookup: () => ({ kind: 'constructor' }) as any } };
      const r = await verifyPCActnCore(p, { insecureSkipPlanRootCheck: true, grant, nowEpoch: NOW, audience: 'rs-1', enforce: { taint: { ctx, maxTaint: 0 } } });
      expect(r.checks.taint_gate).toBe('fail');
      expect(r.allow).toBe(false);
    });
    it('control: a genuinely trusted ref still passes at maxTaint 0', async () => {
      const { grant, p } = build();
      const registry = new InMemoryTrustedInputRegistry().recordTrusted('ref-x');
      const r = await verifyPCActnCore(p, { insecureSkipPlanRootCheck: true, grant, nowEpoch: NOW, audience: 'rs-1', enforce: { taint: { ctx: { registry }, maxTaint: 0 } } });
      expect(r.checks.taint_gate).toBe('pass');
    });
  });
});

// ------------------------------------------------------------------------------------------------
// (4) PolicyVm
// ------------------------------------------------------------------------------------------------
describe('PolicyVm: deepEq is key-order insensitive for lone surrogates; reversibility_max is type-checked', () => {
  const mk = (pairs: Array<[string, number]>): any => {
    const o: any = {};
    for (const [k, v] of pairs) Object.defineProperty(o, k, { value: v, enumerable: true, writable: true, configurable: true });
    return o;
  };
  it('{"\\ud800":1,"\\ud801":2} equals {"\\ud801":2,"\\ud800":1} under eq / ne / in', () => {
    const a = mk([['\ud800', 1], ['\ud801', 2]]);
    const b = mk([['\ud801', 2], ['\ud800', 1]]);
    const ctx = { action: { params: { v: a } } } as any;
    expect(evaluateConditionTri({ field: 'action.params.v', op: 'eq', value: b } as any, ctx)).toBe('true');
    expect(evaluateConditionTri({ field: 'action.params.v', op: 'ne', value: b } as any, ctx)).toBe('false');
    expect(evaluateConditionTri({ field: 'action.params.v', op: 'in', value: [1, b] } as any, ctx)).toBe('true');
    // genuinely different maps stay different
    const c = mk([['\ud800', 1], ['\ud801', 3]]);
    expect(evaluateConditionTri({ field: 'action.params.v', op: 'eq', value: c } as any, ctx)).toBe('false');
    // a real U+FFFD key and a lone surrogate key encode alike: still distinct, still order-insensitive
    const d = mk([['\ud800', 1], ['�', 2]]);
    const e = mk([['�', 2], ['\ud800', 1]]);
    expect(evaluateConditionTri({ field: 'action.params.v', op: 'eq', value: e } as any, { action: { params: { v: d } } } as any)).toBe('true');
  });
  it('compareUtf8 is a deterministic total order over lone surrogates (antisymmetric, 0 only for equal strings)', () => {
    const xs = ['\ud800', '\ud801', '\udc00', '�', 'a', '\u{10000}', '\ud800a', ''];
    for (const x of xs) for (const y of xs) {
      const c = compareUtf8(x, y);
      expect(Math.sign(compareUtf8(y, x)) + Math.sign(c)).toBe(0);
      expect(c === 0).toBe(x === y);
    }
  });
  it('reversibility_max: class must be a string; arrays / objects with toString are not coerced', () => {
    const cx = { now: 1, reversibilityClass: 'irreversible' } as any;
    expect(envelopeCaveatEvaluator({ type: 'reversibility_max', class: 'irreversible' } as any, cx)).toBe(true);
    expect(envelopeCaveatEvaluator({ type: 'reversibility_max', class: ['irreversible'] } as any, cx)).toBe(false);
    expect(envelopeCaveatEvaluator({ type: 'reversibility_max', class: { toString: () => 'irreversible' } } as any, cx)).toBe(false);
    // and the context side
    const lim = { type: 'reversibility_max', class: 'irreversible' } as any;
    expect(envelopeCaveatEvaluator(lim, { now: 1, reversibilityClass: ['reversible'] } as any)).toBe(false);
    expect(envelopeCaveatEvaluator(lim, { now: 1, reversibilityClass: { toString: () => 'reversible' } } as any)).toBe(false);
    expect(envelopeCaveatEvaluator({ type: 'reversibility_max', class: 'reversible' } as any, { now: 1, reversibilityClass: 'rate_limited' } as any)).toBe(false);
  });
});

describe('attacker-keyed lookups: objective-risk canonicalAction', () => {
  it('parameters named constructor / toString / __proto__ are ordinary keys (no spurious duplicate, no dropped key)', async () => {
    const { canonicalAction } = await import('./objective-risk');
    const mk = (params: Record<string, unknown>) => canonicalAction({ verb: 'v', resource: 'r', params } as never);
    const a = Object.create(null) as Record<string, unknown>;
    a['constructor'] = 1;
    a['toString'] = 2;
    expect(() => mk(a)).not.toThrow();
    const p1 = Object.create(null) as Record<string, unknown>;
    p1['__proto__'] = 1;
    const p2 = Object.create(null) as Record<string, unknown>;
    p2['__proto__'] = 2;
    expect(JSON.stringify(mk(p1))).not.toBe(JSON.stringify(mk(p2)));
  });
});

describe('attacker-keyed lookups: facade / templates', () => {
  it('parseLimit rejects inherited-key periods', async () => {
    const { parseLimit } = await import('./facade');
    for (const k of ['constructor', 'toString', 'valueOf', 'hasOwnProperty']) expect(() => parseLimit(`$5/${k}`)).toThrow(/unknown period/);
    expect(parseLimit('$5/day')).toMatchObject({ amount: 5, periodMs: 86_400_000 });
  });
  it('fromTemplate / PolicyBuilder.from reject inherited-key template names', async () => {
    const { fromTemplate } = await import('./policy-templates');
    expect(() => fromTemplate('constructor', { principal: 'p', goal: 'g' } as never)).toThrow(/unknown template/);
  });
});
