/* eslint-disable @typescript-eslint/no-explicit-any */
// Differential tests: the hand-written attestation code (frozen in test/support/legacy) vs the verified Attest.dfy code, which is
// now the PRODUCTION path (src/ext-attest.ts and packages/pca/src/attest-proved.ts, re-exported by test/support/attest-dropins.ts). Scale with ATTEST_N (multiplier, default 1); the cloud runs use ATTEST_N=50 and more.
import * as fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import {
  createAttestationVerifier,
  createDevAttestor,
  attestationRegistry,
  createMultiRootVerifier,
  matchAgentBinding,
  memoryNonceStore,
  requiresAttestation,
  verifyAttestation,
  type AttestationDocument,
  type HardwareAttestationResult,
} from './support/legacy/attestation';
import { mintGrant, type AgentBinding } from '../../pca/src/envelope';
import { buildPCActn } from '../../pca/src/pcactn';
import { encodeKey, generateKeyPair } from '../../pca/src/keys';
import { DEFAULT_RISK_POLICY } from '../../pca/src/risk';
import type { Capability } from '../../pca/src/capability';
import { b64u, hashCanonical } from '../../pca/src/hash';
import {
  signAllowlistManifest,
  verifyAllowlistManifest,
  verifyAllowlistDurable,
  type AllowlistIssuerKey,
} from './support/legacy/attest-allowlist';
import { allowlistAnchorCommit, verifyAllowlistAnchored, type AllowlistAnchorEntry } from './support/legacy/attest-allowlist-anchor';
import { TransparencyLedger, ledgerRootOf, signTreeHead } from '../../pca/src/ledger';
import {
  VerifiedMemoryNonceStore,
  allowlistGate,
  createMultiRootVerifierVerified,
  matchAgentBindingVerified,
  requiresAttestationVerified,
} from '../src/ext-attest';
import {
  createAttestationVerifierVerified,
  verifyAllowlistAnchoredVerified,
  verifyAllowlistDurableVerified,
  verifyAttestationVerified,
} from './support/attest-dropins';
import { Rng } from './support/corpus';

const SCALE = Math.max(1, Number(process.env['ATTEST_N'] ?? 1));
const seedsOf = (n: number, salt: number): number[] => Array.from({ length: n }, (_, i) => (Math.imul(i + 1, 2654435761) ^ salt) >>> 0);
// a pseudo-random pool for Rng: fast-check supplies the entropy so failures shrink/replay by seed
const poolArb = fc.array(fc.integer({ min: 0, max: 2 ** 31 - 1 }), { minLength: 64, maxLength: 512 });
const run = (name: string, runs: number, f: (r: Rng) => void | Promise<void>): void => {
  it(name, async () => {
    await fc.assert(
      fc.asyncProperty(poolArb, async (pool) => {
        await f(new Rng(pool));
      }),
      { numRuns: runs * SCALE },
    );
  }, 600_000);
};
const J = (x: unknown): string => JSON.stringify(x, (_k, v) => (v === undefined ? '__undef' : typeof v === 'number' && !Number.isFinite(v) ? `__num:${String(v)}` : v));

// ---------------------------------------------------------------------------------------------
// A. multi-root
// ---------------------------------------------------------------------------------------------
type Script =
  | { k: 'ok'; m: Record<string, unknown> | boolean | string; host?: unknown; bound?: unknown }
  | { k: 'raw'; v: unknown }
  | { k: 'throw'; v: unknown };
const IDENTS: Array<Record<string, unknown>> = [
  { model_id: 'm1', weights_digest: 'w1', weights_measured: true, runtime_measurement: 'r1', operator: 'o1' },
  { model_id: 'm1', weights_digest: 'w1', weights_measured: false, runtime_measurement: 'r1', operator: '' },
  { model_id: '', weights_digest: '', runtime_measurement: 'r1', operator: 'o1', system_prompt_digest: 's1' },
  { model_id: 'm2', weights_digest: 'w1', weights_measured: true, runtime_measurement: 'r1', operator: 'o1', tool_manifest_digest: 't1' },
  { model_id: 'm1', weights_digest: 'w2', weights_measured: true, runtime_measurement: 'r2', operator: 'o1' },
  { model_id: 'm1', weights_digest: 5, weights_measured: 'yes', runtime_measurement: null, operator: undefined },
  { model_id: 'm1', weights_digest: 'w1', runtime_measurement: 'r1', operator: 'o1', system_prompt_digest: 's2', tool_manifest_digest: 't1' },
  {},
];
const HOSTS = [undefined, { a: 'x' }, { a: 'x', b: 'y' }, 5, 'ab', null];
const RAWS: unknown[] = [null, undefined, 5, 'str', true, {}, { ok: false }, { ok: false, reason: 'nope' }, { ok: true }, { ok: true, bound: true }, { ok: true, bound: true, measured: null }, { ok: 1, bound: true, measured: {} }, { ok: true, bound: 'true', measured: {} }, [], { ok: true, bound: true, measured: true }, { ok: true, bound: true, measured: 'x' }];
function genScript(r: Rng): Script {
  switch (r.next(5)) {
    case 0:
    case 1:
      return { k: 'ok', m: r.pick(IDENTS), host: r.pick(HOSTS) };
    case 2:
      return { k: 'raw', v: r.pick(RAWS) };
    case 3:
      return { k: 'throw', v: r.pick([new Error('boom'), 'str', null, new TypeError('tt')]) };
    default:
      return { k: 'ok', m: r.pick(IDENTS), host: r.pick(HOSTS) };
  }
}
function realize(sc: Script, id: string, calls: Record<string, number>) {
  return {
    verify: async (): Promise<HardwareAttestationResult> => {
      calls[id] = (calls[id] ?? 0) + 1;
      if (sc.k === 'throw') throw sc.v;
      if (sc.k === 'raw') return sc.v as never;
      return { ok: true, bound: true, measured: sc.m as never, ...(sc.host !== undefined ? { hostAsserted: sc.host as never } : {}) };
    },
  };
}
async function compareMulti(scripts: Script[], reqs: boolean[], threshold: number): Promise<void> {
  const mk = (factory: typeof createMultiRootVerifier) => {
    const calls: Record<string, number> = {};
    const v = factory({ roots: scripts.map((s, i) => ({ id: `r${i}`, verifier: realize(s, `r${i}`, calls), required: reqs[i] })), threshold });
    return { v, calls };
  };
  const p = mk(createMultiRootVerifier);
  const q = mk(createMultiRootVerifierVerified as never);
  const rp = await p.v.verify({} as never);
  const rq = await q.v.verify({} as never);
  expect(J(rq)).toBe(J(rp));
  expect(J(q.calls)).toBe(J(p.calls));
}

describe('multi-root N-of-M: production vs verified', () => {
  it('EXHAUSTIVE for M<=3 over the script alphabet x required flags x thresholds', async () => {
    const alphabet: Script[] = [
      { k: 'ok', m: IDENTS[0]! }, { k: 'ok', m: IDENTS[1]!, host: HOSTS[1] }, { k: 'ok', m: IDENTS[2]! }, { k: 'ok', m: IDENTS[4]! },
      { k: 'raw', v: RAWS[7] }, { k: 'raw', v: null }, { k: 'raw', v: RAWS[9] }, { k: 'throw', v: new Error('boom') },
    ];
    let n = 0;
    for (let m = 1; m <= 3; m++) {
      const total = alphabet.length ** m;
      for (let code = 0; code < total; code++) {
        const sc: Script[] = [];
        let c = code;
        for (let i = 0; i < m; i++) { sc.push(alphabet[c % alphabet.length]!); c = Math.floor(c / alphabet.length); }
        for (let rm = 0; rm < 2 ** m; rm++) {
          const reqs = sc.map((_, i) => ((rm >> i) & 1) === 1);
          for (let thr = 1; thr <= m; thr++) { await compareMulti(sc, reqs, thr); n++; }
        }
      }
    }
    expect(n).toBeGreaterThan(5000);
  }, 600_000);

  run('fuzz M<=8, junk results, required flags, thresholds', 400, async (r) => {
    const m = 1 + r.next(8);
    const sc = Array.from({ length: m }, () => genScript(r));
    await compareMulti(sc, sc.map(() => r.next(4) === 0), 1 + r.next(m));
  });

  it('construction errors are identical', () => {
    const v = { verify: async () => ({ ok: true }) };
    for (const pol of [undefined, {}, { roots: [] , threshold: 1}, { roots: [{ id: 'a', verifier: v }], threshold: 0 }, { roots: [{ id: 'a', verifier: v }], threshold: 2 }, { roots: [{ id: 'a', verifier: v }], threshold: 1.5 }, { roots: [{ id: 'a', verifier: v }, { id: 'a', verifier: v }], threshold: 1 }, { roots: [{ id: '', verifier: v }], threshold: 1 }, { roots: [null], threshold: 1 }, { roots: [{ id: 'a', verifier: v }], threshold: 1 }] as any[]) {
      const e1 = (() => { try { createMultiRootVerifier(pol); return 'ok'; } catch (e) { return String(e); } })();
      const e2 = (() => { try { createMultiRootVerifierVerified(pol); return 'ok'; } catch (e) { return String(e); } })();
      expect(e2).toBe(e1);
    }
  });
});

// ---------------------------------------------------------------------------------------------
// B. binding
// ---------------------------------------------------------------------------------------------
/** Literal transcription of the 0.4.2 min_measurement rule (null = passes this stage). */
function strictMin(mm: unknown, rt: unknown): string | null {
  if (mm === undefined || mm === '') return null;
  if (typeof mm === 'string') return rt === mm ? null : 'runtime_measurement does not match required min_measurement';
  const plain = mm !== null && typeof mm === 'object' && !Array.isArray(mm) && [Object.prototype, null].includes(Object.getPrototypeOf(mm));
  const svn = plain ? (mm as { svn?: unknown }).svn : undefined;
  const okSpec = plain && Object.keys(mm as object).join(',') === 'svn' && typeof svn === 'number' && Number.isSafeInteger(svn) && svn >= 0 && !Object.is(svn, -0);
  if (!okSpec) return 'min_measurement is malformed: it must be a non-empty string or {svn: n} with n a non-negative safe integer (fail closed)';
  const n = typeof rt === 'string' && /^(0|[1-9]\d*)$/.test(rt) ? Number(rt) : NaN;
  if (!Number.isSafeInteger(n)) return `runtime_measurement ${rt} is not an integer SVN (required min svn ${svn})`;
  return n < (svn as number) ? `runtime_measurement svn ${n} is below required min svn ${svn}` : null;
}
describe('matchAgentBinding / requiresAttestation: production vs verified', () => {
  const V = ['a', 'b', 'c', '', '7', '12', ' ', 'x1', undefined, null, 5, NaN, true] as unknown[];
  const list = (r: Rng): unknown => r.pick([undefined, [], ['a'], ['a', 'b'], ['b', 'c', 7 as unknown], [NaN], [undefined], 'a', { length: 1 }, ['x1', '7']]);
  const mm = (r: Rng): unknown => r.pick([undefined, '', 'a', 'b', '7', { svn: 5 }, { svn: 7 }, { svn: 0 }, { svn: 12.5 }, { svn: NaN }, { svn: Infinity }, { svn: '5' }, { svn: -0 }, { svn: -1 }, { svn: 5, x: 1 }, {}, null, 5]);
  run('random identities and bindings (incl. junk, thrown runtime types)', 3000, (r) => {
    const id: any = {
      model_id: r.pick(V), weights_digest: r.pick(V), weights_measured: r.pick([true, false, undefined, 'true']),
      runtime_measurement: r.pick(['a', 'b', '7', '5', '4', '0', '12', ' ', '', '1e1', '0x10', ' 8 ', '08', '+8', '7.0', '7.5', 'x', undefined, 5]),
      operator: r.pick(V), system_prompt_digest: r.pick(V), tool_manifest_digest: r.pick(V),
    };
    const b: any = r.pick([undefined, {}, null, 5]) ?? {};
    const binding: any = r.bool() ? { model_allowlist: list(r), min_measurement: mm(r), operator: r.pick(V), weights_allowlist: list(r), system_prompt_allowlist: list(r), tool_manifest_allowlist: list(r), require_hardware: r.pick([true, false, undefined, 1]), require_measured_weights: r.pick([true, false, undefined, 'x']) } : b;
    // 0.4.2: min_measurement / SVN are strict (fail closed). The expected verdict is the frozen oracle's for every other stage and an
    // independent transcription of the new min rule (strictMin) for the min stage; the oracle itself is no longer the reference there.
    const bo = binding !== null && typeof binding === 'object' ? binding : {};
    const withoutMin = { ...bo, min_measurement: undefined };
    const modelFails = Array.isArray(bo.model_allowlist) && bo.model_allowlist.length > 0 && !bo.model_allowlist.includes(id.model_id);
    const minVerdict = strictMin(bo.min_measurement, id.runtime_measurement);
    const expected = modelFails ? matchAgentBinding(id, withoutMin) : minVerdict !== null ? minVerdict : matchAgentBinding(id, withoutMin);
    expect(J(matchAgentBindingVerified(id, binding))).toBe(J(expected));
    const mmPresent = bo.min_measurement !== undefined && bo.min_measurement !== '';
    expect(requiresAttestationVerified(binding)).toBe(requiresAttestation(withoutMin) || mmPresent);
  });
});

// ---------------------------------------------------------------------------------------------
// C/D. verifyAttestation + hook
// ---------------------------------------------------------------------------------------------
const P = generateKeyPair();
const AG = generateKeyPair();
const HOLDER = encodeKey(AG.publicKey);
const T = 1_000_000;
const NONCE = 'q3Vx8mZ0aT7bLk2RwYp9Hs';
const ATT = createDevAttestor(generateKeyPair().secretKey);
const ATT2 = createDevAttestor(generateKeyPair().secretKey);
const BINDINGS: AgentBinding[] = [
  {},
  { model_allowlist: ['gpt-x'], min_measurement: 'm-launch-1', operator: 'acme-cloud', weights_allowlist: ['w-sha-1'] },
  { require_hardware: true },
  { system_prompt_allowlist: ['sp1'], tool_manifest_allowlist: ['tm1'] },
  { min_measurement: { svn: 5 } },
  { require_measured_weights: true, weights_allowlist: ['w-sha-1'] },
];
const grants = BINDINGS.map((b) =>
  mintGrant({ principalSecret: P.secretKey, principalPublic: encodeKey(P.publicKey), holder: HOLDER, goal: 'g', envelope: { predicates: [{ verb: 'read', resource: '/a/*' }], caveats: [], agent_binding: b, risk_policy: DEFAULT_RISK_POLICY } }).grant,
);
function pcactnFor(grant: Capability, quote = NONCE) {
  return buildPCActn({ aud: 'a', grant, chain: [grant], plan: [{ id: 'n1', verb: 'read', resource: '/a/1', reversibility_class: 'reversible' }], nodeId: 'n1', counter: 1, signerSecret: AG.secretKey, attestation: { quote_digest: quote, epoch: 1, model_id: 'gpt-x', measurement: 'm-launch-1', operator: 'acme-cloud' } });
}
const CLAIMS = { model_id: 'gpt-x', weights_digest: 'w-sha-1', runtime_measurement: 'm-launch-1', operator: 'acme-cloud', nonce: NONCE, issued_at: T - 1000, expires_at: T + 60_000 };

function genAttestCase(r: Rng) {
  const gi = r.next(grants.length);
  const grant = grants[gi]!;
  const pc: any = structuredClone(pcactnFor(grant));
  const att = r.next(5) === 0 ? ATT2 : ATT;
  const claims: any = {
    ...CLAIMS,
    runtime_measurement: r.pick(['m-launch-1', '7', '3', '5', 'zz']),
    weights_digest: r.pick(['w-sha-1', 'w-other']),
    model_id: r.pick(['gpt-x', 'gpt-y']),
    issued_at: r.pick([T - 1000, T - 10_000, T + 500, T - 1000.5, T]),
    expires_at: r.pick([T + 60_000, T - 5000, T - 1, T + 0.5, T - 2000]),
    ...(r.bool() ? { system_prompt_digest: r.pick(['sp1', 'sp2']), tool_manifest_digest: r.pick(['tm1', 'tm2']) } : {}),
    nonce: r.next(8) === 0 ? 'other-nonce' : NONCE,
    holder_pub: HOLDER, grant_ref: pc.grant_ref, epoch: r.pick([1, 1, 1, 2]),
  };
  let doc: any = att.attest(claims);
  const sig0: string = doc.sig;
  for (let i = 0, n = r.next(3); i < n; i++) {
    switch (r.next(6)) {
      case 0: doc = { ...doc, sig: r.pick(['x', sig0.slice(1), 5, undefined]) }; break;
      case 1: doc = { ...doc, mode: r.pick(['hardware', 'software', 'x', undefined]) }; break;
      case 2: doc = { ...doc, binding: r.pick(['', 'zz', undefined, 5]) }; break;
      case 3: doc = { ...doc, alg: r.pick(['ml-dsa-65', 'nope', 5]) }; break;
      case 4: doc = { ...doc, expires_at: r.pick([NaN, Infinity, 'x', doc.issued_at - 1]) }; break;
      default: doc = { ...doc, attestor: r.pick([ATT2.publicKey, 5, '']) };
    }
  }
  if (r.next(10) === 0) pc.attestation.epoch = 2;
  if (r.next(10) === 0) pc.attestation.quote_digest = 'zzz';
  if (r.next(12) === 0) pc.grant_ref = 'other';
  const expected: any = { holderPub: HOLDER, grantRef: pc.grant_ref, epoch: r.pick([1, 1, 1, 2]), nonce: pc.attestation.quote_digest === NONCE && r.next(10) ? NONCE : r.pick([NONCE, 'q', 7]), nonceIssuedAt: r.pick([T - 1000, T - 400_000, T + 900, undefined, NaN, '5', T - 1000.5, T - 300_000, T - 299_999, 0.5]) };
  if (r.next(15) === 0) expected.holderPub = 5;
  const hwMode = r.next(4) === 0;
  const hwScripts: HardwareAttestationResult[] = [
    { ok: true, bound: true, measured: { model_id: 'gpt-x', weights_digest: 'w-sha-1', weights_measured: true, runtime_measurement: 'm-launch-1', operator: 'acme-cloud', system_prompt_digest: 'sp1', tool_manifest_digest: 'tm1' } },
    { ok: true, bound: false, measured: { model_id: 'gpt-x', weights_digest: 'w', runtime_measurement: '7', operator: 'x' } },
    { ok: true, bound: true },
    { ok: false, reason: 'hw bad' },
    { ok: false },
    { ok: true, bound: true, measured: { model_id: 'gpt-y', weights_digest: 'w', weights_measured: false, runtime_measurement: '7', operator: 'x' } },
  ];
  const hw = hwMode ? { verify: async () => r.pick(hwScripts) } : undefined;
  const hwSeed = r.next(hwScripts.length);
  const hwv = hwMode ? { verify: async () => hwScripts[hwSeed]! } : undefined;
  void hw;
  return {
    document: doc as AttestationDocument, ctx: { pcactn: pc, grant }, expected,
    nowMs: r.pick([T, T, T, T + 5000, T - 2000, T + 70_000, T + 0.5]), trustedAttestorKeys: r.next(6) === 0 ? [] : [ATT.publicKey],
    hardwareVerifier: hwv, maxNonceAgeMs: r.pick([undefined, 5000, 1e9, 0, -1, NaN, 1500.5, 100]), clockSkewMs: r.pick([undefined, 0, 100, 2000, NaN, 0.5, 1e12, -5]),
  };
}

describe('verifyAttestation / hook: production vs verified', () => {
  run('random software + hardware attestation cases (verdict JSON-identical)', 1500, async (r) => {
    const c = genAttestCase(r);
    const a = await verifyAttestation(c as never);
    const b = await verifyAttestationVerified(c as never);
    expect(J(b)).toBe(J(a));
  });

  run('hook with a single-use nonce store: sequences of repeated presentations', 300, async (r) => {
    const c = genAttestCase(r);
    const cap = r.pick([1, 2, 100]);
    const sp = memoryNonceStore(cap);
    const sv = new VerifiedMemoryNonceStore(cap);
    const mk = (f: any, store: any) =>
      f({ trustedAttestorKeys: c.trustedAttestorKeys as string[], resolveDocument: attestationRegistry([c.document]), expectedBinding: () => c.expected, now: () => c.nowMs, hardwareVerifier: c.hardwareVerifier, maxNonceAgeMs: c.maxNonceAgeMs, clockSkewMs: c.clockSkewMs, nonceStore: store, minNonceBytes: 16 });
    const hp = mk(createAttestationVerifier, sp);
    const hv = mk(createAttestationVerifierVerified, sv);
    for (let i = 0; i < 3; i++) expect(J(await hv(c.ctx))).toBe(J(await hp(c.ctx)));
    // without a store, and with the insecure self-declared nonce opt-out
    const hp2 = createAttestationVerifier({ trustedAttestorKeys: c.trustedAttestorKeys as string[], resolveDocument: attestationRegistry([c.document]), insecure_selfDeclaredNonce: true, now: () => c.nowMs, nonceStore: memoryNonceStore() });
    const hv2 = createAttestationVerifierVerified({ trustedAttestorKeys: c.trustedAttestorKeys as string[], resolveDocument: attestationRegistry([c.document]), insecure_selfDeclaredNonce: true, now: () => c.nowMs, nonceStore: new VerifiedMemoryNonceStore() });
    expect(J(await hv2(c.ctx))).toBe(J(await hp2(c.ctx)));
  });
});

// ---------------------------------------------------------------------------------------------
// D. nonce store model
// ---------------------------------------------------------------------------------------------
describe('memoryNonceStore: production vs the proved model', () => {
  run('random consume sequences x capacities 1..6 x retention x an injected (non-monotone) clock: identical answers', 800, (r) => {
    const cap = 1 + r.next(6);
    const retentionMs = r.pick([1, 5, 10, 100, 3_600_000]);
    let t = r.pick([0, 1_800_000_000_000]);
    const clock = () => t;
    const p = memoryNonceStore(cap, { retentionMs, now: clock });
    const v = new VerifiedMemoryNonceStore(cap, { retentionMs, now: clock });
    for (let i = 0, n = 5 + r.next(80); i < n; i++) {
      t += r.pick([0, 0, 1, 2, 3, 7, 50, -1, -5, retentionMs, retentionMs - 1]);
      const nonce = `n${r.next(9)}`;
      expect(v.consume(nonce), `step ${i}`).toBe(p.consume(nonce));
    }
    // non-integer clock values (NaN, Infinity, fractional ms, a string) are rejected by both (fail closed)
    for (const bad of [Number.NaN, Infinity, t + 0.5, 1e300, '5' as unknown as number]) {
      t = bad;
      expect(v.consume('z')).toBe(false);
      expect(p.consume('z')).toBe(false);
    }
  });
  it('construction checks are identical (max < 1, non-integer, invalid retention)', () => {
    const msg = (f: () => unknown) => { try { f(); return 'ok'; } catch (e) { return String(e); } };
    for (const [m, o] of [[0, {}], [-1, {}], [1.5, {}], [Number.NaN, {}], [1, { retentionMs: 0 }], [1, { retentionMs: Number.NaN }], [1, { retentionMs: -5 }], [1, { retentionMs: 2.5 }], [1, { retentionMs: Infinity }], [3, { retentionMs: 10 }]] as Array<[number, any]>) {
      expect(msg(() => new VerifiedMemoryNonceStore(m, o))).toBe(msg(() => memoryNonceStore(m, o)));
    }
  });
  it('the old replay-after-eviction finding is gone in BOTH (Attest.dfy LiveNeverEvicted / FullOfLiveRefuses)', () => {
    const s1 = memoryNonceStore(1);
    const v1 = new VerifiedMemoryNonceStore(1);
    expect([s1.consume('a'), s1.consume('b'), s1.consume('a')]).toEqual([true, false, false]);
    expect([v1.consume('a'), v1.consume('b'), v1.consume('a')]).toEqual([true, false, false]);
  });
});

// ---------------------------------------------------------------------------------------------
// E. allowlist
// ---------------------------------------------------------------------------------------------
const OPS = generateKeyPair();
const OTHER = generateKeyPair();
const ISSUER_KEYS: Record<string, AllowlistIssuerKey> = { ops: { alg: 'ed25519', keys: { edPub: b64u(OPS.publicKey) } } };
const NOW = 1_800_000_000_000;
const ENTRY = { kind: 'tdx-mrtd' as const, value: 'ab'.repeat(48), label: 'boot' };
const GATE_CODE: Record<string, string> = { shape: 'malformed', options: 'malformed', 'unknown-issuer': 'unknown-issuer', 'alg-mismatch': 'alg-mismatch', 'issuer-expired': 'issuer-expired', 'bad-signature': 'bad-signature', 'not-yet-valid': 'not-yet-valid', expired: 'expired', 'lifetime-too-long': 'lifetime-too-long', 'below-min-version': 'below-min-version', rollback: 'rollback', conflict: 'conflict' };
const DAY = 86_400_000;

describe('allowlist ordering/rollback: production verifyAllowlistManifest vs the proved gate', () => {
  run('random signed manifests x registry variants x numerics', 2500, (r) => {
    const version = 1 + r.next(6);
    const notBefore = NOW + r.pick([-3 * DAY, -DAY, -5, 0, 7, DAY]);
    const expiresAt = notBefore + r.pick([1, 1000, DAY, 30 * DAY]);
    const body = { version, issuedAt: notBefore, notBefore, expiresAt, entries: [ENTRY] };
    const variant = r.next(10);
    const shapeOk = variant !== 0;
    const signer = variant === 1 ? OTHER : OPS;
    const sm: any = signAllowlistManifest(shapeOk ? body : { ...body, version: 1 }, { issuer: 'ops', alg: 'ed25519', secrets: { edSecret: signer.secretKey } });
    if (!shapeOk) sm.body = { ...sm.body, version: 0 };
    const issuerKnown = variant !== 2;
    const algMatches = variant !== 3;
    const nowMs = NOW + r.pick([0, 0, 5, DAY, -DAY, 40 * DAY]);
    const issuerLive = variant !== 4;
    const reg: Record<string, AllowlistIssuerKey> = issuerKnown ? { ops: { alg: algMatches ? 'ed25519' : 'ml-dsa-65', keys: { edPub: b64u(OPS.publicKey) }, ...(issuerLive ? {} : { notAfter: nowMs - 1 }) } } : {};
    const skew = r.pick([undefined, 0, 10, 1000, DAY, 0.5, 2.5, 1000.75, -5, NaN, Infinity]);
    const maxLife = r.pick([undefined, 500, DAY, 100 * DAY, 1500.5, NaN]);
    const minV = r.pick([undefined, 1, 3, 9, NaN]);
    const last = r.pick([undefined, 1, 3, 9, 2.5]);
    const digest = hashCanonical(sm.body ?? body);
    const lastDigest = r.pick([undefined, digest, 'A'.repeat(43)]);
    const opts: any = { issuerKeys: reg, nowMs, ...(skew !== undefined ? { clockSkewMs: skew } : {}), ...(maxLife !== undefined ? { maxLifetimeMs: maxLife } : {}), ...(minV !== undefined ? { minVersion: minV } : {}), ...(last !== undefined ? { lastSeenVersion: last } : {}), ...(lastDigest !== undefined ? { lastSeenDigest: lastDigest } : {}) };
    const prod = verifyAllowlistManifest(sm, opts);
    const gate = allowlistGate({
      shapeOk, issuerKnown, algMatches, issuerLive, sigOk: variant !== 1,
      nowMs, skew: skew ?? 0, notBefore, expiresAt, maxLifetimeMs: maxLife, minVersion: minV, version, lastSeenVersion: last, lastSeenDigest: lastDigest, digest,
    });
    if (prod.ok) expect(gate).toBeUndefined();
    else expect(gate === undefined ? 'ACCEPT' : GATE_CODE[gate]).toBe(prod.code);
  });

  it('FIXED: a NaN / Infinity clockSkewMs no longer disables the manifest validity window (fails closed)', () => {
    const sm = signAllowlistManifest({ version: 1, issuedAt: NOW - 100 * DAY, notBefore: NOW - 100 * DAY, expiresAt: NOW - 50 * DAY, entries: [ENTRY] }, { issuer: 'ops', alg: 'ed25519', secrets: { edSecret: OPS.secretKey } });
    const base = { issuerKeys: ISSUER_KEYS, nowMs: NOW };
    expect(verifyAllowlistManifest(sm, base)).toMatchObject({ ok: false, code: 'expired' });
    expect(verifyAllowlistManifest(sm, { ...base, clockSkewMs: NaN })).toMatchObject({ ok: false });
    expect(verifyAllowlistManifest(sm, { ...base, clockSkewMs: Infinity })).toMatchObject({ ok: false });
    const fut = signAllowlistManifest({ version: 1, issuedAt: NOW, notBefore: NOW + 50 * DAY, expiresAt: NOW + 60 * DAY, entries: [ENTRY] }, { issuer: 'ops', alg: 'ed25519', secrets: { edSecret: OPS.secretKey } });
    expect(verifyAllowlistManifest(fut, { ...base, clockSkewMs: NaN })).toMatchObject({ ok: false });
    // the proved gate rejects a non-finite skew as `options` (Attest.dfy OptionsFailClosed)
    expect(allowlistGate({ shapeOk: true, issuerKnown: true, algMatches: true, issuerLive: true, sigOk: true, nowMs: NOW, skew: NaN, notBefore: 0, expiresAt: 1, version: 1, digest: 'd' })).toBe('options');
  });
});

// ---- durable high-water mark ----
function memKv(initial: Record<string, unknown> = {}, beforeUpdate?: (store: Map<string, unknown>) => void) {
  const store = new Map<string, unknown>(Object.entries(initial));
  return {
    store,
    async get(k: string) { return store.get(k); },
    async set(k: string, v: unknown) { store.set(k, v); },
    async update(k: string, fn: (p: unknown) => unknown) { beforeUpdate?.(store); const n = fn(store.get(k)); if (n !== undefined) store.set(k, n); return store.get(k); },
    async keys() { return [...store.keys()]; },
  };
}
const manifestV = (version: number, label: string) => signAllowlistManifest({ version, issuedAt: NOW, notBefore: NOW - DAY, expiresAt: NOW + 30 * DAY, entries: [{ ...ENTRY, label }] }, { issuer: 'ops', alg: 'ed25519', secrets: { edSecret: OPS.secretKey } });
const MANIFESTS = [manifestV(1, 'a'), manifestV(2, 'a'), manifestV(2, 'b'), manifestV(3, 'a'), manifestV(3, 'b'), manifestV(5, 'a')];
const dig = (m: any): string => hashCanonical(m.body);

describe('verifyAllowlistDurable: production vs verified (sequences, corrupt records, concurrent writers)', () => {
  run('random manifest sequences and injected concurrent writes', 600, async (r) => {
    const init = r.pick([{}, { 'allowlist/ops': { version: 2, digest: dig(MANIFESTS[1]) } }, { 'allowlist/ops': { version: 3, digest: dig(MANIFESTS[3]) } }, { 'allowlist/ops': 'junk' }, { 'allowlist/ops': { version: 2, digest: 'short' } }]);
    const inject = r.next(3) === 0 ? r.pick([{ version: 3, digest: dig(MANIFESTS[3]) }, { version: 2, digest: dig(MANIFESTS[2]) }, { version: 5, digest: dig(MANIFESTS[5]) }, 'junk']) : undefined;
    const seq = Array.from({ length: 1 + r.next(6) }, () => r.pick(MANIFESTS));
    const kvP = memKv(structuredClone(init), inject !== undefined ? (s) => { if (!s.has('__injected')) { s.set('__injected', 1); s.set('allowlist/ops', structuredClone(inject)); } } : undefined);
    const kvV = memKv(structuredClone(init), inject !== undefined ? (s) => { if (!s.has('__injected')) { s.set('__injected', 1); s.set('allowlist/ops', structuredClone(inject)); } } : undefined);
    const opts = { issuerKeys: ISSUER_KEYS, nowMs: NOW };
    for (const m of seq) {
      const a = await verifyAllowlistDurable(m, opts, kvP as never);
      const b = await verifyAllowlistDurableVerified(m, opts, kvV as never);
      expect(J(b)).toBe(J(a));
      expect(J([...kvV.store])).toBe(J([...kvP.store]));
    }
  });

  it('FIXED (Attest.dfy EqualVersionConflict / WritesStrictlyIncrease): a same-version/different-digest racing writer is a conflict and does not overwrite', async () => {
    const m2b = MANIFESTS[2]!;
    const mk = () => memKv({}, (s) => { if (!s.has('__i')) { s.set('__i', 1); s.set('allowlist/ops', { version: 2, digest: dig(MANIFESTS[1]) }); } });
    const kv = mk();
    const res = await verifyAllowlistDurable(m2b, { issuerKeys: ISSUER_KEYS, nowMs: NOW }, kv as never);
    expect(res).toMatchObject({ ok: false, code: 'conflict' });
    expect(kv.store.get('allowlist/ops')).toEqual({ version: 2, digest: dig(MANIFESTS[1]) }); // not overwritten
    const kvV = mk();
    expect(await verifyAllowlistDurableVerified(m2b, { issuerKeys: ISSUER_KEYS, nowMs: NOW }, kvV as never)).toMatchObject({ ok: false, code: 'conflict' });
    expect(kvV.store.get('allowlist/ops')).toEqual({ version: 2, digest: dig(MANIFESTS[1]) });
  });
});

// ---- anchored feed ----
const GUARD = generateKeyPair();
const TRUST = { logKey: b64u(GUARD.publicKey), instanceId: 'inst', principal: 'log' };
const D43 = ['A', 'B', 'C'].map((c) => c.repeat(43));
describe('verifyAllowlistAnchored: production vs verified (real signed heads, proofs, consistency)', () => {
  run('random feeds (conflicts, rollbacks, cached heads, stale heads, bad proofs)', 700, (r) => {
    const n = 1 + r.next(6);
    const entries: AllowlistAnchorEntry[] = Array.from({ length: n }, () => ({ issuer: r.pick(['ops', 'ops', 'ops2']), version: 1 + r.next(4), digest: r.pick(D43) }));
    const ledger = new TransparencyLedger(TRUST.principal);
    const commits = entries.map(allowlistAnchorCommit);
    commits.forEach((c) => ledger.appendCommitment(c));
    const ts = NOW + r.pick([0, -5, -DAY - 10, 100, 61_000, 1e6]);
    const head0 = ledger.head();
    const head = signTreeHead(GUARD.secretKey, { instance_id: TRUST.instanceId, principal: TRUST.principal, size: head0.size, root: head0.root, prev_root: '', timestamp: ts });
    const minePick = r.next(4);
    const mine: AllowlistAnchorEntry = minePick === 0 ? { issuer: 'ops', version: 1 + r.next(5), digest: r.pick(D43) } : { ...entries[r.next(n)]! };
    const idx = r.next(4) === 0 ? r.next(n) : Math.max(0, commits.indexOf(allowlistAnchorCommit(mine)));
    let proof: any;
    try { proof = ledger.inclusionProof(Math.min(idx, n - 1)); } catch { proof = ledger.inclusionProof(0); }
    if (r.next(10) === 0) proof = { ...proof, size: proof.size + 1 };
    let cachedHead: any;
    let consistency: any;
    if (r.next(3) === 0) {
      const csize = r.next(n + 1);
      if (csize > 0) {
        const sub = new TransparencyLedger(TRUST.principal);
        const divergent = r.next(4) === 0;
        commits.slice(0, csize).forEach((c, i) => sub.appendCommitment(divergent && i === csize - 1 ? c + 'x' : c));
        const h = sub.head();
        cachedHead = signTreeHead(GUARD.secretKey, { instance_id: TRUST.instanceId, principal: TRUST.principal, size: h.size, root: h.root, prev_root: '', timestamp: NOW });
        if (csize < n && r.next(5) > 0) { try { consistency = ledger.consistencyProof(csize, n); } catch { /* none */ } }
      } else {
        cachedHead = signTreeHead(GUARD.secretKey, { instance_id: TRUST.instanceId, principal: TRUST.principal, size: 0, root: ledgerRootOf([]), prev_root: '', timestamp: NOW });
      }
    }
    const feedEntries = r.next(15) === 0 ? entries.slice(1) : entries;
    const evidence: any = { head: r.next(25) === 0 ? { ...head, sig: 'AAAA' } : head, entries: feedEntries, proof, ...(consistency ? { consistency } : {}) };
    const verified: any = { ok: true, issuer: mine.issuer, version: mine.version, digest: mine.digest, body: {}, alg: 'ed25519' };
    const opts: any = { trust: TRUST, nowMs: NOW + r.pick([0, 1000, DAY, 3 * DAY]), ...(cachedHead ? { cachedHead } : {}), ...(r.bool() ? { clockSkewMs: r.pick([0, 500, 0.5, NaN, Infinity, 100_000]) } : {}), ...(r.bool() ? { maxHeadAgeMs: r.pick([1000, DAY, 1.5, NaN, Infinity]) } : {}) };
    const a = verifyAllowlistAnchored(verified, evidence, opts);
    const b = verifyAllowlistAnchoredVerified(verified, evidence, opts);
    expect(J(b)).toBe(J(a));
  });
});

void seedsOf;
