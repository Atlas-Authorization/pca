// Glue contract-checking mode. The PRODUCTION glue (packages/pca/src, unmodified) runs the existing conformance corpus plus fuzz; at the
// module boundaries it calls, vi.mock installs wrappers (wrappers.ts) that recompute every signature-verification boolean, every
// canonical-hash/digest and every strict-base64url decision with INDEPENDENT code (reference.ts: BigInt curve model + OpenSSL, OpenSSL ML-DSA/SLH-DSA,
// node:crypto SHA-2, a second canonical-JSON implementation). Any disagreement is recorded; the tests fail if any was recorded.
// Env: GLUE_N (fuzz iterations per workload, default 1500), GLUE_SEED, GLUE_OUT (summary json), GLUE_DUMP (jsonl of primitive calls for the
// multi-implementation replay: tools/pca-trustbase/primitives/run.mjs --suite replay --replay <file>).
import { describe, expect, it, afterAll } from 'vitest';
import { vi } from 'vitest';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

vi.mock('../../../../pca/src/keys', async (orig) => {
  const real = await orig<Record<string, unknown>>();
  const { wrapKeys } = await import('./wrappers');
  const { monitor } = await import('./monitor');
  return wrapKeys(real, monitor);
});
vi.mock('../../../../pca/src/pq', async (orig) => {
  const real = await orig<Record<string, unknown>>();
  const { wrapPq } = await import('./wrappers');
  const { monitor } = await import('./monitor');
  return wrapPq(real, monitor);
});
vi.mock('../../../../pca/src/hash', async (orig) => {
  const real = await orig<Record<string, unknown>>();
  const { wrapHash } = await import('./wrappers');
  const { monitor } = await import('./monitor');
  return wrapHash(real, monitor);
});
vi.mock('../../../../pca/node_modules/@noble/hashes/esm/sha256.js', async (orig) => {
  const real = await orig<Record<string, unknown>>();
  const { wrapShaModule } = await import('./wrappers');
  const { monitor } = await import('./monitor');
  return wrapShaModule(real, monitor, { sha256: 'sha256' });
});
vi.mock('../../../../pca/node_modules/@noble/hashes/esm/sha512.js', async (orig) => {
  const real = await orig<Record<string, unknown>>();
  const { wrapShaModule } = await import('./wrappers');
  const { monitor } = await import('./monitor');
  return wrapShaModule(real, monitor, { sha512: 'sha512', sha384: 'sha384' });
});

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { delegate, mintRoot } from '../../../../pca/src/capability';
import { b64u, unb64u, utf8 } from '../../../../pca/src/hash';
import { generateKeyPair, verifyB64u, verify as edVerify, sign as edSign } from '../../../../pca/src/keys';
import { paramsDigest } from '../../../../pca/src/merkle';
import { buildPCActn, decodePCActn, signPCActnSuite, verifyPCActnCore, type PCActn } from '../../../../pca/src/pcactn';
import {
  encodeMlDsa87PublicKey, encodeMlDsaPublicKey, encodeSlhDsa256sPublicKey, encodeSlhDsaPublicKey, mlDsa65Keygen, mlDsa87Keygen, resolvePqVerifyKey, signWithSuite,
  slhDsa128fKeygen, slhDsa256sKeygen, verifyLeafSuite, verifyWithSuite, type SigAlg,
} from '../../../../pca/src/pq';
import { assembleThreshold, signShare, verifyThreshold, type Signer } from '../../../../pca/src/threshold';
import { verifyPCActn } from '../../../../pca/src/server/verify';
import { Prng, bytes } from './prng';
import { monitor, Monitor } from './monitor';
import { wrapPq, wrapKeys, wrapHash } from './wrappers';
import { loadCorpus } from '../../support/corpus';
// @ts-expect-error plain-ESM helper shared with the primitives harness
import { edAdversarial } from '../../../../../tools/pca-trustbase/primitives/lib/ed-cases.mjs';

const N = Number(process.env.GLUE_N ?? 1500);
const SEED = Number(process.env.GLUE_SEED ?? 424242);
const NOW = 1_800_000_000_000;

const settle = (label: string) => {
  const v = monitor.violations.slice(0, 5);
  expect(v, `${label}: contract violations (first 5 shown); full list in the summary`).toEqual([]);
};

describe('glue contract monitor: self-test (it must catch planted faults)', () => {
  it('flags a wrong signature verdict, a wrong digest and a wrong b64u decision', async () => {
    const m = new Monitor();
    const realPq = { isPinnedPqKey: () => true, verifyWithSuite: () => true, verifyLeafSuite: () => true };
    const w = wrapPq(realPq, m);
    const kp = generateKeyPair();
    const msg = utf8('m');
    const sig = b64u(edSign(kp.secretKey, msg));
    // flip the character that is replaced (testing the LAST character left bad === sig about 1 time in 64)
    const bad = sig.slice(0, -2) + (sig[sig.length - 2] === 'A' ? 'B' : 'A') + sig.slice(-1);
    expect(w.verifyWithSuite('ed25519', { edPub: b64u(kp.publicKey) }, msg, { sig })).toBe(true); // agrees
    expect(m.violationCount).toBe(0);
    w.verifyWithSuite('ed25519', { edPub: b64u(kp.publicKey) }, msg, { sig: bad }); // planted fault: always-true verifier
    expect(m.violationCount).toBe(1);
    const wk = wrapKeys({ verify: () => true, verifyB64u: () => true }, m);
    expect(wk.verifyB64u(b64u(kp.publicKey), msg, bad)).toBe(true);
    expect(m.violationCount).toBe(2);
    const wh = wrapHash({ hashCanonical: () => 'AAAA', canonicalizeStrict: () => '{}', decodeB64uStrict: () => new Uint8Array(1) }, m);
    wh.hashCanonical({ a: 1 });
    wh.canonicalizeStrict({ a: 1 });
    wh.decodeB64uStrict('!!', 1);
    expect(m.violationCount).toBe(5);
    // a verifier that is wrong ONLY on small-order public keys (the realistic bug) is caught
    const so = '0100000000000000000000000000000000000000000000000000000000000000';
    const wk2 = wrapKeys({ verify: () => true, verifyB64u: () => true }, new Monitor());
    const mm = new Monitor();
    const wk3 = wrapKeys({ verify: () => true, verifyB64u: () => true }, mm);
    wk3.verify(Uint8Array.from(Buffer.from(so, 'hex')), msg, new Uint8Array(64));
    expect(mm.violationCount).toBe(1);
    void wk2;
  });
});

// ---------------------------------------------------------------- shared fixtures
const edA = generateKeyPair();
const ml65 = mlDsa65Keygen(new Uint8Array(32).fill(1));
const ml87 = mlDsa87Keygen(new Uint8Array(32).fill(2));
const slh128 = slhDsa128fKeygen(new Uint8Array(48).fill(3));
const slh256 = slhDsa256sKeygen(new Uint8Array(96).fill(4));
const KEYS = { edSecret: edA.secretKey, mlDsa: ml65, mlDsa87: ml87, slhDsa: slh128, slhDsa256s: slh256 };
const PQPK: Record<string, string | undefined> = {
  'ed25519': undefined,
  'ml-dsa-65': encodeMlDsaPublicKey(ml65.publicKey), 'hybrid-ed25519-ml-dsa-65': encodeMlDsaPublicKey(ml65.publicKey), 'hybrid-nested-ed25519-ml-dsa-65': encodeMlDsaPublicKey(ml65.publicKey),
  'ml-dsa-87': encodeMlDsa87PublicKey(ml87.publicKey), 'hybrid-ed25519-ml-dsa-87': encodeMlDsa87PublicKey(ml87.publicKey),
  'slh-dsa-sha2-128f': encodeSlhDsaPublicKey(slh128.publicKey), 'hybrid-ed25519-slh-dsa-sha2-128f': encodeSlhDsaPublicKey(slh128.publicKey),
  'slh-dsa-sha2-256s': encodeSlhDsa256sPublicKey(slh256.publicKey), 'hybrid-ed25519-slh-dsa-sha2-256s': encodeSlhDsa256sPublicKey(slh256.publicKey),
};
const ALGS = Object.keys(PQPK) as SigAlg[];
const SLOW = new Set(['slh-dsa-sha2-256s', 'hybrid-ed25519-slh-dsa-sha2-256s', 'slh-dsa-sha2-128f', 'hybrid-ed25519-slh-dsa-sha2-128f']);

interface Signed { alg: SigAlg; msg: Uint8Array; sig: string; pq_sig?: string; edPub: string; pqPk?: string }
const signedPool: Signed[] = [];
function pool(): Signed[] {
  if (signedPool.length) return signedPool;
  const r = new Prng(SEED);
  for (const alg of ALGS) {
    const reps = SLOW.has(alg) ? 2 : 5;
    for (let i = 0; i < reps; i++) {
      const msg = bytes(r, r.pick([0, 1, 32, 100, 1000]));
      const p = signWithSuite(alg, KEYS as never, msg);
      signedPool.push({ alg, msg, sig: p.sig, ...(p.pq_sig !== undefined ? { pq_sig: p.pq_sig } : {}), edPub: b64u(edA.publicKey), ...(PQPK[alg] ? { pqPk: PQPK[alg] } : {}) });
    }
  }
  return signedPool;
}

const flipChar = (s: any, r: Prng) => { if (typeof s !== 'string' || !s.length) return s; const i = r.int(s.length); const a = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'; return s.slice(0, i) + a[(a.indexOf(s[i]!) + 1 + r.int(63)) % 64] + s.slice(i + 1); };
const flipBit = (s: any, r: Prng) => { if (typeof s !== 'string' || !s.length) return s; const b = Buffer.from(s, 'base64url'); b[r.int(b.length)]! ^= 1 << r.int(8); return b.toString('base64url'); };
const trailing = (s: string) => { // set a non-canonical trailing-bit variant of the last char when possible
  const a = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const rem = s.length % 4; if (rem === 0 || rem === 1) return s + '=';
  const last = a.indexOf(s[s.length - 1]!); const mask = rem === 2 ? 15 : 3; return s.slice(0, -1) + a[last ^ (1 + (last & mask ? 0 : 0))]!;
};
const JUNK: unknown[] = [undefined, null, 0, 1, -1, 1.5, NaN, '', 'x', [], {}, true, false, 'AAAA', '=', 'A'.repeat(100)];

function mutateSigned(s: Signed, r: Prng): { alg: unknown; edPub: unknown; pqPk: unknown; msg: Uint8Array; sig: unknown; pq_sig: unknown } {
  let { alg, msg, sig, pq_sig, edPub, pqPk } = s as { alg: unknown; msg: Uint8Array; sig: unknown; pq_sig: unknown; edPub: unknown; pqPk: unknown };
  const n = 1 + r.int(2);
  for (let k = 0; k < n; k++) {
    switch (r.int(14)) {
      case 0: if (typeof sig === 'string') sig = flipChar(sig, r); break;
      case 1: if (typeof sig === 'string') sig = flipBit(sig, r); break;
      case 2: if (typeof pq_sig === 'string') pq_sig = flipChar(pq_sig, r); break;
      case 3: if (typeof pq_sig === 'string') pq_sig = flipBit(pq_sig, r); break;
      case 4: if (typeof pqPk === 'string') pqPk = flipBit(pqPk, r); break;
      case 5: if (typeof edPub === 'string') edPub = flipBit(edPub, r); break;
      case 6: msg = msg.length ? Uint8Array.from(msg, (b, i) => (i === r.int(msg.length) ? b ^ 1 : b)) : Uint8Array.of(1); break;
      case 7: { const t = sig; sig = pq_sig; pq_sig = t; break; }
      case 8: if (typeof sig === 'string') sig = sig.slice(0, Math.max(0, sig.length - 1 - r.int(4))); break;
      case 9: if (typeof pq_sig === 'string') pq_sig = pq_sig + 'A'.repeat(1 + r.int(3)); break;
      case 10: sig = r.pick(JUNK); break;
      case 11: pq_sig = r.pick(JUNK); break;
      case 12: alg = r.pick([...ALGS, undefined, null, 'ED25519', 'ml-dsa-65 ', 'fn-dsa-512', 'less-cat1', 'hybrid-ed25519-less-cat1', 7, {}]); break;
      case 13: if (typeof sig === 'string') sig = trailing(sig); break;
    }
  }
  return { alg, edPub, pqPk, msg, sig, pq_sig };
}
const mintKey = (pk: unknown) => (typeof pk === 'string' ? resolvePqVerifyKey('', undefined, { trustedPk: pk }) ?? undefined : undefined);

// ---------------------------------------------------------------- workloads
describe('glue contract monitor: conformance corpus through the production verifier', () => {
  it('replays core + adversarial corpus (verifyPCActnCore and verifyPCActn) with every primitive result re-computed', async () => {
    const { core, adversarial } = loadCorpus();
    let n = 0;
    for (const v of [...core, ...adversarial]) {
      let p: any = v.pcactn;
      if (v.pcactn_json !== undefined) { try { p = decodePCActn(v.pcactn_json); } catch { continue; } }
      const o = { grant: v.grant, nowEpoch: v.context.now, audience: v.context.aud };
      await verifyPCActnCore(p, o);
      if (n % 7 === 0) { await verifyPCActnCore(p, { ...o, allowedSuites: ['ed25519'] as never }); await verifyPCActnCore(p, { ...o, allowUnboundPq: true }); }
      if (n % 3 === 0) await verifyPCActn(p, { grant: v.grant, now: v.context.now, audience: v.context.aud } as never);
      n++;
    }
    monitor.note('corpus.vectors', n);
    expect(n).toBeGreaterThan(3000);
    settle('corpus');
  }, 3_600_000);

  it('replays the conformance primitives (threshold shares, PQ artifacts, strict base64url)', () => {
    const file = JSON.parse(readFileSync(join(__dirname, '..', '..', '..', '..', 'pca', 'conformance', 'vectors.json'), 'utf8'));
    for (const e of file.primitives.threshold_share) verifyWithSuite(e.share.alg, { edPub: e.share.publicKey, pq: mintKey(e.share.pq_pk) }, unb64u(e.share_message), { sig: e.share.sig, pq_sig: e.share.pq_sig });
    for (const e of file.primitives.pq_artifact ?? []) verifyWithSuite(e.alg, { edPub: e.ed_pub, pq: mintKey(e.pq_pk) }, unb64u(e.message), { sig: e.sig, pq_sig: e.pq_sig });
    settle('conformance primitives');
  }, 600_000);
});

describe('glue contract monitor: fuzz', () => {
  it('verifyWithSuite / verifyLeafSuite over every suite: valid + structured mutations (swapped fields, trailing bits, truncation, wrong types, other algs)', () => {
    const r = new Prng(SEED + 1); const P = pool(); let valid = 0;
    // all pristine signatures must be accepted by BOTH glue and reference
    for (const s of P) { const ok = verifyWithSuite(s.alg, { edPub: s.edPub, pq: mintKey(s.pqPk) }, s.msg, { sig: s.sig, pq_sig: s.pq_sig }); expect(ok, s.alg).toBe(true); valid++; }
    for (let i = 0; i < N; i++) {
      const s = P[r.int(P.length)]!; const m = mutateSigned(s, r);
      const keys = { edPub: m.edPub, ...(mintKey(m.pqPk) ? { pq: mintKey(m.pqPk) } : {}) };
      verifyWithSuite(m.alg, keys as never, m.msg, { sig: m.sig, pq_sig: m.pq_sig } as never);
      if (i % 4 === 0) verifyLeafSuite({ alg: m.alg as never, holder: m.edPub as never, ...(keys.pq ? { pq: keys.pq } : {}), message: m.msg, sig: m.sig as never, pqSig: m.pq_sig as never });
    }
    // a forged (non-minted) PQ key object must be refused by both
    const pristine = P.find((s) => s.alg === 'ml-dsa-65')!;
    expect(verifyWithSuite('ml-dsa-65', { pq: { b64u: pristine.pqPk } as never }, pristine.msg, { sig: pristine.sig })).toBe(false);
    monitor.note('fuzz.suite.valid', valid);
    settle('suite fuzz');
  }, 3_600_000);

  it('Ed25519 through verifyB64u / verify: the adversarial set (small-order, non-canonical S/A/R, mixed-order, off-curve, zero sigs) + random mutations', () => {
    const r = new Prng(SEED + 2); let n = 0;
    const perCat = Math.max(5, Math.min(200, Math.floor(N / 20)));
    for (const c of edAdversarial({ seed: SEED + 3, perCat }) as Iterable<{ pk: Uint8Array; msg: Uint8Array; sig: Uint8Array; expect: string }>) {
      if (c.msg.length > 100_000) continue; // keep the 1 MiB case out of the per-case b64 loop
      verifyB64u(b64u(c.pk), c.msg, b64u(c.sig)); edVerify(c.pk, c.msg, c.sig); n++;
    }
    for (let i = 0; i < N * 4; i++) { // random valid / mutated
      const kp = generateKeyPair(); const msg = bytes(r, r.pick([0, 1, 32, 64, 65, 200])); const sig = edSign(kp.secretKey, msg);
      let pkS = b64u(kp.publicKey), sgS = b64u(sig), m = msg;
      switch (r.int(8)) { case 1: sgS = flipBit(sgS, r); break; case 2: pkS = flipBit(pkS, r); break; case 3: if (m.length) m = Uint8Array.from(m, (b, j) => (j === 0 ? b ^ 1 : b)); break; case 4: sgS = flipChar(sgS, r); break; case 5: sgS = trailing(sgS); break; case 6: sgS = sgS.slice(0, -1); break; case 7: pkS = pkS + 'A'; break; }
      verifyB64u(pkS, m, sgS); n++;
    }
    monitor.note('fuzz.ed25519.cases', n);
    settle('ed25519 fuzz');
  }, 3_600_000);

  it('PCActn / capability-chain mutations through verifyPCActnCore (exercises capHash, body-digest, parent link, ceq, hop + leaf signatures)', async () => {
    const r = new Prng(SEED + 4);
    const P = generateKeyPair(); const A = generateKeyPair(); const B = generateKeyPair(); const C = generateKeyPair();
    const plan = [{ id: 'n1', verb: 'wire', resource: 'bank', reversibility_class: 'reversible' }, { id: 'n2', verb: 'delete', resource: 'db', reversibility_class: 'irreversible', params_digest: paramsDigest({ k: 1 }) }];
    const bases: { grant: any; p: PCActn; chain: any[] }[] = [];
    const caveatSets: any[][] = [[], [{ type: 'ttl', secs: 60 }], [{ type: 'ttl', secs: 60 }, { type: 'verb', allow: ['wire', 'read'], z: 1.5 }]];
    for (const cav of caveatSets) {
      const root = mintRoot({ principalSecret: P.secretKey, principalPublic: b64u(P.publicKey), holder: b64u(A.publicKey), caveats: cav });
      const d1 = delegate(root, b64u(B.publicKey), [{ type: 'ttl', secs: 30 }], A.secretKey);
      const d2 = delegate(d1, b64u(C.publicKey), [{ type: 'rate', n: 5 }], B.secretKey);
      for (const [chain, leafSecret] of [[[root], A.secretKey], [[root, d1], B.secretKey], [[root, d1, d2], C.secretKey]] as const) {
        const p = buildPCActn({ aud: 'rs', now: NOW, grant: root, chain: chain as never, plan, nodeId: 'n2', params: { k: 1 }, counter: 3, signerSecret: leafSecret, nonce: 'n-1', riskClaim: { r: 0, inputs: {} } } as never);
        bases.push({ grant: root, p, chain: chain as never });
      }
    }
    // PQ leaf suites: holder_pq committed in the root so the F-2 binding passes
    for (const alg of ['ml-dsa-65', 'hybrid-ed25519-ml-dsa-65', 'hybrid-nested-ed25519-ml-dsa-65', 'hybrid-ed25519-slh-dsa-sha2-128f'] as SigAlg[]) {
      const root = mintRoot({ principalSecret: P.secretKey, principalPublic: b64u(P.publicKey), holder: b64u(A.publicKey), holderPq: PQPK[alg]!, caveats: [{ type: 'ttl', secs: 60 }] });
      const base = buildPCActn({ aud: 'rs', now: NOW, grant: root, chain: [root], plan, nodeId: 'n2', params: { k: 1 }, counter: 3, signerSecret: A.secretKey, nonce: 'n-2', riskClaim: { r: 0, inputs: {} } } as never);
      const { sig: _s, ...body } = base as any; void _s;
      bases.push({ grant: root, p: signPCActnSuite(body, { alg, edLeafSecret: A.secretKey, mlDsa: ml65, slhDsa: slh128 }), chain: [root] });
    }
    // sanity: pristine bases verify
    for (const b of bases) { const v = await verifyPCActnCore(b.p, { grant: b.grant, nowEpoch: NOW, audience: 'rs' }); expect(v.checks.leaf_signature, JSON.stringify(v)).toBe('pass'); expect(v.checks.cap_chain, JSON.stringify(v)).toBe('pass'); }
    const clone = (x: any) => structuredClone(x);
    for (let i = 0; i < N; i++) {
      const b = bases[r.int(bases.length)]!; const p: any = clone(b.p); let grant = b.grant;
      for (let k = 0, n = 1 + r.int(3); k < n; k++) {
        const hop0 = Array.isArray(p.cap_chain) ? p.cap_chain[r.int(Math.max(1, p.cap_chain.length))] : undefined;
        const hop = hop0 !== null && typeof hop0 === 'object' ? hop0 : undefined;
        switch (r.int(14)) {
          case 0: if (typeof p.sig === 'string') p.sig = flipChar(p.sig, r); break;
          case 1: if (typeof p.sig === 'string') p.sig = flipBit(p.sig, r); break;
          case 2: if (typeof p.pq_sig === 'string') p.pq_sig = flipBit(p.pq_sig, r); break;
          case 3: if (typeof p.pq_pk === 'string') p.pq_pk = flipBit(p.pq_pk, r); break;
          case 4: if (hop && typeof hop.sig === 'string') hop.sig = flipBit(hop.sig, r); break;
          case 5: if (hop) hop[r.pick(['body_digest', 'id', 'parent'])] = r.pick([flipChar(String(hop.body_digest ?? 'AAAA'), r), ...JUNK]); break;
          case 6: if (hop) hop[r.pick(['issuer', 'holder'])] = r.pick([b64u(generateKeyPair().publicKey), ...JUNK]); break;
          case 7: if (hop?.caveats) hop.caveats = r.pick([[], [...hop.caveats, { type: 'x', v: r.pick(JUNK as never[]) }], hop.caveats.slice(0, -1), 'x']); break;
          case 8: p.cap_chain = r.pick([[], [p.cap_chain?.[0], p.cap_chain?.[0]], [...(p.cap_chain ?? [])].reverse(), (p.cap_chain ?? []).slice(0, -1), 'x']); break;
          case 9: p[r.pick(['alg', 'counter', 'aud', 'iat', 'exp', 'grant_ref', 'nonce'])] = r.pick(JUNK); break;
          case 10: p.action = { ...p.action, [r.pick(['verb', 'resource', 'params_digest'])]: r.pick(['wire', 'z', ...JUNK.map(String)]) }; break;
          case 11: p.plan = { ...p.plan, [r.pick(['root', 'node_id'])]: r.pick(JUNK) }; break;
          case 12: grant = clone(grant); grant.caveats = r.pick([[], [{ type: 'ttl', secs: 61 }], grant.caveats]); break;
          case 13: if (hop && typeof hop === "object" && (hop.alg !== undefined || r.int(3) === 0)) hop.alg = r.pick(ALGS); break;
        }
      }
      await verifyPCActnCore(p, { grant, nowEpoch: NOW, audience: 'rs', ...(r.int(4) === 0 ? { allowUnboundPq: true } : {}) });
    }
    settle('pcactn fuzz');
  }, 3_600_000);

  it('threshold shares through verifyThreshold (ed25519 + hybrid ML-DSA guardian): share signatures re-computed per share', () => {
    const r = new Prng(SEED + 5);
    const ag = generateKeyPair(), gu = generateKeyPair(), pr = generateKeyPair();
    const guPq = encodeMlDsaPublicKey(ml65.publicKey);
    // R6-02: a role that registers a pq_pk is satisfied only by a PQ / hybrid share. The hybrid guardian is therefore
    // registered WITH its pq_pk, the Ed25519-only guardian WITHOUT one; a pristine share set is always one that must verify.
    const setOf = (pq: boolean): Signer[] => [{ role: 'agent', publicKey: b64u(ag.publicKey) }, { role: 'guardian', publicKey: b64u(gu.publicKey), ...(pq ? { pq_pk: guPq } : {}) }, { role: 'principal', publicKey: b64u(pr.publicKey) }];
    let accepted = 0;
    for (let i = 0; i < Math.max(20, Math.floor(N / 4)); i++) {
      const msg = bytes(r, r.pick([0, 8, 40, 200])); const t = r.pick([1, 2, 3]);
      const hy = r.int(2) === 0;
      const set = setOf(hy);
      if (hy && t >= 2) {
        // R6-02 negative: an Ed25519-only guardian share does not count for a PQ-registered guardian
        const edOnly = signShare('guardian', gu.secretKey, msg, { signerSet: set, t });
        expect(verifyThreshold(assembleThreshold([edOnly]), msg, set, t).roles).not.toContain('guardian');
      }
      const shares = [
        signShare('agent', ag.secretKey, msg, { signerSet: set, t }),
        signShare('guardian', gu.secretKey, msg, { signerSet: set, t }, hy ? { alg: 'hybrid-ed25519-ml-dsa-65', mlDsa: ml65 } : undefined),
        signShare('principal', pr.secretKey, msg, { signerSet: set, t }),
      ].slice(0, t);
      const mutated = shares.map((x) => ({ ...x })) as any[];
      for (let k = 0, n = r.int(3); k < n; k++) {
        const sh = mutated[r.int(mutated.length)];
        switch (r.int(7)) {
          case 0: sh.sig = flipBit(sh.sig, r); break;
          case 1: if (typeof sh.pq_sig === 'string') sh.pq_sig = flipBit(sh.pq_sig, r); break;
          case 2: sh.role = r.pick(['agent', 'guardian', 'principal', 'x']); break;
          case 3: sh.publicKey = r.pick([b64u(generateKeyPair().publicKey), set[r.int(3)]!.publicKey, flipBit(sh.publicKey, r)]); break;
          case 4: sh.alg = r.pick([undefined, 'ed25519', 'ml-dsa-65', 'hybrid-ed25519-ml-dsa-65', 'bogus']); break;
          case 5: mutated.push({ ...sh }); break;
          case 6: sh.sig = r.pick(JUNK); break;
        }
      }
      const v = verifyThreshold(assembleThreshold(mutated), msg, set, t);
      if (k0(mutated, shares)) { expect(v.ok, 'pristine shares must verify').toBe(true); accepted++; }
    }
    monitor.note('fuzz.threshold.pristine-accepted', accepted);
    settle('threshold fuzz');
  }, 3_600_000);
});

const k0 = (a: unknown[], b: unknown[]) => JSON.stringify(a) === JSON.stringify(b);

afterAll(() => {
  const out = process.env.GLUE_OUT;
  if (out) { mkdirSync(dirname(out), { recursive: true }); monitor.write(out); }
  const c = monitor.counts;
  console.log('GLUE MONITOR', JSON.stringify({ violations: monitor.violationCount, ...Object.fromEntries(Object.entries(c).filter(([k]) => !k.includes('.alg=') || true)) }));
});
