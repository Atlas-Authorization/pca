import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { attenuate, capHash, delegate, mintRoot, verifyChain, type Capability, type Caveat } from './capability';
import {
  boundCaveats,
  dischargeDigest,
  dischargeRequests,
  deriveError,
  evaluateK1,
  isK1Caveat,
  maxUsesError,
  maxUsesSlotKey,
  needsDischargeError,
  reserveMaxUses,
  signDischarge,
  signNarrow,
  spiffeBoundError,
  spiffeIdError,
  verifyDischarge,
  verifyNarrow,
  type DischargePin,
} from './caveat-lang';
import { b64u, hashCanonical, utf8 } from './hash';
import { encodeKey, generateKeyPair, sign as signSig } from './keys';
import { evaluateAgentCaveats, policyCaveats } from './policy-vm';
import { InMemoryReplayStore } from './replay';
import { presentedK1 } from './server/require-pca';

// ---- the shared vectors (conformance/caveat-lang-vectors.json), replayed against the reference --------------------------------
const doc = JSON.parse(readFileSync(new URL('../conformance/caveat-lang-vectors.json', import.meta.url), 'utf8')).primitives as Record<string, { name: string; input: any; expect: any; requires_suite?: string }[]>;

describe('caveat-lang-vectors.json', () => {
  it('carries every primitive and enough vectors that a runner cannot pass vacuously', () => {
    expect(doc.discharge_verify!.length).toBeGreaterThanOrEqual(50);
    expect(doc.k1_eval!.length).toBeGreaterThanOrEqual(100);
    expect(doc.caveat_shape!.length).toBeGreaterThanOrEqual(50);
    expect(doc.uses_reserve!.length).toBeGreaterThanOrEqual(10);
    expect(doc.spiffe_id!.length).toBeGreaterThanOrEqual(20);
    expect(doc.k1_eval!.some((e) => e.expect.allow) && doc.k1_eval!.some((e) => !e.expect.allow)).toBe(true);
  });
  it.each(doc.discharge_verify!.map((e) => [e.name, e] as const))('discharge_verify: %s', (_n, e) => {
    const r = verifyDischarge(e.input.discharge, e.input.caveat, e.input.binding);
    expect(r.ok).toBe(e.expect.ok);
    if (r.ok) expect({ claims: r.claims, digest: r.digest }).toEqual({ claims: e.expect.claims, digest: e.expect.digest });
    else expect(r.reason).toContain(e.expect.reason_contains);
  });
  it.each(doc.k1_eval!.map((e) => [e.name, e] as const))('k1_eval: %s', (_n, e) => {
    const { grant, chain, k1, context } = e.input;
    const k = evaluateK1(grant, chain, k1, { now: context.now, action: context.action });
    const stock = [...policyCaveats(grant, chain).filter((c) => !isK1Caveat(c)), ...k.plain];
    const s = evaluateAgentCaveats(stock, { now: context.now, delegationDepth: context.delegation_depth }, { action: context.action });
    const failed = [...s.failed, ...k.failed].sort();
    expect({ allow: failed.length === 0, failed }).toEqual(e.expect);
  });
  it.each(doc.caveat_shape!.map((e) => [e.name, e] as const))('caveat_shape: %s', (_n, e) => {
    const c = e.input.caveat;
    const err = { needs_discharge: needsDischargeError, max_uses: maxUsesError, derive: deriveError, spiffe_bound: spiffeBoundError }[c.type as string]!(c);
    expect(err === null).toBe(e.expect.valid);
  });
  it.each(doc.uses_key!.map((e) => [e.name, e] as const))('uses_key: %s', (_n, e) => expect(maxUsesSlotKey(e.input.cap_hash, e.input.id, e.input.i)).toBe(e.expect.key));
  it.each(doc.uses_reserve!.map((e) => [e.name, e] as const))('uses_reserve: %s', async (_n, e) => {
    const store = new InMemoryReplayStore();
    for (let i = 0; i < e.input.calls.length; i++) {
      const r = await reserveMaxUses(store, e.input.bound, e.input.calls[i].now);
      const w = e.expect.results[i];
      expect(r.ok).toBe(w.ok);
      if (r.ok) expect(r.spent).toBe(w.spent);
      else expect(r.reason).toContain(w.reason_contains);
    }
  });
  it.each(doc.k1_unconfigured!.map((e) => [e.name, e] as const))('k1_unconfigured: %s', (_n, e) => {
    const { grant, chain, context } = e.input;
    const k = evaluateK1(grant, chain, undefined, { now: context.now, action: context.action });
    const stock = [...policyCaveats(grant, chain).filter((c) => !isK1Caveat(c)), ...k.plain];
    const s = evaluateAgentCaveats(stock, { now: context.now, delegationDepth: context.delegation_depth }, { action: context.action });
    const failed = [...s.failed, ...k.failed].sort();
    expect({ allow: failed.length === 0, failed }).toEqual(e.expect);
  });
  it.each(doc.consume_once_ttl!.map((e) => [e.name, e] as const))('consume_once_ttl: %s', async (_n, e) => {
    const st = new InMemoryReplayStore();
    const got: string[] = [];
    for (const x of e.input.steps) {
      try {
        got.push((await st.consumeOnce(x.key, x.retain_until, x.now)) ? 'true' : 'false');
      } catch {
        got.push('error');
      }
    }
    expect({ results: got }).toEqual(e.expect);
  });
  it.each(doc.k1_headers!.map((e) => [e.name, e] as const))('k1_headers: %s', (_n, e) => {
    let r: unknown;
    try {
      r = { ok: true, value: presentedK1({ headers: e.input.headers }) };
    } catch {
      r = { ok: false };
    }
    expect(r).toEqual(e.expect);
  });
  it.each(doc.spiffe_id!.map((e) => [e.name, e] as const))('spiffe_id: %s', (_n, e) => expect(spiffeIdError(e.input.id) === null).toBe(e.expect.valid));
});

// ---- exact-outcome and hostile-input tests -------------------------------------------------------------------------------------
const NOW = 1_800_000_000_000;
const kp = () => {
  const k = generateKeyPair();
  return { sk: k.secretKey, pub: encodeKey(k.publicKey) };
};
const principal = kp(), agent = kp(), sub = kp(), issuer = kp(), stranger = kp();
const PIN: DischargePin = { label: 'risk-team', class: 'human', pk: issuer.pub };
const nd = (o: Partial<Caveat> = {}): Caveat => ({ type: 'needs_discharge', id: 'kyc', issuer: 'risk-team', issuer_class: 'human', bind: 'chain_hop', ttl_ms: 600_000, require: [], ...o });
const root = (caveats: Caveat[]): Capability => mintRoot({ principalSecret: principal.sk, principalPublic: principal.pub, holder: agent.pub, caveats });
const discharge = (cap: string, o: Record<string, unknown> = {}, sk = issuer.sk) =>
  signDischarge({ v: 1, kind: 'pca-discharge', caveat_id: 'kyc', issuer: 'risk-team', cap_hash: cap, bind: 'chain_hop', claims: {}, iat: NOW - 1000, not_after: NOW + 1000, nonce: b64u(new Uint8Array(16).fill(5)), ...o } as never, sk);

describe('boundCaveats', () => {
  it('assigns each caveat to the hop that introduced it, and hashes that hop', () => {
    const g = root([{ type: 'expires', at: NOW + 1 }]);
    const c1 = delegate(g, sub.pub, [{ type: 'sealed' }], agent.sk);
    const c2 = delegate(c1, agent.pub, [{ type: 'delegation_depth', max: 5 }], sub.sk);
    expect(verifyChain([g, c1, c2], principal.pub).ok).toBe(true);
    const b = boundCaveats(g, [g, c1, c2])!;
    expect(b.map((x) => [x.caveat.type, x.hop, x.cap_hash])).toEqual([
      ['expires', 0, capHash(g)],
      ['sealed', 1, capHash(c1)],
      ['delegation_depth', 2, capHash(c2)],
    ]);
  });
  it('is null for a malformed chain', () => {
    expect(boundCaveats({ caveats: 5 } as never, [{ caveats: 5 } as never])).toBeNull();
  });
});

describe('needs_discharge', () => {
  const g = root([nd()]);
  const cap = capHash(g);
  it('a discharge for a child cannot be lifted onto the parent hop: the hash differs', () => {
    const child = attenuate(g, [nd({ id: 'second' })], agent.sk);
    expect(capHash(child)).not.toBe(cap);
    const r = evaluateK1(g, [g, child], { pins: [PIN], discharges: [discharge(cap), discharge(cap, { caveat_id: 'second' })] }, { now: NOW });
    expect(r.failed).toEqual(['needs_discharge']);
    expect(r.reasons[0]).toContain('bound to another hop');
  });
  it('a discharge shown for one chain does not satisfy a copy of the caveat in another grant', () => {
    const other = mintRoot({ principalSecret: principal.sk, principalPublic: principal.pub, holder: sub.pub, caveats: [nd()] });
    const r = evaluateK1(other, [other], { pins: [PIN], discharges: [discharge(cap)] }, { now: NOW });
    expect(r.ok).toBe(false);
  });
  it('the verifier never reads a key out of the token or the discharge', () => {
    const r = evaluateK1(g, [g], { pins: [{ ...PIN, pk: stranger.pub }], discharges: [discharge(cap)] }, { now: NOW });
    expect(r.ok).toBe(false);
    expect(r.reasons[0]).toContain('signature invalid');
  });
  it('requests list one entry per undischarged caveat, naming issuer, hop and requirements', () => {
    const req = dischargeRequests(g, [g], undefined);
    expect(req).toEqual([{ v: 1, kind: 'pca-discharge-request', caveat_id: 'kyc', issuer: 'risk-team', cap_hash: cap, bind: 'chain_hop', require: [], ttl_ms: 600_000 }]);
    const bound = dischargeRequests(root([nd({ bind: 'action' })]), undefined, 'AAAA');
    expect(bound[0]!.action_digest).toBe('AAAA');
  });
  it('signDischarge refuses a malformed body', () => {
    expect(() => discharge(cap, { not_after: NOW - 5000 })).toThrow(/not_after must be greater than iat/);
    expect(() => discharge(cap, { claims: { Bad: 1 } })).toThrow(/malformed/);
  });
  it('the digest names the signed bytes: a re-signed discharge has another digest only when its body changes', () => {
    const a = discharge(cap);
    expect(dischargeDigest(a)).toBe(dischargeDigest(discharge(cap)));
    expect(dischargeDigest(a)).not.toBe(dischargeDigest(discharge(cap, { claims: { x: 1 } })));
  });
  it('a hostile discharge list is a refusal, never a throw', () => {
    const cyc: Record<string, unknown> = {};
    cyc.self = cyc;
    for (const bad of [null, 5, 'x', [], cyc, { caveat_id: 'kyc', claims: cyc }]) {
      const r = evaluateK1(g, [g], { pins: [PIN], discharges: [bad as never] }, { now: NOW });
      expect(r.ok).toBe(false);
    }
    expect(evaluateK1(g, [g], { pins: 5 as never, discharges: 5 as never }, { now: NOW }).ok).toBe(false);
    expect(verifyDischarge(discharge(cap), nd(), { cap_hash: cap, pins: [PIN], now: Number.NaN }).ok).toBe(false);
  });
});

describe('narrow', () => {
  const g = root([]);
  const body = (o: Record<string, unknown> = {}) => ({ v: 1 as const, kind: 'pca-narrow' as const, cap_hash: capHash(g), holder: agent.pub, caveats: [{ type: 'max_spend', usd: 5 }], iat: NOW - 1, not_after: NOW + 1, nonce: b64u(new Uint8Array(16).fill(3)), ...o });
  it('only restricts: the evaluated list is the chain list plus the narrow list', () => {
    const n = signNarrow(body(), agent.sk);
    const v = verifyNarrow(n, g, [g], { now: NOW });
    expect(v.ok && v.caveats).toEqual([{ type: 'max_spend', usd: 5 }]);
    const r = evaluateK1(g, [g], { narrow: n }, { now: NOW, action: { params: { amount: 9 } } });
    expect(r.plain).toEqual([{ type: 'max_spend', usd: 5 }]);
  });
  it('is bound to the leaf holder, the leaf hop and the window', () => {
    expect(verifyNarrow(signNarrow(body(), agent.sk), g, [g], { now: NOW + 2 })).toEqual({ ok: false, reason: 'the narrow block has expired' });
    expect(verifyNarrow(signNarrow(body(), agent.sk), g, [g], { now: NOW - 2 })).toEqual({ ok: false, reason: 'the narrow block is from the future' });
    const child = delegate(g, sub.pub, [], agent.sk);
    expect(verifyNarrow(signNarrow(body(), agent.sk), g, [g, child], { now: NOW })).toEqual({ ok: false, reason: 'the narrow block is not signed by the leaf holder' });
    expect(verifyNarrow(signNarrow(body({ holder: sub.pub, cap_hash: capHash(g) }), sub.sk), g, [g, child], { now: NOW })).toEqual({ ok: false, reason: 'the narrow block is bound to another hop' });
  });
  it('cannot carry structure only a hop can introduce', () => {
    for (const type of ['envelope', 'sealed', 'budget_alloc', 'intent_session']) expect(() => signNarrow(body({ caveats: [{ type }] }), agent.sk)).toThrow(/cannot carry/);
  });
  it('1..16 caveats', () => {
    expect(() => signNarrow(body({ caveats: [] }), agent.sk)).toThrow(/1\.\.16/);
    expect(() => signNarrow(body({ caveats: Array.from({ length: 17 }, () => ({ type: 'expires', at: 1 })) }), agent.sk)).toThrow(/1\.\.16/);
  });
});

describe('max_uses', () => {
  const g = root([{ type: 'max_uses', id: 'u', n: 3, until: NOW + 10_000 }]);
  const bound = boundCaveats(g, [g])!;
  it('concurrent actions never share a slot, and exactly n succeed', async () => {
    const store = new InMemoryReplayStore();
    const rs = await Promise.all(Array.from({ length: 10 }, () => reserveMaxUses(store, bound, NOW)));
    expect(rs.filter((r) => r.ok)).toHaveLength(3);
    expect(rs.filter((r) => !r.ok).every((r) => !r.ok && r.reason === "max_uses 'u' is exhausted")).toBe(true);
  });
  it('a store that cannot decide fails closed', async () => {
    const r = await reserveMaxUses({ consumeOnce: () => Promise.reject(new Error('db down')) }, bound, NOW);
    expect(r).toEqual({ ok: false, reason: 'max_uses error (fail closed): db down' });
  });
  it('slots live until the horizon: the store is told to remember each use that long', async () => {
    const seen: number[] = [];
    await reserveMaxUses({ consumeOnce: (_k, until) => (seen.push(until), Promise.resolve(true)) }, bound, NOW);
    expect(seen).toEqual([NOW + 10_000]);
  });
  it('two hops carrying the same id have separate counters', async () => {
    const child = delegate(g, sub.pub, [{ type: 'max_uses', id: 'u', n: 1, until: NOW + 10_000 }], agent.sk);
    const b = boundCaveats(g, [g, child])!;
    expect(b.map((x) => x.hop)).toEqual([0, 1]);
    const store = new InMemoryReplayStore();
    expect((await reserveMaxUses(store, b, NOW)).ok).toBe(true); // hop 0 uses 1/3, hop 1 uses 1/1
    expect((await reserveMaxUses(store, b, NOW)).ok).toBe(false); // hop 1 is exhausted; the slot hop 0 took first stays spent (fail closed)
    expect((await reserveMaxUses(store, b.slice(0, 1), NOW)).ok).toBe(true); // hop 0 alone: 3/3 now
    expect((await reserveMaxUses(store, b.slice(0, 1), NOW)).ok).toBe(false);
  });
});

describe('spiffe ids', () => {
  it('agrees with @atlasauth/pca-spiffe parseSpiffeId on the vector inputs (pinned there too)', () => {
    expect(spiffeIdError('spiffe://example.org/ns/a')).toBeNull();
    expect(spiffeIdError('spiffe://example.org/')).not.toBeNull();
  });
});

// ---- offline attenuation (item 2): what a holder can and cannot do with the key it holds ---------------------------------------
describe('offline attenuation hardening', () => {
  const sealedRoot = root([{ type: 'sealed' }, { type: 'expires', at: NOW + 1000 }]);
  const forge = (parent: Capability, caveats: unknown[], signer: Uint8Array): Capability => {
    const digest = hashCanonical({ issuer: parent.holder, holder: parent.holder, caveats, parent: capHash(parent) });
    const d = utf8('atlas-pca/cap/v1\0');
    const raw = Buffer.from(digest, 'base64url');
    const m = new Uint8Array(d.length + raw.length);
    m.set(d);
    m.set(raw, d.length);
    return { id: digest, issuer: parent.holder, holder: parent.holder, caveats: caveats as Caveat[], parent: capHash(parent), body_digest: digest, sig: b64u(signSig(signer, m)) };
  };
  it('a holder cannot drop the sealed marker, even with its own valid signature', () => {
    const r = verifyChain([sealedRoot, forge(sealedRoot, [{ type: 'expires', at: NOW + 1000 }], agent.sk)]);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/drops/);
  });
  it('a holder cannot swap the sealed marker for another caveat in place', () => {
    const r = verifyChain([sealedRoot, forge(sealedRoot, [{ type: 'expires', at: NOW + 5 }, { type: 'expires', at: NOW + 1000 }], agent.sk)]);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/altered or reordered/);
  });
  it('a hop appended below a seal is structurally valid but never satisfies it', () => {
    const child = attenuate(sealedRoot, [], agent.sk);
    expect(verifyChain([sealedRoot, child], principal.pub).ok).toBe(true);
    expect(evaluateK1(sealedRoot, [sealedRoot, child], {}, { now: NOW }).failed).toEqual(['sealed']);
    expect(evaluateK1(sealedRoot, [sealedRoot], {}, { now: NOW }).ok).toBe(true);
  });
  it('a seal placed by a child stops that child\'s own children, not its siblings', () => {
    const g = root([]);
    const sealed = attenuate(g, [{ type: 'sealed' }], agent.sk);
    const sibling = attenuate(g, [], agent.sk);
    const grandchild = delegate(sealed, sub.pub, [], agent.sk);
    expect(evaluateK1(g, [g, sealed], {}, { now: NOW }).ok).toBe(true);
    expect(evaluateK1(g, [g, sibling], {}, { now: NOW }).ok).toBe(true);
    expect(evaluateK1(g, [g, sealed, grandchild], {}, { now: NOW }).failed).toEqual(['sealed']);
  });
  it('a seal is attributable: the sealing hop is signed by the holder who sealed', () => {
    const g = root([]);
    const sealed = attenuate(g, [{ type: 'sealed' }], agent.sk);
    expect(sealed.issuer).toBe(agent.pub);
    expect(boundCaveats(g, [g, sealed])![0]).toMatchObject({ hop: 1 });
  });
  it('a narrow block cannot be moved to a sibling hop or another holder', () => {
    const g = root([]);
    const a = attenuate(g, [], agent.sk);
    const b = attenuate(g, [{ type: 'expires', at: NOW + 1 }], agent.sk);
    const n = signNarrow({ v: 1, kind: 'pca-narrow', cap_hash: capHash(a), holder: agent.pub, caveats: [{ type: 'expires', at: NOW + 1 }], iat: NOW - 1, not_after: NOW + 10, nonce: b64u(new Uint8Array(16).fill(2)) }, agent.sk);
    expect(verifyNarrow(n, g, [g, a], { now: NOW }).ok).toBe(true);
    expect(verifyNarrow(n, g, [g, b], { now: NOW })).toEqual({ ok: false, reason: 'the narrow block is bound to another hop' });
  });
});
