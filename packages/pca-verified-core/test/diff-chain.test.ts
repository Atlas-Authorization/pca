import * as fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import { attenuate, budgetAllocCaveat, delegate, mintRoot, verifyChain, type Capability, type ChainPolicy } from '../../pca/src/capability';
import { decodePCActn } from '../../pca/src/pcactn';
import { encodeKey, generateKeyPair } from '../../pca/src/keys';
import { encodeMlDsaPublicKey, mlDsa65Keygen, type SigAlg } from '../../pca/src/pq';
import { CAVEAT_CAP_PER_CHAIN, CAVEAT_CAP_PER_HOP, Rng, loadCorpus, overCaveatCap } from './support/corpus';
import { verifyChain as verifyChainLegacy } from './support/legacy/capability';

const seed = () => crypto.getRandomValues(new Uint8Array(32));

function edChain(depth: number, withBudget: boolean): { chain: Capability[]; issuer: string } {
  const P = generateKeyPair();
  let holder = generateKeyPair();
  const root = mintRoot({ principalSecret: P.secretKey, principalPublic: encodeKey(P.publicKey), holder: encodeKey(holder.publicKey), caveats: [{ type: 'ttl', secs: 3600 }, ...(withBudget ? [budgetAllocCaveat(100)] : [])] });
  const chain = [root];
  for (let i = 1; i < depth; i++) {
    const next = generateKeyPair();
    const added = [{ type: 'task', n: i }, ...(withBudget && i % 2 === 0 ? [budgetAllocCaveat(100 - i * 10)] : [])];
    chain.push(i % 2 === 0 ? attenuate(chain[i - 1]!, added, holder.secretKey) : delegate(chain[i - 1]!, encodeKey(next.publicKey), added, holder.secretKey));
    if (i % 2 === 1) holder = next;
  }
  return { chain, issuer: encodeKey(P.publicKey) };
}

function pqChain(): { chain: Capability[]; issuer: string } {
  const P = generateKeyPair();
  const A = generateKeyPair();
  const Apq = mlDsa65Keygen(seed());
  const S = generateKeyPair();
  const Spq = mlDsa65Keygen(seed());
  const root = mintRoot({ principalSecret: P.secretKey, principalPublic: encodeKey(P.publicKey), holder: encodeKey(A.publicKey), holderPq: encodeMlDsaPublicKey(Apq.publicKey), caveats: [{ type: 'ttl' }] });
  const c1 = delegate(root, encodeKey(S.publicKey), [{ type: 'x' }], A.secretKey, { alg: 'hybrid-ed25519-ml-dsa-65', mlDsa: Apq }, encodeMlDsaPublicKey(Spq.publicKey));
  const c2 = attenuate(c1, [{ type: 'y' }], S.secretKey, { alg: 'hybrid-ed25519-ml-dsa-65', mlDsa: Spq });
  return { chain: [root, c1, c2], issuer: encodeKey(P.publicKey) };
}

const CAP_REASON = `chain exceeds caveat limit (max ${CAVEAT_CAP_PER_HOP} per hop, ${CAVEAT_CAP_PER_CHAIN} per chain)`;

/** A real Ed25519 chain of `perHop.length` hops where hop i carries exactly perHop[i] caveats (lists are cumulative). */
function cappedChain(perHop: number[]): { chain: Capability[]; issuer: string } {
  const P = generateKeyPair();
  let holder = generateKeyPair();
  const mk = (n: number, from: number) => Array.from({ length: n }, (_, j) => ({ type: 'c', n: from + j }));
  const root = mintRoot({ principalSecret: P.secretKey, principalPublic: encodeKey(P.publicKey), holder: encodeKey(holder.publicKey), caveats: mk(perHop[0]!, 0) });
  const chain = [root];
  for (let i = 1; i < perHop.length; i++) {
    const added = mk(perHop[i]! - perHop[i - 1]!, perHop[i - 1]!);
    const next = generateKeyPair();
    chain.push(delegate(chain[i - 1]!, encodeKey(next.publicKey), added, holder.secretKey));
    holder = next;
  }
  return { chain, issuer: encodeKey(P.publicKey) };
}

const BASES = [edChain(1, false), edChain(2, false), edChain(3, true), edChain(5, true), edChain(6, true), pqChain()];
const ALGS = [undefined, 'ed25519', 'ml-dsa-65', 'hybrid-ed25519-ml-dsa-65', 'slh-dsa-sha2-128f', 'bogus', 7];
const JUNK: unknown[] = [undefined, null, 0, 1, -1, 1.5, NaN, '', 'x', 'AAAA', [], {}, [{ type: 'x' }], true, false];

function flipChar(s: string, r: Rng): string {
  if (s.length === 0) return 'A';
  const i = r.next(s.length);
  const c = s[i] === 'A' ? 'B' : 'A';
  return s.slice(0, i) + c + s.slice(i + 1);
}

function mutate(chain: Capability[], r: Rng): Capability[] {
  const c: any[] = structuredClone(chain);
  const rounds = 1 + r.next(3);
  for (let k = 0; k < rounds && c.length > 0; k++) {
    const i = r.next(c.length);
    const h = c[i];
    switch (r.next(14)) {
      case 0:
        c.splice(i, 1);
        break;
      case 1:
        c.push(structuredClone(c[r.next(c.length)]));
        break;
      case 2:
        c.splice(0, c.length, ...c.slice(0, 1 + r.next(c.length)));
        break;
      case 3: {
        const j = r.next(c.length);
        [c[i], c[j]] = [c[j], c[i]];
        break;
      }
      case 4:
        if (h && typeof h === 'object') h[r.pick(['id', 'issuer', 'holder', 'parent', 'body_digest', 'sig', 'pq_pk', 'pq_sig', 'holder_pq'])] = r.pick(JUNK);
        break;
      case 5:
        if (h && typeof h === 'object') for (const f of ['sig', 'body_digest', 'parent', 'id', 'issuer', 'holder']) if (r.bool() && typeof h[f] === 'string') h[f] = flipChar(h[f], r);
        break;
      case 6:
        if (h && typeof h === 'object') h.alg = r.pick(ALGS);
        break;
      case 7:
        if (h && Array.isArray(h.caveats) && h.caveats.length) h.caveats.splice(r.next(h.caveats.length), 1);
        break;
      case 8:
        if (h && Array.isArray(h.caveats)) h.caveats.push(r.pick([{ type: 'x' }, budgetAllocCaveat(r.next(200)), { type: 'budget_alloc', limit: -1 }, { type: 'budget_alloc', limit: 'x' }, 5, null]));
        break;
      case 9:
        if (h && Array.isArray(h.caveats) && h.caveats.length > 1) {
          const a = r.next(h.caveats.length);
          const b = r.next(h.caveats.length);
          [h.caveats[a], h.caveats[b]] = [h.caveats[b], h.caveats[a]];
        }
        break;
      case 10:
        if (h && Array.isArray(h.caveats) && h.caveats.length) h.caveats[r.next(h.caveats.length)] = r.pick([{ type: 'ttl', secs: 1 }, { type: 'x', big: Infinity }, { type: 'x', n: BigInt(1) as unknown as number }].slice(0, 2));
        break;
      case 11:
        c[i] = r.pick(JUNK);
        break;
      case 12:
        if (h && typeof h === 'object') delete h[r.pick(['id', 'issuer', 'holder', 'parent', 'sig', 'caveats', 'body_digest', 'alg', 'holder_pq'])];
        break;
      default:
        if (h && typeof h === 'object' && typeof h.parent === 'string') h.parent = undefined;
    }
  }
  return c as Capability[];
}

const policyOf = (r: Rng): ChainPolicy | undefined => {
  switch (r.next(5)) {
    case 0:
      return undefined;
    case 1:
      return { allowedSuites: ['ed25519'] };
    case 2:
      return { allowedSuites: ['ed25519', 'hybrid-ed25519-ml-dsa-65'] as SigAlg[] };
    case 3:
      return { allowUnboundPq: true };
    default:
      return { allowedSuites: [], allowUnboundPq: r.bool() };
  }
};

describe('differential: verifyChain (TS) (production, verified core) vs legacy (frozen TS)', () => {
  it('agrees on every base (unmutated) chain and policy', () => {
    for (const b of BASES) {
      for (const pol of [undefined, { allowedSuites: ['ed25519'] as SigAlg[] }, { allowUnboundPq: true }]) {
        for (const iss of [undefined, b.issuer, 'other']) {
          expect(verifyChain(b.chain, iss, pol)).toEqual(verifyChainLegacy(b.chain, iss, pol));
        }
      }
    }
    expect(verifyChain(BASES[0]!.chain, BASES[0]!.issuer).ok).toBe(true);
  });

  it('agrees on 6000 random mutations (verdict AND exact reason)', () => {
    let rejected = 0;
    let accepted = 0;
    fc.assert(
      fc.property(fc.array(fc.nat(), { minLength: 4, maxLength: 24 }), (pool) => {
        const r = new Rng(pool);
        const base = r.pick(BASES);
        const chain = mutate(base.chain, r);
        const pol = policyOf(r);
        const iss = r.pick([undefined, base.issuer, 'zzz']);
        const a = verifyChainLegacy(chain, iss, pol);
        const b = verifyChain(chain, iss, pol);
        expect(b).toEqual(a);
        if (a.ok) accepted++; else rejected++;
      }),
      { numRuns: 6000 },
    );
    expect(rejected).toBeGreaterThan(1000);
    expect(accepted).toBeGreaterThan(50);
  });

  it('caveat cap boundaries: at-cap chains agree with legacy; over-cap chains are rejected by production (the proved walk is never reached)', () => {
    // at the cap: 256 on one hop; 1024 summed over 4 hops of 256 (cumulative lists: 256 each)
    const atHop = cappedChain([256]);
    const atChain = cappedChain([256, 256, 256, 256]);
    for (const c of [atHop, atChain]) {
      expect(overCaveatCap(c.chain)).toBe(false);
      const r = verifyChain(c.chain, c.issuer);
      expect(r.ok).toBe(true);
      expect(r).toEqual(verifyChainLegacy(c.chain, c.issuer));
    }
    // one over: 257 on one hop; 1025 over the chain (256 x 4 + 1 on a fifth hop is impossible with cumulative lists, so use 205 x 5 = 1025)
    const overHop = cappedChain([257]);
    const overHopLate = cappedChain([10, 257]);
    const overChain = cappedChain([205, 205, 205, 205, 205]);
    for (const c of [overHop, overHopLate, overChain]) {
      expect(overCaveatCap(c.chain)).toBe(true);
      expect(verifyChain(c.chain, c.issuer)).toEqual({ ok: false, reason: CAP_REASON });
      expect(verifyChainLegacy(c.chain, c.issuer).ok).toBe(true); // legacy (pre-cap) accepted it: this is the cap's whole effect
    }
    // just under the chain cap: 204 x 5 = 1020
    const under = cappedChain([204, 204, 204, 204, 204]);
    expect(verifyChain(under.chain, under.issuer)).toEqual(verifyChainLegacy(under.chain, under.issuer));
  });

  it('non-array / absurdly long chains: never throw, identical results', () => {
    for (const x of [undefined, null, 5, 'x', {}, []] as unknown[]) expect(verifyChain(x as never)).toEqual(verifyChainLegacy(x as never));
    const long = Array.from({ length: 5000 }, () => BASES[0]!.chain[0]!);
    expect(verifyChain(long)).toEqual(verifyChainLegacy(long));
  });

  it('agrees on every conformance vector chain (core + full adversarial corpus)', () => {
    const { core, adversarial } = loadCorpus();
    let n = 0;
    let overCap = 0;
    for (const v of [...core, ...adversarial]) {
      let p: any = v.pcactn;
      if (v.pcactn_json !== undefined) {
        try {
          p = decodePCActn(v.pcactn_json);
        } catch {
          continue;
        }
      }
      if (!p || typeof p !== 'object') continue;
      for (const pol of [undefined, { allowedSuites: ['ed25519'] as SigAlg[] }]) {
        if (overCaveatCap(p.cap_chain)) {
          // the frozen legacy copy predates the caveat cap: an over-cap chain must be REJECTED with the cap reason
          expect(verifyChain(p.cap_chain, v.grant?.issuer, pol), v.name).toEqual({ ok: false, reason: CAP_REASON });
          overCap++;
        } else {
          expect(verifyChain(p.cap_chain, v.grant?.issuer, pol), v.name).toEqual(verifyChainLegacy(p.cap_chain, v.grant?.issuer, pol));
        }
      }
      n++;
    }
    expect(n).toBeGreaterThan(3000);
    expect(overCap).toBeGreaterThan(0);
  });
});
