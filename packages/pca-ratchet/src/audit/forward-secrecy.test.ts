import { describe, expect, it } from 'vitest';
import fc from 'fast-check';
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha2';
import { ed25519 } from '@noble/curves/ed25519';
import { b64u, unb64u } from '@atlasauth/pca';
import {
  RatchetError,
  type RatchetState,
  availableLeaves,
  deriveRatchetRoot,
  isLeafAvailable,
  signAtLeaf,
  verifyLeafSignature,
} from '../index';
import { leafPublicKey } from '../ggm';

/**
 * Source construction: Goldreich-Goldwasser-Micali tree PRF (GGM 1986) used as a puncturable PRF in the style
 * of Bellare-Miner forward-secure signatures / Sahai-Waters puncturable PRFs: the secret state is the co-path
 * (the seeds of the siblings hanging off the punctured path); the punctured leaf seed and every on-path seed
 * are deleted. Leaf signing keys are Ed25519 seeds derived from leaf seeds with a separate HMAC domain.
 *
 * DEVIATIONS from the textbook constructions (all recorded in the audit document):
 *  - PRG = HMAC-SHA256 under the seed as key, with a one-byte domain suffix (a PRF used as a PRG; sound in the
 *    standard model if HMAC-SHA256 is a PRF).
 *  - State is an immutable value. Signing returns a NEW state; the old one remains valid until the caller drops
 *    it. "Forward security" is therefore a property of the caller discarding the old state, which JS cannot
 *    enforce or zeroise.
 *  - There is no post-compromise security: whoever steals the CURRENT state can sign every unspent leaf.
 */

const DOM_PRG = new TextEncoder().encode('atlas-pca-ratchet/ggm-prg/v1');
const prg = (seed: Uint8Array, bit: 0 | 1): Uint8Array => hmac(sha256, seed, Uint8Array.of(...DOM_PRG, bit));
const DOMAINS = ['atlas-pca-ratchet/ggm-prg/v1', 'atlas-pca-ratchet/ggm-leafkey/v1', 'atlas-pca-ratchet/ggm-root/v1'].map((s) => new TextEncoder().encode(s));
const hex = (u: Uint8Array) => Buffer.from(u).toString('hex');
const SEED = new Uint8Array(32).map((_, i) => i + 1);
const MSG = new TextEncoder().encode('spend');

/** Everything an attacker can compute from a state: the closure of the covering seeds under the PRG, down to the leaves. */
function derivable(state: RatchetState): { leafSeeds: Map<number, Uint8Array>; allSeeds: Set<string> } {
  const leafSeeds = new Map<number, Uint8Array>();
  const allSeeds = new Set<string>();
  const walk = (seed: Uint8Array, level: number, index: number): void => {
    allSeeds.add(hex(seed));
    if (level === state.depth) {
      leafSeeds.set(index, seed);
      return;
    }
    walk(prg(seed, 0), level + 1, index * 2);
    walk(prg(seed, 1), level + 1, index * 2 + 1);
  };
  for (const n of state.covering.values()) walk(n.seed, n.level, n.nodeIndex);
  return { leafSeeds, allSeeds };
}

describe('GGM forward secrecy: attempts to recover spent keys from the current state', () => {
  it('the set of leaf seeds derivable from the live state is EXACTLY the set of unspent leaves (checked after every spend)', () => {
    const depth = 5;
    let { state } = deriveRatchetRoot(SEED, depth);
    const spent = new Set<number>();
    for (const leaf of [13, 0, 31, 7, 8, 9, 22, 21]) {
      state = signAtLeaf(state, leaf, MSG).newState;
      spent.add(leaf);
      const d = derivable(state);
      const expected = Array.from({ length: 2 ** depth }, (_, i) => i).filter((i) => !spent.has(i));
      expect([...d.leafSeeds.keys()].sort((a, b) => a - b)).toEqual(expected);
      expect(availableLeaves(state)).toEqual(expected);
    }
  });

  it('no seed reachable from the live state (forward through the PRG) equals ANY seed on the punctured paths, nor the punctured leaf seed / signing seed', () => {
    const depth = 6;
    const { state: s0 } = deriveRatchetRoot(SEED, depth);
    const before = derivable(s0); // attacker model: we, the test, know the old state's full tree
    const target = 37;
    const { newState } = signAtLeaf(s0, target, MSG);
    const after = derivable(newState);
    const targetSeed = before.leafSeeds.get(target)!;
    expect(after.leafSeeds.has(target)).toBe(false);
    expect(after.allSeeds.has(hex(targetSeed))).toBe(false);
    // on-path ancestors: root .. parent of the leaf
    let seed = [...s0.covering.values()][0]!.seed;
    const onPath: Uint8Array[] = [seed];
    for (let level = 0; level < depth; level++) {
      const bit = ((target >> (depth - level - 1)) & 1) as 0 | 1;
      seed = prg(seed, bit);
      onPath.push(seed);
    }
    for (const p of onPath) expect(after.allSeeds.has(hex(p))).toBe(false);
  });

  it('derivation attack search: apply every function the library defines (PRG left/right, leaf-key, root KDF, domain HMACs) up to 3 deep to every retained seed; none reaches a punctured secret', () => {
    const depth = 4;
    const { state: s0 } = deriveRatchetRoot(SEED, depth);
    const before = derivable(s0);
    const target = 5;
    const secret = new Set<string>();
    secret.add(hex(before.leafSeeds.get(target)!));
    secret.add(hex(hmac(sha256, before.leafSeeds.get(target)!, DOMAINS[1]!))); // the Ed25519 signing seed
    const rootNode = [...s0.covering.values()][0]!;
    let seed = rootNode.seed;
    for (let level = 0; level < depth; level++) {
      secret.add(hex(seed));
      seed = prg(seed, ((target >> (depth - level - 1)) & 1) as 0 | 1);
    }
    const { newState } = signAtLeaf(s0, target, MSG);
    const fns: ((x: Uint8Array) => Uint8Array)[] = [
      (x) => prg(x, 0),
      (x) => prg(x, 1),
      ...DOMAINS.map((d) => (x: Uint8Array) => hmac(sha256, x, d)),
      ...DOMAINS.map((d) => (x: Uint8Array) => hmac(sha256, d, x)),
      (x) => sha256(x),
      (x) => hmac(sha256, x, new Uint8Array(0)),
    ];
    let frontier: Uint8Array[] = [...newState.covering.values()].map((n) => n.seed);
    const reached = new Set<string>(frontier.map(hex));
    for (let round = 0; round < 3; round++) {
      const next: Uint8Array[] = [];
      for (const x of frontier) for (const f of fns) { const y = f(x); const h = hex(y); if (!reached.has(h)) { reached.add(h); next.push(y); } }
      frontier = next;
    }
    for (const s of secret) expect(reached.has(s), 'a punctured secret was reachable').toBe(false);
  });

  it('the retained state contains no byte string equal to a punctured secret (no stray copy in leafPubKeys, covering, commitments)', () => {
    const { state: s0 } = deriveRatchetRoot(SEED, 5);
    const before = derivable(s0);
    const { newState, signature } = signAtLeaf(s0, 19, MSG);
    const needle = hex(before.leafSeeds.get(19)!);
    const signingSeed = hex(hmac(sha256, before.leafSeeds.get(19)!, DOMAINS[1]!));
    const blob = JSON.stringify({
      d: newState.depth, r: newState.rootCommitment, p: newState.leafPubKeys,
      c: [...newState.covering.values()].map((n) => [n.level, n.nodeIndex, hex(n.seed)]),
      sig: signature,
    }, (_k, v) => (typeof v === 'bigint' ? v.toString() : v));
    for (const n of [needle, signingSeed, Buffer.from(needle, 'hex').toString('base64url'), Buffer.from(signingSeed, 'hex').toString('base64url')]) {
      expect(blob.includes(n)).toBe(false);
    }
  });

  it('a punctured leaf cannot sign again from the new state; every neighbour still can, and the signature verifies under the ORIGINAL root', () => {
    const { rootCommitment, state } = deriveRatchetRoot(SEED, 4);
    const { newState } = signAtLeaf(state, 6, MSG);
    expect(() => signAtLeaf(newState, 6, MSG)).toThrow(RatchetError);
    for (const j of [0, 5, 7, 15]) {
      const m = new TextEncoder().encode(`m${j}`);
      expect(verifyLeafSignature(rootCommitment, j, m, signAtLeaf(newState, j, m).signature)).toBe(true);
    }
  });

  it('property: after any sequence of spends, the covering set is a disjoint exact cover of the unspent leaves and stays small (<= depth nodes per spend)', () => {
    fc.assert(
      fc.property(fc.integer({ min: 2, max: 6 }), fc.array(fc.nat(), { maxLength: 20 }), (depth, picks) => {
        let { state } = deriveRatchetRoot(SEED, depth);
        const spent = new Set<number>();
        for (const p of picks) {
          const leaf = p % 2 ** depth;
          if (spent.has(leaf)) {
            if (isLeafAvailable(state, leaf)) return false;
            continue;
          }
          state = signAtLeaf(state, leaf, MSG).newState;
          spent.add(leaf);
        }
        const avail = availableLeaves(state);
        const uniq = new Set(avail);
        if (uniq.size !== avail.length) return false; // disjoint
        if (avail.length !== 2 ** depth - spent.size) return false; // exact
        for (const s of spent) if (uniq.has(s)) return false;
        return state.covering.size <= 1 + depth * spent.size;
      }),
      { numRuns: 60 },
    );
  });
});

describe('post-compromise behaviour and state-copy semantics (documented limitations, asserted)', () => {
  it('[LIMITATION] there is NO post-compromise security: whoever steals the current state can sign every unspent leaf', () => {
    const { rootCommitment, state } = deriveRatchetRoot(SEED, 4);
    const { newState: stolen } = signAtLeaf(state, 1, MSG);
    for (const j of availableLeaves(stolen)) {
      const m = new TextEncoder().encode('forged');
      expect(verifyLeafSignature(rootCommitment, j, m, signAtLeaf(stolen, j, m).signature)).toBe(true);
    }
  });

  it('compromise of the state AFTER spending reveals nothing about spent leaves (forward security), so past signatures stay unforgeable for those leaves', () => {
    const { rootCommitment, state } = deriveRatchetRoot(SEED, 4);
    const m = new TextEncoder().encode('pay 10');
    const { signature, newState } = signAtLeaf(state, 2, m);
    expect(() => signAtLeaf(newState, 2, new TextEncoder().encode('pay 10000'))).toThrow(RatchetError);
    expect(verifyLeafSignature(rootCommitment, 2, m, signature)).toBe(true);
    // the attacker's only alternative is to guess the Ed25519 signing key; a signature under a different key fails the Merkle binding
    const other = ed25519.utils.randomPrivateKey();
    const forged = { ...signature, edSig: b64u(ed25519.sign(new Uint8Array(40), other)) };
    expect(verifyLeafSignature(rootCommitment, 2, new TextEncoder().encode('pay 10000'), forged)).toBe(false);
  });

  it('[LIMITATION] one-time-use is a property of the state HOLDER: a retained old state can sign the same leaf again with a different message, and both signatures verify', () => {
    const { rootCommitment, state } = deriveRatchetRoot(SEED, 3);
    const a = signAtLeaf(state, 4, new TextEncoder().encode('A'));
    const b = signAtLeaf(state, 4, new TextEncoder().encode('B')); // fork from the OLD state
    expect(verifyLeafSignature(rootCommitment, 4, new TextEncoder().encode('A'), a.signature)).toBe(true);
    expect(verifyLeafSignature(rootCommitment, 4, new TextEncoder().encode('B'), b.signature)).toBe(true);
    // but double-spending is publicly DETECTABLE: same leaf key, two messages, two different valid signatures
    expect(a.signature.leafPubKey).toBe(b.signature.leafPubKey);
    expect(a.signature.edSig).not.toBe(b.signature.edSig);
  });

  it('Ed25519 nonces are deterministic per (key, message): signing the same message twice is byte-identical, different messages never reuse the nonce R', () => {
    const { state } = deriveRatchetRoot(SEED, 3);
    const s1 = signAtLeaf(state, 1, MSG).signature.edSig;
    const s2 = signAtLeaf(state, 1, MSG).signature.edSig;
    expect(s1).toBe(s2);
    const rs = new Set<string>();
    for (let i = 0; i < 20; i++) rs.add(hex(unb64u(signAtLeaf(state, 1, Uint8Array.of(i)).signature.edSig).slice(0, 32)));
    expect(rs.size).toBe(20);
  });
});

describe('signature and Merkle-binding attacks', () => {
  const depth = 4;
  const { rootCommitment, state } = deriveRatchetRoot(SEED, depth);
  const sig = signAtLeaf(state, 9, MSG).signature;

  it('the signature does not verify at another leaf index, another message, another root', () => {
    expect(verifyLeafSignature(rootCommitment, 9, MSG, sig)).toBe(true);
    expect(verifyLeafSignature(rootCommitment, 8, MSG, sig)).toBe(false);
    expect(verifyLeafSignature(rootCommitment, 9, new TextEncoder().encode('spenT'), sig)).toBe(false);
    expect(verifyLeafSignature(deriveRatchetRoot(new Uint8Array(32).fill(7), depth).rootCommitment, 9, MSG, sig)).toBe(false);
  });

  it('a leaf signature cannot be re-targeted by editing merklePath.index (path shape and index are bound)', () => {
    for (const idx of [8, 10, 0, 15, -1, 16, 9.5, Number.NaN]) {
      const lifted = { ...sig, merklePath: { ...sig.merklePath, index: idx } };
      expect(verifyLeafSignature(rootCommitment, idx, MSG, lifted)).toBe(false);
    }
  });

  it('Ed25519 malleability: S + L, flipped R/S bits, truncated / extended / non-canonical-base64 signatures are all rejected', () => {
    const raw = unb64u(sig.edSig);
    const L = ed25519.CURVE.n;
    const S = BigInt('0x' + Buffer.from(raw.slice(32)).reverse().toString('hex'));
    const sPlusL = S + L;
    const mall = new Uint8Array(64);
    mall.set(raw.slice(0, 32));
    const sBytes = Buffer.from(sPlusL.toString(16).padStart(64, '0'), 'hex').reverse();
    mall.set(sBytes.slice(0, 32), 32);
    const variants: Uint8Array[] = [mall, raw.slice(0, 63), Uint8Array.of(...raw, 0)];
    for (let bit = 0; bit < 512; bit += 37) { const v = raw.slice(); v[bit >> 3] = (v[bit >> 3] ?? 0) ^ (1 << (bit & 7)); variants.push(v); }
    for (const v of variants) expect(verifyLeafSignature(rootCommitment, 9, MSG, { ...sig, edSig: b64u(v) })).toBe(false);
    expect(verifyLeafSignature(rootCommitment, 9, MSG, { ...sig, edSig: sig.edSig + '=' })).toBe(false);
  });

  it('swapping in another leaf key (with its own valid Merkle path) breaks the signature; a key outside the tree has no valid path', () => {
    const other = signAtLeaf(state, 3, MSG).signature;
    expect(verifyLeafSignature(rootCommitment, 9, MSG, { ...sig, leafPubKey: other.leafPubKey })).toBe(false);
    expect(verifyLeafSignature(rootCommitment, 9, MSG, { ...sig, merklePath: other.merklePath })).toBe(false);
    const outsider = b64u(ed25519.getPublicKey(ed25519.utils.randomPrivateKey()));
    expect(verifyLeafSignature(rootCommitment, 9, MSG, { ...sig, leafPubKey: outsider })).toBe(false);
  });

  it('second-preimage / interior-node substitution: presenting an interior hash as the leaf, with a shortened path, is rejected', () => {
    const path = sig.merklePath.path;
    const shortened = { ...sig.merklePath, size: 8, path: path.slice(0, path.length - 1) };
    expect(verifyLeafSignature(rootCommitment, 9, MSG, { ...sig, merklePath: shortened })).toBe(false);
    const truncatedLeaf = { ...sig, leafPubKey: path[0]!.hash };
    expect(verifyLeafSignature(rootCommitment, 9, MSG, truncatedLeaf)).toBe(false);
  });

  it('hostile verify inputs never throw', () => {
    const junk: unknown[] = [null, undefined, 5, 'x', {}, { edSig: 1, leafPubKey: 2, merklePath: 3 }, { edSig: '', leafPubKey: '', merklePath: null }, { ...sig, merklePath: { index: 9, size: 16, path: 'no' } }];
    for (const j of junk) expect(() => verifyLeafSignature(rootCommitment, 9, MSG, j as never)).not.toThrow();
    for (const j of junk) expect(verifyLeafSignature(rootCommitment, 9, MSG, j as never)).toBe(false);
  });
});

describe('construction hygiene', () => {
  it('all 2^8 leaf public keys are distinct and none equals a seed-derived key of a different tree', () => {
    const a = deriveRatchetRoot(SEED, 8).state.leafPubKeys;
    const b = deriveRatchetRoot(new Uint8Array(32).fill(1), 8).state.leafPubKeys;
    expect(new Set(a).size).toBe(256);
    expect(a.filter((k) => b.includes(k))).toEqual([]);
  });

  it('seed handling: deterministic, full-length sensitive, rejects short / non-byte seeds and bad depths', () => {
    expect(deriveRatchetRoot(SEED, 3).rootCommitment).toBe(deriveRatchetRoot(SEED, 3).rootCommitment);
    const longA = new Uint8Array(64).fill(1);
    const longB = longA.slice();
    longB[63] = 2; // differs only beyond byte 32
    expect(deriveRatchetRoot(longA, 3).rootCommitment).not.toBe(deriveRatchetRoot(longB, 3).rootCommitment);
    expect(deriveRatchetRoot(SEED, 3).rootCommitment).not.toBe(deriveRatchetRoot(SEED, 4).rootCommitment);
    for (const bad of [new Uint8Array(31), new Uint8Array(0), 'x'.repeat(40), null, [1, 2, 3]]) expect(() => deriveRatchetRoot(bad as never, 3)).toThrow(RatchetError);
    for (const d of [0, -1, 21, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) expect(() => deriveRatchetRoot(SEED, d)).toThrow(RatchetError);
  });

  it('leaf index validation: out of range / fractional / NaN / non-number are rejected without touching state', () => {
    const { state } = deriveRatchetRoot(SEED, 3);
    for (const i of [-1, 8, 1.5, Number.NaN, Number.POSITIVE_INFINITY, '3' as never, null as never]) {
      expect(() => signAtLeaf(state, i as number, MSG)).toThrow(RatchetError);
    }
    expect(availableLeaves(state).length).toBe(8);
  });

  it('the leaf signing key is a different value from the leaf seed, and PRG outputs differ per direction', () => {
    const { state } = deriveRatchetRoot(SEED, 2);
    const root = [...state.covering.values()][0]!.seed;
    expect(hex(prg(root, 0))).not.toBe(hex(prg(root, 1)));
    const leaf = derivable(state).leafSeeds.get(0)!;
    expect(leafPublicKey(leaf)).toBe(state.leafPubKeys[0]);
    expect(hex(hmac(sha256, leaf, DOMAINS[1]!))).not.toBe(hex(leaf));
  });
});
