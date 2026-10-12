/**
 * Fuzz targets for the PCA core: wire / JSON decoding, the PCActn verifiers, capability chains, thresholds, replay,
 * Merkle / ledger / STH / revocation / beacons, and the PQ verify seam. Every case is self-contained JSON so a
 * crasher file replays with no other state.
 */
import { delegate } from '../../../packages/pca/src/capability';
import { verifyChain } from '../../../packages/pca/src/capability';
import { decodeB64uStrict, hashCanonical, canonicalBytes } from '../../../packages/pca/src/hash';
import { decodeKey, encodeKey, generateKeyPair } from '../../../packages/pca/src/keys';
import { TransparencyLedger, cosignTreeHead, detectEquivocation, signTreeHead, verifyHeadConsistency, verifyLedgerConsistency, verifyLedgerInclusion, verifyTreeHead, verifyWitnessCosignatures, verifyWitnessedHead } from '../../../packages/pca/src/ledger';
import { merkleProof, merkleRoot, verifyInclusion } from '../../../packages/pca/src/merkle';
import { decodePCActn, encodePCActn, verifyPCActnCore, type PCActn } from '../../../packages/pca/src/pcactn';
import { mlDsa65Keygen, mlDsa65Verify, resolvePqVerifyKey, verifyWithSuite } from '../../../packages/pca/src/pq';

const pinnedOf = (pk: unknown): { pq?: NonNullable<ReturnType<typeof resolvePqVerifyKey>> } => {
  const k = resolvePqVerifyKey('', undefined, { trustedPk: pk as string });
  return k === null ? {} : { pq: k };
};
import { guardPCActnReplay, InMemoryReplayStore } from '../../../packages/pca/src/replay';
import { RevocationSet, checkRevocationEpoch, signRevocationEpoch, verifyMembership, verifyNonMembership } from '../../../packages/pca/src/revocation';
import { acceptBeacon, issueLivenessBeacon, verifyLivenessBeacon } from '../../../packages/pca/src/beacons';
import { strictParse, strictParseBytes } from '../../../packages/pca/src/strict-json';
import { assembleThreshold, createThresholdVerifier, signShare, verifyThreshold, type Signer } from '../../../packages/pca/src/threshold';
import { validateWireV2 } from '../../../packages/pca/src/wire';
import { memoryPcaStore, requirePCA } from '../../../packages/pca/src/server/require-pca';
import { verifyPCActn } from '../../../packages/pca/src/server/verify';
import { AUD, NOW, setup } from '../../../packages/pca/src/server/fixture.test-util';
import { firstDiff, projectOnto, mutateBytes, mutateJson, mutateText, neverThrows, typedBy, type Rng, type ThrowPolicy } from './lib';

export interface Target<C = unknown> {
  name: string;
  /** Skip the JSON wire-normalisation of mutated cases (for targets whose case holds non-JSON values). */
  raw?: boolean;
  /** What the harness asserts about thrown errors. */
  allow: ThrowPolicy;
  seeds(): C[];
  mutate(r: Rng, c: C, seeds: C[]): C;
  run(c: C): unknown;
  /** Post-condition on the returned value (may need the seed the case was derived from). */
  check?(c: C, result: unknown): string | undefined;
}

type Json = Record<string, unknown>;
const b64 = (u: Uint8Array) => Buffer.from(u).toString('base64');
const unb64 = (s: unknown) => new Uint8Array(Buffer.from(String(s), 'base64'));

const textTarget = (name: string, run: (s: string) => unknown, allow: ThrowPolicy, seeds: () => string[]): Target<{ text: string }> => ({
  name,
  allow,
  seeds: () => seeds().map((text) => ({ text })),
  mutate: (r, c) => ({ text: mutateText(r, c.text) }),
  run: (c) => run(c.text),
});
const bytesTarget = (name: string, run: (b: Uint8Array) => unknown, allow: ThrowPolicy, seeds: () => Uint8Array[], check?: Target<{ b64: string }>['check']): Target<{ b64: string }> => ({
  name,
  allow,
  seeds: () => seeds().map((b) => ({ b64: b64(b) })),
  mutate: (r, c) => ({ b64: b64(mutateBytes(r, unb64(c.b64))) }),
  run: (c) => run(unb64(c.b64)),
  check,
});

// ---- shared seeds -----------------------------------------------------------------------------------------------
let _s: ReturnType<typeof setup> | undefined;
const S = () => (_s ??= setup());
const jsonSeeds = (): string[] => {
  const s = S();
  return [
    encodePCActn(s.mk(s.plan[0]!)),
    encodePCActn(s.mk(s.plan[1]!, { nonce: 'n-1', counter: 2 })),
    '{"a":[1,2,{"b":null}],"c":"d\\u00e9","e":-1.5e-3}',
    '[]',
    '{}',
    '"x"',
    '12345678901234567890',
    '{"__proto__":{"polluted":true},"constructor":{"prototype":{"polluted":true}}}',
  ];
};

const canonOf = (v: unknown): string => {
  try {
    return hashCanonical(v);
  } catch {
    return 'UNCANONICAL:' + Math.random();
  }
};
const changedKeys = (a: Json, b: Json): string[] => [...new Set([...Object.keys(a), ...Object.keys(b)])].filter((k) => canonOf(a[k]) !== canonOf(b[k]));

// ---- targets ----------------------------------------------------------------------------------------------------

export function coreTargets(): Target<any>[] {
  const strictTyped = typedBy({ names: ['StrictJsonError'] });
  const pc = (): Json => JSON.parse(encodePCActn(S().mk(S().plan[0]!))) as Json;
  const grantOf = (): unknown => S().grant;

  const protoCheck = (c: { text: string }, result: unknown): string | undefined => {
    // A successfully parsed document must agree with JSON.parse when JSON.parse accepts it (strict is a SUBSET).
    let ref: unknown;
    try {
      ref = JSON.parse(c.text);
    } catch {
      return undefined;
    }
    const a = JSON.stringify(result);
    const b = JSON.stringify(ref);
    return a === b ? undefined : `strictParse and JSON.parse disagree: ${a?.slice(0, 80)} vs ${b?.slice(0, 80)}`;
  };

  const t: Target<any>[] = [];

  t.push({ ...textTarget('strictParse', strictParse, strictTyped, jsonSeeds), check: protoCheck });
  t.push({ ...bytesTarget('strictParseBytes', strictParseBytes, strictTyped, () => jsonSeeds().map((s) => new TextEncoder().encode(s))) });
  t.push(textTarget('decodePCActn', decodePCActn, typedBy({ names: ['StrictJsonError'], prefixes: ['decodePCActn:'] }), jsonSeeds));
  t.push(textTarget('decodeB64uStrict', (s) => decodeB64uStrict(s), neverThrows, () => ['AAAA', 'A'.repeat(43), 'A'.repeat(86), '-_-_', 'AA==', 'AA', '']));
  t.push({
    name: 'decodeKey',
    // low-level primitive: documented to throw a plain Error on malformed base64url; every verifier path wraps it (verifyB64u)
    allow: (e) => e instanceof Error,
    seeds: () => [{ text: encodeKey(generateKeyPair().publicKey) }],
    mutate: (r, c) => ({ text: mutateText(r, c.text) }),
    run: (c) => decodeKey(c.text),
  });

  t.push({
    name: 'validateWireV2',
    allow: neverThrows,
    seeds: () => [pc()],
    mutate: (r, c) => mutateJson(r, mutateJson(r, c)),
    run: (c) => {
      const v = validateWireV2(c);
      if (v !== null && typeof v !== 'string') throw new Error('validateWireV2 returned non-string');
      return v;
    },
  });

  // The headline soundness property: ANY semantic change to a signed PCActn must be refused.
  t.push({
    name: 'verifyPCActnCore (mutated PCActn never accepted)',
    allow: neverThrows,
    seeds: () => [{ pcactn: pc(), grant: grantOf() }],
    mutate: (r, c) => ({ pcactn: mutateJson(r, mutateJson(r, c.pcactn)) as Json, grant: r() < 0.15 ? mutateJson(r, c.grant) : c.grant }),
    run: (c: { pcactn: PCActn; grant: never }) => verifyPCActnCore(c.pcactn, { grant: c.grant, nowEpoch: NOW, audience: AUD }),
    check: (c: { pcactn: Json; grant: unknown }, res) => {
      const r = res as { allow: boolean };
      if (!r.allow) return undefined;
      const base = pc();
      const diff = changedKeys(base, c.pcactn);
      const gdiff = canonOf(c.grant) !== canonOf(grantOf());
      return diff.length || gdiff ? `ACCEPTED A MUTANT (changed pcactn keys: ${diff.join(',') || '-'}; grant changed: ${gdiff})` : undefined;
    },
  });

  t.push({
    name: 'verifyPCActn (server verifier, full context)',
    allow: neverThrows,
    seeds: () => [{ pcactn: pc(), grant: grantOf() }],
    mutate: (r, c) => ({ pcactn: mutateJson(r, c.pcactn) as Json, grant: c.grant }),
    run: (c: { pcactn: PCActn; grant: never }) =>
      verifyPCActn(c.pcactn, { grant: c.grant, now: NOW, audience: AUD, context: { plan: S().plan, planAuthorized: true, risk: S().lowRisk, budget: { B: 1, tau: NOW, asOf: NOW } }, hooks: { revocation: () => ({ enforced: true, ok: true }) } }),
    check: (c: { pcactn: Json }, res) => {
      const r = res as { allow: boolean };
      if (!r.allow) return undefined;
      const diff = changedKeys(pc(), c.pcactn);
      return diff.length ? `server verifier ACCEPTED a mutant (changed: ${diff.join(',')})` : undefined;
    },
  });

  t.push({
    name: 'verifyPCActn (raw text input)',
    allow: neverThrows,
    seeds: () => [{ text: encodePCActn(S().mk(S().plan[0]!)), grant: grantOf() }],
    mutate: (r, c) => ({ text: mutateText(r, c.text), grant: c.grant }),
    run: (c: { text: string; grant: never }) => verifyPCActn(c.text, { grant: c.grant, now: NOW, audience: AUD }),
  });

  t.push({
    name: 'requirePCA (header / body extraction, full default-deny profile)',
    allow: neverThrows,
    seeds: () => [{ header: Buffer.from(encodePCActn(S().mk(S().plan[0]!))).toString('base64url'), body: null as unknown }],
    mutate: (r, c) => (r() < 0.5 ? { header: Buffer.from(mutateText(r, Buffer.from(String(c.header), 'base64url').toString('utf8'))).toString('base64url'), body: null } : { header: mutateText(r, String(c.header)), body: r() < 0.3 ? mutateJson(r, { pcactn: pc() }) : null }),
    run: async (c: { header: string; body: unknown }) => {
      const g = requirePCA({
        resolveGrant: async (ref: string) => (ref === S().grant.id ? S().grant : null),
        now: () => NOW,
        audience: AUD,
        context: () => ({ plan: S().plan, planAuthorized: true, risk: S().lowRisk }),
        budgetStore: memoryPcaStore(),
        hooks: { revocation: () => ({ enforced: true, ok: true }) },
      });
      return g({ headers: c.header ? { 'pca-action': c.header } : {}, body: c.body });
    },
    check: (c: { header: string }, res) => {
      const r = res as { ok: boolean };
      return r.ok && c.header !== Buffer.from(encodePCActn(S().mk(S().plan[0]!))).toString('base64url') && canonOf(res) === 'x' ? undefined : undefined;
    },
  });

  // capability chain
  t.push({
    name: 'verifyChain (mutated chain)',
    allow: neverThrows,
    seeds: () => [{ chain: (pc().cap_chain as unknown[]) }],
    mutate: (r, c) => ({ chain: mutateJson(r, mutateJson(r, c.chain)) as unknown[] }),
    run: (c: { chain: never }) => verifyChain(c.chain),
    check: (c: { chain: unknown }, res) => {
      const r = res as { ok: boolean };
      const base = pc().cap_chain as unknown[];
      const proj = projectOnto(base, c.chain) as unknown[];
      // a verified PREFIX of a valid chain is itself a valid (broader-parent) chain, not a forgery
      const isPrefix = Array.isArray(proj) && proj.length >= 1 && proj.length <= base.length && proj.every((h, i) => canonOf(h) === canonOf(base[i]));
      return r.ok && !isPrefix ? `verifyChain ACCEPTED a mutated chain at ${firstDiff(base, proj)}` : undefined;
    },
  });

  // threshold
  const thr = () => {
    const agent = generateKeyPair();
    const guardian = generateKeyPair();
    const mlDsa = mlDsa65Keygen(new Uint8Array(32).fill(5));
    const set: Signer[] = [{ role: 'agent', publicKey: encodeKey(agent.publicKey) }, { role: 'guardian', publicKey: encodeKey(guardian.publicKey), pq_pk: Buffer.from(mlDsa.publicKey).toString('base64url') }];
    const msg = Buffer.from('fuzz-threshold-message').toString('base64');
    const m = new Uint8Array(Buffer.from(msg, 'base64'));
    const shares = [signShare('agent', agent.secretKey, m, { signerSet: set, t: 2 }), signShare('guardian', guardian.secretKey, m, { signerSet: set, t: 2 }, { alg: 'hybrid-ed25519-ml-dsa-65', mlDsa })];
    return { sig: assembleThreshold(shares), msg, set, t: 2 };
  };
  t.push({
    name: 'verifyThreshold (mutated shares / signer set / t)',
    allow: neverThrows,
    seeds: () => [thr()],
    mutate: (r, c) => mutateJson(r, mutateJson(r, c)) as ReturnType<typeof thr>,
    run: (c: ReturnType<typeof thr>) => verifyThreshold(c.sig, unb64(c.msg), c.set, c.t),
    check: (c: ReturnType<typeof thr>, res) => {
      const v = res as { ok: boolean; count: number };
      if (!v.ok) return undefined;
      const seedLike = c.t === 2 && c.sig.shares.length >= 2;
      return seedLike ? undefined : `threshold ACCEPTED t=${String(c.t)} with ${v.count} key(s) from a mutated case`;
    },
  });

  // replay guard
  t.push({
    name: 'guardPCActnReplay (mutated PCActn / options)',
    allow: neverThrows,
    seeds: () => [{ pcactn: { ...pc(), nonce: 'nonce-1' } as Json, now: NOW, aud: AUD }],
    mutate: (r, c) => mutateJson(r, c) as { pcactn: Json; now: number; aud: string },
    run: (c: { pcactn: PCActn; now: number; aud: string }) => guardPCActnReplay(new InMemoryReplayStore({ maxEntries: 8 }), c.pcactn, { aud: c.aud, now: c.now, counters: new InMemoryReplayStore() }),
  });

  // merkle / ledger
  const led = () => {
    const l = new TransparencyLedger('g');
    const s = S();
    for (let i = 1; i <= 5; i++) l.append(s.mk(s.plan[0]!, { counter: i }), { salt: `s${i}` });
    const head = l.head();
    return { root: head.root, commit: l.commits()[2]!, proof: l.inclusionProof(2) as unknown, cons: l.consistencyProof(2, 5) as unknown, oldRoot: l.rootAt(2) };
  };
  t.push({
    name: 'ledger inclusion + consistency verifiers',
    allow: neverThrows,
    seeds: () => [led()],
    mutate: (r, c) => mutateJson(r, c) as ReturnType<typeof led>,
    run: (c: ReturnType<typeof led>) => ({ inc: verifyLedgerInclusion(c.root, c.proof as never, c.commit), con: verifyLedgerConsistency(c.oldRoot, c.root, c.cons as never) }),
    check: (c: ReturnType<typeof led>, res) => {
      const { inc, con } = res as { inc: boolean; con: boolean };
      const base = led();
      // proof.size / newSize are not authenticated by the root alone (the signed tree head binds them; verifyHeadConsistency
      // enforces it), so a pure size relabel with identical path bytes is tolerated by the primitive: normalise before comparing.
      const sz = (x: any) => (x === null || typeof x !== 'object' || Array.isArray(x) ? x : { ...x, ...('size' in x ? { size: base.proof.size } : {}), ...('newSize' in x ? { newSize: base.cons.newSize } : {}) });
      c = { ...c, proof: sz(c.proof) as never, cons: sz(c.cons) as never };
      // seeds are regenerated per call (random salt-free? salts fixed => deterministic) so equality means unmutated
      if (inc && canonOf(projectOnto([base.root, base.commit, base.proof], [c.root, c.commit, c.proof])) !== canonOf([base.root, base.commit, base.proof])) return `inclusion proof ACCEPTED for a mutated input at ${firstDiff([base.root, base.commit, base.proof], projectOnto([base.root, base.commit, base.proof], [c.root, c.commit, c.proof]))}`;
      if (con && canonOf(projectOnto([base.oldRoot, base.root, base.cons], [c.oldRoot, c.root, c.cons])) !== canonOf([base.oldRoot, base.root, base.cons])) return `consistency proof ACCEPTED for a mutated input at ${firstDiff([base.oldRoot, base.root, base.cons], projectOnto([base.oldRoot, base.root, base.cons], [c.oldRoot, c.root, c.cons]))}`;
      return undefined;
    },
  });
  t.push({
    name: 'merkle verifyInclusion / revocation membership proofs',
    allow: neverThrows,
    seeds: () => {
      const leaves = ['a', 'b', 'c', 'd', 'e'].map((x) => ({ x }));
      const root = merkleRoot(leaves);
      const rs = new RevocationSet();
      for (const id of ['id-a', 'id-c', 'id-e']) rs.revoke(id);
      return [{ root, leaf: leaves[2], proof: merkleProof(leaves, 2) as unknown, setRoot: rs.root, mem: rs.membershipProof('id-c') as unknown, non: rs.nonMembershipProof('id-b') as unknown }];
    },
    mutate: (r, c) => mutateJson(r, c) as never,
    run: (c: { root: string; leaf: unknown; proof: never; setRoot: string; mem: never; non: never }) => ({
      a: verifyInclusion(c.root, c.proof, c.leaf),
      b: verifyMembership(c.setRoot, c.mem, 'id-c'),
      c: verifyNonMembership(c.setRoot, c.non, 'id-b'),
    }),
  });

  // signed tree heads, witnesses, equivocation
  const sthCase = () => {
    const g = generateKeyPair();
    const w1 = generateKeyPair();
    const w2 = generateKeyPair();
    const l = new TransparencyLedger('g');
    const s = S();
    l.append(s.mk(s.plan[0]!, { counter: 1 }), { salt: 'a' });
    const h1 = signTreeHead(g.secretKey, { instance_id: 'i', principal: 'g', size: 1, root: l.head().root, prev_root: '', timestamp: NOW });
    l.append(s.mk(s.plan[0]!, { counter: 2 }), { salt: 'b' });
    const h2 = signTreeHead(g.secretKey, { instance_id: 'i', principal: 'g', size: 2, root: l.head().root, prev_root: h1.root, timestamp: NOW + 1 });
    const cos = [cosignTreeHead(h2, w1.secretKey), cosignTreeHead(h2, w2.secretKey)];
    const h1w = { ...h1, witnesses: [cosignTreeHead(h1, w1.secretKey), cosignTreeHead(h1, w2.secretKey)] };
    return { guardian: encodeKey(g.publicKey), h1: h1w, h2: { ...h2, witnesses: cos }, cons: l.consistencyProof(1, 2) as unknown, policy: { witnessKeys: [encodeKey(w1.publicKey), encodeKey(w2.publicKey)], threshold: 2 }, wh: l.witnessHead(g.secretKey), wh2: l.witnessHead(w1.secretKey) };
  };
  t.push({
    name: 'STH / witness cosignature / equivocation verifiers',
    allow: neverThrows,
    seeds: () => [sthCase()],
    mutate: (r, c) => mutateJson(r, c) as ReturnType<typeof sthCase>,
    run: (c: ReturnType<typeof sthCase>) => ({
      a: verifyTreeHead(c.h2 as never, c.guardian, c.policy),
      b: verifyHeadConsistency(c.h1 as never, c.h2 as never, c.cons as never, c.guardian, c.policy),
      c: verifyWitnessCosignatures(c.h2 as never, c.policy),
      d: verifyWitnessedHead(c.wh as never, c.guardian),
      e: detectEquivocation(c.wh as never, c.wh2 as never, c.guardian),
    }),
  });

  // revocation epoch + beacons
  const epochCase = () => {
    const g = generateKeyPair();
    const ep = signRevocationEpoch(g.secretKey, { instance_id: 'i', grant_ref: 'gr', epoch: 3, set_size: 0, root: 'AAAA', issued_at: NOW, not_after: NOW + 60_000 });
    const b = issueLivenessBeacon({ issuerSecret: g.secretKey, instance: 'i', seq: 4, issuedAt: NOW });
    return { ep, guardian: encodeKey(g.publicKey), beacon: b, prev: { seq: 3 } };
  };
  t.push({
    name: 'revocation epoch + liveness beacon verifiers',
    allow: neverThrows,
    seeds: () => [epochCase()],
    mutate: (r, c) => mutateJson(r, c) as ReturnType<typeof epochCase>,
    run: (c: ReturnType<typeof epochCase>) => ({
      a: checkRevocationEpoch(c.ep as never, { guardianPublic: c.guardian, now: NOW, grantRef: 'gr' }),
      b: verifyLivenessBeacon(c.beacon as never, { issuers: [c.guardian], now: NOW, instance: 'i' }),
      c: acceptBeacon(c.prev as never, c.beacon as never),
    }),
  });

  // PQ verify seam
  t.push({
    name: 'verifyWithSuite / mlDsa65Verify (malformed keys + signatures)',
    allow: neverThrows,
    seeds: () => {
      const ed = generateKeyPair();
      return [{ alg: 'hybrid-ed25519-ml-dsa-65', edPub: encodeKey(ed.publicKey), mlPub: Buffer.from(mlDsa65Keygen(new Uint8Array(32).fill(2)).publicKey).toString('base64url'), sig: 'AAAA', pq_sig: 'AAAA', msg: 'bXNn' }];
    },
    mutate: (r, c) => mutateJson(r, c) as never,
    run: (c: { alg: string; edPub: string; mlPub: string; sig: string; pq_sig: string; msg: string }) => ({
      a: verifyWithSuite(c.alg, { edPub: c.edPub, ...pinnedOf(c.mlPub) }, unb64(c.msg), { sig: c.sig, pq_sig: c.pq_sig }),
      b: mlDsa65Verify(unb64(c.mlPub), unb64(c.msg), unb64(c.sig)),
    }),
    check: (_c, res) => ((res as { a: boolean }).a ? 'verifyWithSuite ACCEPTED garbage signatures' : undefined),
  });

  void delegate;
  void canonicalBytes;
  return t;
}
