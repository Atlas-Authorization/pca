/**
 * Cross-domain mesh conformance vectors (conformance/mesh-vectors.json).
 *
 * Each vector is a whole MeshProof plus the verifier's MeshTrust and the verdict the TypeScript reference returns
 * (`ok`, and for a refusal the exact `reason` and failing `hop`). A native verifier reproduces `ok` on every vector
 * and the reason on every vector whose reason does not come from the capability-chain check (those start `chain:`
 * and are compared by prefix). Vectors that need an RFC 9162 consistency proof from a pin (`requires:
 * ['pin_consistency']`) are for verifiers that implement it.
 *
 *     tsx packages/pca/scripts/gen-conformance-mesh.ts [--check]
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { type Capability, capHash } from '../src/capability';
import { b64u, hashCanonical, unb64u, utf8 } from '../src/hash';
import { encodeKey, publicKeyOf, sign } from '../src/keys';
import { type MeshProof, type MeshTrust, MeshDomain, MeshWitness, assembleMeshProof, buildMeshExample, keyRevocationId, verifyMeshProof, type MeshExample } from '../src/mesh';

const NOW = 1_800_000_000_000;
const pub = (s: Uint8Array) => encodeKey(publicKeyOf(s));
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x)) as T;

function forgeHop(parent: Capability, holder: string, caveats: Capability['caveats'], signer: Uint8Array): Capability {
  const body = { issuer: parent.holder, holder, caveats, parent: capHash(parent) };
  const digest = hashCanonical(body);
  const p = utf8('atlas-pca/cap/v1\0');
  const d = unb64u(digest);
  const m = new Uint8Array(p.length + d.length);
  m.set(p);
  m.set(d, p.length);
  return { id: digest, issuer: body.issuer, holder, caveats, parent: body.parent, body_digest: digest, sig: b64u(sign(signer, m)) } as Capability;
}

interface Vec {
  name: string;
  requires?: string[];
  proof: unknown;
  trust: unknown;
  expect: { ok: boolean; reason?: string; hop?: number };
}
const vectors: Vec[] = [];
const seen = new Set<string>();

function emit(name: string, proof: unknown, trust: unknown, requires?: string[]): void {
  if (seen.has(name)) throw new Error(`duplicate vector ${name}`);
  seen.add(name);
  const v = verifyMeshProof(clone(proof) as MeshProof, clone(trust) as MeshTrust);
  vectors.push({ name, ...(requires ? { requires } : {}), proof: clone(proof), trust: clone(trust), expect: { ok: v.ok, ...(v.reason !== undefined ? { reason: v.reason } : {}), ...(v.hop !== undefined ? { hop: v.hop } : {}) } });
}
/** Mutate a fresh example's proof and/or trust. */
function variant(name: string, f: (ex: MeshExample, p: any, t: any) => void | { proof?: unknown; trust?: unknown }, requires?: string[]): void {
  const ex = buildMeshExample(NOW);
  const p = clone(ex.proof) as any;
  const t = clone(ex.trust) as any;
  const r = f(ex, p, t);
  emit(name, r && r.proof !== undefined ? r.proof : p, r && r.trust !== undefined ? r.trust : t, requires);
}

// ---- the valid proof and trust-side variants
variant('valid/base', () => {});
variant('valid/threshold-1', (_e, _p, t) => void (t.threshold = 1));
variant('valid/threshold-3', (_e, _p, t) => void (t.threshold = 3));
variant('valid/pin-equals-presented-head', (e, _p, t) => void (t.pinnedHeads = { [e.domains.A.id]: e.heads.A.head }));
variant('valid/issuer-domain-pin-correct', (e, _p, t) => void (t.issuerDomains = { [pub(e.keys.orchestrator)]: e.domains.A.id }));
variant('valid/max-action-age-ok', (_e, _p, t) => void (t.maxActionAgeMs = 10));
variant('valid/clock-skew-zero', (_e, _p, t) => void (t.maxClockSkewMs = 0));
variant('trust/head-age-exact-boundary', (e, _p, t) => void (t.now = NOW - 1000 + 300_000, t.maxClockSkewMs = 0, e));
variant('trust/head-age-boundary-plus-1', (_e, _p, t) => void (t.now = NOW - 1000 + 300_001, t.maxClockSkewMs = 0));
variant('trust/head-future-beyond-skew', (_e, _p, t) => void (t.now = NOW - 1000 - 60_001));
variant('trust/head-future-within-skew', (_e, _p, t) => void (t.now = NOW - 1000 - 60_000));
variant('trust/unpinned-witnesses', (_e, _p, t) => void (t.witnesses = [t.witnesses[0], pub(new Uint8Array(32).fill(7))]));
variant('trust/wrong-human', (_e, _p, t) => void (t.humanPrincipal = pub(new Uint8Array(32).fill(5))));
variant('trust/domain-b-not-allowed', (e, _p, t) => void (t.allowedDomains = [e.domains.A.id, e.domains.C.id]));
variant('trust/root-domain-not-allowed', (_e, _p, t) => void (t.rootDomain = 'nowhere'));
variant('trust/root-domain-other-allowed-domain', (e, _p, t) => void (t.rootDomain = e.domains.B.id));
variant('trust/allowed-domains-missing', (_e, _p, t) => void delete t.allowedDomains);
variant('trust/allowed-domains-empty', (_e, _p, t) => void (t.allowedDomains = []));
variant('trust/root-domain-missing', (_e, _p, t) => void delete t.rootDomain);
variant('trust/issuer-domain-pinned-elsewhere', (e, _p, t) => void (t.issuerDomains = { [pub(e.keys.orchestrator)]: e.domains.B.id }));
variant('trust/issuer-domains-not-strings', (_e, _p, t) => void (t.issuerDomains = { x: 5 }));
variant('trust/max-chain-length-3', (_e, _p, t) => void (t.maxChainLength = 3));
variant('trust/max-chain-length-4', (_e, _p, t) => void (t.maxChainLength = 4));
variant('trust/invalid/max-action-age-negative', (_e, _p, t) => void (t.maxActionAgeMs = -0.5 + 0));
for (const [n, patch] of Object.entries({
  'threshold-0': { threshold: 0 },
  'threshold-4': { threshold: 4 },
  'threshold-fraction': { threshold: 1.5 },
  'threshold-nan': { threshold: null },
  'now-null': { now: null },
  'witnesses-string': { witnesses: 'x' },
  'witnesses-empty': { witnesses: [] },
  'max-head-age-negative': { maxHeadAgeMs: -1 },
  'max-skew-negative': { maxClockSkewMs: -5 },
  'max-chain-zero': { maxChainLength: 0 },
  'allowed-domains-string': { allowedDomains: 'a' },
  'pinned-heads-array': { pinnedHeads: [] },
  'human-number': { humanPrincipal: 5 },
} as Record<string, object>)) variant(`trust/invalid/${n}`, (_e, _p, t) => void Object.assign(t, patch));
variant('trust/duplicate-witnesses-threshold-2', (_e, _p, t) => void (t.witnesses = ['w', 'w', 'w'], t.threshold = 2));

// ---- structural mutations of the proof
const mutations: [string, (p: any, e: MeshExample) => void][] = [
  ['chain-removed', (p) => delete p.chain],
  ['chain-empty', (p) => (p.chain = [])],
  ['heads-null', (p) => (p.heads = null)],
  ['rev-leaves-string', (p) => (p.rev_leaves = 'x')],
  ['hops-empty', (p) => (p.hops = [])],
  ['hop-null', (p) => (p.hops[0] = null)],
  ['hop-head-index-out-of-range', (p) => (p.hops[0].head = 99)],
  ['hop-head-index-negative', (p) => (p.hops[0].head = -1)],
  ['hop-head-index-fraction', (p) => (p.hops[0].head = 0.5)],
  ['hop-domain-number', (p) => (p.hops[0].domain = 5)],
  ['hop-revocation-null', (p) => (p.hops[1].revocation = null)],
  ['nm-index-out-of-range', (p) => (p.hops[2].revocation.cap = { size: 0, lo: 50 })],
  ['nm-size-negative', (p) => (p.hops[2].revocation.cap = { size: -1 })],
  ['nm-size-lying', (p) => (p.hops[2].revocation.issuer_key = { size: 3 })],
  ['inclusion-null', (p) => (p.hops[0].inclusion = null)],
  ['inclusion-path-huge', (p) => (p.hops[0].inclusion.path = new Array(500).fill({ side: 'L', hash: 'AA' }))],
  ['inclusion-other-hop', (p) => (p.hops[1].inclusion = p.hops[0].inclusion)],
  ['inclusion-size-mismatch', (p) => (p.hops[0].inclusion.size += 1)],
  ['head-null', (p) => (p.heads[0] = null)],
  ['head-cosigs-null', (p) => (p.heads[0].cosigs = null)],
  ['head-cosig-entries-null', (p) => (p.heads[0].cosigs = [null, 7])],
  ['head-cosigs-flood', (p) => (p.heads[0].cosigs = new Array(1000).fill(p.heads[0].cosigs[0]))],
  ['head-cosigs-one-witness-thrice', (p) => { for (const h of p.heads) h.cosigs = [h.cosigs[0], h.cosigs[0], h.cosigs[0]]; }],
  ['head-cosigs-only-one', (p) => { for (const h of p.heads) h.cosigs = h.cosigs.slice(0, 1); }],
  ['head-cosig-sig-flipped', (p) => { for (const h of p.heads) for (const c of h.cosigs) c.sig = c.sig.slice(0, -2) + (c.sig.endsWith('AA') ? 'BB' : 'AA'); }],
  ['head-sig-number', (p) => (p.heads[0].sig = 5)],
  ['head-size-negative', (p) => (p.heads[0].head.size = -1)],
  ['head-size-incremented', (p) => (p.heads[p.hops[2].head].head.size += 1)],
  ['head-root-empty-with-size', (p) => (p.heads[0].head.root = '')],
  ['head-timestamp-string', (p) => (p.heads[0].head.timestamp = 'x')],
  ['head-domain-missing', (p) => delete p.heads[0].head.domain],
  ['head-extra-unreferenced', (p, e) => p.heads.push(clone(e.heads.A0))],
  ['head-table-short', (p) => p.heads.pop()],
  ['head-swapped-for-other-domain', (p, e) => (p.heads[p.hops[2].head] = clone(e.heads.A))],
  ['binding-null', (p) => (p.hops[1].binding = null)],
  ['binding-role-number', (p) => (p.hops[1].binding.role = 5)],
  ['binding-missing', (p) => delete p.hops[2].binding],
  ['binding-other-agent', (p, e) => (p.hops[2].binding.agent = pub(e.keys.service))],
  ['binding-sig-flipped', (p) => (p.hops[2].binding.sig = p.hops[2].binding.sig.slice(0, -2) + (p.hops[2].binding.sig.endsWith('AA') ? 'BB' : 'AA'))],
  ['action-null', (p) => (p.action = null)],
  ['action-amount-nan', (p) => (p.action.amount = null)],
  ['action-amount-string', (p) => (p.action.amount = '1')],
  ['action-nonce-number', (p) => (p.action.nonce = 1)],
  ['action-at-null', (p) => (p.action.at = null)],
  ['action-sig-number', (p) => (p.action_sig = 5)],
  ['action-nonce-changed-after-signing', (p) => (p.action.nonce = 'n-0002')],
  ['pin-proofs-not-array', (p) => (p.pin_proofs = {})],
  ['pin-proofs-bad-entry', (p) => (p.pin_proofs = [{ domain: 1 }])],
  ['chain-element-null', (p) => (p.chain[1] = null)],
  ['chain-element-wrong-shape', (p) => (p.chain[2] = { id: 1 })],
  ['chain-caveats-not-array', (p) => (p.chain[1].caveats = 'x')],
  ['chain-sig-flipped', (p) => (p.chain[1].sig = p.chain[1].sig.slice(0, -2) + (p.chain[1].sig.endsWith('AA') ? 'BB' : 'AA'))],
  ['chain-reordered', (p) => ([p.chain[1], p.chain[2]] = [p.chain[2], p.chain[1]])],
  ['chain-truncated', (p) => p.chain.pop()],
  ['hops-extra', (p) => p.hops.push(clone(p.hops[3]))],
  ['rev-leaves-flooded', (p) => (p.rev_leaves = new Array(20).fill({ id: 'x', proof: { index: 0, size: 1, path: [] } }))],
  ['rev-leaves-bad-entry', (p) => (p.rev_leaves = [{ id: 5 }])],
];
for (const [n, m] of mutations) variant(`mutation/${n}`, (e, p) => void m(p, e));

// ---- action variants (re-signed by the leaf where the action changes, so the failure is the action's own)
function withAction(name: string, patch: Record<string, unknown>, sign_ = true, trustPatch: Record<string, unknown> = {}): void {
  variant(name, (e, _p, t) => {
    const action = JSON.parse(JSON.stringify({ ...e.proof.action, ...patch }));
    const proof = assembleMeshProof({ chain: e.chain, hops: e.evidence, action: action as never, leafSecret: sign_ ? e.keys.leaf : e.keys.tool });
    return { proof, trust: { ...t, ...trustPatch } };
  });
}
withAction('action/amount-at-ceiling', { amount: 50 });
withAction('action/amount-over-ceiling', { amount: 50.01 });
withAction('action/amount-missing', { amount: undefined });
withAction('action/amount-zero', { amount: 0 });
withAction('action/type-out-of-scope', { type: 'payments.read' });
withAction('action/type-in-root-but-not-leaf-scope', { type: 'orders.read' });
withAction('action/resource-outside-prefix', { resource: '/orders/43/x' });
withAction('action/resource-exact-prefix', { resource: '/orders/42' });
withAction('action/service-domain-wrong', { service_domain: 'org-A' });
withAction('action/signed-by-wrong-holder', {}, false);
withAction('action/in-future-beyond-skew', { at: NOW + 60_001 }, true, {});
withAction('action/in-future-within-skew', { at: NOW + 60_000 }, true, {});
withAction('action/stale-with-max-age', { at: NOW - 11 }, true, { maxActionAgeMs: 10 });
withAction('action/at-max-age-boundary', { at: NOW - 10 }, true, { maxActionAgeMs: 10 });
variant('action/capability-expired', (e, _p, t) => {
  const late = { ...t, now: NOW + 2 * 3_600_000, maxHeadAgeMs: 10 * 3_600_000 };
  const proof = assembleMeshProof({ chain: e.chain, hops: e.evidence, action: { ...e.proof.action, at: late.now }, leafSecret: e.keys.leaf });
  return { proof, trust: late };
});
variant('action/at-expiry-boundary', (e, _p, t) => {
  const edge = { ...t, now: NOW + 3_600_000, maxHeadAgeMs: 10 * 3_600_000 };
  const proof = assembleMeshProof({ chain: e.chain, hops: e.evidence, action: { ...e.proof.action, at: edge.now }, leafSecret: e.keys.leaf });
  return { proof, trust: edge };
});

// ---- attenuation: a hop that widens must be refused even though every signature is valid
function widen(name: string, caveats: (c1: Capability) => Capability['caveats']): void {
  variant(name, (e, _p, t) => {
    const [root, c1] = e.chain;
    const wide = forgeHop(c1!, pub(e.keys.service), caveats(c1!), e.keys.tool);
    e.domains.B.record(wide);
    const hB = e.domains.B.publishHead(e.witnesses, NOW - 500);
    const evidence = [e.evidence[0]!, e.evidence[1]!, e.domains.B.evidence(wide, hB, e.bindings.tool)];
    return { proof: assembleMeshProof({ chain: [root!, c1!, wide], hops: evidence, action: e.proof.action, leafSecret: e.keys.service }), trust: t };
  });
}
widen('attenuation/drops-parent-caveat', (c1) => [c1.caveats[0]!]);
widen('attenuation/larger-ceiling', (c1) => c1.caveats.map((c) => (c.type === 'max_amount' ? { ...c, max: 10_000 } : c)));
widen('attenuation/unknown-caveat-type', (c1) => [...c1.caveats, { type: 'mystery' }]);
widen('attenuation/narrowing-extra-caveat-ok', (c1) => [...c1.caveats, { type: 'max_amount', max: 10 }]);
widen('attenuation/malformed-scope-caveat', (c1) => [...c1.caveats, { type: 'scope', actions: 'x' }]);
widen('attenuation/malformed-expires-caveat', (c1) => [...c1.caveats, { type: 'expires', at: 'soon' }]);
widen('attenuation/reordered-parent-caveats', (c1) => [...c1.caveats].reverse());

// ---- revocation
variant('revocation/mid-chain-cap-revoked-after-head', (e, p) => {
  e.domains.B.revoke(e.chain[2]!.id);
  const hB2 = e.domains.B.publishHead(e.witnesses, NOW - 100);
  p.heads[p.hops[2].head] = clone(hB2); // the new head with the old (stale) non-membership proofs
});
variant('revocation/mid-chain-cap-revoked-pinned', (e, p, t) => {
  e.domains.B.revoke(e.chain[2]!.id);
  const hB2 = e.domains.B.publishHead(e.witnesses, NOW - 100);
  t.pinnedHeads = { [e.domains.B.id]: clone(hB2.head) };
  void p;
});
variant('revocation/root-revoked-pinned', (e, _p, t) => {
  e.domains.A.revoke(e.chain[0]!.id);
  const hA2 = e.domains.A.publishHead(e.witnesses, NOW - 100);
  t.pinnedHeads = { [e.domains.A.id]: clone(hA2.head) };
}, ['pin_consistency']);
variant('revocation/agent-key-revoked-spliced-head', (e, p) => {
  e.domains.B.revoke(keyRevocationId(pub(e.keys.tool)));
  const hB2 = e.domains.B.publishHead(e.witnesses, NOW - 100);
  p.heads[p.hops[2].head] = clone(hB2);
});
variant('revocation/unrelated-revocations-compact-leaves', (e) => {
  for (const id of ['some-other-cap', 'aaa', 'zzz', 'key:other']) e.domains.B.revoke(id);
  const hB2 = e.domains.B.publishHead(e.witnesses, NOW - 100);
  const evidence = [...e.evidence];
  evidence[2] = e.domains.B.evidence(e.chain[2]!, hB2, e.bindings.tool);
  return { proof: assembleMeshProof({ chain: e.chain, hops: evidence, action: e.proof.action, leafSecret: e.keys.leaf }) };
});
variant('revocation/unrelated-wrong-leaf-index', (e) => {
  for (const id of ['some-other-cap', 'aaa', 'zzz', 'key:other']) e.domains.B.revoke(id);
  const hB2 = e.domains.B.publishHead(e.witnesses, NOW - 100);
  const evidence = [...e.evidence];
  evidence[2] = e.domains.B.evidence(e.chain[2]!, hB2, e.bindings.tool);
  const p = clone(assembleMeshProof({ chain: e.chain, hops: evidence, action: e.proof.action, leafSecret: e.keys.leaf })) as any;
  p.hops[2].revocation.cap = { size: 4, lo: 0, hi: 0 };
  return { proof: p };
});
variant('revocation/unrelated-adjacent-below-minimum', (e) => {
  for (const id of ['zzz', 'zzy']) e.domains.B.revoke(id);
  const hB2 = e.domains.B.publishHead(e.witnesses, NOW - 100);
  const evidence = [...e.evidence];
  evidence[2] = e.domains.B.evidence(e.chain[2]!, hB2, e.bindings.tool);
  return { proof: assembleMeshProof({ chain: e.chain, hops: evidence, action: e.proof.action, leafSecret: e.keys.leaf }) };
});

// ---- pins
variant('pin/rollback-pin-larger-than-head', (e, _p, t) => void (t.pinnedHeads = { [e.domains.A.id]: { ...clone(e.heads.A.head), size: 3 } }));
variant('pin/equivocation-same-size-other-root', (e, _p, t) => void (t.pinnedHeads = { [e.domains.A.id]: { ...clone(e.heads.A.head), root: e.heads.A0.head.root } }));
variant('pin/revocation-size-shrinks', (e, _p, t) => void (t.pinnedHeads = { [e.domains.A.id]: { ...clone(e.heads.A.head), rev_size: 5 } }));
variant('pin/larger-head-without-consistency-proof', (e, _p, t) => void (t.pinnedHeads = { [e.domains.A.id]: clone(e.heads.A0.head) }));
variant('pin/larger-head-with-consistency-proof', (e, p, t) => {
  t.pinnedHeads = { [e.domains.A.id]: clone(e.heads.A0.head) };
  p.pin_proofs = [{ domain: e.domains.A.id, proof: clone(e.domains.A.consistencyProof(1, 2)) }];
}, ['pin_consistency']);
variant('pin/prototype-named-domain', (_e, _p, t) => void (t.pinnedHeads = { __proto__x: {} }));

// ---- a rogue domain re-vouches a revoked chain
variant('rogue/root-anchored-in-allowed-rogue-domain', (e, _p, t) => {
  const E = new MeshDomain('rogue', utf8(hashCanonical({ seed: 'rogue' })).slice(0, 32));
  E.record(e.chain[0]!);
  E.record(e.chain[1]!);
  const hE = E.publishHead(e.witnesses, NOW - 500);
  const bE = E.enroll(pub(e.keys.orchestrator), 'orchestrator');
  const evidence = [E.evidence(e.chain[0]!, hE), E.evidence(e.chain[1]!, hE, bE), e.evidence[2]!, e.evidence[3]!];
  return {
    proof: assembleMeshProof({ chain: e.chain, hops: evidence, action: { ...e.proof.action, nonce: 'n-0002' }, leafSecret: e.keys.leaf }),
    trust: { ...t, allowedDomains: [...t.allowedDomains, E.id] },
  };
});
variant('rogue/head-cosigned-only-by-unpinned-witnesses', (e, _p, t) => {
  const rogue = [new MeshWitness(new Uint8Array(32).fill(1)), new MeshWitness(new Uint8Array(32).fill(2))];
  const evil = new MeshDomain('evil-B', new Uint8Array(32).fill(9));
  const c2 = e.chain[2]!;
  evil.record(c2);
  const h = evil.publishHead(rogue, NOW - 100);
  const evidence = [...e.evidence];
  evidence[2] = evil.evidence(c2, h, evil.enroll(c2.issuer, 'tool-agent'));
  return { proof: assembleMeshProof({ chain: e.chain, hops: evidence, action: e.proof.action, leafSecret: e.keys.leaf }), trust: { ...t, allowedDomains: [...t.allowedDomains, evil.id] } };
});

const doc = {
  format: 'pca-mesh-conformance/1',
  description:
    'Whole cross-domain mesh proofs (MeshProof) with the verifier trust (MeshTrust) and the TypeScript verdict. A native verifier must reproduce `ok` on every vector it supports and `reason` / `hop` on every vector whose reason does not start `chain:`; vectors with `requires: ["pin_consistency"]` need RFC 9162 consistency verification from a pinned head.',
  now: NOW,
  mesh: vectors,
};
const text = JSON.stringify(doc) + '\n';
const out = join(__dirname, '..', 'conformance', 'mesh-vectors.json');
if (process.argv.includes('--check')) {
  if (readFileSync(out, 'utf8') !== text) {
    console.error('mesh-vectors.json is stale: run gen-conformance-mesh.ts');
    process.exit(1);
  }
} else {
  writeFileSync(out, text);
  const ok = vectors.filter((v) => v.expect.ok).length;
  console.log(`${vectors.length} mesh vectors (${ok} accept, ${vectors.length - ok} refuse)`);
}
