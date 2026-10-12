/**
 * Mutation-kill tests for mesh.ts `narrows` / "hop widens authority". With the REAL chain verifier a widening hop can never get
 * this far (caveats are byte-prefix append-only), so the defence-in-depth predicate is exercised here by stubbing ONLY
 * `verifyChain` to accept anything; every other check (heads, inclusion, bindings, revocation, signatures) stays real.
 */
import { describe, expect, it, vi } from 'vitest';

vi.mock('./capability', async (importOriginal) => {
  const m = await importOriginal<typeof import('./capability')>();
  return { ...m, verifyChain: () => ({ ok: true }) };
});

import { type Capability, type Caveat, capHash, mintRoot } from './capability';
import { b64u, hashCanonical, unb64u, utf8 } from './hash';
import { encodeKey, generateKeyPair, publicKeyOf, sign } from './keys';
import { assembleMeshProof, type MeshAction, MeshDomain, type MeshTrust, MeshWitness, verifyMeshProof } from './mesh';

const NOW = 1_800_000_000_000;
const pubOf = (s: Uint8Array) => encodeKey(publicKeyOf(s));

/** A validly SIGNED hop with arbitrary caveats (no append-only discipline). */
function forgeHop(parent: Capability, holder: string, caveats: Caveat[], signer: Uint8Array): Capability {
  const body = { issuer: parent.holder, holder, caveats, parent: capHash(parent) };
  const digest = hashCanonical(body);
  const p = utf8('atlas-pca/cap/v1\0');
  const d = unb64u(digest);
  const m = new Uint8Array(p.length + d.length);
  m.set(p);
  m.set(d, p.length);
  return { id: digest, issuer: body.issuer, holder, caveats, parent: body.parent, body_digest: digest, sig: b64u(sign(signer, m)) };
}

/** hops[i] are the FULL caveat lists of hop i. */
function run(hops: ((Caveat | ((d: string) => Caveat))[])[]) {
  const human = generateKeyPair();
  const keys = hops.map(() => generateKeyPair());
  const dom = new MeshDomain('D', generateKeyPair().secretKey);
  const resolve = (cs: (Caveat | ((d: string) => Caveat))[]): Caveat[] => cs.map((c) => (typeof c === 'function' ? c(dom.id) : c));
  const chain: Capability[] = [mintRoot({ principalSecret: human.secretKey, principalPublic: pubOf(human.secretKey), holder: pubOf(keys[0]!.secretKey), caveats: resolve(hops[0]!) })];
  for (let i = 1; i < hops.length; i++) chain.push(forgeHop(chain[i - 1]!, pubOf(keys[i]!.secretKey), resolve(hops[i]!), keys[i - 1]!.secretKey));
  const ws = [new MeshWitness(generateKeyPair().secretKey), new MeshWitness(generateKeyPair().secretKey)];
  for (const c of chain) dom.record(c);
  const head = dom.publishHead(ws, NOW - 1000);
  const evidence = chain.map((c, i) => dom.evidence(c, head, i === 0 ? undefined : dom.enroll(c.issuer, 'r')));
  const action: MeshAction = { type: 't', resource: '/a/b', amount: 1, service_domain: dom.id, nonce: 'n', at: NOW };
  const proof = assembleMeshProof({ chain, hops: evidence, action, leafSecret: keys[keys.length - 1]!.secretKey });
  const trust: MeshTrust = { humanPrincipal: pubOf(human.secretKey), witnesses: ws.map((w) => w.id), threshold: 2, now: NOW, allowedDomains: [dom.id], rootDomain: dom.id };
  return verifyMeshProof(proof, trust);
}
const pair = (parent: Caveat[], child: Caveat[]) => run([parent, child]);
const WIDENS = { ok: false, reason: 'hop widens authority', hop: 1 };
const widens = (r: ReturnType<typeof run>) => expect({ ok: r.ok, reason: r.reason, hop: r.hop }).toEqual(WIDENS);
const accepts = (r: ReturnType<typeof run>) => expect({ ok: r.ok, reason: r.reason }).toEqual({ ok: true, reason: undefined });

describe('narrows (defence in depth, reached by stubbing the chain verifier)', () => {
  it('sanity: with the stub an unrelated pair is accepted and the trace is complete', () => {
    const r = pair([], []);
    accepts(r);
    expect(r.trace).toHaveLength(2);
  });
  it('scope', () => {
    const sc = (...a: string[]): Caveat => ({ type: 'scope', actions: a });
    accepts(pair([sc('t', 'u')], [sc('t')]));
    accepts(pair([sc('t', 'u')], [sc('t', 'u')]));
    accepts(pair([], [sc('t')])); // parent unconstrained
    widens(pair([sc('t', 'u')], [sc('t', 'u', 'v')]));
    widens(pair([sc('t', 'u')], [sc('t', 'zzz')])); // overlap is not containment
    widens(pair([sc('t', 'u')], [])); // child unconstrained
    widens(pair([sc('t', 'u')], [{ type: 'max_amount', max: 1 }]));
  });
  it('audience', () => {
    const au = (...a: (string | ((d: string) => string))[]): ((d: string) => Caveat) => (d) => ({ type: 'audience', domains: a.map((x) => (typeof x === 'function' ? x(d) : x)) });
    const self = (d: string) => d;
    accepts(run([[au(self, 'x')], [au(self)]]));
    accepts(run([[au(self, 'x')], [au(self, 'x')]]));
    accepts(run([[], [au(self)]]));
    const r1 = run([[au(self, 'x')], [au(self, 'y')]]);
    widens(r1);
    widens(run([[au(self, 'x')], []]));
    widens(run([[au(self)], [au(self, 'x')]]));
  });
  it('max_amount: ceiling may stay or shrink, never grow or vanish', () => {
    const ma = (max: number): Caveat => ({ type: 'max_amount', max });
    accepts(pair([ma(5)], [ma(5)]));
    accepts(pair([ma(5)], [ma(3)]));
    accepts(pair([], [ma(3)]));
    widens(pair([ma(5)], [ma(6)]));
    widens(pair([ma(5)], []));
    widens(pair([ma(5)], [{ type: 'resource', prefix: '/a' }]));
  });
  it('expires: the expiry may stay or move earlier, never later or vanish', () => {
    const ex = (at: number): Caveat => ({ type: 'expires', at });
    accepts(pair([ex(NOW + 1000)], [ex(NOW + 1000)]));
    accepts(pair([ex(NOW + 1000)], [ex(NOW + 5)]));
    accepts(pair([], [ex(NOW + 5)]));
    widens(pair([ex(NOW + 1000)], [ex(NOW + 1001)]));
    widens(pair([ex(NOW + 1000)], []));
  });
  it('max_hops: the cap may stay or shrink, never grow or vanish', () => {
    const mh = (n: number): Caveat => ({ type: 'max_hops', n });
    accepts(pair([mh(3)], [mh(3)]));
    accepts(pair([mh(3)], [mh(2)]));
    accepts(pair([], [mh(2)]));
    widens(pair([mh(3)], [mh(4)]));
    widens(pair([mh(3)], []));
  });
  it('resource prefixes: every parent prefix must survive in the child', () => {
    const rp = (prefix: string): Caveat => ({ type: 'resource', prefix });
    accepts(pair([rp('/a')], [rp('/a')]));
    accepts(pair([rp('/a')], [rp('/a'), rp('/a/b')]));
    accepts(pair([rp('/a')], [rp('/a/b'), rp('/a')]));
    accepts(pair([], [rp('/a')]));
    widens(pair([rp('/a')], []));
    widens(pair([rp('/a')], [rp('/b')]));
    widens(pair([rp('/a'), rp('/a/b')], [rp('/a')]));
    widens(pair([rp('/a'), rp('/a/b')], [rp('/a/b')]));
  });
  it('each hop is compared with the PREVIOUS hop (not the root)', () => {
    const ma = (max: number): Caveat => ({ type: 'max_amount', max });
    const r = run([[ma(10)], [ma(5)], [ma(8)]]); // 8 <= 10 (root) but 8 > 5 (previous hop)
    expect({ ok: r.ok, reason: r.reason, hop: r.hop }).toEqual({ ok: false, reason: 'hop widens authority', hop: 2 });
    expect(r.trace).toHaveLength(2);
    accepts(run([[ma(10)], [ma(5)], [ma(5)]]));
  });
  it('the combined case: one widened dimension among narrowed ones is enough', () => {
    const r = pair([{ type: 'max_amount', max: 5 }, { type: 'max_hops', n: 3 }], [{ type: 'max_amount', max: 1 }, { type: 'max_hops', n: 4 }]);
    widens(r);
  });
});
