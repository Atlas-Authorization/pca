// Track K9: the provenance gates (shared vectors), the artifact caveat and discharge, and the whole path through requirePCA:
// a grant that requires slsa_level >= 2, a source repository and the runtime join admits the image the provenance describes
// and refuses a swapped one.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { capHash, type Caveat } from './capability';
import { dischargeActionDigest, dischargeRequests, signDischarge, verifyDischarge, type DischargePin } from './caveat-lang';
import { b64u } from './hash';
import { encodeKey, generateKeyPair } from './keys';
import { provenanceCaveat, provenanceDischargeBody, provenanceGate, rfc9162LeafHash, verifyRfc9162Inclusion, type BuildProvenanceFacts, type BuildProvenancePolicy } from './provenance-gate';
import { isModelDerivedPath } from './decision';
import { memoryPcaStore, requirePCA as requirePCA05 } from './server/require-pca';
import { AUD, NOW, setup } from './server/fixture.test-util';

const V: { primitives: { merkle_inclusion: any[]; gate: any[]; model_path: any[] } } = JSON.parse(readFileSync(join(__dirname, '..', 'conformance', 'provenance-vectors.json'), 'utf8'));
const unhex = (h: string) => new Uint8Array(Buffer.from(h, 'hex'));

describe('provenance vectors (shared with the natives)', () => {
  it.each(V.primitives.merkle_inclusion.map((v: { name: string }) => [v.name, v] as [string, any]))('merkle %s', (_n: string, v: any) => {
    const i = v.input;
    expect(verifyRfc9162Inclusion(rfc9162LeafHash(unhex(i.leaf_hex)), i.index, i.size, i.proof_hex.map(unhex), unhex(i.root_hex))).toBe(v.expect.ok);
  });
  it.each(V.primitives.gate.map((v: { name: string }) => [v.name, v] as [string, any]))('gate %s', (_n: string, v: any) => {
    const r = provenanceGate(v.input);
    expect(r.ok ? { ok: true, level: r.level, claims: r.claims } : { ok: false, code: r.code }).toEqual(v.expect);
  });
  it.each(V.primitives.model_path.map((v: { name: string }) => [v.name, v] as [string, any]))('%s', (_n: string, v: any) => {
    expect(isModelDerivedPath(v.input.path)).toBe(v.expect.model);
  });
});

describe('provenance gate edges', () => {
  it('never throws on garbage and refuses it', () => {
    for (const x of [null, 1, 'x', [], { facts: null }, { facts: {}, policy: {}, now: 1 }]) expect(provenanceGate(x as never).ok).toBe(false);
  });
  it('inclusion refuses non-integer or out-of-range positions', () => {
    const l = rfc9162LeafHash(new Uint8Array([1]));
    expect(verifyRfc9162Inclusion(l, 0, 1, [], l)).toBe(true);
    expect(verifyRfc9162Inclusion(l, 0.5, 1, [], l)).toBe(false);
    expect(verifyRfc9162Inclusion(l, -1, 1, [], l)).toBe(false);
    expect(verifyRfc9162Inclusion(l, 0, 1, [], l.slice(1))).toBe(false);
  });
  it('provenanceCaveat asks an artifact verifier for level, repository and the runtime join', () => {
    const c = provenanceCaveat({ issuer: 'prov', min_level: 3, source_repo: 'https://github.com/acme/tool' });
    expect(c).toEqual({ type: 'needs_discharge', id: 'provenance', issuer: 'prov', issuer_class: 'artifact', bind: 'action', ttl_ms: 300_000, require: [{ claim: 'slsa_level', op: 'gte', value: 3 }, { claim: 'source_repo', op: 'eq', value: 'https://github.com/acme/tool' }, { claim: 'runtime_bound', op: 'eq', value: true }] });
    expect(provenanceCaveat({ issuer: 'prov', min_level: 1, require_runtime: false, builder_ids: ['b'], oidc_issuer: 'i' }).require.map((r) => r.claim)).toEqual(['slsa_level', 'builder_id', 'oidc_issuer']);
  });
  it('no discharge body without a passing gate, and none longer than the caveat allows', () => {
    const req = { v: 1 as const, kind: 'pca-discharge-request' as const, caveat_id: 'provenance', issuer: 'prov', cap_hash: 'x', bind: 'chain_hop' as const, require: [], ttl_ms: 1000 };
    expect(() => provenanceDischargeBody(req, { ok: false, code: 'no_root' }, { iat: 1, ttl_ms: 10, nonce: 'n' })).toThrow(/no_root/);
    const ok = provenanceGate(V.primitives.gate[0].input);
    expect(() => provenanceDischargeBody(req, ok, { iat: 1, ttl_ms: 1001, nonce: 'n' })).toThrow(/ttl_ms/);
  });
});

// ------------------------------------------------------------------------------------------------ through requirePCA
const requirePCA = (o: Parameters<typeof requirePCA05>[0]): ReturnType<typeof requirePCA05> => requirePCA05({ insecureAllowUnboundOperation: true, multiInstance: false, ...o });
const enc = (v: unknown) => Buffer.from(JSON.stringify(v)).toString('base64url');
const verifierKey = generateKeyPair();
const workloadKey = generateKeyPair();
const PINS: DischargePin[] = [
  { label: 'prov', class: 'artifact', pk: encodeKey(verifierKey.publicKey) },
  { label: 'runtime', class: 'workload', pk: encodeKey(workloadKey.publicKey) },
];
const REPO = 'https://github.com/acme/tool';
const IMAGE = 'ab'.repeat(32);
const FACTS: BuildProvenanceFacts = {
  v: 1, predicate_type: 'https://slsa.dev/provenance/v1', build_type: 'https://actions.github.io/buildtypes/workflow/v1', builder_id: 'https://github.com/actions/runner/github-hosted',
  subjects: [{ alg: 'sha256', digest: IMAGE }], identity: `${REPO}/.github/workflows/release.yml@refs/tags/v1.0.0`, oidc_issuer: 'https://token.actions.githubusercontent.com',
  source_repo: REPO, source_ref: 'refs/tags/v1.0.0', source_digest: 'a'.repeat(40), integrated_time: Math.floor(NOW / 1000) - 60, rekor_log_index: 7,
};
const POLICY: BuildProvenancePolicy = { roots: [{ oidc_issuer: 'https://token.actions.githubusercontent.com', identity_prefix: `${REPO}/.github/workflows/release.yml@refs/tags/`, builder_id: 'https://github.com/actions/runner/github-hosted', level: 2 }], min_level: 2, source_repo: REPO, require_runtime: true };

function world() {
  const caveat = provenanceCaveat({ issuer: 'prov', min_level: 2, source_repo: REPO });
  const s = setup({ taskCaveats: [caveat as unknown as Caveat] as never });
  const guard = requirePCA({
    resolveGrant: async (ref: string) => (ref === s.grant.id ? s.grant : null),
    now: () => NOW,
    audience: AUD,
    context: () => ({ plan: s.plan, planAuthorized: true, risk: s.lowRisk }),
    budgetStore: memoryPcaStore(),
    hooks: { revocation: () => ({ enforced: true, ok: true }) },
    k1: { pins: PINS },
  });
  const p = (counter = 1) => s.mk(s.plan[0]!, { counter });
  return { s, guard, p, caveat };
}

/** What the attestation verifier does: gate the facts against ITS policy and the image digest IT measured, then sign. */
function attest(w: ReturnType<typeof world>, pcactn: ReturnType<ReturnType<typeof world>['p']>, measured: string, signer = verifierKey.secretKey) {
  const [req] = dischargeRequests(w.s.grant as never, pcactn.cap_chain as never, dischargeActionDigest(pcactn));
  const gate = provenanceGate({ facts: FACTS, policy: POLICY, runtime: { alg: 'sha256', digest: measured }, now: Math.floor(NOW / 1000) });
  if (!gate.ok) return { gate, discharge: undefined };
  return { gate, discharge: signDischarge(provenanceDischargeBody(req!, gate, { iat: NOW - 1000, ttl_ms: 60_000, nonce: b64u(new Uint8Array(16).fill(3)) }), signer) };
}

describe('K9 provenance through requirePCA', () => {
  it('admits the image the provenance describes, built from the pinned repository', async () => {
    const w = world();
    const pc = w.p();
    const { discharge } = attest(w, pc, IMAGE);
    const r = await w.guard({ headers: { 'pca-discharges': enc([discharge]) }, body: { pcactn: pc } });
    expect(r.ok).toBe(true);
  });

  it('a swapped tool image gets no discharge, and the action is refused', async () => {
    const w = world();
    const pc = w.p();
    const { gate, discharge } = attest(w, pc, 'ee'.repeat(32));
    expect(gate).toEqual({ ok: false, code: 'runtime_mismatch' });
    expect(discharge).toBeUndefined();
    const r = await w.guard({ headers: {}, body: { pcactn: pc } });
    expect(r.ok).toBe(false);
    expect(!r.ok && r.verdict.reasons.join('|')).toContain('no discharge presented');
  });

  it('a discharge for one action does not admit the next one (bind action)', async () => {
    const w = world();
    const { discharge } = attest(w, w.p(1), IMAGE);
    const r = await w.guard({ headers: { 'pca-discharges': enc([discharge]) }, body: { pcactn: w.p(2) } });
    expect(r.ok).toBe(false);
    expect(!r.ok && r.verdict.reasons.join('|')).toContain('bound to another action');
  });

  it('a workload key cannot stand in for the artifact verifier, and a forged claim breaks the signature', async () => {
    const w = world();
    const pc = w.p();
    const { discharge } = attest(w, pc, IMAGE);
    const asWorkload = signDischarge({ ...(({ sig, ...b }) => b)(discharge!), issuer: 'runtime' } as never, workloadKey.secretKey);
    expect(verifyDischarge(asWorkload, { ...w.caveat, issuer: 'runtime' }, { now: NOW, cap_hash: capHash(pc.cap_chain[1]!), action_digest: dischargeActionDigest(pc), pins: PINS })).toEqual({ ok: false, reason: expect.stringContaining('not of the class') });
    const raised = { ...discharge!, claims: { ...discharge!.claims, slsa_level: 3 } };
    expect((await w.guard({ headers: { 'pca-discharges': enc([raised]) }, body: { pcactn: pc } })).ok).toBe(false);
  });

  it('a level below the caveat floor is refused at the verifier even if an issuer signed it', async () => {
    const w = world();
    const pc = w.p();
    const [req] = dischargeRequests(w.s.grant as never, pc.cap_chain as never, dischargeActionDigest(pc));
    const low = provenanceGate({ facts: FACTS, policy: { ...POLICY, roots: [{ ...POLICY.roots[0]!, level: 1 }], min_level: 1 }, runtime: { alg: 'sha256', digest: IMAGE }, now: Math.floor(NOW / 1000) });
    expect(low.ok).toBe(true);
    const d = signDischarge(provenanceDischargeBody(req!, low, { iat: NOW - 1000, ttl_ms: 60_000, nonce: b64u(new Uint8Array(16).fill(4)) }), verifierKey.secretKey);
    const r = await w.guard({ headers: { 'pca-discharges': enc([d]) }, body: { pcactn: pc } });
    expect(r.ok).toBe(false);
    expect(!r.ok && r.verdict.reasons.join('|')).toContain("claim 'slsa_level' does not satisfy");
  });
});
