import { describe, expect, it } from 'vitest';
import type { DischargeRequest } from './caveat-lang';
import { sha256 } from './hash';
import {
  SLSA_PROVENANCE_V1,
  provenanceCaveat,
  provenanceDischargeBody,
  provenanceFactsError,
  provenanceGate,
  provenancePolicyError,
  rfc9162LeafHash,
  verifyRfc9162Inclusion,
  type ProvenanceGateResult,
} from './provenance-gate';

const D = 'a'.repeat(64);
const D512 = 'b'.repeat(128);
const ISS = 'https://issuer.example.com';
const ID = 'https://github.com/acme/tool/.github/workflows/build.yml@refs/heads/main';
const NOW = 2000;
const FACTS: Record<string, unknown> = {
  v: 1, predicate_type: SLSA_PROVENANCE_V1, build_type: 'bt', builder_id: 'b', subjects: [{ alg: 'sha256', digest: D }], identity: ID, oidc_issuer: ISS, integrated_time: 1000, rekor_log_index: 5,
};
const ROOT = { oidc_issuer: ISS, builder_id: 'b', identity: ID, level: 3 };
const POLICY: Record<string, unknown> = { roots: [ROOT], min_level: 1 };
const omit = (o: Record<string, unknown>, k: string): Record<string, unknown> => Object.fromEntries(Object.entries(o).filter(([key]) => key !== k));
const factsErr = (f: Record<string, unknown> = {}) => provenanceFactsError({ ...FACTS, ...f });
const policyErr = (p: Record<string, unknown> = {}) => provenancePolicyError({ ...POLICY, ...p });
const run = (f: Record<string, unknown> = {}, p: Record<string, unknown> = {}, extra: Record<string, unknown> = {}): ProvenanceGateResult => provenanceGate({ facts: { ...FACTS, ...f }, policy: { ...POLICY, ...p }, now: NOW, ...extra } as never);
const code = (r: ProvenanceGateResult): string => (r.ok ? 'ok' : r.code);

describe('RFC 9162 inclusion', () => {
  const leaf = (i: number) => rfc9162LeafHash(new Uint8Array([i]));
  const node = (l: Uint8Array, r: Uint8Array) => {
    const m = new Uint8Array(65);
    m[0] = 1;
    m.set(l, 1);
    m.set(r, 33);
    return sha256(m);
  };
  const L = [leaf(0), leaf(1), leaf(2)];
  const ROOT3 = node(node(L[0]!, L[1]!), L[2]!);

  it('accepts real proofs and nothing else', () => {
    expect(verifyRfc9162Inclusion(L[0]!, 0, 3, [L[1]!, L[2]!], ROOT3)).toBe(true);
    expect(verifyRfc9162Inclusion(L[1]!, 1, 3, [L[0]!, L[2]!], ROOT3)).toBe(true);
    expect(verifyRfc9162Inclusion(L[2]!, 2, 3, [node(L[0]!, L[1]!)], ROOT3)).toBe(true);
    expect(verifyRfc9162Inclusion(L[0]!, 0, 1, [], L[0]!)).toBe(true);
    expect(verifyRfc9162Inclusion(L[1]!, 0, 3, [L[1]!, L[2]!], ROOT3)).toBe(false);
  });
  it('index and size must be non-negative safe integers with index < size', () => {
    const l = L[0]!;
    expect(verifyRfc9162Inclusion(l, -0, 1, [], l)).toBe(false);
    expect(verifyRfc9162Inclusion(l, 0, -0, [], l)).toBe(false);
    expect(verifyRfc9162Inclusion(l, 1, 1, [], l)).toBe(false);
    expect(verifyRfc9162Inclusion(l, 2, 1, [], l)).toBe(false);
    expect(verifyRfc9162Inclusion(l, 0, 0, [], l)).toBe(false);
  });
  it('hash arguments must be 32-byte Uint8Arrays', () => {
    const l = L[0]!;
    expect(verifyRfc9162Inclusion(Array.from(l) as never, 0, 1, [], l)).toBe(false);
    expect(verifyRfc9162Inclusion(l, 0, 1, [], Array.from(l) as never)).toBe(false);
    expect(verifyRfc9162Inclusion(l, 0, 1, [], l.slice(1))).toBe(false);
    const short = l.slice(1);
    const p = L[1]!;
    expect(verifyRfc9162Inclusion(short, 0, 2, [p], node(short, p))).toBe(false);
  });
  it('proof entries must be 32-byte Uint8Arrays in a real array', () => {
    const l = L[0]!;
    const p = L[1]!;
    const root = node(l, p);
    expect(verifyRfc9162Inclusion(l, 0, 2, [p], root)).toBe(true);
    expect(verifyRfc9162Inclusion(l, 0, 2, new Uint8Array(0) as never, l)).toBe(false);
    const p31 = p.slice(1);
    expect(verifyRfc9162Inclusion(l, 0, 2, [p31], node(l, p31))).toBe(false);
    expect(verifyRfc9162Inclusion(l, 0, 2, [Array.from(p) as never], root)).toBe(false);
    expect(verifyRfc9162Inclusion(l, 0, 2, Array.from({ length: 65 }, () => p), root)).toBe(false);
  });
  it('a proof longer than the tree is deep, and one that stops short, are refused', () => {
    const l = L[0]!;
    const p = L[1]!;
    expect(verifyRfc9162Inclusion(l, 0, 1, [p], node(p, l))).toBe(false);
    expect(verifyRfc9162Inclusion(l, 0, 4, [], l)).toBe(false);
  });
  it('an exception while checking is a refusal', () => {
    const boom = new Proxy([], { get() { throw new Error('x'); } });
    expect(verifyRfc9162Inclusion(L[0]!, 0, 1, boom as never, L[0]!)).toBe(false);
  });
});

describe('facts shape', () => {
  it('top level', () => {
    expect(factsErr()).toBeNull();
    expect(provenanceFactsError(null)).toBe('facts must be an object');
    expect(provenanceFactsError('x')).toBe('facts must be an object');
    expect(factsErr({ extra: 1 })).toBe("unknown member 'facts.extra'");
    expect(provenanceFactsError(omit(FACTS, 'builder_id'))).toBe("missing member 'facts.builder_id'");
    expect(factsErr({ v: 2 })).toBe('facts.v must be 1');
  });
  it('bounded strings: non-empty, at most 2048 UTF-8 bytes, strings only', () => {
    for (const k of ['predicate_type', 'build_type', 'builder_id', 'identity', 'oidc_issuer']) {
      const MSG = `facts.${k} must be a non-empty string`;
      for (const bad of [5, null, '', 'x'.repeat(2049), 'é'.repeat(1025)]) expect(factsErr({ [k]: bad })).toBe(MSG);
    }
    expect(factsErr({ build_type: 'x'.repeat(2048) })).toBeNull();
    expect(factsErr({ build_type: 'é'.repeat(1024) })).toBeNull();
  });
  it('optional source members, when present, are bounded strings too', () => {
    for (const k of ['source_repo', 'source_ref', 'source_digest']) {
      for (const bad of [5, '', 'x'.repeat(2049)]) expect(factsErr({ [k]: bad })).toBe(`facts.${k} must be a non-empty string`);
      expect(factsErr({ [k]: 'x' })).toBeNull();
    }
  });
  it('subjects: 1..64 well-formed {alg, digest}', () => {
    const MSG = 'facts.subjects must be 1..64 {alg, digest}';
    const one = { alg: 'sha256', digest: D };
    expect(factsErr({ subjects: 'x' })).toBe(MSG);
    expect(factsErr({ subjects: [] })).toBe(MSG);
    expect(factsErr({ subjects: Array.from({ length: 65 }, () => one) })).toBe(MSG);
    expect(factsErr({ subjects: Array.from({ length: 64 }, () => one) })).toBeNull();
    expect(factsErr({ subjects: [one, 5] })).toBe(MSG);
    expect(factsErr({ subjects: [5, one] })).toBe(MSG);
    expect(factsErr({ subjects: [null] })).toBe(MSG);
    expect(factsErr({ subjects: [{ ...one, extra: 1 }] })).toBe(MSG);
    expect(factsErr({ subjects: [{ alg: 'sha256' }] })).toBe(MSG);
    expect(factsErr({ subjects: [{ alg: 'md5', digest: D }] })).toBe(MSG);
    expect(factsErr({ subjects: [{ alg: 'sha256', digest: [D] }] })).toBe(MSG);
    expect(factsErr({ subjects: [{ alg: 'sha256', digest: D.toUpperCase() }] })).toBe(MSG);
    expect(factsErr({ subjects: [{ alg: 'sha256', digest: 'a'.repeat(63) }] })).toBe(MSG);
    expect(factsErr({ subjects: [{ alg: 'sha256', digest: D512 }] })).toBe(MSG);
    expect(factsErr({ subjects: [{ alg: 'sha512', digest: D }] })).toBe(MSG);
    expect(factsErr({ subjects: [{ alg: 'sha512', digest: D512 }] })).toBeNull();
  });
  it('log numbers are non-negative safe integers', () => {
    const T = 'facts.integrated_time must be a non-negative integer';
    const R = 'facts.rekor_log_index must be a non-negative integer';
    for (const bad of [-1, 1.5, '5', null]) {
      expect(factsErr({ integrated_time: bad })).toBe(T);
      expect(factsErr({ rekor_log_index: bad })).toBe(R);
    }
    expect(factsErr({ integrated_time: 0, rekor_log_index: 0 })).toBeNull();
  });
  it('provenance_source: a closed {uri, git_commit?} of bounded strings', () => {
    const MSG = 'facts.provenance_source is malformed';
    expect(factsErr({ provenance_source: { uri: 'git+x' } })).toBeNull();
    expect(factsErr({ provenance_source: { uri: 'git+x', git_commit: 'c' } })).toBeNull();
    for (const bad of [null, 5, 'x', [], {}, { uri: '' }, { uri: 5 }, { uri: 'u', extra: 1 }, { uri: 'u', git_commit: '' }, { uri: 'u', git_commit: 5 }]) expect(factsErr({ provenance_source: bad })).toBe(MSG);
  });
});

describe('policy shape', () => {
  it('top level and roots', () => {
    expect(policyErr()).toBeNull();
    expect(provenancePolicyError(null)).toBe('policy must be an object');
    expect(provenancePolicyError('x')).toBe('policy must be an object');
    expect(policyErr({ extra: 1 })).toBe("unknown member 'policy.extra'");
    const MSG = 'policy.roots must hold 1..32 pairs';
    for (const roots of ['x', [], Array.from({ length: 33 }, () => ROOT)]) expect(policyErr({ roots })).toBe(MSG);
    expect(policyErr({ roots: Array.from({ length: 32 }, () => ROOT) })).toBeNull();
  });
  it('each root', () => {
    const MAL = 'policy root is malformed';
    for (const bad of [null, 5, 'x', [], { ...ROOT, extra: 1 }, omit(ROOT, 'builder_id'), omit(ROOT, 'level')]) expect(policyErr({ roots: [bad] })).toBe(MAL);
    const NEED = 'policy root needs oidc_issuer and builder_id';
    expect(policyErr({ roots: [{ ...ROOT, oidc_issuer: '' }] })).toBe(NEED);
    expect(policyErr({ roots: [{ ...ROOT, builder_id: '' }] })).toBe(NEED);
    expect(policyErr({ roots: [{ ...ROOT, oidc_issuer: 5 }] })).toBe(NEED);
    const ONE = 'policy root needs exactly one of identity and identity_prefix';
    expect(policyErr({ roots: [omit(ROOT, 'identity')] })).toBe(ONE);
    expect(policyErr({ roots: [{ ...ROOT, identity_prefix: 'https://github.com/' }] })).toBe(ONE);
    expect(policyErr({ roots: [{ ...ROOT, identity: '' }] })).toBe('policy root identity is malformed');
    const PREFIX = 'policy root identity_prefix must be at least 10 characters';
    const byPrefix = (identity_prefix: unknown) => policyErr({ roots: [{ ...omit(ROOT, 'identity'), identity_prefix }] });
    expect(byPrefix('abcdefghi')).toBe(PREFIX);
    expect(byPrefix('')).toBe(PREFIX);
    expect(byPrefix(5)).toBe(PREFIX);
    expect(byPrefix('abcdefghij')).toBeNull();
    for (const level of [0, 4, '3', null]) expect(policyErr({ roots: [{ ...ROOT, level }] })).toBe('policy root level must be 1, 2 or 3');
    for (const level of [1, 2, 3]) expect(policyErr({ roots: [{ ...ROOT, level }] })).toBeNull();
  });
  it('scalar members', () => {
    for (const min_level of [0, 4, '1', undefined]) expect(policyErr({ min_level })).toBe('policy.min_level must be 1, 2 or 3');
    expect(policyErr({ source_repo: '' })).toBe('policy.source_repo is malformed');
    expect(policyErr({ source_ref: 'r', source_ref_prefix: 'p' })).toBe('policy takes source_ref or source_ref_prefix, not both');
    expect(policyErr({ source_ref: '' })).toBe('policy.source_ref is malformed');
    expect(policyErr({ source_ref_prefix: '' })).toBe('policy.source_ref_prefix is malformed');
    expect(policyErr({ source_repo: 'r', source_ref: 'r' })).toBeNull();
    expect(policyErr({ source_ref_prefix: 'p' })).toBeNull();
    for (const bad of [0, -1, 1.5, '5', null]) expect(policyErr({ max_age_s: bad })).toBe('policy.max_age_s must be a positive integer');
    expect(policyErr({ max_age_s: 1 })).toBeNull();
    expect(policyErr({ require_runtime: 'yes' })).toBe('policy.require_runtime must be a boolean');
    expect(policyErr({ require_runtime: false })).toBeNull();
  });
  it('build_types: 1..16 bounded strings', () => {
    const MSG = 'policy.build_types must hold 1..16 strings';
    for (const bad of ['x', [], Array.from({ length: 17 }, () => 't'), ['t', 5], [5, 't'], [''], null]) expect(policyErr({ build_types: bad })).toBe(MSG);
    expect(policyErr({ build_types: Array.from({ length: 16 }, () => 't') })).toBeNull();
    expect(policyErr({ build_types: ['t'] })).toBeNull();
  });
});

describe('provenanceGate', () => {
  const GOOD = { ok: true, level: 3, claims: { subject_alg: 'sha256', subject_digest: D, slsa_level: 3, builder_id: 'b', build_type: 'bt', oidc_issuer: ISS, identity: ID, rekor_log_index: 5, runtime_bound: false } };
  it('a passing run, and the optional claims only when the facts carry them', () => {
    expect(run()).toEqual(GOOD);
    expect(Object.keys((run() as { claims: object }).claims).sort()).toEqual(Object.keys(GOOD.claims).sort());
    const full = run({ source_repo: 'https://example.com/r', source_ref: 'refs/heads/main', source_digest: 'abc' });
    expect(full).toEqual({ ...GOOD, claims: { ...GOOD.claims, source_repo: 'https://example.com/r', source_ref: 'refs/heads/main', source_digest: 'abc' } });
    for (const k of ['source_repo', 'source_ref', 'source_digest']) {
      const only = run({ [k]: 'v' }) as { claims: Record<string, unknown> };
      expect(Object.keys(only.claims).filter((c) => c.startsWith('source_'))).toEqual([k]);
    }
  });
  it('malformed input is refused with the right code', () => {
    for (const x of [null, 1, 'x', []]) expect(provenanceGate(x as never)).toEqual({ ok: false, code: 'malformed_facts' });
    expect(provenanceGate({ facts: FACTS, policy: null, now: NOW } as never)).toEqual({ ok: false, code: 'malformed_policy' });
    expect(provenanceGate({ facts: null, policy: POLICY, now: NOW } as never)).toEqual({ ok: false, code: 'malformed_facts' });
    expect(run({}, {}, { runtime: { alg: 'sha256', digest: 'zz' } })).toEqual({ ok: false, code: 'malformed_runtime' });
    expect(run({}, {}, { runtime: 5 })).toEqual({ ok: false, code: 'malformed_runtime' });
  });
  it('an exception while evaluating fails closed', () => {
    const input = { get facts(): never { throw new Error('x'); }, policy: POLICY, now: NOW };
    expect(provenanceGate(input as never)).toEqual({ ok: false, code: 'malformed_facts' });
  });
  it('the verifier clock is a non-negative safe integer', () => {
    const at = (now: unknown, f: Record<string, unknown> = {}) => provenanceGate({ facts: { ...FACTS, ...f }, policy: POLICY, now } as never);
    expect(at(-1, { integrated_time: 0 })).toEqual({ ok: false, code: 'malformed_facts' });
    expect(at(1.5)).toEqual({ ok: false, code: 'malformed_facts' });
    expect(at('2000')).toEqual({ ok: false, code: 'malformed_facts' });
    expect(code(at(0, { integrated_time: 0 }))).toBe('ok');
  });
  it('time: not from the future, not older than max_age_s', () => {
    expect(code(run({ integrated_time: NOW + 1 }))).toBe('future');
    expect(code(run({ integrated_time: NOW }))).toBe('ok');
    expect(code(run({}, { max_age_s: 1000 }))).toBe('ok');
    expect(code(run({}, { max_age_s: 999 }))).toBe('stale');
    expect(code(run({}, { max_age_s: 1 }))).toBe('stale');
  });
  it('the highest matching pair decides the level, then the floor applies', () => {
    const other = { oidc_issuer: ISS, builder_id: 'b', identity_prefix: 'https://github.com/acme/', level: 2 };
    expect(run({}, { roots: [{ ...ROOT, level: 1 }, other] })).toMatchObject({ ok: true, level: 2 });
    expect(run({}, { roots: [other, { ...ROOT, level: 1 }] })).toMatchObject({ ok: true, level: 2 });
    expect(run({}, { roots: [{ ...ROOT, level: 1 }] })).toMatchObject({ ok: true, level: 1 });
    expect(code(run({}, { roots: [{ ...ROOT, level: 1 }], min_level: 2 }))).toBe('level');
    expect(code(run({}, { roots: [{ ...ROOT, builder_id: 'x' }] }))).toBe('no_root');
    expect(code(run({}, { roots: [{ ...ROOT, oidc_issuer: 'https://other.example.com' }] }))).toBe('no_root');
    expect(code(run({}, { roots: [{ ...ROOT, identity: `${ID}x` }] }))).toBe('no_root');
    expect(code(run({}, { roots: [{ ...other, identity_prefix: 'https://github.com/other/' }] }))).toBe('no_root');
  });
  it('the provenance source and the certificate must agree', () => {
    const repo = 'https://github.com/acme/tool';
    const withPs = (ps: unknown, f: Record<string, unknown> = {}) => code(run({ provenance_source: ps, ...f }));
    expect(withPs({ uri: 'git+other' })).toBe('ok');
    expect(withPs({ uri: 'git+other', git_commit: 'c1' })).toBe('ok');
    expect(withPs({ uri: 'git+other' }, { source_digest: 'c1' })).toBe('ok');
    expect(withPs({ uri: 'u', git_commit: 'c1' }, { source_digest: 'c1' })).toBe('ok');
    expect(withPs({ uri: 'u', git_commit: 'c1' }, { source_digest: 'c2' })).toBe('source_mismatch');
    expect(withPs({ uri: `git+${repo}` }, { source_repo: repo })).toBe('ok');
    expect(withPs({ uri: `git+${repo}@refs/heads/main` }, { source_repo: repo })).toBe('ok');
    expect(withPs({ uri: `git+${repo}x` }, { source_repo: repo })).toBe('source_mismatch');
    expect(withPs({ uri: `git+${repo}-fork@refs/heads/main` }, { source_repo: repo })).toBe('source_mismatch');
    expect(withPs({ uri: 'git+https://example.com/elsewhere' }, { source_repo: repo })).toBe('source_mismatch');
    expect(withPs({ uri: repo }, { source_repo: repo })).toBe('source_mismatch');
  });
  it('repository and reference pins', () => {
    const f = { source_repo: 'https://example.com/r', source_ref: 'refs/heads/main' };
    expect(code(run(f, { source_repo: 'https://example.com/r' }))).toBe('ok');
    expect(code(run(f, { source_repo: 'https://example.com/other' }))).toBe('source_repo');
    expect(code(run({}, { source_repo: 'https://example.com/r' }))).toBe('source_repo');
    expect(code(run(f, { source_ref: 'refs/heads/main' }))).toBe('ok');
    expect(code(run(f, { source_ref: 'refs/heads/dev' }))).toBe('source_ref');
    expect(code(run({}, { source_ref: 'refs/heads/main' }))).toBe('source_ref');
    expect(code(run(f, { source_ref_prefix: 'refs/heads/' }))).toBe('ok');
    expect(code(run(f, { source_ref_prefix: 'refs/tags/' }))).toBe('source_ref');
    expect(code(run({}, { source_ref_prefix: 'refs/heads/' }))).toBe('source_ref');
  });
  it('build types', () => {
    expect(code(run({}, { build_types: ['bt', 'other'] }))).toBe('ok');
    expect(code(run({}, { build_types: ['other'] }))).toBe('build_type');
  });
  it('subject and runtime join', () => {
    const two = [{ alg: 'sha256', digest: D }, { alg: 'sha512', digest: D512 }];
    expect(code(run({ subjects: two }))).toBe('subject_ambiguous');
    expect(code(run({}, { require_runtime: true }))).toBe('runtime_required');
    expect(run({ subjects: two }, {}, { runtime: { alg: 'sha512', digest: D512 } })).toMatchObject({ ok: true, claims: { subject_alg: 'sha512', subject_digest: D512, runtime_bound: true } });
    expect(code(run({ subjects: two }, {}, { runtime: { alg: 'sha256', digest: 'c'.repeat(64) } }))).toBe('runtime_mismatch');
    expect(code(run({}, {}, { runtime: { alg: 'sha512', digest: D512 } }))).toBe('runtime_mismatch');
  });
  it('a claim string is at most 256 bytes', () => {
    expect(code(run({ build_type: 'x'.repeat(256) }))).toBe('ok');
    expect(code(run({ build_type: 'x'.repeat(257) }))).toBe('claim_too_long');
    expect(code(run({ build_type: 'é'.repeat(129) }))).toBe('claim_too_long');
  });
});

describe('caveat and discharge body', () => {
  it('the caveat names each requirement with its operator', () => {
    expect(provenanceCaveat({ issuer: 'prov', min_level: 2, builder_ids: ['b1', 'b2'], oidc_issuer: ISS, source_repo: 'r' }).require).toEqual([
      { claim: 'slsa_level', op: 'gte', value: 2 },
      { claim: 'source_repo', op: 'eq', value: 'r' },
      { claim: 'builder_id', op: 'in', value: ['b1', 'b2'] },
      { claim: 'oidc_issuer', op: 'eq', value: ISS },
      { claim: 'runtime_bound', op: 'eq', value: true },
    ]);
    expect(provenanceCaveat({ issuer: 'prov', min_level: 1, id: 'p2', bind: 'chain_hop', ttl_ms: 5 })).toMatchObject({ id: 'p2', bind: 'chain_hop', ttl_ms: 5 });
  });
  const req = (extra: Partial<DischargeRequest> = {}): DischargeRequest => ({ v: 1, kind: 'pca-discharge-request', caveat_id: 'provenance', issuer: 'prov', cap_hash: 'h', bind: 'chain_hop', require: [], ttl_ms: 1000, ...extra });
  it('the body binds the request and the gate claims; the ttl may equal the caveat limit but not exceed it', () => {
    const gate = run();
    expect(() => provenanceDischargeBody(req(), gate, { iat: 1, ttl_ms: 1001, nonce: 'n' })).toThrow('provenanceDischargeBody: ttl_ms exceeds what the caveat accepts');
    expect(() => provenanceDischargeBody(req(), { ok: false, code: 'level' }, { iat: 1, ttl_ms: 1, nonce: 'n' })).toThrow('provenanceDischargeBody: the provenance gate refused (level)');
    const body = provenanceDischargeBody(req(), gate, { iat: 10, ttl_ms: 1000, nonce: 'n' });
    expect(body).toStrictEqual({ v: 1, kind: 'pca-discharge', caveat_id: 'provenance', issuer: 'prov', cap_hash: 'h', bind: 'chain_hop', claims: (gate as { claims: object }).claims, iat: 10, not_after: 1010, nonce: 'n' });
    expect(provenanceDischargeBody(req({ bind: 'action', action_digest: 'ad' }), gate, { iat: 10, ttl_ms: 5, nonce: 'n' })).toMatchObject({ bind: 'action', action_digest: 'ad', not_after: 15 });
  });
});
