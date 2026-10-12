/** Round-2 mutation-kill tests for pcactn.ts (verifyPCActnCore glue, buildPCActn, signPCActnSuite, decodePCActn). */
import { describe, expect, it } from 'vitest';
import { generateKeyPair } from './keys';
import {
  PCACTN_VERSION,
  buildPCActn,
  decodePCActn,
  notEnforced,
  signPCActnSuite,
  verifyPCActnCore,
  type PCActn,
} from './pcactn';
import { mlDsa65Keygen, mlDsa87Keygen, slhDsa256sKeygen, slhDsa128fKeygen, encodeMlDsaPublicKey } from './pq';
import { AUD, NOW, setup } from './server/fixture.test-util';
import { holderPqCommitment } from './capability';
import { mintGrant } from './envelope';
import { encodeKey } from './keys';
import { DEFAULT_RISK_POLICY } from './risk';

const core = (s: ReturnType<typeof setup>, p: PCActn | Record<string, unknown>, over: Record<string, unknown> = {}) =>
  verifyPCActnCore(p as PCActn, { grant: s.grant, nowEpoch: NOW, audience: AUD, ...over } as never);
const rndN = (n: number) => crypto.getRandomValues(new Uint8Array(n));
const rnd = () => rndN(32);

describe('verifyPCActnCore: status marks and exact reasons', () => {
  it('an honest action: every always-on check passes, the rest are explicitly not-enforced', async () => {
    const s = setup();
    const r = await core(s, s.mk(s.plan[0]!));
    expect(r.allow).toBe(true);
    expect(r.checks).toMatchObject({
      wire: 'pass', version: 'pass', audience: 'pass', validity: 'pass', cap_chain: 'pass', grant_ref_bound: 'pass',
      plan_inclusion: 'pass', plan_root_authorized: 'not-enforced', leaf_signature: 'pass', counter: 'pass', taint_gate: 'not-enforced',
    });
  });
  it('bond_ref marks bond not-enforced; absent leaves it unmarked', async () => {
    const s = setup();
    expect((await core(s, s.mk(s.plan[0]!, { extra: { bond_ref: 'b' } }))).checks.bond).toBe('not-enforced');
    expect((await core(s, s.mk(s.plan[0]!))).checks.bond).toBeUndefined();
  });
  it('a non-safe-integer verifier clock is a validity failure with its own reason', async () => {
    const s = setup();
    for (const nowEpoch of [1.5, NaN, Infinity, 2 ** 60]) {
      const r = await core(s, s.mk(s.plan[0]!), { nowEpoch });
      expect(r.checks.validity, String(nowEpoch)).toBe('fail');
      expect(r.reason, String(nowEpoch)).toBe('validity: the verifier clock is not a safe integer epoch-ms');
    }
  });
  it('a different protocol version is refused with the exact message (or by the wire gate)', async () => {
    const s = setup();
    const r = await core(s, s.mk(s.plan[0]!, { extra: { ver: PCACTN_VERSION + 1 } }));
    expect(r.allow).toBe(false);
    expect(r.checks.version).toBe('fail');
    expect(r.reason).toBe(`version: unsupported ver ${PCACTN_VERSION + 1} (this verifier requires ${PCACTN_VERSION})`);
  });
  it('grant_ref must be a non-empty string equal to cap_chain[0].id', async () => {
    const s = setup();
    for (const g of ['', 5, null]) {
      const r = await core(s, s.mk(s.plan[0]!, { extra: { grant_ref: g } }));
      expect(r.allow, String(g)).toBe(false);
    }
    const r = await core(s, s.mk(s.plan[0]!, { extra: { grant_ref: s.grant.id.slice(1) + 'A' } }));
    expect(r.checks.grant_ref_bound).toBe('fail');
    expect(r.reason).toContain('grant_ref is not the id of the root capability in cap_chain');
  });
  it('counter must be a non-negative safe integer (0 allowed)', async () => {
    const s = setup();
    expect((await core(s, s.mk(s.plan[0]!, { counter: 0 }))).checks.counter).toBe('pass');
    const r = await core(s, s.mk(s.plan[0]!, { extra: { counter: -1 } }));
    expect(r.checks.counter).toBe('fail');
    expect(r.reason).toBe('counter: missing or not a non-negative safe integer');
    for (const c of [1.5, '1', null]) {
      expect((await core(s, s.mk(s.plan[0]!, { extra: { counter: c } }))).allow, String(c)).toBe(false);
    }
  });
  it('the hook stub reports not enforced, exactly', async () => {
    expect(notEnforced({} as never)).toEqual({ enforced: false });
  });
});

describe('verifyPCActnCore: freshness gate shape', () => {
  const gate = { epochMs: 1000, maxAgeMs: 5000 };
  it('a missing / empty / non-positive anchor is refused with the stub message', async () => {
    const s = setup();
    const a = s.mk(s.plan[0]!, { beaconRef: 'ref', extra: { freshness: { beacon_ref: 'ref', epoch: 0, accumulator_witness: '' } } });
    const r = await core(s, a, { enforce: { freshness: gate } });
    expect(r.checks.freshness).toBe('fail');
    expect(r.reason).toBe('freshness: freshness anchor is missing (empty beacon_ref or non-positive epoch stub)');
    const e = await core(s, s.mk(s.plan[0]!, { extra: { freshness: { beacon_ref: '', epoch: 5, accumulator_witness: '' } } }), { enforce: { freshness: gate } });
    expect(e.reason).toBe('freshness: freshness anchor is missing (empty beacon_ref or non-positive epoch stub)');
    const neg = await core(s, s.mk(s.plan[0]!, { extra: { freshness: { beacon_ref: 'r', epoch: -1, accumulator_witness: '' } } }), { enforce: { freshness: gate } });
    expect(neg.reason).toBe('freshness: freshness anchor is missing (empty beacon_ref or non-positive epoch stub)');
    const ok = await core(s, s.mk(s.plan[0]!, { extra: { freshness: { beacon_ref: 'r', epoch: Math.floor(NOW / 1000), accumulator_witness: '' } } }), { enforce: { freshness: gate } });
    expect(ok.checks.freshness).toBe('pass');
  });
});

describe('verifyPCActnCore: leaf suite policy and PQ binding reasons', () => {
  it('allowedSuites: ed25519 chain hops are checked first; undefined / listed ed25519 pass', async () => {
    const s = setup();
    const r = await core(s, s.mk(s.plan[0]!), { allowedSuites: ['hybrid-ed25519-ml-dsa-65'] });
    expect(r.allow).toBe(false);
    expect(r.reason).toBe("cap_chain: hop 0: signature suite 'ed25519' is not allowed by this verifier's suite policy");
    expect((await core(s, s.mk(s.plan[0]!), { allowedSuites: ['ed25519'] })).checks.leaf_signature).toBe('pass');
    expect((await core(s, s.mk(s.plan[0]!), { allowedSuites: undefined })).checks.leaf_signature).toBe('pass');
  });
  it('a hybrid leaf whose holder has no holder_pq commitment is refused with the labelled binding reason; allowUnboundPq admits it', async () => {
    const principal = generateKeyPair();
    const agent = generateKeyPair();
    const pPub = encodeKey(principal.publicKey);
    const aPub = encodeKey(agent.publicKey);
    const { grant } = mintGrant({
      principalSecret: principal.secretKey, principalPublic: pPub, holder: aPub, goal: 'g',
      envelope: { predicates: [{ verb: '*' }], caveats: [], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY },
    });
    const s = setup();
    const { sig: _s, ...body }: Record<string, unknown> = { ...s.mk(s.plan[0]!), grant_ref: grant.id, cap_chain: [grant] };
    const pq = mlDsa65Keygen(rnd());
    const signed = signPCActnSuite(body as never, { alg: 'hybrid-ed25519-ml-dsa-65', edLeafSecret: agent.secretKey, mlDsa: pq });
    const opts = { grant, nowEpoch: NOW, audience: AUD } as never;
    const r = await verifyPCActnCore(signed, opts);
    expect(r.checks.leaf_signature).toBe('fail');
    expect(r.reason).toContain("leaf_signature: leaf: suite 'hybrid-ed25519-ml-dsa-65' needs a PQ key bound to the signer");
    const ok = await verifyPCActnCore(signed, { ...(opts as object), allowUnboundPq: true } as never);
    expect(ok.checks.leaf_signature).toBe('pass');
    const pol = await verifyPCActnCore(signed, { ...(opts as object), allowUnboundPq: true, allowedSuites: ['ed25519'] } as never);
    expect(pol.checks.leaf_signature).toBe('fail');
    expect(pol.reason).toBe("leaf_signature: signature suite 'hybrid-ed25519-ml-dsa-65' is not allowed by this verifier's suite policy");
    const pol2 = await verifyPCActnCore(signed, { ...(opts as object), allowUnboundPq: true, allowedSuites: ['ed25519', 'hybrid-ed25519-ml-dsa-65'] } as never);
    expect(pol2.checks.leaf_signature).toBe('pass');
    void holderPqCommitment; void encodeMlDsaPublicKey;
  });
});

describe('signPCActnSuite: every suite family signs (key material is read, not just required)', () => {
  const s = setup();
  const body = (() => {
    const { sig: _s, ...b } = s.mk(s.plan[0]!) as unknown as Record<string, unknown>;
    return b as never;
  })();
  const A = generateKeyPair();
  it.each([
    ['ml-dsa-87', { mlDsa87: mlDsa87Keygen(rnd()) }],
    ['slh-dsa-sha2-256s', { slhDsa256s: slhDsa256sKeygen(rndN(96)) }],
    ['slh-dsa-sha2-128f', { slhDsa: slhDsa128fKeygen(rndN(48)) }],
    ['ml-dsa-65', { mlDsa: mlDsa65Keygen(rnd()) }],
  ] as const)('%s', (alg, keys) => {
    const p = signPCActnSuite(body, { alg, edLeafSecret: A.secretKey, ...keys } as never);
    expect(p.alg).toBe(alg);
    expect(typeof p.pq_pk).toBe('string');
    expect(typeof p.sig).toBe('string');
  });
  it('missing key material is named; an unknown alg is refused', () => {
    expect(() => signPCActnSuite(body, { alg: 'ml-dsa-87', edLeafSecret: A.secretKey } as never)).toThrow("signPCActnSuite: 'ml-dsa-87' requires mlDsa87 key material");
    expect(() => signPCActnSuite(body, { alg: 'slh-dsa-sha2-256s', edLeafSecret: A.secretKey } as never)).toThrow("signPCActnSuite: 'slh-dsa-sha2-256s' requires slhDsa256s key material");
    expect(() => signPCActnSuite(body, { alg: 'nope' as never, edLeafSecret: A.secretKey })).toThrow('signPCActnSuite: unknown alg nope');
    expect(() => signPCActnSuite(body, { alg: 'ed25519' })).toThrow("signPCActnSuite: 'ed25519' requires edLeafSecret");
  });
});

describe('buildPCActn defaults and optional fields', () => {
  const s = setup();
  const k = generateKeyPair();
  const mk = (over: Record<string, unknown> = {}) =>
    buildPCActn({ grant: s.grant, chain: [s.grant], plan: s.plan, nodeId: 'n1', counter: 1, signerSecret: k.secretKey, aud: AUD, now: NOW, ...over } as never);
  it('requires a non-empty string aud', () => {
    for (const aud of ['', undefined, 5]) expect(() => mk({ aud })).toThrow('buildPCActn: aud (audience) is required');
  });
  it('stubs are the exact documented empty structures', () => {
    const p = mk();
    expect(p.attestation).toEqual({ quote_digest: '', epoch: 0, model_id: 'unattested', measurement: '', operator: 'unattested' });
    expect(p.provenance).toEqual({ causal_hash: '', taint_level: 0, trusted_refs: [] });
    expect(p.freshness).toEqual({ beacon_ref: '', epoch: 0, accumulator_witness: '' });
    expect(p.risk_claim).toEqual({ r: 0, inputs: {} });
  });
  it('optional fields appear only when supplied, with their wire names', () => {
    const bare = mk() as unknown as Record<string, unknown>;
    for (const f of ['caution', 'rationale_commitment', 'progress_step', 'prohibition_evidence', 'tool_binding']) expect(f in bare, f).toBe(false);
    const full = mk({ caution: 0.5, rationaleCommitment: 'rc', progressStep: { a: 1 }, prohibitionEvidence: [1], toolBinding: 'tb' }) as unknown as Record<string, unknown>;
    expect(full).toMatchObject({ caution: 0.5, rationale_commitment: 'rc', progress_step: { a: 1 }, prohibition_evidence: [1], tool_binding: 'tb' });
    expect(mk({ caution: 0 }) as unknown as Record<string, unknown>).toMatchObject({ caution: 0 });
  });
});

describe('decodePCActn', () => {
  it('refuses null, arrays and primitives with the exact message', () => {
    for (const v of ['null', '[]', '5', '"x"']) expect(() => decodePCActn(v)).toThrow('decodePCActn: not an object');
  });
});
