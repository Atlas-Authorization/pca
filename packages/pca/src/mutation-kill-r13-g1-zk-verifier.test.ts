/**
 * r13 g1: zk.ts createZkVerifier / attested prover, exact outcomes. Before r13 the zk*.test.ts files were excluded from the
 * Stryker run (the Groth16 tests need circuits/build), so most of zk.ts was NoCoverage; these pin every refusal reason, the
 * freshness window edges, the clock-skew handling, the SNARK-seam policy-commit selection and the error path.
 */
import { describe, expect, it } from 'vitest';
import {
  actionCommitment,
  createAttestedComplianceProver,
  createZkVerifier,
  pinnedPolicyCommitment,
  policyCommitment,
  type ComplianceStatement,
  type SnarkBackend,
  type ZkVerifierOpts,
} from './zk';
import { canonicalBytes, hashCanonical, utf8 } from './hash';
import { mintGrant } from './envelope';
import { buildPCActn, type PCActn } from './pcactn';
import { type DecideInput } from './policy-vm';
import { encodeKey, generateKeyPair, sign } from './keys';
import { b64u } from './hash';
import { DEFAULT_RISK_POLICY, type TrustBudget } from './risk';
import type { Capability } from './capability';
import type { PlanNode } from './merkle';

// Outcome capture: a mutant that throws where a value is expected (or returns where a refusal is expected) fails an
// explicit toEqual assertion instead of an uncaught error.
type Outcome = { ok: true; value: unknown } | { ok: false; error: { name: string; message: string } };
const caught = (e: unknown): Outcome => ({
  ok: false,
  error: e instanceof Error ? { name: e.constructor.name, message: e.message } : { name: typeof e, message: String(e) },
});
const settle = (f: () => unknown): Outcome => {
  try {
    return { ok: true, value: f() };
  } catch (e) {
    return caught(e);
  }
};
const settleAsync = async (f: () => unknown): Promise<Outcome> => {
  try {
    return { ok: true, value: await f() };
  } catch (e) {
    return caught(e);
  }
};
const ok = (value: unknown): Outcome => ({ ok: true, value });
const refused = (message: string, name = 'Error'): Outcome => ({ ok: false, error: { name, message } });

const P = generateKeyPair();
const A = generateKeyPair();
const NOW = 1_000_000;
const fresh: TrustBudget = { B: 1, tau: NOW, asOf: NOW };
const GRANT: Capability = mintGrant({
  principalSecret: P.secretKey,
  principalPublic: encodeKey(P.publicKey),
  holder: encodeKey(A.publicKey),
  goal: 'secure my account',
  envelope: {
    predicates: [{ verb: 'revoke_session', resource: '/acct/*' }],
    caveats: [{ type: 'expires', at: 9e12 }],
    agent_binding: {},
    risk_policy: DEFAULT_RISK_POLICY,
  },
}).grant;
const NODES: PlanNode[] = [{ id: 'n1', verb: 'revoke_session', resource: '/acct/1/s', reversibility_class: 'reversible' }];

function actn(verb = 'revoke_session'): PCActn {
  const nodes: PlanNode[] = [{ id: 'n1', verb, resource: '/acct/1/s', reversibility_class: 'reversible' }];
  return buildPCActn({ aud: 'test-aud', grant: GRANT, chain: [GRANT], plan: nodes, nodeId: 'n1', counter: 1, signerSecret: A.secretKey });
}
function decideInputFor(p: PCActn, risk = 0): DecideInput {
  return {
    grant: GRANT,
    chain: [GRANT],
    action: { action: { verb: p.action.verb, resource: p.action.resource, params: {}, reversibility_class: p.action.reversibility_class } },
    plan: NODES,
    risk: { semanticDistance: risk, reversibility: 1, blastRadius: 0, taint: 0, confidence: 1, age: 0 },
    budget: fresh,
    now: NOW,
    nodeId: p.plan.node_id,
  };
}

const attestor = generateKeyPair();
const prover = createAttestedComplianceProver(attestor.secretKey);
const DOMAIN = 'atlas-pca/zk-compliance/v1\0';

/** Re-sign an arbitrary statement body with the trusted attestor (to reach the checks after the signature). */
function resign(body: Record<string, unknown>): ComplianceStatement {
  const d = canonicalBytes(body);
  const pfx = utf8(DOMAIN);
  const m = new Uint8Array(pfx.length + d.length);
  m.set(pfx);
  m.set(d, pfx.length);
  return { ...(body as object), sig: b64u(sign(attestor.secretKey, m)) } as ComplianceStatement;
}
function stmt(p: PCActn, over: Partial<ComplianceStatement> = {}): ComplianceStatement {
  const s = prover.prove({ pcactn: p, decideInput: decideInputFor(p), issued_at: NOW - 1000, expires_at: NOW + 1000 });
  const { sig: _sig, ...body } = s;
  return Object.keys(over).length === 0 ? s : resign({ ...body, ...over });
}
const verifier = (o: Partial<ZkVerifierOpts> = {}) =>
  createZkVerifier({ trustedProverKeys: [prover.publicKey], policyCommitments: [policyCommitment(GRANT)], now: () => NOW, ...o });
async function reason(p: PCActn, o: Partial<ZkVerifierOpts> = {}, grant: Capability = GRANT): Promise<unknown> {
  return verifier(o)({ pcactn: p, grant });
}
const fail = (reason: string) => ({ enforced: true, ok: false, reason });

describe('attested prover statement shape', () => {
  it('commits exactly the action/policy/plan, the VM risk and the window, signed by the attestor', () => {
    const p = actn();
    const s = prover.prove({ pcactn: p, decideInput: decideInputFor(p), issued_at: 5, expires_at: 9 });
    expect(Object.keys(s).sort()).toEqual(['action_commit', 'expires_at', 'issued_at', 'mode', 'plan_commit', 'policy_commit', 'prover', 'r', 'released', 'sig', 'v']);
    expect(s).toMatchObject({ v: 1, mode: 'attested-vm', action_commit: actionCommitment(p), policy_commit: GRANT.id, plan_commit: p.plan.root, released: true, issued_at: 5, expires_at: 9, prover: prover.publicKey });
    expect(typeof s.r).toBe('number');
    expect(prover.publicKey).toBe(b64u(attestor.publicKey));
  });

  it('a PCActn without a string plan root commits the empty plan', () => {
    const p = actn();
    const q = { ...p, plan: { ...p.plan, root: 7 as unknown as string } } as PCActn;
    expect(settle(() => prover.prove({ pcactn: q, decideInput: decideInputFor(p), issued_at: 1, expires_at: 2 }).plan_commit)).toEqual(ok(''));
  });

  it('refuses a non-compliant action with the joined decision reasons', () => {
    const p = actn('exfiltrate');
    let msg = '';
    try {
      prover.prove({ pcactn: p, decideInput: decideInputFor(p), issued_at: 1, expires_at: 2 });
    } catch (e) {
      msg = (e as Error).message;
    }
    expect(settle(() => msg.startsWith('createAttestedComplianceProver: action is not compliant, nothing to prove ('))).toEqual(ok(true));
    expect(msg.endsWith(')')).toBe(true);
    // more than one reason is joined with '; '
    const p2 = actn('exfiltrate');
    let msg2 = '';
    try {
      prover.prove({ pcactn: p2, decideInput: { ...decideInputFor(p2, 1), budget: { B: 0, tau: NOW, asOf: NOW } }, issued_at: 1, expires_at: 2 });
    } catch (e) {
      msg2 = (e as Error).message;
    }
    expect(msg2).toMatch(/\(.+; .+\)$/);
  });

  it('no PCActn at all: the statement commits the null action and the empty plan', () => {
    const p = actn();
    let s = {} as ComplianceStatement;
    expect(() => {
      s = prover.prove({ pcactn: undefined as unknown as PCActn, decideInput: decideInputFor(p), issued_at: 1, expires_at: 2 });
    }).not.toThrow();
    expect(s.plan_commit).toBe('');
    expect(s.action_commit).toBe(hashCanonical(null));
  });

  it('policyCommitment of a missing grant is the canonical hash of the value itself', () => {
    const outcome = (f: () => string): string => {
      try {
        return f();
      } catch (e) {
        return `threw ${(e as Error).constructor.name}: ${(e as Error).message}`;
      }
    };
    for (const g of [undefined, null]) {
      expect(settle(() => outcome(() => policyCommitment(g as unknown as Capability)))).toEqual(ok(outcome(() => hashCanonical(g))));
      expect(settle(() => outcome(() => pinnedPolicyCommitment(g as unknown as Capability)))).toEqual(ok(outcome(() => hashCanonical(g))));
    }
  });

  it('a PCActn with no plan at all commits the empty plan; actionCommitment of no PCActn is the hash of null', () => {
    const p = actn();
    const q = { ...p, plan: undefined } as unknown as PCActn;
    expect(settle(() => prover.prove({ pcactn: q, decideInput: decideInputFor(p), issued_at: 1, expires_at: 2 }).plan_commit)).toEqual(ok(''));
    expect(settle(() => actionCommitment(undefined as unknown as PCActn))).toEqual(ok(hashCanonical(null)));
    expect(settle(() => actionCommitment(null as unknown as PCActn))).toEqual(ok(hashCanonical(null)));
  });

  it('policyCommitment: grant.id when it is a string, else the canonical hash; pinnedPolicyCommitment agrees', () => {
    expect(settle(() => policyCommitment(GRANT))).toEqual(ok(GRANT.id));
    const noId = { a: 1 } as unknown as Capability;
    expect(settle(() => policyCommitment(noId))).toEqual(ok(hashCanonical({ a: 1 })));
    expect(settle(() => pinnedPolicyCommitment(GRANT))).toEqual(ok(GRANT.id));
    expect(settle(() => pinnedPolicyCommitment(noId))).toEqual(ok(hashCanonical({ a: 1 })));
    expect(settle(() => actionCommitment({} as PCActn))).toEqual(ok(hashCanonical(null)));
  });
});

describe('createZkVerifier attested-VM mode: exact refusals', () => {
  it('accepts a good statement', async () => {
    const p = actn();
    p.zk_compliance = stmt(p);
    expect(await settleAsync(() => reason(p))).toEqual(ok({ enforced: true, ok: true }));
  });

  it('no proof (undefined or null), including a context without a PCActn', async () => {
    expect(await settleAsync(() => verifier()({ grant: GRANT } as unknown as Parameters<ReturnType<typeof createZkVerifier>>[0]))).toEqual(ok(fail('no zk_compliance proof present')));
    expect(await settleAsync(() => verifier()(undefined as unknown as Parameters<ReturnType<typeof createZkVerifier>>[0]))).toEqual(ok(fail('no zk_compliance proof present')));
    const p = actn();
    expect(await settleAsync(() => reason(p))).toEqual(ok(fail('no zk_compliance proof present')));
    p.zk_compliance = null;
    expect(await settleAsync(() => reason(p))).toEqual(ok(fail('no zk_compliance proof present')));
  });

  it('unrecognized statement (wrong v / wrong mode)', async () => {
    const p = actn();
    p.zk_compliance = stmt(p, { v: 2 as 1 });
    expect(await settleAsync(() => reason(p))).toEqual(ok(fail('unrecognized compliance statement')));
    p.zk_compliance = stmt(p, { mode: 'snark' as 'attested-vm' });
    expect(await settleAsync(() => reason(p))).toEqual(ok(fail('unrecognized compliance statement')));
  });

  it('statement that does not assert release', async () => {
    const p = actn();
    p.zk_compliance = stmt(p, { released: false as true });
    expect(await settleAsync(() => reason(p))).toEqual(ok(fail('statement does not assert release')));
  });

  it('untrusted / non-string prover', async () => {
    const p = actn();
    p.zk_compliance = stmt(p);
    expect(await settleAsync(() => reason(p, { trustedProverKeys: [] }))).toEqual(ok(fail('prover key is not trusted')));
    p.zk_compliance = { ...stmt(p), prover: 5 } as unknown as ComplianceStatement;
    expect(await settleAsync(() => reason(p))).toEqual(ok(fail('prover key is not trusted')));
  });

  it('a non-string prover is never trusted, even if the trusted list holds the same non-string value', async () => {
    const p = actn();
    p.zk_compliance = { ...stmt(p), prover: 5 } as unknown as ComplianceStatement;
    expect(await settleAsync(() => reason(p, { trustedProverKeys: [5 as unknown as string] }))).toEqual(ok(fail('prover key is not trusted')));
  });

  it('a verified PCActn view without a plan binds to the empty plan commitment', async () => {
    const p = actn();
    const { plan: _plan, ...noPlan } = p;
    const q = noPlan as unknown as PCActn;
    q.zk_compliance = stmt(p, { plan_commit: '' });
    expect(await settleAsync(() => reason(q))).toEqual(ok({ enforced: true, ok: true }));
  });

  it('a non-array trustedProverKeys trusts nothing', async () => {
    const p = actn();
    p.zk_compliance = stmt(p);
    expect(await settleAsync(() => reason(p, { trustedProverKeys: prover.publicKey as unknown as string[] }))).toEqual(ok(fail('prover key is not trusted')));
    // even a statement naming the placeholder text as its prover is not trusted
    p.zk_compliance = { ...stmt(p), prover: 'Stryker was here' };
    expect(await settleAsync(() => reason(p, { trustedProverKeys: 'x' as unknown as string[] }))).toEqual(ok(fail('prover key is not trusted')));
  });

  it('missing / bad signature', async () => {
    const p = actn();
    const { sig: _s, ...body } = stmt(p);
    p.zk_compliance = body;
    expect(await settleAsync(() => reason(p))).toEqual(ok(fail('compliance statement signature does not verify')));
    p.zk_compliance = { ...stmt(p), r: 0.5 };
    expect(await settleAsync(() => reason(p))).toEqual(ok(fail('compliance statement signature does not verify')));
  });

  it('malformed validity window: non-finite bounds or expires_at < issued_at', async () => {
    const p = actn();
    for (const over of [{ issued_at: null as unknown as number }, { expires_at: null as unknown as number }, { issued_at: '5' as unknown as number }, { expires_at: String(NOW + 1000) as unknown as number }, { issued_at: NOW, expires_at: NOW - 1 }]) {
      p.zk_compliance = stmt(p, over);
      expect(await settleAsync(() => reason(p))).toEqual(ok(fail('malformed statement validity window')));
    }
    // expires_at == issued_at is a valid (zero-length) window
    p.zk_compliance = stmt(p, { issued_at: NOW, expires_at: NOW });
    expect(await settleAsync(() => reason(p))).toEqual(ok({ enforced: true, ok: true }));
  });

  it('not yet valid / expired, with the exact edges', async () => {
    const p = actn();
    p.zk_compliance = stmt(p, { issued_at: NOW + 1, expires_at: NOW + 10 });
    expect(await settleAsync(() => reason(p))).toEqual(ok(fail('compliance statement not yet valid')));
    p.zk_compliance = stmt(p, { issued_at: NOW - 10, expires_at: NOW - 1 });
    expect(await settleAsync(() => reason(p))).toEqual(ok(fail('compliance statement expired')));
    // boundaries are inclusive: issued_at == now and expires_at == now are both valid
    p.zk_compliance = stmt(p, { issued_at: NOW, expires_at: NOW + 10 });
    expect(await settleAsync(() => reason(p))).toEqual(ok({ enforced: true, ok: true }));
    p.zk_compliance = stmt(p, { issued_at: NOW - 10, expires_at: NOW });
    expect(await settleAsync(() => reason(p))).toEqual(ok({ enforced: true, ok: true }));
  });

  it('clock skew widens both edges; a negative or non-finite skew counts as 0', async () => {
    const p = actn();
    const early = stmt(p, { issued_at: NOW + 50, expires_at: NOW + 100 });
    const late = stmt(p, { issued_at: NOW - 100, expires_at: NOW - 50 });
    p.zk_compliance = early;
    expect(await settleAsync(() => reason(p, { clockSkewMs: 50 }))).toEqual(ok({ enforced: true, ok: true }));
    expect(await settleAsync(() => reason(p, { clockSkewMs: 49 }))).toEqual(ok(fail('compliance statement not yet valid')));
    p.zk_compliance = late;
    expect(await settleAsync(() => reason(p, { clockSkewMs: 50 }))).toEqual(ok({ enforced: true, ok: true }));
    expect(await settleAsync(() => reason(p, { clockSkewMs: 49 }))).toEqual(ok(fail('compliance statement expired')));
    for (const clockSkewMs of [-1000, Number.NaN, Number.POSITIVE_INFINITY]) {
      p.zk_compliance = early;
      expect(await settleAsync(() => reason(p, { clockSkewMs }))).toEqual(ok(fail('compliance statement not yet valid')));
      p.zk_compliance = late;
      expect(await settleAsync(() => reason(p, { clockSkewMs }))).toEqual(ok(fail('compliance statement expired')));
    }
  });

  it('the default clock is Date.now', async () => {
    const p = actn();
    p.zk_compliance = stmt(p, { issued_at: Date.now() - 60_000, expires_at: Date.now() + 60_000 });
    expect(await settleAsync(() => createZkVerifier({ trustedProverKeys: [prover.publicKey], policyCommitments: [GRANT.id] })({ pcactn: p, grant: GRANT }))).toEqual(ok({ enforced: true, ok: true }));
    p.zk_compliance = stmt(p); // window around NOW = 1e6 ms after the epoch: long expired
    expect(await settleAsync(() => createZkVerifier({ trustedProverKeys: [prover.publicKey], policyCommitments: [GRANT.id] })({ pcactn: p, grant: GRANT }))).toEqual(ok(fail('compliance statement expired')));
  });

  it('binding: action, plan, policy (string, expected)', async () => {
    const p = actn();
    p.zk_compliance = stmt(p, { action_commit: 'x' });
    expect(await settleAsync(() => reason(p))).toEqual(ok(fail('statement does not bind to this action')));
    p.zk_compliance = stmt(p, { plan_commit: 'x' });
    expect(await settleAsync(() => reason(p))).toEqual(ok(fail('statement does not bind to this plan commitment')));
    p.zk_compliance = stmt(p, { policy_commit: 'x' });
    expect(await settleAsync(() => reason(p))).toEqual(ok(fail('statement policy commitment is not an expected policy')));
    p.zk_compliance = stmt(p, { policy_commit: 5 as unknown as string });
    expect(await settleAsync(() => reason(p, { policyCommitments: [5 as unknown as string] }))).toEqual(ok(fail('statement policy commitment is not an expected policy')));
  });

  it('a PCActn whose plan root is not a string binds to the empty plan commitment', async () => {
    const p = actn();
    const q = { ...p, plan: { ...p.plan, root: 3 as unknown as string } } as PCActn;
    q.zk_compliance = stmt(p, { plan_commit: '' });
    expect(await settleAsync(() => reason(q))).toEqual(ok({ enforced: true, ok: true }));
    q.zk_compliance = stmt(p, { plan_commit: 'Stryker was here!' });
    expect(await settleAsync(() => reason(q))).toEqual(ok(fail('statement does not bind to this plan commitment')));
  });

  it('without policyCommitments the policy is derived from ctx.grant (a non-array counts as unset)', async () => {
    const p = actn();
    p.zk_compliance = stmt(p);
    expect(await settleAsync(() => reason(p, { policyCommitments: undefined }))).toEqual(ok({ enforced: true, ok: true }));
    expect(await settleAsync(() => reason(p, { policyCommitments: GRANT.id as unknown as string[] }))).toEqual(ok({ enforced: true, ok: true }));
    const other = { id: 'other-grant' } as unknown as Capability;
    expect(await settleAsync(() => reason(p, { policyCommitments: undefined }, other))).toEqual(ok(fail('statement policy commitment is not an expected policy')));
  });

  it('a thrown error inside verification fails closed with its message; a non-Error throw says unknown', async () => {
    const boom = { get pcactn(): PCActn { throw new Error('kaboom'); } } as unknown as Parameters<ReturnType<typeof createZkVerifier>>[0];
    expect(await settleAsync(() => verifier()(boom))).toEqual(ok(fail('zk verification error (fail closed): kaboom')));
    const boom2 = { get pcactn(): PCActn { throw 'str'; } } as unknown as Parameters<ReturnType<typeof createZkVerifier>>[0];
    expect(await settleAsync(() => verifier()(boom2))).toEqual(ok(fail('zk verification error (fail closed): unknown')));
  });
});

describe('createZkVerifier SNARK seam', () => {
  const capture = (ret: boolean) => {
    const seen: Array<{ action_commit: string; policy_commit: string; plan_commit: string }> = [];
    const backend: SnarkBackend = { verify: ({ publicInputs }) => (seen.push(publicInputs), ret) };
    return { seen, backend };
  };

  it('a single expected policy commitment is passed; with several (or none) the grant-derived one is', async () => {
    const p = actn();
    p.zk_compliance = { opaque: true };
    const c1 = capture(true);
    expect(await settleAsync(() => reason(p, { snarkBackend: c1.backend, policyCommitments: ['pinned'] }))).toEqual(ok({ enforced: true, ok: true }));
    expect(c1.seen).toEqual([{ action_commit: actionCommitment(p), policy_commit: 'pinned', plan_commit: p.plan.root }]);
    const c2 = capture(true);
    await reason(p, { snarkBackend: c2.backend, policyCommitments: ['a', 'b'] });
    expect(c2.seen[0]!.policy_commit).toBe(GRANT.id);
    const c3 = capture(true);
    await reason(p, { snarkBackend: c3.backend, policyCommitments: undefined });
    expect(c3.seen[0]!.policy_commit).toBe(GRANT.id);
    const c4 = capture(true);
    await reason(p, { snarkBackend: c4.backend, policyCommitments: [] });
    expect(c4.seen[0]!.policy_commit).toBe(GRANT.id);
  });

  it('a rejecting backend fails with the exact reason; a non-string plan root passes the empty plan', async () => {
    const p = actn();
    p.zk_compliance = { opaque: true };
    expect(await settleAsync(() => reason(p, { snarkBackend: capture(false).backend }))).toEqual(ok(fail('snark backend rejected the proof')));
    const q = { ...p, plan: { ...p.plan, root: undefined as unknown as string } } as PCActn;
    const c = capture(true);
    await reason(q, { snarkBackend: c.backend });
    expect(c.seen[0]!.plan_commit).toBe('');
  });

  it('the backend stays the caller\'s live object (not a frozen snapshot)', async () => {
    const p = actn();
    p.zk_compliance = { opaque: true };
    const backend = { ok: false, verify(): boolean { return this.ok; } };
    const v = verifier({ snarkBackend: backend });
    expect(await settleAsync(() => v({ pcactn: p, grant: GRANT }))).toEqual(ok(fail('snark backend rejected the proof')));
    backend.ok = true;
    expect(await settleAsync(() => v({ pcactn: p, grant: GRANT }))).toEqual(ok({ enforced: true, ok: true }));
  });

  it('a backend throw fails closed', async () => {
    const p = actn();
    p.zk_compliance = { opaque: true };
    const backend: SnarkBackend = { verify: () => { throw new Error('backend down'); } };
    expect(await settleAsync(() => reason(p, { snarkBackend: backend }))).toEqual(ok(fail('zk verification error (fail closed): backend down')));
  });
});
