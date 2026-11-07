/**
 * Threat-model traceability gaps T-008, T-015, T-019, T-041: failing-first tests.
 *
 * T-008 is a REAL control and was a real bug: before the per-grant critical section in `requirePCA`, N concurrent
 * requests carrying the same counter were ALL accepted (replay) and N concurrent spends all debited the same
 * starting budget (over-spend), even on a single node. These tests fail against that code.
 *
 * T-015 and T-019 are documented NON-GOALS. Their tests do not claim a mitigation: they pin the stated residual
 * (no confidentiality; a compromised principal is total within its grant) so the documentation cannot silently
 * drift from the behaviour, and they assert the mitigations the threat model DOES name (commit-only plan privacy,
 * attributable ledger entry, rotation by dropping the grant).
 *
 * T-041 documents what a resource server must do to defeat log omission, using only the shipped ledger primitives.
 */
import { describe, expect, it } from 'vitest';
import { delegate } from './capability';
import { mintGrant } from './envelope';
import { hashCanonical } from './hash';
import { encodeKey, generateKeyPair } from './keys';
import { TransparencyLedger, cosignTreeHead, signTreeHead, verifyHeadConsistency, verifyLedgerInclusion, verifyTreeHead, type SignedTreeHead } from './ledger';
import { commitPlan, conditionsDigest, type PlanNode } from './merkle';
import { PCACTN_VERSION, encodePCActn, signPCActn, verifyPCActnCore, type PCActn } from './pcactn';
import { DEFAULT_RISK_POLICY } from './risk';
import { AUD, NOW, setup } from './server/fixture.test-util';
import { memoryPcaStore, pcaStateKey, requirePCA as requirePCA05, type PcaStateStore } from './server/require-pca';
const requirePCA = (o: Parameters<typeof requirePCA05>[0]): ReturnType<typeof requirePCA05> => requirePCA05({ insecureAllowUnboundOperation: true, multiInstance: false, ...o }); // unbound and single-instance on purpose: these tests are not about operation binding or store scope (see breaking-05.test.ts)


const revocation = () => ({ enforced: true, ok: true });
const ZERO_RISK = { reversibility: 1, blastRadius: 0, confidence: 1, semanticDistance: 0, taint: 0 };
const RISK = { reversibility: 0.5, blastRadius: 0.3, confidence: 0.8, semanticDistance: 0.1, taint: 0 };

function makeGuard(s: ReturnType<typeof setup>, store: PcaStateStore, extra: Record<string, unknown> = {}) {
  return requirePCA({
    resolveGrant: async (ref: string) => (ref === s.grant.id ? s.grant : null),
    now: () => NOW,
    audience: AUD,
    context: () => ({ plan: s.plan, planAuthorized: true, risk: s.lowRisk }),
    budgetStore: store,
    hooks: { revocation },
    ...extra,
  });
}
const spend = (s: ReturnType<typeof setup>) => ({ context: () => ({ plan: s.plan, planAuthorized: true, risk: RISK }) });
const req = (p: PCActn) => ({ headers: {}, body: { pcactn: p } });

describe('T-008: counter and budget races (concurrent verifiers sharing one store)', () => {
  it('50 concurrent requests carrying the SAME PCActn: exactly one is accepted', async () => {
    const s = setup();
    const g = makeGuard(s, memoryPcaStore());
    const a = s.mk(s.plan[0]!, { counter: 5 });
    const rs = await Promise.all(Array.from({ length: 50 }, () => g(req(a))));
    expect(rs.filter((r) => r.ok)).toHaveLength(1);
    for (const r of rs.filter((x) => !x.ok)) expect(!r.ok && r.verdict.checks.replay).toBe('fail');
  });

  it('two independent guard instances over ONE store also admit exactly one', async () => {
    const s = setup();
    const store = memoryPcaStore();
    const g1 = makeGuard(s, store);
    const g2 = makeGuard(s, store);
    const a = s.mk(s.plan[0]!, { counter: 9 });
    const rs = await Promise.all(Array.from({ length: 40 }, (_, i) => (i % 2 ? g1 : g2)(req(a))));
    expect(rs.filter((r) => r.ok)).toHaveLength(1);
  });

  it('concurrent DISTINCT counters: accepted counters are strictly increasing in acceptance order and the pin never regresses', async () => {
    const s = setup();
    const base = memoryPcaStore();
    const puts: number[] = [];
    const store: PcaStateStore = {
      get: (k) => base.get(k),
      put: async (k, v) => {
        if (v.lastCounter !== undefined) puts.push(v.lastCounter);
        await base.put(k, v);
      },
    };
    const g = makeGuard(s, store);
    const counters = Array.from({ length: 30 }, (_, i) => i + 1).sort(() => Math.random() - 0.5);
    const rs = await Promise.all(counters.map((c) => g(req(s.mk(s.plan[0]!, { counter: c })))));
    const accepted = rs.flatMap((r) => (r.ok ? [r.pcactn.counter] : []));
    expect(accepted.length).toBeGreaterThan(0);
    for (let i = 1; i < puts.length; i++) expect(puts[i]!).toBeGreaterThan(puts[i - 1]!);
    expect(new Set(accepted).size).toBe(accepted.length);
    expect(puts.at(-1)).toBe(Math.max(...accepted));
  });

  it('parallel spends never exceed the budget and no debit is lost', async () => {
    const s = setup();
    const store = memoryPcaStore();
    const key = pcaStateKey(s.grant.id, s.aPub, undefined, AUD);
    await store.put(key, { budget: { B: 1, tau: NOW, asOf: NOW } });
    const g = makeGuard(s, store, spend(s));
    const rs = await Promise.all(Array.from({ length: 40 }, (_, i) => g(req(s.mk(s.plan[1]!, { counter: i + 1 })))));
    const accepted = rs.filter((r) => r.ok).length;
    const cost = 0.205; // kappa * r for this action under RISK / DEFAULT_RISK_POLICY (measured serially in the first assertion)
    expect(accepted).toBe(Math.floor(1 / cost)); // sequential semantics: 4 spends fit in a budget of 1
    const final = (await store.get(key))!.budget!.B;
    expect(final).toBeCloseTo(1 - accepted * cost, 9);
    expect(final).toBeGreaterThanOrEqual(0);
  });

  it('the serial baseline for the same inputs admits the same number (concurrency changes nothing)', async () => {
    const s = setup();
    const store = memoryPcaStore();
    await store.put(`${s.grant.id}:${s.aPub}`, { budget: { B: 1, tau: NOW, asOf: NOW } });
    const g = makeGuard(s, store, spend(s));
    let n = 0;
    for (let i = 0; i < 40; i++) if ((await g(req(s.mk(s.plan[1]!, { counter: i + 1 })))).ok) n++;
    expect(n).toBe(4);
  });

  it('a multi-node store supplies withKeyLock: it is used (keyed by grant) and its failure fails CLOSED', async () => {
    const s = setup();
    const base = memoryPcaStore();
    const locked: string[] = [];
    const store: PcaStateStore = {
      get: (k) => base.get(k),
      put: (k, v) => base.put(k, v),
      withKeyLock: async (k, fn) => {
        locked.push(k);
        return fn();
      },
    };
    const ok = await makeGuard(s, store)(req(s.mk(s.plan[0]!, { counter: 1 })));
    expect(ok.ok).toBe(true);
    expect(locked).toEqual([s.grant.id]);

    const broken: PcaStateStore = { ...store, withKeyLock: () => Promise.reject(new Error('lock service down')) };
    const r = await makeGuard(s, broken)(req(s.mk(s.plan[0]!, { counter: 2 })));
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.status).toBe(403);
      expect(r.verdict.reasons[0]).toContain('lock service down');
    }
  });

  it('a throwing request does not wedge the lock for the next one', async () => {
    const s = setup();
    const base = memoryPcaStore();
    let boom = true;
    const store: PcaStateStore = {
      get: async (k) => {
        if (boom) {
          boom = false;
          throw new Error('transient');
        }
        return base.get(k);
      },
      put: (k, v) => base.put(k, v),
    };
    const g = makeGuard(s, store);
    const [a, b] = await Promise.all([g(req(s.mk(s.plan[0]!, { counter: 1 }))), g(req(s.mk(s.plan[0]!, { counter: 2 })))]);
    expect(a.ok).toBe(false);
    expect(b.ok).toBe(true);
  });
});

describe('T-015: passive eavesdropping (documented non-goal: no confidentiality)', () => {
  it('the wire form is plaintext: action verb/resource are readable by anyone on the path (use TLS)', () => {
    const s = setup();
    const wire = encodePCActn(s.mk(s.plan[1]!));
    expect(wire).toContain('"rotate_recovery_keys"');
    expect(wire).toContain('"account:me"');
  });

  it('commitment-only plan privacy: other plan nodes and the plaintext params never appear, only digests', () => {
    const s = setup();
    const wire = encodePCActn(s.mk(s.plan[1]!));
    const p = JSON.parse(wire) as PCActn;
    expect(p.action.params_digest).toBe(hashCanonical(s.params));
    expect(wire).not.toContain('"scope"');
    expect(wire).not.toContain('"n1"'); // the sibling node id is not disclosed, only the Merkle path
    expect(p.plan.node_id).toBe('n2');
  });

  it('a captured PCActn is inert: it cannot be replayed, retargeted or altered', async () => {
    const s = setup();
    const store = memoryPcaStore();
    const g = makeGuard(s, store);
    const captured = s.mk(s.plan[0]!, { counter: 3 });
    expect((await g(req(captured))).ok).toBe(true);
    expect((await g(req(captured))).ok).toBe(false); // replay
    const other = await makeGuard(s, memoryPcaStore(), { audience: 'another-rs' })(req(captured));
    expect(other.ok).toBe(false); // other audience
    const tampered = { ...captured, action: { ...captured.action, resource: 'account:other' } } as PCActn;
    expect((await makeGuard(s, memoryPcaStore())(req(tampered))).ok).toBe(false); // altered
  });
});

describe('T-019: compromised principal key (documented non-goal: total within the grant)', () => {
  function rogue() {
    const principal = generateKeyPair(); // the attacker now holds this
    const pPub = encodeKey(principal.publicKey);
    const { grant } = mintGrant({
      principalSecret: principal.secretKey,
      principalPublic: pPub,
      holder: pPub,
      goal: 'attacker goal',
      envelope: {
        predicates: [{ verb: 'wire_funds', resource: 'acct:*' }],
        caveats: [{ type: 'expires', at: NOW + 3_600_000 }],
        agent_binding: {} as never,
        risk_policy: DEFAULT_RISK_POLICY,
      },
    });
    const agent = generateKeyPair();
    const aPub = encodeKey(agent.publicKey);
    const task = delegate(grant, aPub, [{ type: 'expires', at: NOW + 600_000 }], principal.secretKey);
    const plan: PlanNode[] = [{ id: 'x', verb: 'wire_funds', resource: 'acct:9', params_digest: hashCanonical({}), reversibility_class: 'reversible' }];
    const committed = commitPlan(plan);
    const pc = signPCActn(
      {
        ver: PCACTN_VERSION,
        action: { verb: 'wire_funds', resource: 'acct:9', params_digest: plan[0]!.params_digest!, reversibility_class: 'reversible' },
        grant_ref: grant.id,
        cap_chain: [grant, task],
        plan: { root: committed.root, inclusion_proof: committed.proofFor('x'), node_id: 'x', conditions_digest: conditionsDigest(undefined, undefined) },
        attestation: { quote_digest: '', epoch: 0, model_id: 'm', measurement: '', operator: 'o' },
        provenance: { causal_hash: '', taint_level: 0, trusted_refs: [] },
        freshness: { beacon_ref: '', epoch: 0, accumulator_witness: '' },
        counter: 1,
        risk_claim: { r: 0, inputs: {} },
        aud: AUD,
        iat: NOW,
        exp: NOW + 600_000,
      } as never,
      agent.secretKey,
    );
    return { grant, pc, plan };
  }

  it('with the principal key an attacker mints a grant and the cryptographic checks all pass (stated residual)', async () => {
    const { grant, pc } = rogue();
    const v = await verifyPCActnCore(pc, { insecureSkipPlanRootCheck: true, grant, nowEpoch: NOW, audience: AUD });
    expect(v.allow).toBe(true);
    expect(v.checks.cap_chain).toBe('pass');
    expect(v.checks.leaf_signature).toBe('pass');
  });

  it('mitigation: a resource server that only resolves grants IT enrolled denies a grant the attacker minted', async () => {
    const s = setup();
    const { grant, pc, plan } = rogue();
    const g = requirePCA({
      resolveGrant: async (ref) => (ref === s.grant.id ? s.grant : null), // the RS knows only the legitimate grant
      now: () => NOW,
      audience: AUD,
      context: () => ({ plan, planAuthorized: true, risk: ZERO_RISK }),
      budgetStore: memoryPcaStore(),
      hooks: { revocation },
    });
    const r = await g(req(pc));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.status).toBe(401);
    expect(grant.id).not.toBe(s.grant.id);
  });

  it('rotation: dropping the compromised grant at the resource server stops every PCActn under it, immediately', async () => {
    const { grant, pc, plan } = rogue();
    let enrolled = true;
    const g = requirePCA({
      resolveGrant: async (ref) => (enrolled && ref === grant.id ? grant : null),
      now: () => NOW,
      audience: AUD,
      context: () => ({ plan, planAuthorized: true, risk: ZERO_RISK }),
      budgetStore: memoryPcaStore(),
      hooks: { revocation },
    });
    expect((await g(req(pc))).ok).toBe(true);
    enrolled = false;
    const after = await g(req({ ...pc, counter: 2 } as PCActn));
    expect(after.ok).toBe(false);
  });

  it('detection: what the compromised key signed is attributable after the fact via the ledger', () => {
    const { pc } = rogue();
    const ledger = new TransparencyLedger('grant');
    const { index, commit } = ledger.append(pc);
    expect(ledger.auditOpenings()).toEqual([]);
    expect(ledger.verifyInclusion(ledger.head().root, ledger.inclusionProof(index), commit)).toBe(true);
    expect(ledger.entry(index).opening?.pcactn.action.verb).toBe('wire_funds');
  });
});

describe('T-041: log censorship / omission (the resource server must demand a witnessed inclusion proof)', () => {
  const guardian = generateKeyPair();
  const witnessA = generateKeyPair();
  const witnessB = generateKeyPair();
  const gPub = encodeKey(guardian.publicKey);
  const policy = { witnessKeys: [encodeKey(witnessA.publicKey), encodeKey(witnessB.publicKey)], threshold: 2 };

  /** A resource server's acceptance rule built from shipped primitives only. */
  function rsAccepts(
    commit: string,
    evidence: { sth: SignedTreeHead; proof: ReturnType<TransparencyLedger['inclusionProof']> } | undefined,
  ): boolean {
    if (!evidence) return false; // no proof presented: refuse
    if (!verifyTreeHead(evidence.sth, gPub, policy)) return false; // head must be guardian-signed AND witnessed by k-of-n
    return verifyLedgerInclusion(evidence.sth.root, evidence.proof, commit);
  }

  function headOf(l: TransparencyLedger, prev = ''): SignedTreeHead {
    const { size, root } = l.head();
    const sth = signTreeHead(guardian.secretKey, { instance_id: 'i', principal: 'grant', size, root, prev_root: prev, timestamp: NOW });
    return { ...sth, witnesses: [cosignTreeHead(sth, witnessA.secretKey), cosignTreeHead(sth, witnessB.secretKey)] };
  }

  const s = setup();
  const act = (c: number) => s.mk(s.plan[0]!, { counter: c });

  it('an action WITH an inclusion proof against a guardian-signed, k-of-n witnessed head is accepted', () => {
    const l = new TransparencyLedger('grant');
    l.append(act(1));
    const { index, commit } = l.append(act(2));
    expect(rsAccepts(commit, { sth: headOf(l), proof: l.inclusionProof(index) })).toBe(true);
  });

  it('an action the operator never appended (omission) is refused: no proof exists for its commit', () => {
    const l = new TransparencyLedger('grant');
    l.append(act(1));
    const sth = headOf(l);
    const omittedCommit = new TransparencyLedger('x').append(act(2)).commit;
    expect(rsAccepts(omittedCommit, undefined)).toBe(false); // nothing presented
    // a proof for a DIFFERENT entry cannot be passed off for the omitted one
    expect(rsAccepts(omittedCommit, { sth, proof: l.inclusionProof(0) })).toBe(false);
  });

  it('a proof against an UNWITNESSED or under-witnessed head is refused', () => {
    const l = new TransparencyLedger('grant');
    const { index, commit } = l.append(act(1));
    const full = headOf(l);
    const { witnesses: _w, ...bare } = full;
    expect(rsAccepts(commit, { sth: bare as SignedTreeHead, proof: l.inclusionProof(index) })).toBe(false);
    const one = { ...full, witnesses: full.witnesses!.slice(0, 1) };
    expect(rsAccepts(commit, { sth: one, proof: l.inclusionProof(index) })).toBe(false);
  });

  it('a head signed by someone other than the pinned guardian, or with a doctored root, is refused', () => {
    const l = new TransparencyLedger('grant');
    const { index, commit } = l.append(act(1));
    const good = headOf(l);
    const forgerKey = generateKeyPair();
    const forged = signTreeHead(forgerKey.secretKey, { instance_id: 'i', principal: 'grant', size: 1, root: good.root, prev_root: '', timestamp: NOW });
    expect(rsAccepts(commit, { sth: { ...forged, witnesses: good.witnesses }, proof: l.inclusionProof(index) })).toBe(false);
    expect(rsAccepts(commit, { sth: { ...good, root: 'AAAA' }, proof: l.inclusionProof(index) })).toBe(false);
  });

  it('RESIDUAL (pinned): omission is invisible in the log itself - a log without the entry is a perfectly consistent log', () => {
    const honest = new TransparencyLedger('grant');
    honest.append(act(1));
    const before = headOf(honest);
    const censored = TransparencyLedger.fromEntries(honest.commits().map((commit) => ({ commit })), 'grant'); // act(2) never appended
    const after = headOf(censored, before.root);
    // heads, witnesses and the consistency proof between them all verify: nothing in the log betrays the missing action
    expect(verifyHeadConsistency(before, after, censored.consistencyProof(before.size, after.size), gPub, policy)).toBe(true);
    // ... so the ONLY defence is the resource server refusing an action that comes with no proof (previous test)
    expect(rsAccepts(new TransparencyLedger('x').append(act(2)).commit, { sth: after, proof: censored.inclusionProof(0) })).toBe(false);
  });
});
