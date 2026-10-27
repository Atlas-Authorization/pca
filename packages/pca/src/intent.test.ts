import { describe, expect, it } from 'vitest';
import {
  DEFAULT_RISK_POLICY,
  b64u,
  buildPCActn,
  encodeMlDsaPublicKey,
  mintGrant,
  mlDsa65Keygen,
  publicKeyOf,
  sha256,
  signPCActn,
  utf8,
  verifyPCActnCore,
  type PCActn,
} from './index';
import {
  INTENT_ANCHOR_LOG,
  intentAnchorCommit,
  verifyIntentAnchor,
  decideIntentBinding,
  intentGoal,
  intentGoalCommit,
  intentMapDigest,
  intentRef,
  parseIntentGoal,
  signIntentMapAttestation,
  signIntentObservation,
  signIntentStatement,
  validateIntentWire,
  verifyIntentMapAttestation,
  verifyIntentObservation,
  verifyIntentStatement,
  type EnvelopeIntent,
  type IntentMapLike,
} from './ext/intent';
import { TransparencyLedger, signTreeHead } from './ext/ledger';

const key = (l: string) => sha256(utf8('intent-test/' + l));
const PRINCIPAL = key('principal');
const AGENT = key('agent');
const pub = (sk: Uint8Array) => b64u(publicKeyOf(sk));
const ML = mlDsa65Keygen(key('ml'));
const ML_PK = encodeMlDsaPublicKey(ML.publicKey);
const PINS = { [pub(PRINCIPAL)]: ML_PK };

const STMT = {
  v: 1 as const,
  text: 'Refund customers up to $200, only alice or bob',
  slots: { verbs: ['stripe.refund'], constraints: [{ verb: 'stripe.refund', path: 'action.params.amount', max: 200 }] },
  sources: [{ kind: 'ticket' as const, uri: 'T-1', digest: b64u(key('src')) }],
  created_at: 1_700_000_000_000,
  nonce: 'bm9uY2U',
};
const MAP: IntentMapLike = {
  v: 1,
  kind: 'pca-intent-map',
  intent_ref: null,
  metrics: { fidelity_est_ppm: 950_000, residual_risk_ppm: 12_000 },
};

describe('IntentStatement (suite-agile)', () => {
  it('ed25519: signs, verifies, ref ignores the signature, tamper fails', () => {
    const s = signIntentStatement(STMT, PRINCIPAL);
    expect(s.alg).toBeUndefined();
    expect(verifyIntentStatement(s)).toEqual({ ok: true });
    expect(verifyIntentStatement(s, { expectedSigner: pub(PRINCIPAL) })).toEqual({ ok: true });
    expect(verifyIntentStatement(s, { expectedSigner: pub(AGENT) }).ok).toBe(false);
    expect(verifyIntentStatement({ ...s, text: s.text + '!' }).ok).toBe(false);
    // the ref names the CONTENT (principal included): the signed artifact and its unsigned body share one ref
    expect(intentRef(s)).toBe(intentRef({ ...STMT, principal: pub(PRINCIPAL) }));
    expect(intentRef(s)).not.toBe(intentRef({ ...STMT, principal: pub(AGENT) }));
    expect(verifyIntentStatement({ ...s, pq_pk: ML_PK }).ok).toBe(false); // stray PQ key on an ed25519 artifact
  });
  it('ml-dsa-65 and hybrid: verify only under a pinned PQ key', () => {
    for (const alg of ['ml-dsa-65', 'hybrid-ed25519-ml-dsa-65'] as const) {
      const s = signIntentStatement(STMT, PRINCIPAL, { alg, mlDsa: ML });
      expect(s.alg).toBe(alg);
      expect(s.pq_pk).toBe(ML_PK);
      expect(verifyIntentStatement(s, { pqPins: PINS })).toEqual({ ok: true });
      expect(verifyIntentStatement(s).ok).toBe(false); // unpinned: fail closed
      expect(verifyIntentStatement({ ...s, alg: undefined } as never, { pqPins: PINS }).ok).toBe(false); // downgrade
      expect(intentRef(s)).toBe(intentRef(signIntentStatement(STMT, PRINCIPAL)));
    }
    const h = signIntentStatement(STMT, PRINCIPAL, { alg: 'hybrid-ed25519-ml-dsa-65', mlDsa: ML });
    expect(verifyIntentStatement({ ...h, pq_sig: undefined } as never, { pqPins: PINS }).ok).toBe(false);
  });
  it('rejects malformed statements without throwing', () => {
    expect(verifyIntentStatement(null).ok).toBe(false);
    expect(verifyIntentStatement({ ...signIntentStatement(STMT, PRINCIPAL), sources: [{ kind: 'bogus', digest: 'x' }] }).ok).toBe(false);
    expect(() => signIntentStatement({ ...STMT, principal: pub(AGENT) }, PRINCIPAL)).toThrow();
  });
});

describe('Intent Map attestation and runtime observations', () => {
  it('map attestation binds the digest and intent_ref', () => {
    const a = signIntentMapAttestation(MAP, PRINCIPAL, 5);
    expect(a.map_digest).toBe(intentMapDigest(MAP));
    expect(verifyIntentMapAttestation(a, MAP)).toEqual({ ok: true });
    expect(verifyIntentMapAttestation(a, { ...MAP, metrics: { ...MAP.metrics, fidelity_est_ppm: 999_999 } }).ok).toBe(false);
    const h = signIntentMapAttestation(MAP, PRINCIPAL, 5, { alg: 'hybrid-ed25519-ml-dsa-65', mlDsa: ML });
    expect(verifyIntentMapAttestation(h, MAP, { pqPins: PINS })).toEqual({ ok: true });
    expect(verifyIntentMapAttestation(h, MAP).ok).toBe(false);
  });
  it('observation signs and verifies; tamper and bad shape fail', () => {
    const o = signIntentObservation({ map_digest: intentMapDigest(MAP), verb: 'stripe.refund', values: { 'action.params.amount': 201 }, y: 0, source: 'runtime', observed_at: 9 }, AGENT);
    expect(verifyIntentObservation(o)).toEqual({ ok: true });
    expect(verifyIntentObservation({ ...o, y: 1 }).ok).toBe(false);
    expect(verifyIntentObservation({ ...o, source: 'gossip' }).ok).toBe(false);
    const m = signIntentObservation({ map_digest: intentMapDigest(MAP), verb: 'v', values: {}, y: 1, source: 'witness', observed_at: 1 }, AGENT, { alg: 'ml-dsa-65', mlDsa: ML });
    expect(verifyIntentObservation(m, { pqPins: { [pub(AGENT)]: ML_PK } })).toEqual({ ok: true });
  });
});

describe('envelope.intent binding', () => {
  const s = signIntentStatement(STMT, PRINCIPAL);
  const ref = intentRef(s);
  const md = intentMapDigest({ ...MAP, intent_ref: ref });
  const salt = 'c2FsdA';
  const { grant } = mintGrant({
    principalSecret: PRINCIPAL,
    principalPublic: pub(PRINCIPAL),
    holder: pub(AGENT),
    envelope: { predicates: [], caveats: [], agent_binding: {}, risk_policy: DEFAULT_RISK_POLICY },
    goal: intentGoal(ref, md),
    salt,
  });
  const intent: EnvelopeIntent = { ref, map_digest: md, goal_salt: salt, fidelity_ppm: 950_000, residual_risk_ppm: 12_000 };
  const plan = [{ id: 'n', verb: 'read', resource: 'r' }];
  const NOW = 1_800_000_000_000;
  const mk = (i?: EnvelopeIntent): PCActn => buildPCActn({ grant, chain: [grant], plan, nodeId: 'n', counter: 1, signerSecret: AGENT, aud: 'rs', now: NOW, ...(i ? { intent: i } : {}) });
  const verify = (p: PCActn, intentPolicy?: Parameters<typeof decideIntentBinding>[2]) => verifyPCActnCore(p, { grant, nowEpoch: NOW, audience: 'rs', ...(intentPolicy ? { intent: intentPolicy } : {}) });

  it('goal helpers round-trip and the commit opens', () => {
    expect(parseIntentGoal(intentGoal(ref, md))).toEqual({ intentRef: ref, mapDigest: md });
    expect(parseIntentGoal('other')).toBeNull();
    expect(intentGoalCommit(intent)).toBe((grant.caveats[0] as unknown as { goal_commit: string }).goal_commit);
  });
  it('bound intent passes; absent intent without policy reports no check (back-compat)', async () => {
    const r = await verify(mk(intent));
    expect(r.allow).toBe(true);
    expect(r.checks.intent).toBe('pass');
    const r0 = await verify(mk());
    expect(r0.allow).toBe(true);
    expect('intent' in r0.checks).toBe(false);
  });
  it('policies fail closed', async () => {
    expect((await verify(mk(), { require: true })).checks.intent).toBe('fail');
    expect((await verify(mk(), { min_fidelity_ppm: 1 })).checks.intent).toBe('fail');
    expect((await verify(mk(intent), { min_fidelity_ppm: 950_000, max_residual_risk_ppm: 12_000 })).allow).toBe(true);
    expect((await verify(mk(intent), { min_fidelity_ppm: 950_001 })).checks.intent).toBe('fail');
    expect((await verify(mk(intent), { max_residual_risk_ppm: 11_999 })).checks.intent).toBe('fail');
    expect((await verify(mk(intent), { min_fidelity_ppm: -1 })).checks.intent).toBe('fail');
    expect((await verify(mk(intent), { require: false })).checks.intent).toBe('pass');
  });
  it('binding mismatches fail the intent check only', async () => {
    for (const bad of [{ ref: md }, { map_digest: ref }, { goal_salt: 'nope' }]) {
      const r = await verify(mk({ ...intent, ...bad }));
      expect(r.allow).toBe(false);
      expect(r.checks.intent).toBe('fail');
      expect(r.checks.leaf_signature).toBe('pass');
    }
  });
  it('the slot is signed and wire-validated', async () => {
    const p = mk(intent);
    const tampered = { ...p, intent: { ...intent, fidelity_ppm: 999_999 } };
    expect((await verify(tampered)).checks.leaf_signature).toBe('fail');
    const { sig: _s, ...body } = p;
    void _s;
    const r = await verify(signPCActn({ ...body, intent: { ...intent, fidelity_ppm: 1_000_001 } }, AGENT));
    expect(r.checks).toEqual({ wire: 'fail' });
    expect(validateIntentWire(intent)).toBeNull();
    expect(validateIntentWire({ ...intent, extra: 1 })).toMatch(/unknown field/);
    expect(validateIntentWire({ ...intent, goal_salt: 'é'.repeat(64) })).toBeNull();
    expect(validateIntentWire({ ...intent, goal_salt: 'é'.repeat(64) + 'a' })).toMatch(/goal_salt/);
    expect(validateIntentWire({ ...intent, residual_risk_ppm: 0.5 })).toMatch(/residual/);
  });
  it('decideIntentBinding needs an envelope goal commitment on the grant', () => {
    expect(decideIntentBinding(intent, { caveats: [] })).toMatchObject({ status: 'fail' });
    expect(decideIntentBinding(intent, { caveats: [{ type: 'envelope', goal_commit: intentGoalCommit(intent) }] })).toEqual({ status: 'pass' });
    expect(decideIntentBinding(undefined, grant)).toEqual({ status: 'absent' });
  });
});

describe('ledger anchoring of intent artifacts', () => {
  const G = key('guardian');
  const digests = [b64u(key('a')), b64u(key('b')), b64u(key('c'))];
  const kinds = ['statement', 'map', 'observation'] as const;
  const log = TransparencyLedger.fromEntries(digests.map((d, i) => ({ commit: intentAnchorCommit(kinds[i]!, d) })), INTENT_ANCHOR_LOG);
  const head = log.head();
  const sth = signTreeHead(G, { instance_id: 'ins_1', principal: INTENT_ANCHOR_LOG, size: head.size, root: head.root, prev_root: '', timestamp: 1 });
  const receipt = (i: number) => ({ kind: kinds[i]!, digest: digests[i]!, index: i, proof: log.inclusionProof(i), signed_tree_head: sth });
  it('a receipt verifies for each anchored artifact', () => {
    for (let i = 0; i < 3; i++) expect(verifyIntentAnchor(receipt(i), pub(G), 'ins_1')).toEqual({ ok: true });
  });
  it('wrong kind, digest, instance, guardian or index fail', () => {
    expect(verifyIntentAnchor({ ...receipt(1), kind: 'statement' }, pub(G), 'ins_1').ok).toBe(false);
    expect(verifyIntentAnchor({ ...receipt(1), digest: digests[0]! }, pub(G), 'ins_1').ok).toBe(false);
    expect(verifyIntentAnchor(receipt(1), pub(G), 'ins_2').ok).toBe(false);
    expect(verifyIntentAnchor(receipt(1), pub(AGENT), 'ins_1').ok).toBe(false);
    expect(verifyIntentAnchor({ ...receipt(1), index: 2 }, pub(G), 'ins_1').ok).toBe(false);
  });
});
