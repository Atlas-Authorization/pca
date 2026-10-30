import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  RevocationSet,
  buildPCActn,
  delegate,
  encodeKey,
  encodeMlDsaPublicKey,
  hashCanonical,
  merkleProof,
  merkleRoot,
  mlDsa65Keygen,
  paramsDigest,
  pcactnDigest,
  publicKeyOf,
  signRevocationEpoch,
  type Capability,
  type CapSuiteOpts,
  type KeyPair,
  type PCActn,
  type PlanNode,
  type Predicate,
} from '@atlasauth/pca';
import {
  INTENT_ANCHOR_LOG,
  actionSchemaDigest,
  actionSchemaKeyOf,
  deltaRevocationId,
  intentActionDigest,
  intentRef,
  mintSessionGrant,
  sessionRevocationScope,
  sessionRootDigest,
  pcactnReservationDigest,
  signAccReceipt,
  signActionSchema,
  signSequencerKeySet,
  signClassifierVerdict,
  signFact,
  signIntentStatement,
  signLabels,
  signOfferSet,
  signSessionRoot,
  type SessionRoot,
} from '@atlasauth/pca/ext/intent';
import { signTreeHead } from '@atlasauth/pca/ext/ledger';
import { createLearner, deriveOmega, emitIntentMap, intentMapDigest, rng } from '@atlasauth/pca-intent';
import { verifyStatement, statementPayload } from '@atlasauth/pca-scitt';
import { signIntentAnswer, typedDigest, type SignedIntentAnswer } from '@atlasauth/pca-wallet';
import {
  buildEvidenceBundle,
  capOf,
  evidenceAnchorCommit,
  evidenceDigest,
  evidenceSignedStatement,
  runCli,
  verifyEvidenceBundle,
  type EvidenceBundle,
  type EvidenceTrust,
  type FindingCode,
  type FindingsReport,
} from './index';

// ---- the §4 walkthrough, with real keys and the core signers -----------------------------------------------------------

const AUD = 'skyair.example';
const T0 = Date.UTC(2026, 10, 1, 12, 0, 0);
const KID = 'skyair-schema-2026';

/** Deterministic keys keep the fixture (and so every digest) stable across runs. */
const seeded = (n: number): KeyPair => {
  const secretKey = new Uint8Array(32).map((_, i) => (n * 31 + i * 7 + 1) & 0xff);
  return { secretKey, publicKey: publicKeyOf(secretKey) };
};

interface World {
  bundle: EvidenceBundle;
  trust: EvidenceTrust;
  ana: KeyPair;
  agent: KeyPair;
  site: KeyPair;
  guardian: KeyPair;
  seqKey: KeyPair;
  seqRoot: KeyPair;
  S: SessionRoot;
  sRef: string;
  session: string;
  md: [string, string];
  G0: Capability;
  D1: Capability;
  subject: PCActn;
}

const PARAMS_OK = { offer_id: 'OF-1', passengers: ['px_ana', 'px_sam'], total: 77800, add_ons: ['none'], payment_ref: 'pm_ana_visa', refundable: false };
const PARAMS_INJ = { offer_id: 'OF-2', passengers: ['px_ana', 'px_sam'], total: 85400, add_ons: ['tripshield'], payment_ref: 'pm_ana_visa', refundable: false };

const capPredicates = (cap: number): Predicate[] => [{ verb: 'air.book', resource: '*', where: [{ field: 'env.acc.trip_spend.post', op: 'lte', value: cap }] }];

function sessionGrant(w: { ana: KeyPair }, a: { session: string; seq: number; prev?: string; root: string; mapDigest: string; cap: number }, signer: KeyPair = w.ana, suite?: CapSuiteOpts): Capability {
  const pub = encodeKey(signer.publicKey);
  return mintSessionGrant({ principalSecret: signer.secretKey, principalPublic: pub, holder: encodeKey(w.ana.publicKey), session: a.session, seq: a.seq, ...(a.prev !== undefined ? { prev: a.prev } : {}), root: a.root, mapDigest: a.mapDigest, predicates: capPredicates(a.cap), salt: `salt-${a.seq}`, ...(suite ? { suite } : {}) }).grant;
}

function emitAction(grant: Capability, holderSecret: Uint8Array, agentPub: string, params: Record<string, unknown>, counter: number, iat: number, agent: KeyPair): PCActn {
  const task = delegate(grant, agentPub, [], holderSecret);
  const plan: PlanNode[] = [{ id: 'n1', verb: 'air.book', resource: 'skyair.example/bookings', params_digest: paramsDigest(params), reversibility_class: 'irreversible' }];
  return buildPCActn({ grant, chain: [grant, task], plan, nodeId: 'n1', params, counter, signerSecret: agent.secretKey, aud: AUD, iat, exp: iat + 600_000 });
}

function mapPair(ref: string): [ReturnType<typeof emitIntentMap>, ReturnType<typeof emitIntentMap>] {
  const omega = deriveOmega({ policies: [], slots: { verbs: ['stripe.refund'], constraints: [{ path: 'action.params.amount', max: 400 }, { path: 'action.params.amount', max: 800 }] } });
  const l = createLearner(omega, { nullMass: 0.05 });
  const m0 = emitIntentMap(l, ref);
  l.observe({ verb: 'stripe.refund', values: { 'action.params.amount': 401 } }, 1, 'elicitation');
  return [m0, emitIntentMap(l, ref)];
}

/** A sequencer reservation receipt for the subject booking, issued at `issuedAt` (lifetime 10 min). */
function reserve(session: string, p: PCActn, seqKey: KeyPair, issuedAt: number) {
  return signAccReceipt(
    { v: 1, kind: 'pca-acc-receipt', session, acc: 'trip_budget', seq: 1, pre: 0, delta: 77800, post: 77800, pcactn_digest: pcactnReservationDigest(p as unknown as Record<string, unknown>), aud: AUD, issued_at: issuedAt, expires_at: issuedAt + 600_000, kid: 'k1', ledger: { index: 0, head: hashCanonical('seq-head') } },
    seqKey.secretKey,
  );
}

/** Ana's deterministic ML-DSA-65 key, for the post-quantum walkthrough. */
const anaMlDsa = (n: number) => mlDsa65Keygen(new Uint8Array(32).map((_, i) => (n * 53 + i * 11 + 3) & 0xff));

/**
 * The §4 world; `principalSeed` lets a test play an attacker who makes up the principal key (a fabricated bundle).
 * `pqSuite`: Ana signs S, G_0 and D_1 with that PQ suite (her ML-DSA-65 key from `pqSeed`), and the trust pins it.
 */
function walkthrough(principalSeed = 1, pq?: { suite: 'ml-dsa-65' | 'hybrid-ed25519-ml-dsa-65'; pqSeed?: number }): World {
  const ana = seeded(principalSeed);
  const ml = pq ? anaMlDsa(pq.pqSeed ?? principalSeed) : undefined;
  const anaPq = ml ? encodeMlDsaPublicKey(ml.publicKey) : undefined;
  const suite: CapSuiteOpts | undefined = pq && ml ? { alg: pq.suite, mlDsa: ml } : undefined;
  const agent = seeded(2);
  const site = seeded(3);
  const guardian = seeded(4);
  const anchorKey = seeded(5);
  const seqRoot = seeded(6);
  const seqKey = seeded(7);
  const anaPub = encodeKey(ana.publicKey);
  const agentPub = encodeKey(agent.publicKey);
  const session = hashCanonical({ session: 'ana-sky-1' });

  const statement = signIntentStatement({ v: 1, text: 'Book me and Sam a one-way flight SFO to JFK on Nov 20, under $400.', slots: {}, sources: [], created_at: T0, nonce: 'n-1' }, ana.secretKey);
  const ref = intentRef(statement);
  const [map0, map1] = mapPair(ref);
  const md: [string, string] = [intentMapDigest(map0), intentMapDigest(map1)];

  const schemaDoc = signActionSchema(
    {
      v: 1, kind: 'pca-action-schema', site: 'https://skyair.example', aud: AUD, version: '2026-10-01',
      units: { usd_cents: { kind: 'money', currency: 'USD', exponent: 2 } },
      verbs: [{
        verb: 'air.book', kind: 'write', reversibility: 'irreversible',
        params: {
          'action.params.offer_id': { type: 'string', semantic: 'product.ref', sensitivity: 'material' },
          'action.params.passengers': { type: 'array', semantic: 'person.identity', sensitivity: 'critical' },
          'action.params.total': { type: 'integer', unit: 'usd_cents', min: 0, max: 5_000_000, semantic: 'money.amount', sensitivity: 'critical', accumulates_into: ['spend.usd_cents'] },
          'action.params.add_ons': { type: 'set', values: ['none', 'tripshield', 'seat_plus', 'bag'], semantic: 'product.addon', sensitivity: 'material' },
          'action.params.payment_ref': { type: 'string', semantic: 'credential.payment_ref', sensitivity: 'critical' },
          'action.params.refundable': { type: 'boolean', semantic: 'flag', sensitivity: 'material' },
        },
      }],
    },
    KID,
    site.secretKey,
  );
  const S = signSessionRoot(
    {
      v: 1, kind: 'pca-intent-session', session, principals: [pq ? { key: anaPub, alg: pq.suite, pq_pk: anaPq } : { key: anaPub }], intent_ref: ref,
      schema: { aud: AUD, digest: actionSchemaDigest(schemaDoc) },
      layers: { task: { map_digest: md[0] } },
      accumulators: [
        { id: 'trip_spend', agg: 'sum', val: 'action.params.total', unit: 'usd_cents', sel: { verbs: ['air.book'] }, win: { kind: 'task' }, key: null, domain_max: 500000, holder: { kind: 'site_local' } },
        // A second, cross-site budget held by a sequencer (its receipts are bundled).
        { id: 'trip_budget', agg: 'sum', val: 'action.params.total', unit: 'usd_cents', sel: { verbs: ['air.book'] }, win: { kind: 'task' }, key: null, holder: { kind: 'sequenced', uri: 'https://seq.example', root: encodeKey(seqRoot.publicKey) } },
      ],
      monitors: [],
      question_uri: `https://atlas.example/v1/pca/intent/sessions/${session}/questions`,
      revocation: { epoch_uri: 'https://atlas.example/v1/pca/revocation/ana', max_age_s: 60, key: encodeKey(guardian.publicKey) },
      expires_at: T0 + 86_400_000,
    },
    ana.secretKey,
    suite,
  );
  const sRef = sessionRootDigest(S);
  const G0 = sessionGrant({ ana }, { session, seq: 0, root: sRef, mapDigest: md[0], cap: 40000 }, ana, suite);
  const D1 = sessionGrant({ ana }, { session, seq: 1, prev: G0.id, root: sRef, mapDigest: md[1], cap: 80000 }, ana, suite);

  const attempt1 = emitAction(G0, ana.secretKey, agentPub, PARAMS_INJ, 1, T0 + 1000, agent);
  const subject = emitAction(D1, ana.secretKey, agentPub, PARAMS_OK, 3, T0 + 5000, agent);
  const sd = pcactnDigest(subject);
  const ad = intentActionDigest(subject.action);

  const veto = signIntentAnswer(
    { map_digest: md[0], session, question_id: 'q_1', verb: 'air.book', cell: { trip_spend: [4, 4], 'action.params.add_ons': ['tripshield'] }, y: 0, source: 'elicitation', observed_at: T0 + 2000, ux: { tier: 'typed', rendered_digest: hashCanonical('card-1'), canary: false } },
    ana.secretKey,
  );
  const canary = signIntentAnswer(
    { map_digest: md[0], session, question_id: 'q_c1', verb: 'air.book', cell: { trip_spend: [4, 4], 'action.params.add_ons': ['none'] }, y: 0, source: 'elicitation', observed_at: T0 + 2500, ux: { tier: 'hold', rendered_digest: hashCanonical('card-c'), canary: true } },
    ana.secretKey,
  );
  const yes = signIntentAnswer(
    {
      map_digest: md[1], session, question_id: 'q_7Hk2', verb: 'air.book', cell: { trip_spend: [2, 3], 'action.params.add_ons': ['none'] }, y: 1, source: 'elicitation', observed_at: T0 + 4000,
      ux: { tier: 'typed', rendered_digest: hashCanonical('card-2'), typed_digest: typedDigest('q_7Hk2', '778'), canary: false, action_digest: ad, consent_for_action: true },
    },
    ana.secretKey,
  );

  const rs = new RevocationSet(['pca-intent:session:someone-else']);
  const epoch = signRevocationEpoch(guardian.secretKey, { instance_id: 'atlas', grant_ref: sessionRevocationScope(session), epoch: rs.size, set_size: rs.size, root: rs.root, issued_at: T0 + 4500, not_after: T0 + 4500 + 300_000 });
  const revoked = rs.list();
  const keySet = signSequencerKeySet({ v: 1, kind: 'pca-sequencer-keys', version: 1, issued_at: T0, keys: [{ kid: 'k1', pk: encodeKey(seqKey.publicKey), not_before: T0 - 600_000 }] }, seqRoot.secretKey);
  const receipt = reserve(session, subject, seqKey, T0 + 4800);

  const bundle = buildEvidenceBundle({
    subject: { pcactn_digest: sd, aud: AUD, session },
    statement: { commit: ref, opening: statement },
    session_root: S,
    schema: { doc: schemaDoc },
    root_grant: G0,
    maps: [{ seq: 0, commit: md[0], map: map0 }, { seq: 1, commit: md[1], map: map1 }],
    answers: [veto, canary, yes],
    canary_labels: [{ question_id: 'q_c1', label: 0 }],
    canaries: { asked: 1, false_yes: 0, false_no: 0 },
    deltas: [D1],
    pcactns: [attempt1, subject],
    verdicts: [],
    accumulator: { holder: 'site_local', events: [{ acc: 'trip_spend', post: 77800, pcactn_digest: sd, delta: 1, status: 'committed' }], receipts: [receipt], sequencer_keys: [keySet] },
    effects: [{ pcactn_digest: sd, params: PARAMS_OK, charged: { amount: 77800, ref: 'action.params.total' }, frame_violations: [] }],
    revocation_epochs: [{ epoch, revoked }],
    anchors: [],
  });
  const digest = evidenceDigest(bundle);
  const leaves = [hashCanonical('earlier-leaf'), evidenceAnchorCommit(digest)];
  const sth = signTreeHead(anchorKey.secretKey, { instance_id: 'atlas', principal: INTENT_ANCHOR_LOG, size: 2, root: merkleRoot(leaves), prev_root: '', timestamp: T0 + 6000 });
  bundle.anchors = [{ kind: 'evidence', digest, index: 1, proof: merkleProof(leaves, 1), signed_tree_head: sth }];

  const trust: EvidenceTrust = {
    // Ana's key, pinned out of band (her account record): the bundle is attributed to her only through this pin.
    principals: [pq ? { key: encodeKey(seeded(1).publicKey), pq_pk: encodeMlDsaPublicKey(anaMlDsa(1).publicKey) } : { key: encodeKey(seeded(1).publicKey) }],
    siteKeys: [actionSchemaKeyOf(KID, site.secretKey)],
    minTier: { 'air.book': 'typed' },
    typedValues: { q_7Hk2: '778' },
    anchorGuardian: { public: encodeKey(anchorKey.publicKey), instance: 'atlas' },
    verifiers: { effect: () => ({ ok: true }) },
  };
  return { bundle, trust, ana, agent, site, guardian, seqKey, seqRoot, S, sRef, session, md, G0, D1, subject };
}

const statusOf = (r: FindingsReport, code: FindingCode): string[] => [...new Set(r.findings.filter((x) => x.code === code).map((x) => x.status))].sort();
const clone = <T>(v: T): T => JSON.parse(JSON.stringify(v)) as T;
const flip = (s: string): string => (s[0] === 'A' ? 'B' : 'A') + s.slice(1);

describe('evidence bundle: the §4.4 chargeback walkthrough', () => {
  it('replays to a complete, passing findings report with the walkthrough facts', async () => {
    const w = walkthrough();
    const r = await verifyEvidenceBundle(w.bundle, w.trust);
    expect(r.findings.filter((x) => x.status !== 'pass')).toEqual([]);
    expect(r.ok).toBe(true);
    expect(r.complete).toBe(true);
    expect(r.digest).toBe(evidenceDigest(w.bundle));
    expect(r.summary.admitted_under).toBe('D_1');
    expect(r.summary.consent).toEqual({ question_id: 'q_7Hk2', tier: 'typed', signer: encodeKey(w.ana.publicKey) });
    expect(r.summary.charged).toEqual({ amount: 77800, bound: 77800 });
    expect(r.summary.refusals).toEqual(['q_1']);
    expect(r.summary.canary_accuracy).toEqual({ correct: 1, asked: 1 });
    expect(r.summary.answers).toEqual({ total: 2, yes: 1, no: 1, partial: 0, canaries: 1 });
    expect(r.summary.not_proven.join(' ')).toMatch(/understood/);
  });

  it('without ports and keys, unverifiable artifacts are "unverified", never "pass"', async () => {
    const w = walkthrough();
    const r = await verifyEvidenceBundle(w.bundle, {});
    // Consistent, but not attributed: without pinned principal keys `ok` is never true.
    expect(r.consistent).toBe(true);
    expect(r.attributed).toBe(false);
    expect(r.ok).toBe(false);
    expect(statusOf(r, 'principal.pinned')).toEqual(['unverified']);
    expect(r.complete).toBe(false);
    for (const code of ['schema.signature', 'answer.typed', 'effect.signature', 'anchor.inclusion'] as FindingCode[]) {
      expect(statusOf(r, code)).toEqual(['unverified']);
    }
    // Artifacts with a core verifier and keys pinned inside the bundle's own signed session root need no trust input.
    for (const code of ['session_root.signature', 'revocation.epoch', 'delta.chain', 'root_grant', 'jit.consent'] as FindingCode[]) {
      expect(statusOf(r, code)).toEqual(['pass']);
    }
    expect(r.summary.not_proven.some((s) => s.includes('effect.signature'))).toBe(true);
  });

  it('an unopened statement and an unrevealed map stay commitments (unverified)', async () => {
    const w = walkthrough();
    const b = clone(w.bundle);
    delete b.statement.opening;
    delete b.maps[1]!.map;
    const r = await verifyEvidenceBundle(b, w.trust);
    expect(statusOf(r, 'statement.opening')).toEqual(['unverified']);
    expect(statusOf(r, 'statement.commit')).toEqual(['pass']);
    expect(r.findings.find((x) => x.code === 'map.replay' && x.refs[0] === 'map:1')?.status).toBe('unverified');
    expect(r.ok).toBe(true);
  });
});

describe('tampering: every artifact kind has a specific failing finding', () => {
  const cases: [string, (b: EvidenceBundle, w: World) => void, FindingCode][] = [
    ['answer signature byte', (b) => void (b.answers[2]!.sig = flip(b.answers[2]!.sig)), 'answer.signature'],
    ['answer y flipped', (b) => void (b.answers.find((a) => a.question_id === 'q_1')!.y = 1), 'answer.signature'],
    ['answer from another session', (b, w) => void (b.answers[0] = signIntentAnswer({ ...strip(b.answers[0]!), session: hashCanonical('other') }, w.ana.secretKey)), 'answer.signature'],
    ['answer by a non-principal', (b, w) => void (b.answers[0] = signIntentAnswer(strip(b.answers[0]!), w.agent.secretKey)), 'answer.signature'],
    ['answer on an unknown map', (b, w) => void (b.answers[0] = signIntentAnswer({ ...strip(b.answers[0]!), map_digest: hashCanonical('nomap') }, w.ana.secretKey)), 'answer.map'],
    ['delta signature byte', (b) => void (b.deltas[0]!.sig = flip(b.deltas[0]!.sig)), 'delta.signature'],
    ['delta caveat edited', (b) => void ((b.deltas[0]!.caveats.find((c) => c.type === 'envelope') as unknown as { predicates: { where: { value: number }[] }[] }).predicates[0]!.where[0]!.value = 90000), 'delta.signature'],
    ['session root edited', (b) => void (b.session_root.question_uri = 'https://evil.example/q'), 'session_root.signature'],
    ['session root signature byte', (b) => void (b.session_root.sig = flip(b.session_root.sig)), 'session_root.signature'],
    ['root grant signature byte', (b) => void (b.root_grant.sig = flip(b.root_grant.sig)), 'root_grant'],
    ['pcactn counter', (b) => void (b.pcactns[1]!.counter = 99), 'pcactn.verify'],
    ['pcactn signature byte', (b) => void (b.pcactns[0]!.sig = flip(b.pcactns[0]!.sig)), 'pcactn.verify'],
    ['schema edited', (b) => void (b.schema.doc.version = '2026-12-01'), 'schema.signature'],
    ['schema edited breaks the session binding', (b) => void (b.schema.doc.version = '2026-12-01'), 'schema.digest'],
    ['statement text', (b) => void (b.statement.opening!.text = 'Book anything.'), 'statement.opening'],
    ['statement commit', (b) => void (b.statement.commit = hashCanonical('x')), 'statement.commit'],
    ['map metrics', (b) => void (b.maps[1]!.map!.metrics.residual_risk_ppm += 5000), 'map.replay'],
    ['map commit', (b) => void (b.maps[0]!.commit = hashCanonical('other-map')), 'map.replay'],
    ['effect overcharge', (b) => void (b.effects[0]!.charged = { amount: 80000, ref: 'action.params.total' }), 'effect.charged'],
    ['effect params swapped', (b) => void (b.effects[0]!.params = { ...PARAMS_OK, total: 70000 }), 'effect.binding'],
    ['frame violation reported', (b) => void (b.effects[0]!.frame_violations = ['account.contact_email']), 'effect.frame'],
    ['accumulator post forged', (b) => void (b.accumulator.events[0]!.post = 70000), 'accumulator.arithmetic'],
    ['undeclared accumulator', (b) => void (b.accumulator.events[0]!.acc = 'other'), 'accumulator.declared'],
    ['canary summary forged', (b) => void (b.canaries = { asked: 0, false_yes: 0, false_no: 0 }), 'canaries.summary'],
    ['canary label missing', (b) => void (b.canary_labels = []), 'canaries.summary'],
    ['revocation epoch root', (b) => void (b.revocation_epochs[0]!.epoch.root = hashCanonical('r')), 'revocation.epoch'],
    ['revocation list does not match the signed set', (b) => void (b.revocation_epochs[0]!.revoked = []), 'revocation.epoch'],
    ['revoked delta', (b, w) => {
      const rs = new RevocationSet([deltaRevocationId(w.D1.id)]);
      const ep = signRevocationEpoch(w.guardian.secretKey, { instance_id: 'atlas', grant_ref: sessionRevocationScope(w.session), epoch: rs.size, set_size: rs.size, root: rs.root, issued_at: T0 + 4600, not_after: T0 + 400_000 });
      b.revocation_epochs = [{ epoch: ep, revoked: rs.list() }];
    }, 'revocation.epoch'],
    ['anchor names another digest', (b) => void (b.anchors[0]!.digest = hashCanonical('d')), 'anchor.inclusion'],
    ['anchor head signature', (b) => void (b.anchors[0]!.signed_tree_head.sig = flip(b.anchors[0]!.signed_tree_head.sig)), 'anchor.inclusion'],
    ['consent removed', (b, w) => void (b.answers = b.answers.map((a) => (a.question_id === 'q_7Hk2' ? signIntentAnswer({ ...strip(a), ux: { tier: 'typed', rendered_digest: a.ux.rendered_digest, typed_digest: a.ux.typed_digest!, canary: false } }, w.ana.secretKey) : a))), 'jit.consent'],
    ['consent at tap tier', (b, w) => void (b.answers = b.answers.map((a) => (a.question_id === 'q_7Hk2' ? signIntentAnswer({ ...strip(a), ux: { ...a.ux, tier: 'tap', typed_digest: undefined } }, w.ana.secretKey) : a))), 'jit.consent'],
    ['typed value differs', (b, w) => void (b.answers = b.answers.map((a) => (a.question_id === 'q_7Hk2' ? signIntentAnswer({ ...strip(a), ux: { ...a.ux, typed_digest: typedDigest('q_7Hk2', '800') } }, w.ana.secretKey) : a))), 'answer.typed'],
    ['subject missing', (b) => void (b.subject.pcactn_digest = hashCanonical('nope')), 'subject.present'],
  ];
  for (const [name, mutate, code] of cases) {
    it(name, async () => {
      const w = walkthrough();
      const b = clone(w.bundle);
      mutate(b, w);
      const r = await verifyEvidenceBundle(b, w.trust);
      expect(statusOf(r, code)).toContain('fail');
      expect(r.ok).toBe(false);
    });
  }

  it('an unknown member anywhere the bundle owns is refused', async () => {
    const w = walkthrough();
    for (const mutate of [
      (b: Record<string, unknown>) => void (b.extra = 1),
      (b: Record<string, unknown>) => void ((b.subject as Record<string, unknown>).note = 'x'),
      (b: Record<string, unknown>) => void ((b.canaries as Record<string, unknown>).trusted = true),
      (b: Record<string, unknown>) => void (((b.accumulator as { events: Record<string, unknown>[] }).events[0]!).claim = 1),
    ]) {
      const b = clone(w.bundle) as unknown as Record<string, unknown>;
      mutate(b);
      const r = await verifyEvidenceBundle(b, w.trust);
      expect(r.ok).toBe(false);
      expect(r.digest).toBeNull();
      expect(statusOf(r, 'shape')).toEqual(['fail']);
    }
  });
});

function strip(a: SignedIntentAnswer): Omit<SignedIntentAnswer, 'v' | 'kind' | 'signer' | 'alg' | 'sig'> {
  const { v: _v, kind: _k, signer: _s, alg: _a, sig: _g, ...rest } = a;
  return rest;
}

// ---- properties ----------------------------------------------------------------------------------------------------

function shuffle<T>(xs: T[], r: () => number): T[] {
  const out = [...xs];
  for (let i = out.length - 1; i > 0; i--) {
    const j = Math.floor(r() * (i + 1));
    [out[i], out[j]] = [out[j]!, out[i]!];
  }
  return out;
}

/** Re-create every object with its members in a random order (arrays keep their order). */
function reorderKeys(v: unknown, r: () => number): unknown {
  if (Array.isArray(v)) return v.map((x) => reorderKeys(x, r));
  if (v === null || typeof v !== 'object') return v;
  const out: Record<string, unknown> = {};
  for (const k of shuffle(Object.keys(v), r)) out[k] = reorderKeys((v as Record<string, unknown>)[k], r);
  return out;
}

describe('properties (seeded)', () => {
  it('determinism: shuffled set members and member order give the identical report', async () => {
    const w = walkthrough();
    const base = await verifyEvidenceBundle(w.bundle, w.trust);
    for (let seed = 1; seed <= 12; seed++) {
      const r = rng(seed);
      const b = clone(w.bundle);
      b.answers = shuffle(b.answers, r);
      b.pcactns = shuffle(b.pcactns, r);
      b.maps = shuffle(b.maps, r);
      b.effects = shuffle(b.effects, r);
      b.revocation_epochs = shuffle(b.revocation_epochs, r);
      const again = await verifyEvidenceBundle(reorderKeys(b, r), w.trust);
      expect(again.report_digest).toBe(base.report_digest);
      expect(again.digest).toBe(base.digest);
      expect(evidenceDigest(buildEvidenceBundle(reorderKeys(b, r) as EvidenceBundle))).toBe(base.digest);
    }
  });

  it('delta chain: replay from another session, gaps, duplicates and a broken prev are refused', async () => {
    const w = walkthrough();
    const anaPub = encodeKey(w.ana.publicKey);
    const mk = (cv: { session: string; seq: number; prev: string; root: string }, signer: KeyPair = w.ana) => sessionGrant(w, { ...cv, mapDigest: w.md[1], cap: 80000 }, signer);
    const D2 = mk({ session: w.session, seq: 2, prev: w.D1.id, root: w.sRef });
    const ok = clone(w.bundle);
    ok.deltas = [D2, w.D1];
    expect(statusOf(await verifyEvidenceBundle(ok, w.trust), 'delta.chain')).toEqual(['pass']);
    const variants: Capability[][] = [
      [mk({ session: hashCanonical('other'), seq: 1, prev: w.G0.id, root: w.sRef })],
      [mk({ session: w.session, seq: 1, prev: w.G0.id, root: hashCanonical('other-root') })],
      [mk({ session: w.session, seq: 2, prev: w.G0.id, root: w.sRef })],
      [w.D1, mk({ session: w.session, seq: 1, prev: w.G0.id, root: w.sRef })],
      [w.D1, mk({ session: w.session, seq: 2, prev: w.G0.id, root: w.sRef })],
      [mk({ session: w.session, seq: 1, prev: w.G0.id, root: w.sRef }, w.agent)],
    ];
    for (const deltas of variants) {
      const b = clone(w.bundle);
      b.deltas = deltas;
      const r = await verifyEvidenceBundle(b, w.trust);
      expect(r.ok).toBe(false);
      expect([...statusOf(r, 'delta.chain'), ...statusOf(r, 'delta.signature')]).toContain('fail');
    }
  });

  it('the claimed canary summary is never trusted: any claim other than the recomputed one fails', async () => {
    const w = walkthrough();
    const r = rng(7);
    for (let i = 0; i < 25; i++) {
      const claim = { asked: Math.floor(r() * 3), false_yes: Math.floor(r() * 2), false_no: Math.floor(r() * 2) };
      const b = clone(w.bundle);
      b.canaries = claim;
      const rep = await verifyEvidenceBundle(b, w.trust);
      const truth = claim.asked === 1 && claim.false_yes === 0 && claim.false_no === 0;
      expect(statusOf(rep, 'canaries.summary')).toEqual([truth ? 'pass' : 'fail']);
    }
    // A wrong canary answer is counted from the signed answer, whatever the bundle claims.
    const b = clone(w.bundle);
    b.answers = b.answers.map((a) => (a.question_id === 'q_c1' ? signIntentAnswer({ ...strip(a), y: 1 }, w.ana.secretKey) : a));
    expect(statusOf(await verifyEvidenceBundle(b, w.trust), 'canaries.summary')).toEqual(['fail']);
    b.canaries = { asked: 1, false_yes: 1, false_no: 0 };
    const fixed = await verifyEvidenceBundle(b, w.trust);
    expect(statusOf(fixed, 'canaries.summary')).toEqual(['pass']);
    expect(fixed.summary.canary_accuracy).toEqual({ correct: 0, asked: 1 });
  });

  it('accumulator overspend: a post above the admitting grant cap always fails, at or below passes', async () => {
    const w = walkthrough();
    const r = rng(11);
    for (let i = 0; i < 20; i++) {
      const post = 40001 + Math.floor(r() * 80000);
      const b = clone(w.bundle);
      b.accumulator.events[0]!.post = post;
      b.effects[0]!.params = { ...PARAMS_OK, total: post };
      const rep = await verifyEvidenceBundle(b, w.trust);
      expect(statusOf(rep, 'accumulator.cap')).toEqual([post <= 80000 ? 'pass' : 'fail']);
      expect(statusOf(rep, 'accumulator.arithmetic')).toEqual(['pass']);
    }
  });

  it('an event claimed under a different grant than the PCActn root is refused', async () => {
    const w = walkthrough();
    const b = clone(w.bundle);
    b.accumulator.events[0]!.delta = 0;
    expect(statusOf(await verifyEvidenceBundle(b, w.trust), 'accumulator.cap')).toEqual(['fail']);
  });
});

// ---- core verifiers for W-B artifacts, receipts and the signed intent_session member ---------------------------------

describe('core verifiers are the default; ports override; nothing pinned stays unverified', () => {
  const wb = (w: World) => {
    const oracle = seeded(10);
    const judge = seeded(11);
    const fact = signFact({ name: 'fare_quote', subject: 'OF-1', value: 38900, t_obs: T0 + 3000, oracle: 'quotes' }, oracle.secretKey);
    const verdict = signClassifierVerdict({ classifier: 'tone', session: w.session, content_digest: hashCanonical('msg'), label: 'neutral', measurement: 'm1' }, judge.secretKey);
    const offers = signOfferSet({ v: 1, kind: 'pca-offer-set', site: 'https://skyair.example', session: w.session, query: { from: 'SFO', to: 'JFK' }, rank: 'price_asc', complete: true, offers: [{ offer_id: 'OF-1', price: 38900 }, { offer_id: 'OF-2', price: 39800 }], issued_at: T0 + 3000, kid: KID }, w.site.secretKey);
    const labels = signLabels({ site: 'https://skyair.example', session: w.session, response_digest: hashCanonical('resp'), fields: { '/email': { class: 'pii.contact', value_digest: hashCanonical('e') } }, issued_at: T0 + 3000, kid: KID }, w.site.secretKey);
    return { oracle, judge, fact, verdict, offers, labels };
  };

  it('facts, classifier verdicts, offer sets and label receipts verify under pinned keys', async () => {
    const w = walkthrough();
    const x = wb(w);
    const b = clone(w.bundle);
    b.facts = [x.fact];
    b.classifier = [x.verdict];
    b.offer_sets = [x.offers];
    b.labels = [x.labels];
    const pinned = await verifyEvidenceBundle(b, { ...w.trust, oracleKeys: { quotes: encodeKey(x.oracle.publicKey) }, judges: [encodeKey(x.judge.publicKey)] });
    for (const code of ['fact.signature', 'classifier.signature', 'offer_set.signature', 'labels.signature'] as FindingCode[]) expect(statusOf(pinned, code)).toEqual(['pass']);
    const unpinned = await verifyEvidenceBundle(b, { ...w.trust, siteKeys: undefined });
    for (const code of ['fact.signature', 'classifier.signature', 'offer_set.signature', 'labels.signature'] as FindingCode[]) expect(statusOf(unpinned, code)).toEqual(['unverified']);
    const t = clone(b);
    t.facts![0]!.value = 30000;
    t.classifier![0]!.label = 'hostile';
    t.offer_sets![0]!.offers[0]!.price = 100;
    t.labels![0]!.issued_at += 1;
    const tampered = await verifyEvidenceBundle(t, { ...w.trust, oracleKeys: { quotes: encodeKey(x.oracle.publicKey) }, judges: [encodeKey(x.judge.publicKey)] });
    for (const code of ['fact.signature', 'classifier.signature', 'offer_set.signature', 'labels.signature'] as FindingCode[]) expect(statusOf(tampered, code)).toEqual(['fail']);
  });

  it('a port overrides the core default', async () => {
    const w = walkthrough();
    const b = clone(w.bundle);
    b.session_root.question_uri = 'https://evil.example/q';
    const r = await verifyEvidenceBundle(b, { ...w.trust, verifiers: { ...w.trust.verifiers, sessionRoot: () => ({ ok: true }) } });
    expect(statusOf(r, 'session_root.signature')).toEqual(['pass']);
    const r2 = await verifyEvidenceBundle(w.bundle, { ...w.trust, verifiers: { ...w.trust.verifiers, schema: () => ({ ok: false, reason: 'revoked site key' }) } });
    expect(statusOf(r2, 'schema.signature')).toEqual(['fail']);
  });

  it('a reservation receipt for an accumulator that is not sequenced is refused; a sequenced holder needs receipts', async () => {
    const w = walkthrough();
    const b = clone(w.bundle);
    b.accumulator.receipts = [{ v: 1, kind: 'pca-acc-receipt', session: w.session, acc: 'trip_spend', seq: 1, pre: 0, delta: 77800, post: 77800, pcactn_digest: hashCanonical('x'), aud: AUD, issued_at: T0, expires_at: T0 + 60_000, kid: 'guardian-1', ledger: { index: 0, head: hashCanonical('h') }, signer: encodeKey(w.site.publicKey), sig: 'AA' }];
    expect(statusOf(await verifyEvidenceBundle(b, w.trust), 'accumulator.receipts')).toEqual(['fail']);
    const c = clone(w.bundle);
    c.accumulator.holder = 'sequenced';
    c.accumulator.receipts = [];
    expect(statusOf(await verifyEvidenceBundle(c, w.trust), 'accumulator.receipts')).toEqual(['fail']);
  });

  it('a PCActn whose signed intent_session names another session fails pcactn.session', async () => {
    const w = walkthrough();
    const task = delegate(w.D1, encodeKey(w.agent.publicKey), [], w.ana.secretKey);
    const plan: PlanNode[] = [{ id: 'n1', verb: 'air.book', resource: 'skyair.example/bookings', params_digest: paramsDigest(PARAMS_OK), reversibility_class: 'irreversible' }];
    const p = buildPCActn({
      grant: w.D1, chain: [w.D1, task], plan, nodeId: 'n1', params: PARAMS_OK, counter: 4, signerSecret: w.agent.secretKey, aud: AUD, iat: T0 + 5500, exp: T0 + 600_000,
      intentSession: { session: hashCanonical('other'), root: w.sRef, seq: 1, schema: w.S.schema.digest },
    });
    const b = clone(w.bundle);
    b.pcactns = [...b.pcactns, p];
    const r = await verifyEvidenceBundle(b, w.trust);
    expect(r.findings.find((x) => x.code === 'pcactn.session' && x.refs[0] === `pcactn:${pcactnDigest(p)}`)?.status).toBe('fail');
  });

  it('capOf reads the envelope predicates: tightest per predicate, loosest across a union', () => {
    const w = walkthrough();
    expect(capOf(w.G0, 'trip_spend', 'air.book')).toBe(40000);
    expect(capOf(w.D1, 'trip_spend', 'air.book')).toBe(80000);
    expect(capOf(w.D1, 'trip_spend', 'hotel.book')).toBeNull();
    expect(capOf(w.D1, 'other', 'air.book')).toBeNull();
  });
});

// ---- the commitments-only digest -------------------------------------------------------------------------------------

describe('evidenceDigest commits to commitments only: openings can be withheld, a wrong opening fails on its own', () => {
  const withhold = (b: EvidenceBundle, mask: number): EvidenceBundle => {
    const x = clone(b);
    if (mask & 1) delete x.statement.opening;
    if (mask & 2) delete x.maps.find((m) => m.seq === 0)!.map;
    if (mask & 4) delete x.maps.find((m) => m.seq === 1)!.map;
    if (mask & 8) for (const e of x.effects) delete e.params;
    return x;
  };

  it('property: any subset of openings withheld leaves the digest, and so the anchor, unchanged', async () => {
    const w = walkthrough();
    const base = evidenceDigest(w.bundle);
    const r = rng(23);
    const masks = new Set<number>([0, 15]);
    while (masks.size < 10) masks.add(Math.floor(r() * 16));
    for (const mask of masks) {
      const b = withhold(w.bundle, mask);
      expect(evidenceDigest(b)).toBe(base);
      const rep = await verifyEvidenceBundle(b, w.trust);
      expect(statusOf(rep, 'anchor.inclusion')).toEqual(['pass']);
      expect(rep.ok).toBe(true);
    }
  });

  it('a wrong opening fails its own finding while the anchor still passes', async () => {
    const w = walkthrough();
    const other = signIntentStatement({ v: 1, text: 'Book anything at any price.', slots: {}, sources: [], created_at: T0, nonce: 'n-2' }, w.ana.secretKey);
    const cases: [(b: EvidenceBundle) => void, FindingCode][] = [
      [(b) => void (b.statement.opening = other), 'statement.opening'],
      [(b) => void (b.maps.find((m) => m.seq === 1)!.map = clone(b.maps.find((m) => m.seq === 0)!.map!)), 'map.replay'],
      [(b) => void (b.effects[0]!.params = { ...PARAMS_OK, total: 70000 }), 'effect.binding'],
    ];
    for (const [mutate, code] of cases) {
      const b = clone(w.bundle);
      mutate(b);
      expect(evidenceDigest(b)).toBe(evidenceDigest(w.bundle));
      const rep = await verifyEvidenceBundle(b, w.trust);
      expect(statusOf(rep, code)).toContain('fail');
      expect(statusOf(rep, 'anchor.inclusion')).toEqual(['pass']);
    }
  });

  it('changing any commitment changes the digest and fails the anchor', async () => {
    const w = walkthrough();
    const cases: ((b: EvidenceBundle) => void)[] = [
      (b) => void (b.statement.commit = hashCanonical('another statement')),
      (b) => void (b.maps[0]!.commit = hashCanonical('another map')),
      (b) => void (b.maps[0]!.disclosed = ['metrics']),
      (b) => void (b.accumulator.events[0]!.post = 77801),
      (b) => void (b.effects[0]!.charged = { amount: 77000, ref: 'action.params.total' }),
      (b) => void (b.canary_labels[0]!.label = 1),
      (b) => void (b.subject.aud = 'other.example'),
    ];
    for (const mutate of cases) {
      const b = clone(w.bundle);
      mutate(b);
      expect(evidenceDigest(b)).not.toBe(evidenceDigest(w.bundle));
      expect(statusOf(await verifyEvidenceBundle(b, w.trust), 'anchor.inclusion')).toContain('fail');
    }
  });
});

// ---- rule 13 append-only revocation across the bundle's epochs, rule 15 receipt freshness at admission ----------------

describe('revocation chain and receipt freshness', () => {
  const X = 'pca-intent:session:someone-else';
  const Y = 'pca-intent:map:some-other-map';
  const Z = 'pca-intent:delta:some-other-delta';
  const epochOf = (w: World, ids: string[], issuedAt: number) => {
    const rs = new RevocationSet(ids);
    const epoch = signRevocationEpoch(w.guardian.secretKey, { instance_id: 'atlas', grant_ref: sessionRevocationScope(w.session), epoch: rs.size, set_size: rs.size, root: rs.root, issued_at: issuedAt, not_after: issuedAt + 300_000 });
    return { epoch, revoked: rs.list() };
  };
  const run = async (w: World, epochs: ReturnType<typeof epochOf>[]) => {
    const b = clone(w.bundle);
    b.revocation_epochs = epochs;
    return verifyEvidenceBundle(b, w.trust);
  };

  it('an append-only chain passes', async () => {
    const w = walkthrough();
    const r = await run(w, [epochOf(w, [X], T0 + 3000), epochOf(w, [X, Y], T0 + 4500)]);
    expect(statusOf(r, 'revocation.history')).toEqual(['pass']);
    expect(statusOf(r, 'revocation.epoch')).toEqual(['pass']);
  });
  it('a later epoch that drops an id (same size, or larger) fails the chain', async () => {
    const w = walkthrough();
    for (const later of [[Y], [Y, Z]]) {
      const r = await run(w, [epochOf(w, [X], T0 + 3000), epochOf(w, later, T0 + 4500)]);
      expect(statusOf(r, 'revocation.history')).toContain('fail');
      expect(statusOf(r, 'revocation.epoch')).toEqual(['fail']);
    }
  });
  it('a rollback to a lower epoch number issued later fails the chain', async () => {
    const w = walkthrough();
    const r = await run(w, [epochOf(w, [X, Y], T0 + 3000), epochOf(w, [X], T0 + 4500)]);
    expect(statusOf(r, 'revocation.history')).toContain('fail');
    expect(statusOf(r, 'revocation.epoch')).toEqual(['fail']);
  });
  it('a drop after the action is still a chain failure (the authority misbehaved)', async () => {
    const w = walkthrough();
    const r = await run(w, [epochOf(w, [X], T0 + 4500), epochOf(w, [Y], T0 + 9000)]);
    expect(statusOf(r, 'revocation.history')).toContain('fail');
  });
  it('an epoch signed by a principal (not the dedicated authority) fails', async () => {
    const w = walkthrough();
    const rs = new RevocationSet([X]);
    const epoch = signRevocationEpoch(w.ana.secretKey, { instance_id: 'atlas', grant_ref: sessionRevocationScope(w.session), epoch: 1, set_size: 1, root: rs.root, issued_at: T0 + 4500, not_after: T0 + 300_000 });
    const r = await run(w, [{ epoch, revoked: rs.list() }]);
    expect(statusOf(r, 'revocation.epoch')).toEqual(['fail']);
  });

  it('receipts are judged at admission time: fresh passes, stale / expired / future-issued fail', async () => {
    const w = walkthrough();
    const admitted = w.subject.iat;
    const verdictFor = async (issuedAt: number) => {
      const b = clone(w.bundle);
      b.accumulator.receipts = [reserve(w.session, w.subject, w.seqKey, issuedAt)];
      return statusOf(await verifyEvidenceBundle(b, w.trust), 'accumulator.receipts');
    };
    expect(await verifyEvidenceBundle(w.bundle, w.trust).then((r) => statusOf(r, 'accumulator.receipts'))).toEqual(['pass']);
    expect(await verifyEvidenceBundle(w.bundle, w.trust).then((r) => r.complete)).toBe(true);
    expect(await verdictFor(admitted - 1_000_000)).toEqual(['fail']);
    expect(await verdictFor(admitted - 700_000)).toEqual(['fail']);
    expect(await verdictFor(admitted + 120_000)).toEqual(['fail']);
  });
  it('a receipt signed by a key the sequencer root never listed fails', async () => {
    const w = walkthrough();
    const b = clone(w.bundle);
    b.accumulator.receipts = [reserve(w.session, w.subject, seeded(99), w.subject.iat - 100)];
    expect(statusOf(await verifyEvidenceBundle(b, w.trust), 'accumulator.receipts')).toEqual(['fail']);
  });
});

// ---- rule 15 key-set version tracking and configurable freshness (trust.acc) -------------------------------------------

describe('sequencer key sets replayed in issue order; trust.acc freshness bounds', () => {
  const keySet = (w: World, version: number, issuedAt: number, keys: [string, KeyPair][]) =>
    signSequencerKeySet({ v: 1, kind: 'pca-sequencer-keys', version, issued_at: issuedAt, keys: keys.map(([kid, k]) => ({ kid, pk: encodeKey(k.publicKey), not_before: T0 - 600_000 })) }, w.seqRoot.secretKey);
  const withSets = (w: World, sets: unknown[], receiptAt?: number) => {
    const b = clone(w.bundle);
    b.accumulator.sequencer_keys = sets;
    if (receiptAt !== undefined) b.accumulator.receipts = [reserve(w.session, w.subject, w.seqKey, receiptAt)];
    return b;
  };

  it('monotone versions pass, and the receipt verifies under the set in force', async () => {
    const w = walkthrough();
    const r = await verifyEvidenceBundle(withSets(w, [keySet(w, 1, T0, [['k1', w.seqKey]]), keySet(w, 2, T0 + 3000, [['k1', w.seqKey]])]), w.trust);
    expect(statusOf(r, 'acc.keysets')).toEqual(['pass']);
    expect(statusOf(r, 'accumulator.receipts')).toEqual(['pass']);
  });
  it('a version rollback across two bundled key sets fails the chain', async () => {
    const w = walkthrough();
    const r = await verifyEvidenceBundle(withSets(w, [keySet(w, 2, T0, [['k1', w.seqKey]]), keySet(w, 1, T0 + 3000, [['k1', w.seqKey]])]), w.trust);
    expect(statusOf(r, 'acc.keysets')).toEqual(['fail', 'pass']);
    expect(r.ok).toBe(false);
  });
  it('a receipt checked against a superseded set fails (the tracked minimum version skips it)', async () => {
    const w = walkthrough();
    const k2 = seeded(42);
    const r = await verifyEvidenceBundle(withSets(w, [keySet(w, 1, T0, [['k1', w.seqKey]]), keySet(w, 2, T0 + 3000, [['k2', k2]])]), w.trust);
    expect(statusOf(r, 'acc.keysets')).toEqual(['pass']);
    expect(statusOf(r, 'accumulator.receipts')).toEqual(['fail']);
  });
  it('a key set issued after the admission it is used for does not count', async () => {
    const w = walkthrough();
    const r = await verifyEvidenceBundle(withSets(w, [keySet(w, 1, w.subject.iat + 120_000, [['k1', w.seqKey]])]), w.trust);
    expect(statusOf(r, 'accumulator.receipts')).toEqual(['fail']);
  });
  it('a key set signed by a root the session does not pin fails', async () => {
    const w = walkthrough();
    const rogue = signSequencerKeySet({ v: 1, kind: 'pca-sequencer-keys', version: 3, issued_at: T0, keys: [{ kid: 'k1', pk: encodeKey(w.seqKey.publicKey), not_before: T0 - 600_000 }] }, seeded(43).secretKey);
    expect(statusOf(await verifyEvidenceBundle(withSets(w, [rogue]), w.trust), 'acc.keysets')).toEqual(['fail']);
  });

  it('equivocation: two different sets under one root and version fail, and no receipt can rely on either', async () => {
    const w = walkthrough();
    const a = keySet(w, 1, T0, [['k1', w.seqKey]]);
    const b2 = keySet(w, 1, T0 + 1000, [['k1', w.seqKey], ['k2', seeded(44)]]);
    const r = await verifyEvidenceBundle(withSets(w, [a, b2]), w.trust);
    const eq = r.findings.filter((x) => x.code === 'acc.keysets.equivocation');
    expect(eq.map((x) => x.status)).toEqual(['fail']);
    expect(eq[0]!.refs).toHaveLength(2);
    expect(statusOf(r, 'accumulator.receipts')).toEqual(['fail']);
    expect(r.ok).toBe(false);
  });
  it('an equivocation at a later version also blocks falling back to an older set', async () => {
    const w = walkthrough();
    const sets = [keySet(w, 1, T0 - 2000, [['k1', w.seqKey]]), keySet(w, 2, T0 - 1000, [['k1', w.seqKey]]), keySet(w, 2, T0, [['k1', w.seqKey], ['k3', seeded(45)]])];
    const r = await verifyEvidenceBundle(withSets(w, sets), w.trust);
    expect(statusOf(r, 'acc.keysets.equivocation')).toEqual(['fail']);
    expect(statusOf(r, 'accumulator.receipts')).toEqual(['fail']);
  });
  it('an identical duplicate set is not equivocation', async () => {
    const w = walkthrough();
    const a = keySet(w, 1, T0, [['k1', w.seqKey]]);
    const r = await verifyEvidenceBundle(withSets(w, [a, clone(a)]), w.trust);
    expect(statusOf(r, 'acc.keysets.equivocation')).toEqual([]);
    expect(statusOf(r, 'acc.keysets')).toEqual(['pass']);
    expect(statusOf(r, 'accumulator.receipts')).toEqual(['pass']);
  });
  it('different versions still follow the monotone rule (a lower version issued later is a rollback, not equivocation)', async () => {
    const w = walkthrough();
    const r = await verifyEvidenceBundle(withSets(w, [keySet(w, 2, T0, [['k1', w.seqKey]]), keySet(w, 1, T0 + 1000, [['k1', w.seqKey], ['k2', seeded(46)]])]), w.trust);
    expect(statusOf(r, 'acc.keysets.equivocation')).toEqual([]);
    expect(statusOf(r, 'acc.keysets')).toEqual(['fail', 'pass']);
  });

  it('custom receipt age limit: just inside passes, just outside fails', async () => {
    const w = walkthrough();
    const b = withSets(w, [keySet(w, 1, T0, [['k1', w.seqKey]])], w.subject.iat - 10_000);
    expect(statusOf(await verifyEvidenceBundle(b, { ...w.trust, acc: { max_receipt_age_s: 10 } }), 'accumulator.receipts')).toEqual(['pass']);
    expect(statusOf(await verifyEvidenceBundle(b, { ...w.trust, acc: { max_receipt_age_s: 9 } }), 'accumulator.receipts')).toEqual(['fail']);
  });
  it('custom key-set age limit: just inside passes, just outside fails', async () => {
    const w = walkthrough();
    const b = withSets(w, [keySet(w, 1, w.subject.iat - 5000, [['k1', w.seqKey]])]);
    expect(statusOf(await verifyEvidenceBundle(b, { ...w.trust, acc: { max_keyset_age_s: 5 } }), 'accumulator.receipts')).toEqual(['pass']);
    expect(statusOf(await verifyEvidenceBundle(b, { ...w.trust, acc: { max_keyset_age_s: 4 } }), 'accumulator.receipts')).toEqual(['fail']);
  });
  it('bad trust.acc members and values fail the replay closed', async () => {
    const w = walkthrough();
    for (const acc of [{ foo: 1 }, { max_receipt_age_s: -1 }, { max_receipt_age_s: 1.5 }, { max_keyset_age_s: '10' }, null, []]) {
      const r = await verifyEvidenceBundle(w.bundle, { ...w.trust, acc: acc as unknown as EvidenceTrust['acc'] });
      expect(r.ok).toBe(false);
      expect(r.digest).toBeNull();
      expect(statusOf(r, 'trust.acc')).toEqual(['fail']);
    }
  });
});

// ---- attribution: pinned principal keys (a self-signed session root proves consistency only) --------------------------

describe('attribution requires pinned principal keys', () => {
  it('a fully fabricated, self-consistent bundle without pins is consistent but NOT ok', async () => {
    const fake = walkthrough(77);
    const { principals: _p, ...unpinned } = fake.trust;
    void _p;
    const r = await verifyEvidenceBundle(fake.bundle, unpinned);
    expect(r.consistent).toBe(true);
    expect(r.attributed).toBe(false);
    expect(r.ok).toBe(false);
    expect(statusOf(r, 'principal.pinned')).toEqual(['unverified']);
    expect(r.summary.attribution).toEqual({ pinned: false, keys_to_check: [encodeKey(seeded(77).publicKey)] });
    expect(r.summary.not_proven[0]).toMatch(/internally consistent but NOT attributed/);
    expect(r.summary.proven.join(' ')).toMatch(/NOT pinned/);
  });
  it('the real walkthrough with the real pins is ok and attributed', async () => {
    const w = walkthrough();
    const r = await verifyEvidenceBundle(w.bundle, w.trust);
    expect(r.ok).toBe(true);
    expect(r.attributed).toBe(true);
    expect(statusOf(r, 'principal.pinned')).toEqual(['pass']);
    expect(r.summary.attribution.pinned).toBe(true);
  });
  it('pins that do not match the signing keys fail (a fabricated bundle against the real principal)', async () => {
    const fake = walkthrough(77);
    const r = await verifyEvidenceBundle(fake.bundle, { ...fake.trust, principals: [{ key: encodeKey(seeded(1).publicKey) }] });
    expect(statusOf(r, 'principal.pinned')).toEqual(['fail']);
    expect(r.ok).toBe(false);
    expect(r.consistent).toBe(false);
  });
  it('a pin with a PQ key the session root does not bind fails', async () => {
    const w = walkthrough();
    const r = await verifyEvidenceBundle(w.bundle, { ...w.trust, principals: [{ key: encodeKey(w.ana.publicKey), pq_pk: 'AAAA' }] });
    expect(statusOf(r, 'principal.pinned')).toEqual(['fail']);
  });
  // A PQ / hybrid session verifies only under the READER's pin (trust.principals[].pq_pk), never the bundle's own S.principals:
  // the session root, G_0, the deltas and every PCActn root (pcactn.verify) all take the pinned key.
  for (const s of ['ml-dsa-65', 'hybrid-ed25519-ml-dsa-65'] as const) {
    it(`a ${s} session with the principal's PQ key pinned verifies and is attributed`, async () => {
      const w = walkthrough(1, { suite: s });
      expect(w.S.alg).toBe(s);
      expect(w.G0.alg).toBe(s);
      const r = await verifyEvidenceBundle(w.bundle, w.trust);
      expect(r.findings.filter((x) => x.status === 'fail')).toEqual([]);
      for (const code of ['session_root.signature', 'root_grant', 'delta.signature', 'pcactn.verify', 'principal.pinned'] as const) expect(statusOf(r, code)).toEqual(['pass']);
      expect(r.ok).toBe(true);
      expect(r.attributed).toBe(true);
    });
  }
  it('a PQ session whose principal is pinned WITHOUT a PQ key fails closed (the bundle names its own pq_pk)', async () => {
    const w = walkthrough(1, { suite: 'ml-dsa-65' });
    const r = await verifyEvidenceBundle(w.bundle, { ...w.trust, principals: [{ key: encodeKey(w.ana.publicKey) }] });
    for (const code of ['session_root.signature', 'root_grant', 'delta.signature', 'pcactn.verify'] as const) expect(statusOf(r, code)).toEqual(['fail']);
    expect(r.findings.find((x) => x.code === 'session_root.signature')?.text).toMatch(/pinned by the verifier/);
    expect(r.consistent).toBe(false);
    expect(r.ok).toBe(false);
  });
  it('a PQ session with no pins at all fails closed', async () => {
    const w = walkthrough(1, { suite: 'ml-dsa-65' });
    const { principals: _p, ...unpinned } = w.trust;
    void _p;
    const r = await verifyEvidenceBundle(w.bundle, unpinned);
    for (const code of ['session_root.signature', 'root_grant', 'delta.signature', 'pcactn.verify'] as const) expect(statusOf(r, code)).toEqual(['fail']);
    expect(r.ok).toBe(false);
  });
  it('a PQ bundle carrying a different pq_pk than the pin fails (an attacker\'s own ML-DSA key under the real Ed25519 identity)', async () => {
    // Same Ed25519 identity as the real principal, but S / G_0 / D_1 signed with a PQ key the attacker generated.
    const forged = walkthrough(1, { suite: 'ml-dsa-65', pqSeed: 99 });
    const r = await verifyEvidenceBundle(forged.bundle, forged.trust); // trust pins Ana's REAL PQ key
    for (const code of ['session_root.signature', 'root_grant', 'delta.signature', 'pcactn.verify', 'principal.pinned'] as const) expect(statusOf(r, code)).toEqual(['fail']);
    expect(r.findings.find((x) => x.code === 'session_root.signature')?.text).toMatch(/does not match the verifier's pin/);
    expect(r.ok).toBe(false);
  });
  it('extra pinned keys that sign nothing do not hurt', async () => {
    const w = walkthrough();
    const extra = { ...w.trust, principals: [{ key: encodeKey(w.ana.publicKey) }, { key: encodeKey(seeded(50).publicKey) }] };
    expect(statusOf(await verifyEvidenceBundle(w.bundle, extra), 'principal.pinned')).toEqual(['pass']);
  });
  it('malformed pins fail the replay closed', async () => {
    const w = walkthrough();
    for (const principals of [[], ['k'], [{ key: 'short' }], [{ key: encodeKey(w.ana.publicKey), extra: 1 }], null]) {
      const r = await verifyEvidenceBundle(w.bundle, { ...w.trust, principals: principals as unknown as EvidenceTrust['principals'] });
      expect(statusOf(r, 'trust.principals')).toEqual(['fail']);
      expect(r.ok).toBe(false);
    }
  });
});

// ---- SCITT + CLI ---------------------------------------------------------------------------------------------------

describe('SCITT registration', () => {
  it('signs the bundle reference as a COSE signed statement', () => {
    const w = walkthrough();
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const st = evidenceSignedStatement(w.bundle, { alg: 'EdDSA', key: privateKey, issuer: 'skyair.example' });
    expect(verifyStatement(st, publicKey)).toBe(true);
    const payload = JSON.parse(new TextDecoder().decode(statementPayload(st))) as { kind: string; digest: string };
    expect(payload).toMatchObject({ kind: 'pca-intent-evidence-ref', digest: evidenceDigest(w.bundle) });
  });
});

describe('CLI', () => {
  const io = (files: Record<string, string>) => {
    const out: string[] = [];
    const err: string[] = [];
    return { out, err, io: { readFile: (p: string) => { if (!(p in files)) throw new Error(`no such file ${p}`); return files[p]!; }, stdout: (s: string) => void out.push(s), stderr: (s: string) => void err.push(s) } };
  };
  const trustJson = (t: EvidenceTrust) => JSON.stringify({ principals: t.principals, siteKeys: t.siteKeys, minTier: t.minTier, typedValues: t.typedValues, anchorGuardian: t.anchorGuardian });

  it('verify: exit 0 on a passing bundle, prints proven and not proven', async () => {
    const w = walkthrough();
    const x = io({ 'b.json': JSON.stringify(w.bundle), 't.json': trustJson(w.trust) });
    expect(await runCli(['verify', 'b.json', '--trust', 't.json'], x.io)).toBe(0);
    expect(x.out.join('\n')).toMatch(/OK \(incomplete/);
    expect(x.out.join('\n')).toMatch(/Not proven:/);
  });
  it('verify --json: the same report as the library', async () => {
    const w = walkthrough();
    const x = io({ 'b.json': JSON.stringify(w.bundle) });
    expect(await runCli(['verify', 'b.json', '--json'], x.io)).toBe(3);
    const lib = await verifyEvidenceBundle(w.bundle, {});
    expect((JSON.parse(x.out[0]!) as FindingsReport).report_digest).toBe(lib.report_digest);
  });
  it('verify: exit 1 on a failing bundle', async () => {
    const w = walkthrough();
    const b = clone(w.bundle);
    b.canaries = { asked: 0, false_yes: 0, false_no: 0 };
    const x = io({ 'b.json': JSON.stringify(b) });
    expect(await runCli(['verify', 'b.json'], x.io)).toBe(1);
  });
  it('digest, usage and parse errors', async () => {
    const w = walkthrough();
    const x = io({ 'b.json': JSON.stringify(w.bundle), 'bad.json': '{"a":1,"a":2}', 't.json': '{"verifiers":{}}' });
    expect(await runCli(['digest', 'b.json'], x.io)).toBe(0);
    expect(x.out[0]).toBe(evidenceDigest(w.bundle));
    expect(await runCli([], x.io)).toBe(2);
    expect(await runCli(['verify'], x.io)).toBe(2);
    expect(await runCli(['verify', 'missing.json'], x.io)).toBe(2);
    expect(await runCli(['verify', 'bad.json'], x.io)).toBe(2);
    expect(await runCli(['verify', 'b.json', '--trust', 't.json'], x.io)).toBe(2);
    expect(await runCli(['verify', 'b.json', '--frobnicate'], x.io)).toBe(2);
  });
  it('a fabricated bundle without pins exits 3; with the real pins it exits 1; --allow-unpinned exits 0 and lists the keys', async () => {
    const fake = walkthrough(77);
    const attackerKey = encodeKey(seeded(77).publicKey);
    const x = io({ 'b.json': JSON.stringify(fake.bundle), 'none.json': '{}', 'real.json': JSON.stringify({ principals: [{ key: encodeKey(seeded(1).publicKey) }] }) });
    expect(await runCli(['verify', 'b.json'], x.io)).toBe(3);
    expect(x.out.join('\n')).toMatch(/CONSISTENT BUT NOT ATTRIBUTED/);
    expect(x.err.join('\n')).toContain(attackerKey);
    expect(await runCli(['verify', 'b.json', '--trust', 'none.json'], x.io)).toBe(3);
    expect(await runCli(['verify', 'b.json', '--trust', 'real.json'], x.io)).toBe(1);
    x.err.length = 0;
    expect(await runCli(['verify', 'b.json', '--allow-unpinned'], x.io)).toBe(0);
    expect(x.err.join('\n')).toMatch(/principal keys to verify out of band: .*/);
    expect(x.err.join('\n')).toContain(attackerKey);
    // --allow-unpinned never hides a failure: a failing fabricated bundle still exits 1.
    const b = clone(fake.bundle);
    b.canaries = { asked: 0, false_yes: 0, false_no: 0 };
    const y = io({ 'b.json': JSON.stringify(b) });
    expect(await runCli(['verify', 'b.json', '--allow-unpinned'], y.io)).toBe(1);
  });
  it('trust.principals in the trust file: closed and typed (exit 2)', async () => {
    const w = walkthrough();
    const x = io({ 'b.json': JSON.stringify(w.bundle), 'p1.json': '{"principals":[]}', 'p2.json': '{"principals":["abc"]}', 'p3.json': '{"principals":[{"key":"short"}]}', 'p4.json': JSON.stringify({ principals: [{ key: encodeKey(w.ana.publicKey), role: 'x' }] }) });
    for (const t of ['p1.json', 'p2.json', 'p3.json', 'p4.json']) expect(await runCli(['verify', 'b.json', '--trust', t], x.io)).toBe(2);
  });
  it('trust.acc in the trust file: closed and typed (exit 2), valid bounds accepted', async () => {
    const w = walkthrough();
    const x = io({ 'b.json': JSON.stringify(w.bundle), 'bad1.json': '{"acc":{"foo":1}}', 'bad2.json': '{"acc":{"max_receipt_age_s":-1}}', 'bad3.json': '{"acc":{"max_keyset_age_s":"10"}}', 'ok.json': JSON.stringify({ principals: w.trust.principals, acc: { max_receipt_age_s: 900, max_keyset_age_s: 3600 } }) });
    for (const t of ['bad1.json', 'bad2.json', 'bad3.json']) expect(await runCli(['verify', 'b.json', '--trust', t], x.io)).toBe(2);
    expect(await runCli(['verify', 'b.json', '--trust', 'ok.json'], x.io)).toBe(0);
  });
});
