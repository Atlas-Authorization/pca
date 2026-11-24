// Oracle (java extra 2): the dispute-evidence replay verifyEvidenceBundle (pca-evidence verify.ts) over the walkthrough world of the package's own tests (real keys and
// core signers, derived from fixed seeds) and mutations of it. Every case is [bundle, trustSpec]; trustSpec is the reference trust object as JSON except that each
// verifiers.<name> is the string 'ok' | 'fail' | 'throws' (a port returning {ok:true}, {ok:false, reason:'port refused'}, or throwing Error('boom')).
// The PQ walkthrough cases sign with hedged ML-DSA, so regenerating them changes those bundles (the verdicts stay the same).
// PORTING (fn(args) -> native entry point, comparison rule; the whole report is compared as JSON, report_digest included):
//   verifyEvidenceBundle(bundle, trustSpec) -> EvidenceVerify.verifyEvidenceBundle(bundle, trust, ports): ports built from the same three kinds.
import { generateKeyPairSync } from 'node:crypto';
import * as NS2 from '@atlasauth/pca';
const { RevocationSet, buildPCActn, delegate, encodeKey, encodeMlDsaPublicKey, hashCanonical, merkleProof, merkleRoot, mlDsa65Keygen, paramsDigest, pcactnDigest, publicKeyOf, signRevocationEpoch } = ((NS2 as any).default ?? NS2) as any;
import * as NS3 from '@atlasauth/pca/ext/intent';
const { actionSchemaDigest, actionSchemaKeyOf, deltaRevocationId, intentActionDigest, intentRef, mintSessionGrant, sessionRevocationScope, sessionRootDigest, pcactnReservationDigest, signAccReceipt, signActionSchema, signSequencerKeySet, signClassifierVerdict, signFact, signIntentStatement, signLabels, signOfferSet, signSessionRoot } = ((NS3 as any).default ?? NS3) as any;
import * as NS4 from '@atlasauth/pca/ext/ledger';
const { signTreeHead } = ((NS4 as any).default ?? NS4) as any;
import * as NS5 from '@atlasauth/pca-intent';
const { createLearner, deriveOmega, emitIntentMap, intentMapDigest, rng } = ((NS5 as any).default ?? NS5) as any;
import * as NS6 from '@atlasauth/pca-scitt';
const { verifyStatement, statementPayload } = ((NS6 as any).default ?? NS6) as any;
import * as NS7 from '@atlasauth/pca-wallet';
const { answerRef, signIntentAnswer, typedDigest } = ((NS7 as any).default ?? NS7) as any;
import * as NS8 from '@atlasauth/pca-evidence';
const { anchorCommit, buildEvidenceBundle, capOf, evidenceAnchorCommit, evidenceDigest, evidenceSignedStatement, runCli, verifyEvidenceBundle } = ((NS8 as any).default ?? NS8) as any;

// ---- the §4 walkthrough, with real keys and the core signers -----------------------------------------------------------

const INTENT_ANCHOR_LOG = 'pca-intent:v1';
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

const clone = <T>(v: T): T => JSON.parse(JSON.stringify(v)) as T;
const flip = (s: string): string => (s[0] === 'A' ? 'B' : 'A') + s.slice(1);
function strip(a: SignedIntentAnswer): Omit<SignedIntentAnswer, 'v' | 'kind' | 'signer' | 'alg' | 'sig'> {
  const { v: _v, kind: _k, signer: _s, alg: _a, sig: _g, ...rest } = a;
  return rest;
}

// ---- the oracle ----------------------------------------------------------------------------------------------------------------
import * as NS9 from './lib.mjs';
const { Oracle, refWrite } = ((NS9 as any).default ?? NS9) as any;

const o = new Oracle('evidence-java-extra2', 'tools/pca-audit/oracles/evidence-java-extra2.mts', 'TS-reference oracle for the dispute-evidence replay (verifyEvidenceBundle).');
type PortSpec = 'ok' | 'fail' | 'throws';
const port = (kind: PortSpec) => (): { ok: boolean; reason?: string } => {
  if (kind === 'throws') throw new Error('boom');
  return kind === 'ok' ? { ok: true } : { ok: false, reason: 'port refused' };
};
/** The JSON trust spec (what crosses the oracle) -> the reference's trust object: every verifiers.<name> is 'ok' | 'fail' | 'throws'. */
const mkTrust = (spec: any): EvidenceTrust => {
  const t: any = { ...spec };
  if (spec.verifiers) t.verifiers = Object.fromEntries(Object.entries(spec.verifiers).map(([k, v]) => [k, port(v as PortSpec)]));
  return t;
};
const runVerify = (bundle: any, spec: any) => verifyEvidenceBundle(bundle, mkTrust(spec));
let n = 0;
const run = (name: string, bundle: any, spec: any) => o.run('verifyEvidenceBundle', `${name}#${n++}`, runVerify, [bundle, spec]);
const specOf = (w: World, extra: any = {}) => ({ ...clone(w.trust), verifiers: { effect: 'ok' }, ...extra });

const w0 = walkthrough();
const T = specOf(w0);
await run('base', w0.bundle, T);
await run('no trust', w0.bundle, {});
await run('no trust only effect port', w0.bundle, { verifiers: { effect: 'ok' } });
{
  const b = clone(w0.bundle);
  delete b.statement.opening;
  delete b.maps[1]!.map;
  await run('unopened', b, T);
}

// ---- the tampering table (every artifact kind has a specific failing finding)
const WA = { credential_id: 'cred1', authenticator_data: Buffer.alloc(37, 1).toString('base64url'), client_data_json: Buffer.from('{"type":"webauthn.get"}').toString('base64url'), signature: Buffer.alloc(64, 2).toString('base64url') };
const cases: [string, (b: EvidenceBundle, w: World) => void][] = [
  ['answer signature byte', (b) => void (b.answers[2]!.sig = flip(b.answers[2]!.sig))],
  ['answer y flipped', (b) => void (b.answers.find((a) => a.question_id === 'q_1')!.y = 1)],
  ['answer from another session', (b, w) => void (b.answers[0] = signIntentAnswer({ ...strip(b.answers[0]!), session: hashCanonical('other') }, w.ana.secretKey))],
  ['answer by a non-principal', (b, w) => void (b.answers[0] = signIntentAnswer(strip(b.answers[0]!), w.agent.secretKey))],
  ['answer on an unknown map', (b, w) => void (b.answers[0] = signIntentAnswer({ ...strip(b.answers[0]!), map_digest: hashCanonical('nomap') }, w.ana.secretKey))],
  ['delta signature byte', (b) => void (b.deltas[0]!.sig = flip(b.deltas[0]!.sig))],
  ['delta caveat edited', (b) => void ((b.deltas[0]!.caveats.find((c) => c.type === 'envelope') as unknown as { predicates: { where: { value: number }[] }[] }).predicates[0]!.where[0]!.value = 90000)],
  ['session root edited', (b) => void (b.session_root.question_uri = 'https://evil.example/q')],
  ['session root signature byte', (b) => void (b.session_root.sig = flip(b.session_root.sig))],
  ['root grant signature byte', (b) => void (b.root_grant.sig = flip(b.root_grant.sig))],
  ['pcactn counter', (b) => void (b.pcactns[1]!.counter = 99)],
  ['pcactn signature byte', (b) => void (b.pcactns[0]!.sig = flip(b.pcactns[0]!.sig))],
  ['schema edited', (b) => void (b.schema.doc.version = '2026-12-01')],
  ['statement text', (b) => void (b.statement.opening!.text = 'Book anything.')],
  ['statement commit', (b) => void (b.statement.commit = hashCanonical('x'))],
  ['map metrics', (b) => void (b.maps[1]!.map!.metrics.residual_risk_ppm += 5000)],
  ['map commit', (b) => void (b.maps[0]!.commit = hashCanonical('other-map'))],
  ['effect overcharge', (b) => void (b.effects[0]!.charged = { amount: 80000, ref: 'action.params.total' })],
  ['effect params swapped', (b) => void (b.effects[0]!.params = { ...PARAMS_OK, total: 70000 })],
  ['effect params withheld', (b) => void delete b.effects[0]!.params],
  ['frame violation reported', (b) => void (b.effects[0]!.frame_violations = ['account.contact_email', 'a.b'])],
  ['accumulator post forged', (b) => void (b.accumulator.events[0]!.post = 70000)],
  ['undeclared accumulator', (b) => void (b.accumulator.events[0]!.acc = 'other')],
  ['canary summary forged', (b) => void (b.canaries = { asked: 0, false_yes: 0, false_no: 0 })],
  ['canary label missing', (b) => void (b.canary_labels = [])],
  ['revocation epoch root', (b) => void (b.revocation_epochs[0]!.epoch.root = hashCanonical('r'))],
  ['revocation list does not match the signed set', (b) => void (b.revocation_epochs[0]!.revoked = [])],
  ['revocation none', (b) => void (b.revocation_epochs = [])],
  ['anchor names another digest', (b) => void (b.anchors[0]!.digest = hashCanonical('d'))],
  ['anchor head signature', (b) => void (b.anchors[0]!.signed_tree_head.sig = flip(b.anchors[0]!.signed_tree_head.sig))],
  ['anchor removed', (b) => void (b.anchors = [])],
  ['schema anchor', (b) => void (b.schema.anchor = { log: 'l', index: 1, head: hashCanonical('x') } as any)],
  ['subject missing', (b) => void (b.subject.pcactn_digest = hashCanonical('nope'))],
  ['session root other session', (b) => void (b.subject.session = hashCanonical('other-session'))],
  ['subject aud', (b) => void (b.subject.aud = 'other.example')],
  ['receipts removed', (b) => void (b.accumulator.receipts = [])],
  ['events empty', (b) => void (b.accumulator.events = [])],
  ['event released', (b) => void (b.accumulator.events[0]!.status = 'released')],
  ['event reverted post', (b) => void ((b.accumulator.events[0]!.status = 'reverted'), (b.accumulator.events[0]!.post = 5))],
  ['event delta 0', (b) => void (b.accumulator.events[0]!.delta = 0)],
  ['consent removed', (b, w) => void (b.answers = b.answers.map((a) => (a.question_id === 'q_7Hk2' ? signIntentAnswer({ ...strip(a), ux: { tier: 'typed', rendered_digest: a.ux.rendered_digest, typed_digest: a.ux.typed_digest!, canary: false } }, w.ana.secretKey) : a)))],
  ['consent at tap tier', (b, w) => void (b.answers = b.answers.map((a) => (a.question_id === 'q_7Hk2' ? signIntentAnswer({ ...strip(a), ux: { ...a.ux, tier: 'tap', typed_digest: undefined } }, w.ana.secretKey) : a)))],
  ['typed value differs', (b, w) => void (b.answers = b.answers.map((a) => (a.question_id === 'q_7Hk2' ? signIntentAnswer({ ...strip(a), ux: { ...a.ux, typed_digest: typedDigest('q_7Hk2', '800') } }, w.ana.secretKey) : a)))],
  ['device tier unknown authenticator', (b, w) => void (b.answers = b.answers.map((a) => (a.question_id === 'q_7Hk2' ? signIntentAnswer({ ...strip(a), ux: { ...a.ux, tier: 'device', typed_digest: undefined, webauthn: WA } }, w.ana.secretKey) : a)))],
  ['partial yes', (b, w) => void (b.answers = b.answers.map((a) => (a.question_id === 'q_7Hk2' ? signIntentAnswer({ ...strip(a), ux: { tier: a.ux.tier, rendered_digest: a.ux.rendered_digest, typed_digest: a.ux.typed_digest, canary: false }, partial: { path: 'action.params.total', upTo: 50000 } } as any, w.ana.secretKey) : a)))],
  ['no deltas', (b) => void (b.deltas = [])],
  ['no pcactns', (b) => void (b.pcactns = [])],
  ['only attempt', (b) => void (b.pcactns = [b.pcactns[0]!])],
  ['revoked delta', (b, w) => {
    const rs = new RevocationSet([deltaRevocationId(w.D1.id)]);
    const ep = signRevocationEpoch(w.guardian.secretKey, { instance_id: 'atlas', grant_ref: sessionRevocationScope(w.session), epoch: rs.size, set_size: rs.size, root: rs.root, issued_at: T0 + 4600, not_after: T0 + 400_000 });
    b.revocation_epochs = [{ epoch: ep, revoked: rs.list() }];
  }],
];
for (const [name, mutate] of cases) {
  const w = walkthrough();
  const b = clone(w.bundle);
  mutate(b, w);
  await run(name, b, specOf(w));
}
// unknown members anywhere the bundle owns
for (const mutate of [
  (b: Record<string, unknown>) => void (b.extra = 1),
  (b: Record<string, unknown>) => void ((b.subject as Record<string, unknown>).note = 'x'),
  (b: Record<string, unknown>) => void ((b.canaries as Record<string, unknown>).trusted = true),
  (b: Record<string, unknown>) => void (((b.accumulator as { events: Record<string, unknown>[] }).events[0]!).claim = 1),
]) {
  const b = clone(w0.bundle) as unknown as Record<string, unknown>;
  mutate(b);
  await run('unknown member', b, T);
}
for (const bad of [null, 5, 'x', [], {}]) await run('not a bundle', bad, T);

// ---- trust variants
const tv: [string, any][] = [
  ['principals wrong', { principals: [{ key: encodeKey(seeded(9).publicKey) }] }],
  ['principals extra', { principals: [{ key: encodeKey(seeded(1).publicKey) }, { key: encodeKey(seeded(8).publicKey) }] }],
  ['principals pq mismatch', { principals: [{ key: encodeKey(seeded(1).publicKey), pq_pk: 'AAAA' }] }],
  ['principals empty', { principals: [] }],
  ['principals bad key', { principals: [{ key: 'short' }] }],
  ['principals unknown member', { principals: [{ key: encodeKey(seeded(1).publicKey), x: 1 }] }],
  ['principals not array', { principals: 'x' }],
  ['principals null', { principals: null }],
  ['acc foo', { acc: { foo: 1 } }], ['acc negative', { acc: { max_receipt_age_s: -1 } }], ['acc fraction', { acc: { max_receipt_age_s: 1.5 } }], ['acc string', { acc: { max_keyset_age_s: '10' } }], ['acc null', { acc: null }], ['acc array', { acc: [] }],
  ['acc receipt age 0', { acc: { max_receipt_age_s: 0 } }], ['acc receipt age big', { acc: { max_receipt_age_s: 100000 } }], ['acc keyset age 0', { acc: { max_keyset_age_s: 0 } }],
  ['minTier tap', { minTier: { 'air.book': 'tap' } }], ['minTier device', { minTier: { 'air.book': 'device' } }], ['minTier garbage', { minTier: { 'air.book': 'zzz' } }],
  ['jitTier device', { jitTier: 'device' }], ['jitTier tap', { jitTier: 'tap' }],
  ['typedValues missing', { typedValues: undefined }], ['typedValues wrong', { typedValues: { q_7Hk2: '999' } }],
  ['canaryLabels override', { canaryLabels: { q_c1: 1 } }], ['canaryLabels same', { canaryLabels: { q_c1: 0 } }],
  ['sessionRootDigest override', { sessionRootDigest: hashCanonical('other') }],
  ['no siteKeys', { siteKeys: undefined }], ['siteKeys other', { siteKeys: [{ kid: 'zzz', alg: 'ed25519', pk: encodeKey(seeded(3).publicKey) }] }],
  ['anchorGuardian wrong', { anchorGuardian: { public: encodeKey(seeded(6).publicKey), instance: 'atlas' } }], ['anchorGuardian instance', { anchorGuardian: { public: encodeKey(seeded(5).publicKey), instance: 'other' } }], ['no anchorGuardian', { anchorGuardian: undefined }],
  ['effect port fails', { verifiers: { effect: 'fail' } }], ['effect port throws', { verifiers: { effect: 'throws' } }],
  ['sessionRoot port ok', { verifiers: { effect: 'ok', sessionRoot: 'ok' } }], ['sessionRoot port fail', { verifiers: { effect: 'ok', sessionRoot: 'fail' } }], ['schema port fail', { verifiers: { effect: 'ok', schema: 'fail' } }], ['schema port ok no keys', { siteKeys: undefined, verifiers: { effect: 'ok', schema: 'ok' } }],
  ['receipt port ok', { verifiers: { effect: 'ok', receipt: 'ok' } }], ['receipt port fail', { verifiers: { effect: 'ok', receipt: 'fail' } }], ['verdict port', { verifiers: { effect: 'ok', verdict: 'ok' } }],
];
for (const [name, extra] of tv) await run('trust ' + name, w0.bundle, specOf(w0, extra));
{
  const w = walkthrough();
  const b = clone(w.bundle);
  b.answers = b.answers.map((a) => (a.question_id === 'q_7Hk2' ? signIntentAnswer({ ...strip(a), ux: { ...a.ux, tier: 'device', typed_digest: undefined, webauthn: WA } }, w.ana.secretKey) : a));
  const jwk = { kty: 'OKP', crv: 'Ed25519', x: encodeKey(seeded(60).publicKey) };
  await run('device known credential junk assertion', b, specOf(w, { credentials: { cred1: { publicKey: jwk, rpId: 'skyair.example', origins: ['https://skyair.example'] } } }));
  await run('device known credential signCount', b, specOf(w, { credentials: { cred1: { publicKey: jwk, rpId: 'skyair.example', origins: ['https://skyair.example'], signCount: 5 } } }));
  await run('device no rpId', b, specOf(w, { credentials: { cred1: { publicKey: jwk, rpId: '', origins: [] } } }));
}
const fake = walkthrough(77);
await run('fabricated no pins', fake.bundle, specOf(fake, { principals: undefined }));
await run('fabricated real pins', fake.bundle, specOf(fake, { principals: [{ key: encodeKey(seeded(1).publicKey) }] }));
await run('fabricated own pins', fake.bundle, specOf(fake, { principals: [{ key: encodeKey(seeded(77).publicKey) }] }));
// a PQ / hybrid session verifies only under the reader's pin
for (const s of ['hybrid-ed25519-ml-dsa-65'] as const) {
  const pw = walkthrough(1, { suite: s });
  await run(`pq ${s}`, pw.bundle, specOf(pw));
  await run(`pq ${s} pinned without pq`, pw.bundle, specOf(pw, { principals: [{ key: encodeKey(pw.ana.publicKey) }] }));
  await run(`pq ${s} no pins`, pw.bundle, specOf(pw, { principals: undefined }));
  await run(`pq ${s} wrong pq pin`, pw.bundle, specOf(pw, { principals: [{ key: encodeKey(pw.ana.publicKey), pq_pk: 'AAAA' }] }));
}
const forged = walkthrough(1, { suite: 'hybrid-ed25519-ml-dsa-65', pqSeed: 99 });
await run('pq forged own pq key', forged.bundle, specOf(forged));

// ---- delta chain variants
{
  const w = walkthrough();
  const mk = (cv: { session: string; seq: number; prev: string; root: string }, signer: KeyPair = w.ana) => sessionGrant(w, { ...cv, mapDigest: w.md[1], cap: 80000 }, signer);
  const D2 = mk({ session: w.session, seq: 2, prev: w.D1.id, root: w.sRef });
  const variants: Capability[][] = [
    [D2, w.D1],
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
    await run('deltas', b, specOf(w));
  }
  // canary claims and overspend
  for (const claim of [{ asked: 1, false_yes: 0, false_no: 0 }, { asked: 2, false_yes: 0, false_no: 0 }, { asked: 1, false_yes: 1, false_no: 0 }, { asked: 1, false_yes: 0, false_no: 1 }]) {
    const b = clone(w.bundle);
    b.canaries = claim;
    await run('canary claim', b, specOf(w));
  }
  {
    const b = clone(w.bundle);
    b.answers = b.answers.map((a) => (a.question_id === 'q_c1' ? signIntentAnswer({ ...strip(a), y: 1 }, w.ana.secretKey) : a));
    await run('canary wrong answer', b, specOf(w));
    b.canaries = { asked: 1, false_yes: 1, false_no: 0 };
    await run('canary wrong answer claimed', b, specOf(w));
  }
  for (const post of [30000, 40000, 40001, 70000, 77800, 80000, 80001, 120000]) {
    const b = clone(w.bundle);
    b.accumulator.events[0]!.post = post;
    b.effects[0]!.params = { ...PARAMS_OK, total: post };
    await run('overspend ' + post, b, specOf(w));
  }
  // a PCActn whose signed intent_session names another session
  const task = delegate(w.D1, encodeKey(w.agent.publicKey), [], w.ana.secretKey);
  const plan: PlanNode[] = [{ id: 'n1', verb: 'air.book', resource: 'skyair.example/bookings', params_digest: paramsDigest(PARAMS_OK), reversibility_class: 'irreversible' }];
  for (const [name, is] of [['other session', { session: hashCanonical('other'), root: w.sRef, seq: 1, schema: w.S.schema.digest }], ['other root', { session: w.session, root: hashCanonical('r'), seq: 1, schema: w.S.schema.digest }], ['other schema', { session: w.session, root: w.sRef, seq: 1, schema: hashCanonical('s') }], ['other seq', { session: w.session, root: w.sRef, seq: 0, schema: w.S.schema.digest }], ['good', { session: w.session, root: w.sRef, seq: 1, schema: w.S.schema.digest }]] as const) {
    const p = buildPCActn({ grant: w.D1, chain: [w.D1, task], plan, nodeId: 'n1', params: PARAMS_OK, counter: 4, signerSecret: w.agent.secretKey, aud: AUD, iat: T0 + 5500, exp: T0 + 600_000, intentSession: is as any });
    const b = clone(w.bundle);
    b.pcactns = [...b.pcactns, p];
    await run('intent_session ' + name, b, specOf(w));
  }
  // W-B artifacts under pinned keys
  const oracle = seeded(10), judge = seeded(11);
  const fact = signFact({ name: 'fare_quote', subject: 'OF-1', value: 38900, t_obs: T0 + 3000, oracle: 'quotes' }, oracle.secretKey);
  const verdict = signClassifierVerdict({ classifier: 'tone', session: w.session, content_digest: hashCanonical('msg'), label: 'neutral', measurement: 'm1' }, judge.secretKey);
  const offers = signOfferSet({ v: 1, kind: 'pca-offer-set', site: 'https://skyair.example', session: w.session, query: { from: 'SFO', to: 'JFK' }, rank: 'price_asc', complete: true, offers: [{ offer_id: 'OF-1', price: 38900 }, { offer_id: 'OF-2', price: 39800 }], issued_at: T0 + 3000, kid: KID }, w.site.secretKey);
  const labels = signLabels({ site: 'https://skyair.example', session: w.session, response_digest: hashCanonical('resp'), fields: { '/email': { class: 'pii.contact', value_digest: hashCanonical('e') } }, issued_at: T0 + 3000, kid: KID }, w.site.secretKey);
  const wb = clone(w.bundle);
  wb.facts = [fact];
  wb.classifier = [verdict];
  wb.offer_sets = [offers];
  wb.labels = [labels];
  const pins = { oracleKeys: { quotes: encodeKey(oracle.publicKey) }, judges: [encodeKey(judge.publicKey)] };
  await run('wb pinned', wb, specOf(w, pins));
  await run('wb unpinned', wb, specOf(w, { siteKeys: undefined }));
  await run('wb ports', wb, specOf(w, { verifiers: { effect: 'ok', fact: 'fail', classifier: 'ok', offerSet: 'throws', labels: 'fail', settlement: 'ok' } }));
  await run('wb wrong judge', wb, specOf(w, { oracleKeys: pins.oracleKeys, judges: [encodeKey(seeded(12).publicKey)] }));
  await run('wb labelKeys override', wb, specOf(w, { ...pins, labelKeys: [{ site: 'https://skyair.example', kid: KID, pk: encodeKey(w.site.publicKey) }] }));
  await run('wb labelKeys other site', wb, specOf(w, { ...pins, labelKeys: [{ site: 'https://other.example', kid: KID, pk: encodeKey(w.site.publicKey) }] }));
  const t = clone(wb);
  t.facts![0]!.value = 30000;
  t.classifier![0]!.label = 'hostile';
  t.offer_sets![0]!.offers[0]!.price = 100;
  t.labels![0]!.issued_at += 1;
  await run('wb tampered', t, specOf(w, pins));
  const other = clone(wb);
  other.classifier![0]!.session = hashCanonical('s2');
  other.offer_sets![0]!.session = hashCanonical('s2');
  other.labels![0]!.session = hashCanonical('s2');
  await run('wb other session', other, specOf(w, pins));
  const st = clone(w.bundle);
  st.settlements = [{ x: 1 }] as any;
  st.verdicts = [{ pcactn_digest: w.bundle.subject.pcactn_digest, verdict: 'ok' }] as any;
  await run('settlements and verdicts unverified', st, specOf(w));
  await run('settlements and verdicts ports', st, specOf(w, { verifiers: { effect: 'ok', settlement: 'ok', verdict: 'fail' } }));
}

// ---- receipts at admission time, key sets
{
  const w = walkthrough();
  const admitted = w.subject.iat;
  for (const issuedAt of [admitted - 1_000_000, admitted - 700_000, admitted - 10_000, admitted - 100, admitted + 120_000]) {
    const b = clone(w.bundle);
    b.accumulator.receipts = [reserve(w.session, w.subject, w.seqKey, issuedAt)];
    await run('receipt issued ' + (issuedAt - admitted), b, specOf(w));
  }
  { const b = clone(w.bundle); b.accumulator.receipts = [reserve(w.session, w.subject, seeded(99), admitted - 100)]; await run('receipt unlisted key', b, specOf(w)); }
  { const b = clone(w.bundle); b.accumulator.receipts = [{ ...clone(b.accumulator.receipts![0]!), acc: 'trip_spend' } as any]; await run('receipt unsequenced acc', b, specOf(w)); }
  { const b = clone(w.bundle); b.accumulator.holder = 'sequenced'; b.accumulator.receipts = []; await run('sequenced without receipts', b, specOf(w)); }
  { const b = clone(w.bundle); b.accumulator.receipts = [{ ...clone(b.accumulator.receipts![0]!), post: 5 } as any]; await run('receipt arithmetic', b, specOf(w)); }
  { const b = clone(w.bundle); b.accumulator.receipts = [{ ...clone(b.accumulator.receipts![0]!), session: hashCanonical('z') } as any]; await run('receipt other session', b, specOf(w)); }
  { const b = clone(w.bundle); b.accumulator.receipts = [{ ...clone(b.accumulator.receipts![0]!), pcactn_digest: hashCanonical('zz') } as any]; await run('receipt other pcactn', b, specOf(w)); }
  { const b = clone(w.bundle); delete b.effects[0]!.params; await run('receipt params withheld', b, specOf(w)); }
  const keySet = (version: number, issuedAt: number, keys: [string, KeyPair][], root: KeyPair = w.seqRoot) =>
    signSequencerKeySet({ v: 1, kind: 'pca-sequencer-keys', version, issued_at: issuedAt, keys: keys.map(([kid, k]) => ({ kid, pk: encodeKey(k.publicKey), not_before: T0 - 600_000 })) }, root.secretKey);
  const withSets = (sets: unknown[], receiptAt?: number) => {
    const b = clone(w.bundle);
    b.accumulator.sequencer_keys = sets;
    if (receiptAt !== undefined) b.accumulator.receipts = [reserve(w.session, w.subject, w.seqKey, receiptAt)];
    return b;
  };
  const k1 = ['k1', w.seqKey] as [string, KeyPair];
  await run('keysets monotone', withSets([keySet(1, T0, [k1]), keySet(2, T0 + 3000, [k1])]), specOf(w));
  await run('keysets rollback', withSets([keySet(2, T0, [k1]), keySet(1, T0 + 3000, [k1])]), specOf(w));
  await run('keysets superseded', withSets([keySet(1, T0, [k1]), keySet(2, T0 + 3000, [['k2', seeded(42)]])]), specOf(w));
  await run('keysets future', withSets([keySet(1, w.subject.iat + 120_000, [k1])]), specOf(w));
  await run('keysets rogue root', withSets([keySet(3, T0, [k1], seeded(43))]), specOf(w));
  await run('keysets equivocation', withSets([keySet(1, T0, [k1]), keySet(1, T0 + 1000, [k1, ['k2', seeded(44)]])]), specOf(w));
  await run('keysets equivocation later', withSets([keySet(1, T0 - 2000, [k1]), keySet(2, T0 - 1000, [k1]), keySet(2, T0, [k1, ['k3', seeded(45)]])]), specOf(w));
  { const a = keySet(1, T0, [k1]); await run('keysets duplicate', withSets([a, clone(a)]), specOf(w)); }
  await run('keysets lower later', withSets([keySet(2, T0, [k1]), keySet(1, T0 + 1000, [k1, ['k2', seeded(46)]])]), specOf(w));
  await run('keysets none', withSets([]), specOf(w));
  await run('keysets not objects', withSets([5, 'x', null]), specOf(w));
  const b10 = withSets([keySet(1, T0, [k1])], w.subject.iat - 10_000);
  for (const age of [10, 9, 11]) await run('receipt age ' + age, b10, specOf(w, { acc: { max_receipt_age_s: age } }));
  const bk = withSets([keySet(1, w.subject.iat - 5000, [k1])]);
  for (const age of [5, 4, 6]) await run('keyset age ' + age, bk, specOf(w, { acc: { max_keyset_age_s: age } }));
}

// ---- revocation chain
{
  const w = walkthrough();
  const X = 'pca-intent:session:someone-else', Y = 'pca-intent:map:some-other-map', Z = 'pca-intent:delta:some-other-delta';
  const epochOf = (ids: string[], issuedAt: number, signer: KeyPair = w.guardian, notAfter = issuedAt + 300_000) => {
    const rs = new RevocationSet(ids);
    const epoch = signRevocationEpoch(signer.secretKey, { instance_id: 'atlas', grant_ref: sessionRevocationScope(w.session), epoch: rs.size, set_size: rs.size, root: rs.root, issued_at: issuedAt, not_after: notAfter });
    return { epoch, revoked: rs.list() };
  };
  const chains: [string, any[]][] = [
    ['append-only', [epochOf([X], T0 + 3000), epochOf([X, Y], T0 + 4500)]],
    ['drops same size', [epochOf([X], T0 + 3000), epochOf([Y], T0 + 4500)]],
    ['drops larger', [epochOf([X], T0 + 3000), epochOf([Y, Z], T0 + 4500)]],
    ['rollback', [epochOf([X, Y], T0 + 3000), epochOf([X], T0 + 4500)]],
    ['drop after action', [epochOf([X], T0 + 4500), epochOf([Y], T0 + 9000)]],
    ['principal signer', [epochOf([X], T0 + 4500, w.ana)]],
    ['all after action', [epochOf([X], T0 + 9000)]],
    ['stale', [epochOf([X], T0 + 4500 - 61_000)]],
    ['expired not_after', [epochOf([X], T0 + 4500, w.guardian, T0 + 4501)]],
    ['revokes session', [epochOf(['pca-intent:session:' + w.session], T0 + 4500)]],
    ['revokes map', [epochOf(['pca-intent:map:' + w.md[0]], T0 + 4500)]],
    ['empty set', [epochOf([], T0 + 4500)]],
  ];
  for (const [name, ch] of chains) { const b = clone(w.bundle); b.revocation_epochs = ch; await run('revocation ' + name, b, specOf(w)); }
  { const b = clone(w.bundle); delete (b.session_root as any).revocation; await run('revocation authority absent', b, specOf(w)); }
}

// ---- anchors of every kind
{
  const w = walkthrough();
  const anchorKey = seeded(5);
  const mk = (kind: string, digest: string) => {
    const leaves = [hashCanonical('earlier-leaf'), anchorCommit(kind, digest)];
    const sth = signTreeHead(anchorKey.secretKey, { instance_id: 'atlas', principal: INTENT_ANCHOR_LOG, size: 2, root: merkleRoot(leaves), prev_root: '', timestamp: T0 + 6000 });
    return { kind, digest, index: 1, proof: merkleProof(leaves, 1), signed_tree_head: sth };
  };
  const ev = clone(w.bundle.anchors[0]!);
  const yes = w.bundle.answers.find((a) => a.question_id === 'q_7Hk2')!;
  const sets: [string, any[]][] = [
    ['all kinds', [ev, mk('statement', w.bundle.statement.commit), mk('map', w.md[0]), mk('schema', w.S.schema.digest), mk('observation', answerRef(yes))]],
    ['unknown kind', [ev, mk('weird', hashCanonical('q'))]],
    ['statement other', [ev, mk('statement', hashCanonical('q'))]],
    ['observation other', [ev, mk('observation', hashCanonical('q'))]],
    ['bad proof index', [{ ...clone(ev), proof: { ...clone(ev.proof), index: 0 } }]],
    ['bad proof size', [{ ...clone(ev), proof: { ...clone(ev.proof), size: 3 } }]],
    ['bad head principal', [(() => { const e = clone(ev); (e.signed_tree_head as any).principal = 'x'; return e; })()]],
  ];
  for (const [name, a] of sets) { const b = clone(w.bundle); b.anchors = a; await run('anchors ' + name, b, specOf(w)); }
}
refWrite(o, 'evidence-java-extra2');
