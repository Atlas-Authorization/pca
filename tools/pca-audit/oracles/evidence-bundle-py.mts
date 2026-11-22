// Oracle (Python lane): @atlasauth/pca-evidence verifyEvidenceBundle over the section 4 chargeback walkthrough (real Ed25519 keys and the core
// signers, all deterministic) and its tampered / re-trusted variants. The whole findings report, report_digest included, is compared.
// PORTING: verifyEvidenceBundle(bundle, trust) -> evidence.verify_evidence_bundle(bundle, trust); trust is the reference's EvidenceTrust as JSON
// except `verifiers`, whose members are constant descriptors {ok, reason?} (a port that returns that verdict). Writes out/ref-evidence-bundle-py.json.gz.
import * as C0 from '@atlasauth/pca';
import * as I0 from '@atlasauth/pca/ext/intent';
import * as L0 from '@atlasauth/pca/ext/ledger';
import * as N0 from '@atlasauth/pca-intent';
import * as W0 from '@atlasauth/pca-wallet';
import * as E0 from '@atlasauth/pca-evidence';
import { Oracle, refWrite } from './lib.mjs';

const d = (m: any) => m.default ?? m;
const C: any = d(C0), I: any = d(I0), L: any = d(L0), N: any = d(N0), W: any = d(W0), E: any = d(E0);
const o = new Oracle('evidence-bundle-py', 'tools/pca-audit/oracles/evidence-bundle-py.mts', 'TS-reference oracle for verifyEvidenceBundle (Python lane).');
const AUD = 'skyair.example', T0 = Date.UTC(2026, 10, 1, 12, 0, 0), KID = 'skyair-schema-2026';
const seeded = (n: number) => { const secretKey = new Uint8Array(32).map((_, i) => (n * 31 + i * 7 + 1) & 0xff); return { secretKey, publicKey: C.publicKeyOf(secretKey) }; };
const clone = (v: any) => JSON.parse(JSON.stringify(v));
const flip = (s: string) => (s[0] === 'A' ? 'B' : 'A') + s.slice(1);
const PARAMS_OK = { offer_id: 'OF-1', passengers: ['px_ana', 'px_sam'], total: 77800, add_ons: ['none'], payment_ref: 'pm_ana_visa', refundable: false };
const PARAMS_INJ = { offer_id: 'OF-2', passengers: ['px_ana', 'px_sam'], total: 85400, add_ons: ['tripshield'], payment_ref: 'pm_ana_visa', refundable: false };
const capPredicates = (cap: number) => [{ verb: 'air.book', resource: '*', where: [{ field: 'env.acc.trip_spend.post', op: 'lte', value: cap }] }];

function sessionGrant(w: any, a: any, signer: any = w.ana) {
  return I.mintSessionGrant({ principalSecret: signer.secretKey, principalPublic: C.encodeKey(signer.publicKey), holder: C.encodeKey(w.ana.publicKey), session: a.session, seq: a.seq, ...(a.prev !== undefined ? { prev: a.prev } : {}), root: a.root, mapDigest: a.mapDigest, predicates: capPredicates(a.cap), salt: `salt-${a.seq}` }).grant;
}
function emitAction(grant: any, holderSecret: Uint8Array, agentPub: string, params: any, counter: number, iat: number, agent: any, extra: any = {}) {
  const task = C.delegate(grant, agentPub, [], holderSecret);
  const plan = [{ id: 'n1', verb: 'air.book', resource: 'skyair.example/bookings', params_digest: C.paramsDigest(params), reversibility_class: 'irreversible' }];
  return C.buildPCActn({ grant, chain: [grant, task], plan, nodeId: 'n1', params, counter, signerSecret: agent.secretKey, aud: AUD, iat, exp: iat + 600_000, ...extra });
}
function mapPair(ref: string) {
  const omega = N.deriveOmega({ policies: [], slots: { verbs: ['stripe.refund'], constraints: [{ path: 'action.params.amount', max: 400 }, { path: 'action.params.amount', max: 800 }] } });
  const l = N.createLearner(omega, { nullMass: 0.05 });
  const m0 = N.emitIntentMap(l, ref);
  l.observe({ verb: 'stripe.refund', values: { 'action.params.amount': 401 } }, 1, 'elicitation');
  return [m0, N.emitIntentMap(l, ref)];
}
const reserve = (session: string, p: any, seqKey: any, issuedAt: number) => I.signAccReceipt(
  { v: 1, kind: 'pca-acc-receipt', session, acc: 'trip_budget', seq: 1, pre: 0, delta: 77800, post: 77800, pcactn_digest: I.pcactnReservationDigest(p), aud: AUD, issued_at: issuedAt, expires_at: issuedAt + 600_000, kid: 'k1', ledger: { index: 0, head: C.hashCanonical('seq-head') } },
  seqKey.secretKey,
);
const strip = (a: any) => { const { v, kind, signer, alg, sig, ...rest } = a; return rest; };

function walkthrough(principalSeed = 1): any {
  const ana = seeded(principalSeed), agent = seeded(2), site = seeded(3), guardian = seeded(4), anchorKey = seeded(5), seqRoot = seeded(6), seqKey = seeded(7);
  const anaPub = C.encodeKey(ana.publicKey), agentPub = C.encodeKey(agent.publicKey);
  const session = C.hashCanonical({ session: 'ana-sky-1' });
  const statement = I.signIntentStatement({ v: 1, text: 'Book me and Sam a one-way flight SFO to JFK on Nov 20, under $400.', slots: {}, sources: [], created_at: T0, nonce: 'n-1' }, ana.secretKey);
  const ref = I.intentRef(statement);
  const [map0, map1] = mapPair(ref);
  const md = [N.intentMapDigest(map0), N.intentMapDigest(map1)];
  const schemaDoc = I.signActionSchema({
    v: 1, kind: 'pca-action-schema', site: 'https://skyair.example', aud: AUD, version: '2026-10-01',
    units: { usd_cents: { kind: 'money', currency: 'USD', exponent: 2 } },
    verbs: [{ verb: 'air.book', kind: 'write', reversibility: 'irreversible', params: {
      'action.params.offer_id': { type: 'string', semantic: 'product.ref', sensitivity: 'material' },
      'action.params.passengers': { type: 'array', semantic: 'person.identity', sensitivity: 'critical' },
      'action.params.total': { type: 'integer', unit: 'usd_cents', min: 0, max: 5_000_000, semantic: 'money.amount', sensitivity: 'critical', accumulates_into: ['spend.usd_cents'] },
      'action.params.add_ons': { type: 'set', values: ['none', 'tripshield', 'seat_plus', 'bag'], semantic: 'product.addon', sensitivity: 'material' },
      'action.params.payment_ref': { type: 'string', semantic: 'credential.payment_ref', sensitivity: 'critical' },
      'action.params.refundable': { type: 'boolean', semantic: 'flag', sensitivity: 'material' },
    } }],
  }, KID, site.secretKey);
  const S = I.signSessionRoot({
    v: 1, kind: 'pca-intent-session', session, principals: [{ key: anaPub }], intent_ref: ref, schema: { aud: AUD, digest: I.actionSchemaDigest(schemaDoc) }, layers: { task: { map_digest: md[0] } },
    accumulators: [
      { id: 'trip_spend', agg: 'sum', val: 'action.params.total', unit: 'usd_cents', sel: { verbs: ['air.book'] }, win: { kind: 'task' }, key: null, domain_max: 500000, holder: { kind: 'site_local' } },
      { id: 'trip_budget', agg: 'sum', val: 'action.params.total', unit: 'usd_cents', sel: { verbs: ['air.book'] }, win: { kind: 'task' }, key: null, holder: { kind: 'sequenced', uri: 'https://seq.example', root: C.encodeKey(seqRoot.publicKey) } },
    ],
    monitors: [], question_uri: `https://atlas.example/v1/pca/intent/sessions/${session}/questions`,
    revocation: { epoch_uri: 'https://atlas.example/v1/pca/revocation/ana', max_age_s: 60, key: C.encodeKey(guardian.publicKey) }, expires_at: T0 + 86_400_000,
  }, ana.secretKey);
  const sRef = I.sessionRootDigest(S);
  const w: any = { ana, agent, site, guardian, seqRoot, seqKey, S, sRef, session, md };
  const G0 = sessionGrant(w, { session, seq: 0, root: sRef, mapDigest: md[0], cap: 40000 });
  const D1 = sessionGrant(w, { session, seq: 1, prev: G0.id, root: sRef, mapDigest: md[1], cap: 80000 });
  const attempt1 = emitAction(G0, ana.secretKey, agentPub, PARAMS_INJ, 1, T0 + 1000, agent);
  const subject = emitAction(D1, ana.secretKey, agentPub, PARAMS_OK, 3, T0 + 5000, agent);
  const sd = C.pcactnDigest(subject), ad = I.intentActionDigest(subject.action);
  const ans = (x: any) => W.signIntentAnswer(x, ana.secretKey);
  const veto = ans({ map_digest: md[0], session, question_id: 'q_1', verb: 'air.book', cell: { trip_spend: [4, 4], 'action.params.add_ons': ['tripshield'] }, y: 0, source: 'elicitation', observed_at: T0 + 2000, ux: { tier: 'typed', rendered_digest: C.hashCanonical('card-1'), canary: false } });
  const canary = ans({ map_digest: md[0], session, question_id: 'q_c1', verb: 'air.book', cell: { trip_spend: [4, 4], 'action.params.add_ons': ['none'] }, y: 0, source: 'elicitation', observed_at: T0 + 2500, ux: { tier: 'hold', rendered_digest: C.hashCanonical('card-c'), canary: true } });
  const yes = ans({ map_digest: md[1], session, question_id: 'q_7Hk2', verb: 'air.book', cell: { trip_spend: [2, 3], 'action.params.add_ons': ['none'] }, y: 1, source: 'elicitation', observed_at: T0 + 4000,
    ux: { tier: 'typed', rendered_digest: C.hashCanonical('card-2'), typed_digest: W.typedDigest('q_7Hk2', '778'), canary: false, action_digest: ad, consent_for_action: true } });
  const rs = new C.RevocationSet(['pca-intent:session:someone-else']);
  const epoch = C.signRevocationEpoch(guardian.secretKey, { instance_id: 'atlas', grant_ref: I.sessionRevocationScope(session), epoch: rs.size, set_size: rs.size, root: rs.root, issued_at: T0 + 4500, not_after: T0 + 4500 + 300_000 });
  const keySet = I.signSequencerKeySet({ v: 1, kind: 'pca-sequencer-keys', version: 1, issued_at: T0, keys: [{ kid: 'k1', pk: C.encodeKey(seqKey.publicKey), not_before: T0 - 600_000 }] }, seqRoot.secretKey);
  const receipt = reserve(session, subject, seqKey, T0 + 4800);
  const bundle = E.buildEvidenceBundle({
    subject: { pcactn_digest: sd, aud: AUD, session }, statement: { commit: ref, opening: statement }, session_root: S, schema: { doc: schemaDoc }, root_grant: G0,
    maps: [{ seq: 0, commit: md[0], map: map0 }, { seq: 1, commit: md[1], map: map1 }], answers: [veto, canary, yes], canary_labels: [{ question_id: 'q_c1', label: 0 }],
    canaries: { asked: 1, false_yes: 0, false_no: 0 }, deltas: [D1], pcactns: [attempt1, subject], verdicts: [],
    accumulator: { holder: 'site_local', events: [{ acc: 'trip_spend', post: 77800, pcactn_digest: sd, delta: 1, status: 'committed' }], receipts: [receipt], sequencer_keys: [keySet] },
    effects: [{ pcactn_digest: sd, params: PARAMS_OK, charged: { amount: 77800, ref: 'action.params.total' }, frame_violations: [] }],
    revocation_epochs: [{ epoch, revoked: rs.list() }], anchors: [],
  });
  const digest = E.evidenceDigest(bundle);
  const leaves = [C.hashCanonical('earlier-leaf'), E.evidenceAnchorCommit(digest)];
  const sth = L.signTreeHead(anchorKey.secretKey, { instance_id: 'atlas', principal: I.INTENT_ANCHOR_LOG, size: 2, root: C.merkleRoot(leaves), prev_root: '', timestamp: T0 + 6000 });
  bundle.anchors = [{ kind: 'evidence', digest, index: 1, proof: C.merkleProof(leaves, 1), signed_tree_head: sth }];
  const trust = {
    principals: [{ key: C.encodeKey(seeded(1).publicKey) }], siteKeys: [I.actionSchemaKeyOf(KID, site.secretKey)], minTier: { 'air.book': 'typed' }, typedValues: { q_7Hk2: '778' },
    anchorGuardian: { public: C.encodeKey(anchorKey.publicKey), instance: 'atlas' }, verifiers: { effect: { ok: true } },
  };
  return { ...w, bundle: clone(bundle), trust: clone(trust), G0, D1, subject, md, map0, map1, statement, ans, strip };
}

const portsOf = (v: any) => (v === undefined || v === null ? v : Object.fromEntries(Object.entries(v).map(([k, x]) => [k, () => x])));
const verify = async (b: any, t: any) => E.verifyEvidenceBundle(b, t === null ? undefined : { ...t, ...(t.verifiers !== undefined ? { verifiers: portsOf(t.verifiers) } : {}) });
let n = 0;
const add = (name: string, b: any, t: any) => o.run('verifyEvidenceBundle', `${name}#${n++}`, verify, [b, t]);
const w = walkthrough();
const base = () => clone(w.bundle), tr = (over: any = {}) => ({ ...clone(w.trust), ...over });
const mut = async (name: string, f: (b: any) => void, t: any = tr()) => { const b = base(); f(b); await add(name, b, t); };

await add('walkthrough', base(), tr());
await add('no trust', base(), {});
await add('undefined trust', base(), null);
await add('no principals', base(), (({ principals, ...r }) => r)(tr()));
await mut('statement unopened + map unrevealed', (b) => { delete b.statement.opening; delete b.maps[1].map; });
for (let mask = 0; mask < 16; mask += 3) await mut(`withhold ${mask}`, (b) => {
  if (mask & 1) delete b.statement.opening;
  if (mask & 2) delete b.maps.find((m: any) => m.seq === 0).map;
  if (mask & 4) delete b.maps.find((m: any) => m.seq === 1).map;
  if (mask & 8) for (const e of b.effects) delete e.params;
});

const anaS = w.ana.secretKey, sign = (a: any) => W.signIntentAnswer(a, anaS);
const tamper: [string, (b: any) => void][] = [
  ['answer sig byte', (b) => { b.answers[2].sig = flip(b.answers[2].sig); }],
  ['answer y flipped', (b) => { b.answers.find((a: any) => a.question_id === 'q_1').y = 1; }],
  ['answer other session', (b) => { b.answers[0] = sign({ ...w.strip(b.answers[0]), session: C.hashCanonical('other') }); }],
  ['answer by non-principal', (b) => { b.answers[0] = W.signIntentAnswer(w.strip(b.answers[0]), w.agent.secretKey); }],
  ['answer unknown map', (b) => { b.answers[0] = sign({ ...w.strip(b.answers[0]), map_digest: C.hashCanonical('nomap') }); }],
  ['delta sig byte', (b) => { b.deltas[0].sig = flip(b.deltas[0].sig); }],
  ['delta caveat edited', (b) => { b.deltas[0].caveats.find((c: any) => c.type === 'envelope').predicates[0].where[0].value = 90000; }],
  ['session root edited', (b) => { b.session_root.question_uri = 'https://evil.example/q'; }],
  ['session root sig', (b) => { b.session_root.sig = flip(b.session_root.sig); }],
  ['root grant sig', (b) => { b.root_grant.sig = flip(b.root_grant.sig); }],
  ['pcactn counter', (b) => { b.pcactns[1].counter = 99; }],
  ['pcactn sig', (b) => { b.pcactns[0].sig = flip(b.pcactns[0].sig); }],
  ['schema edited', (b) => { b.schema.doc.version = '2026-12-01'; }],
  ['schema anchor', (b) => { b.schema.anchor = { log: 'l', index: 1 }; }],
  ['statement text', (b) => { b.statement.opening.text = 'Book anything.'; }],
  ['statement commit', (b) => { b.statement.commit = C.hashCanonical('x'); }],
  ['map metrics', (b) => { b.maps[1].map.metrics.residual_risk_ppm += 5000; }],
  ['map commit', (b) => { b.maps[0].commit = C.hashCanonical('other-map'); }],
  ['effect overcharge', (b) => { b.effects[0].charged = { amount: 80000, ref: 'action.params.total' }; }],
  ['effect charged ref', (b) => { b.effects[0].charged = { amount: 1, ref: 'action.params.nope' }; }],
  ['effect params swapped', (b) => { b.effects[0].params = { ...PARAMS_OK, total: 70000 }; }],
  ['effect no pcactn', (b) => { b.effects[0].pcactn_digest = C.hashCanonical('zz'); }],
  ['frame violation', (b) => { b.effects[0].frame_violations = ['b.x', 'a.y']; }],
  ['acc post forged', (b) => { b.accumulator.events[0].post = 70000; }],
  ['acc undeclared', (b) => { b.accumulator.events[0].acc = 'other'; }],
  ['acc delta other', (b) => { b.accumulator.events[0].delta = 0; }],
  ['acc event released', (b) => { b.accumulator.events[0].status = 'released'; }],
  ['acc unknown pcactn', (b) => { b.accumulator.events[0].pcactn_digest = C.hashCanonical('np'); }],
  ['canary summary forged', (b) => { b.canaries = { asked: 0, false_yes: 0, false_no: 0 }; }],
  ['canary label missing', (b) => { b.canary_labels = []; }],
  ['canary wrong answer', (b) => { b.answers = b.answers.map((a: any) => (a.question_id === 'q_c1' ? sign({ ...w.strip(a), y: 1 }) : a)); }],
  ['revocation epoch root', (b) => { b.revocation_epochs[0].epoch.root = C.hashCanonical('r'); }],
  ['revocation list', (b) => { b.revocation_epochs[0].revoked = []; }],
  ['revocation none', (b) => { b.revocation_epochs = []; }],
  ['anchor other digest', (b) => { b.anchors[0].digest = C.hashCanonical('d'); }],
  ['anchor head sig', (b) => { b.anchors[0].signed_tree_head.sig = flip(b.anchors[0].signed_tree_head.sig); }],
  ['anchors none', (b) => { b.anchors = []; }],
  ['anchor kind statement', (b) => { b.anchors.push({ ...b.anchors[0], kind: 'statement', digest: b.statement.commit }); }],
  ['consent removed', (b) => { b.answers = b.answers.map((a: any) => (a.question_id === 'q_7Hk2' ? sign({ ...w.strip(a), ux: { tier: 'typed', rendered_digest: a.ux.rendered_digest, typed_digest: a.ux.typed_digest, canary: false } }) : a)); }],
  ['consent tap', (b) => { b.answers = b.answers.map((a: any) => (a.question_id === 'q_7Hk2' ? sign({ ...w.strip(a), ux: { ...a.ux, tier: 'tap', typed_digest: undefined } }) : a)); }],
  ['typed value differs', (b) => { b.answers = b.answers.map((a: any) => (a.question_id === 'q_7Hk2' ? sign({ ...w.strip(a), ux: { ...a.ux, typed_digest: W.typedDigest('q_7Hk2', '800') } }) : a)); }],
  ['partial answer', (b) => { b.answers = b.answers.map((a: any) => (a.question_id === 'q_1' ? sign({ ...w.strip(a), y: 1, ux: { tier: 'hold', rendered_digest: a.ux.rendered_digest, canary: false, hold_ms: 2500 }, partial: { path: 'action.params.total', upTo: 5 } }) : a)); }],
  ['subject missing', (b) => { b.subject.pcactn_digest = C.hashCanonical('nope'); }],
  ['subject aud', (b) => { b.subject.aud = 'other.example'; }],
  ['subject session', (b) => { b.subject.session = C.hashCanonical('other'); }],
  ['no receipts', (b) => { delete b.accumulator.receipts; }],
  ['sequenced no receipts', (b) => { b.accumulator.holder = 'sequenced'; b.accumulator.receipts = []; }],
  ['no key sets', (b) => { delete b.accumulator.sequencer_keys; }],
  ['pcactns none', (b) => { b.pcactns = []; }],
  ['pcactn no chain', (b) => { b.pcactns[1].cap_chain = []; }],
  ['pcactn root other', (b) => { b.pcactns[1].cap_chain[0] = clone(w.G0); }],
  ['extra member', (b) => { b.extra = 1; }],
  ['subject note', (b) => { b.subject.note = 'x'; }],
  ['canaries trusted', (b) => { b.canaries.trusted = true; }],
  ['event claim', (b) => { b.accumulator.events[0].claim = 1; }],
  ['bad kind', (b) => { b.kind = 'x'; }],
  ['no maps array', (b) => { b.maps = {}; }],
];
for (const [name, f] of tamper) await mut(`tamper/${name}`, f);

// trust variants over the intact bundle
const T = (over: any) => tr(over);
await add('trust/no siteKeys', base(), (({ siteKeys, ...r }) => r)(tr()));
await add('trust/empty siteKeys', base(), tr({ siteKeys: [] }));
await add('trust/minTier device', base(), tr({ minTier: { 'air.book': 'device' } }));
await add('trust/minTier tap', base(), tr({ minTier: { 'air.book': 'tap' } }));
await add('trust/jitTier device', base(), tr({ jitTier: 'device' }));
await add('trust/typedValues wrong', base(), tr({ typedValues: { q_7Hk2: '779' } }));
await add('trust/typedValues none', base(), tr({ typedValues: {} }));
await add('trust/canaryLabels override', base(), tr({ canaryLabels: { q_c1: 1 } }));
await add('trust/sessionRootDigest', base(), tr({ sessionRootDigest: C.hashCanonical('x') }));
await add('trust/principals other', base(), tr({ principals: [{ key: C.encodeKey(seeded(9).publicKey) }] }));
await add('trust/principals extra', base(), tr({ principals: [{ key: C.encodeKey(seeded(1).publicKey) }, { key: C.encodeKey(seeded(9).publicKey) }] }));
await add('trust/principals pq pin', base(), tr({ principals: [{ key: C.encodeKey(seeded(1).publicKey), pq_pk: 'AAAA' }] }));
for (const p of [[], 'x', [{}], [{ key: 'AAAA' }], [{ key: C.encodeKey(seeded(1).publicKey), extra: 1 }], [{ key: C.encodeKey(seeded(1).publicKey), pq_pk: '+/' }]]) await add(`trust/principals bad ${JSON.stringify(p).slice(0, 30)}`, base(), tr({ principals: p }));
for (const acc of [{ max_receipt_age_s: 10 }, { max_receipt_age_s: 9 }, { max_keyset_age_s: 5 }, { max_keyset_age_s: 4 }, {}, { foo: 1 }, { max_receipt_age_s: -1 }, { max_receipt_age_s: 1.5 }, { max_keyset_age_s: '10' }, null, []]) await add(`trust/acc ${JSON.stringify(acc)}`, base(), tr({ acc }));
await add('trust/anchorGuardian other instance', base(), tr({ anchorGuardian: { ...w.trust.anchorGuardian, instance: 'other' } }));
await add('trust/anchorGuardian other key', base(), tr({ anchorGuardian: { ...w.trust.anchorGuardian, public: C.encodeKey(seeded(50).publicKey) } }));
await add('trust/no anchorGuardian', base(), (({ anchorGuardian, ...r }) => r)(tr()));
for (const [k, v] of [['sessionRoot', { ok: true }], ['schema', { ok: false, reason: 'revoked site key' }], ['receipt', { ok: false }], ['effect', { ok: false, reason: 'bad' }], ['verdict', { ok: true }], ['settlement', { ok: true }]] as any[]) {
  const b = base();
  if (k === 'sessionRoot') b.session_root.question_uri = 'https://evil.example/q';
  if (k === 'verdict') b.verdicts = [{ pcactn_digest: w.bundle.subject.pcactn_digest, allow: true }];
  if (k === 'settlement') b.settlements = [{ id: 's1' }];
  await add(`port/${k}`, b, tr({ verifiers: { ...w.trust.verifiers, [k]: v } }));
}
await add('port/none', base(), tr({ verifiers: {} }));

// W-B artifacts
{
  const oracle = seeded(10), judge = seeded(11);
  const fact = I.signFact({ name: 'fare_quote', subject: 'OF-1', value: 38900, t_obs: T0 + 3000, oracle: 'quotes' }, oracle.secretKey);
  const verdict = I.signClassifierVerdict({ classifier: 'tone', session: w.session, content_digest: C.hashCanonical('msg'), label: 'neutral', measurement: 'm1' }, judge.secretKey);
  const offers = I.signOfferSet({ v: 1, kind: 'pca-offer-set', site: 'https://skyair.example', session: w.session, query: { from: 'SFO', to: 'JFK' }, rank: 'price_asc', complete: true, offers: [{ offer_id: 'OF-1', price: 38900 }, { offer_id: 'OF-2', price: 39800 }], issued_at: T0 + 3000, kid: KID }, w.site.secretKey);
  const labels = I.signLabels({ site: 'https://skyair.example', session: w.session, response_digest: C.hashCanonical('resp'), fields: { '/email': { class: 'pii.contact', value_digest: C.hashCanonical('e') } }, issued_at: T0 + 3000, kid: KID }, w.site.secretKey);
  const wbB = () => { const b = base(); b.facts = [fact]; b.classifier = [verdict]; b.offer_sets = [offers]; b.labels = [labels]; return b; };
  const keys = { oracleKeys: { quotes: C.encodeKey(oracle.publicKey) }, judges: [C.encodeKey(judge.publicKey)] };
  await add('wb/pinned', wbB(), tr(keys));
  await add('wb/unpinned', wbB(), (({ siteKeys, ...r }) => r)(tr()));
  await add('wb/no keys', wbB(), tr());
  const t = wbB();
  t.facts[0].value = 30000; t.classifier[0].label = 'hostile'; t.offer_sets[0].offers[0].price = 100; t.labels[0].issued_at += 1;
  await add('wb/tampered', t, tr(keys));
  const o2 = wbB(); o2.classifier[0].session = C.hashCanonical('other'); o2.offer_sets[0].session = C.hashCanonical('other'); o2.labels[0].session = C.hashCanonical('other');
  await add('wb/other session', o2, tr(keys));
  await add('wb/judge not pinned', wbB(), tr({ ...keys, judges: [] }));
  await add('wb/labelKeys', wbB(), tr({ ...keys, labelKeys: [{ site: 'https://skyair.example', kid: KID, pk: I.actionSchemaKeyOf(KID, w.site.secretKey).pk }] }));
  await add('wb/labelKeys empty', wbB(), tr({ ...keys, labelKeys: [] }));
}

// delta chains, receipts, key sets, revocation epochs, another bundle
{
  const mk = (cv: any, signer: any = w.ana) => sessionGrant(w, { ...cv, mapDigest: w.md[1], cap: 80000 }, signer);
  const D2 = mk({ session: w.session, seq: 2, prev: w.D1.id, root: w.sRef });
  const dv: [string, any[]][] = [
    ['ok D2 D1', [D2, w.D1]], ['other session', [mk({ session: C.hashCanonical('other'), seq: 1, prev: w.G0.id, root: w.sRef })]], ['other root', [mk({ session: w.session, seq: 1, prev: w.G0.id, root: C.hashCanonical('r') })]],
    ['gap', [mk({ session: w.session, seq: 2, prev: w.G0.id, root: w.sRef })]], ['dup', [w.D1, mk({ session: w.session, seq: 1, prev: w.G0.id, root: w.sRef })]], ['broken prev', [w.D1, mk({ session: w.session, seq: 2, prev: w.G0.id, root: w.sRef })]],
    ['agent signed', [mk({ session: w.session, seq: 1, prev: w.G0.id, root: w.sRef }, w.agent)]], ['no deltas', []],
  ];
  for (const [name, deltas] of dv) await mut(`deltas/${name}`, (b) => { b.deltas = deltas; });
  const X = 'pca-intent:session:someone-else', Y = 'pca-intent:map:some-other-map', Z = 'pca-intent:delta:some-other-delta';
  const epochOf = (ids: string[], issuedAt: number, signer: any = w.guardian) => {
    const rs = new C.RevocationSet(ids);
    return { epoch: C.signRevocationEpoch(signer.secretKey, { instance_id: 'atlas', grant_ref: I.sessionRevocationScope(w.session), epoch: rs.size, set_size: rs.size, root: rs.root, issued_at: issuedAt, not_after: issuedAt + 300_000 }), revoked: rs.list() };
  };
  const ev: [string, any[]][] = [
    ['append-only', [epochOf([X], T0 + 3000), epochOf([X, Y], T0 + 4500)]], ['drop same size', [epochOf([X], T0 + 3000), epochOf([Y], T0 + 4500)]], ['drop larger', [epochOf([X], T0 + 3000), epochOf([Y, Z], T0 + 4500)]],
    ['rollback', [epochOf([X, Y], T0 + 3000), epochOf([X], T0 + 4500)]], ['drop after action', [epochOf([X], T0 + 4500), epochOf([Y], T0 + 9000)]], ['all after action', [epochOf([X], T0 + 9000)]],
    ['principal signed', [epochOf([X], T0 + 4500, w.ana)]], ['revoked delta', [epochOf([C.hashCanonical('x') && I.deltaRevocationId(w.D1.id)], T0 + 4600)]], ['revoked session', [epochOf([I.sessionRevocationId(w.session)], T0 + 4600)]],
    ['revoked map', [epochOf([I.mapRevocationId(w.md[0])], T0 + 4600)]], ['stale epoch', [epochOf([X], T0 - 400_000)]],
  ];
  for (const [name, epochs] of ev) await mut(`revocation/${name}`, (b) => { b.revocation_epochs = epochs; });
  const ks = (version: number, issuedAt: number, keys: [string, any][], signer: any = w.seqRoot) => I.signSequencerKeySet({ v: 1, kind: 'pca-sequencer-keys', version, issued_at: issuedAt, keys: keys.map(([kid, k]) => ({ kid, pk: C.encodeKey(k.publicKey), not_before: T0 - 600_000 })) }, signer.secretKey);
  const k1 = (v: number, at: number) => ks(v, at, [['k1', w.seqKey]]);
  const sets: [string, any[], number?][] = [
    ['monotone', [k1(1, T0), k1(2, T0 + 3000)]], ['rollback', [k1(2, T0), k1(1, T0 + 3000)]], ['superseded', [k1(1, T0), ks(2, T0 + 3000, [['k2', seeded(42)]])]], ['issued after admission', [k1(1, w.subject.iat + 120_000)]],
    ['rogue root', [ks(3, T0, [['k1', w.seqKey]], seeded(43))]], ['equivocation', [k1(1, T0), ks(1, T0 + 1000, [['k1', w.seqKey], ['k2', seeded(44)]])]],
    ['equivocation later', [k1(1, T0 - 2000), k1(2, T0 - 1000), ks(2, T0, [['k1', w.seqKey], ['k3', seeded(45)]])]], ['duplicate', [k1(1, T0), k1(1, T0)]],
    ['lower later', [k1(2, T0), ks(1, T0 + 1000, [['k1', w.seqKey], ['k2', seeded(46)]])]], ['age 10', [k1(1, T0)], w.subject.iat - 10_000], ['age 9', [k1(1, T0)], w.subject.iat - 9_000],
    ['keyset age', [k1(1, w.subject.iat - 5000)]], ['junk', [{ a: 1 }, 5]],
  ];
  for (const [name, s, at] of sets) for (const acc of [undefined, { max_receipt_age_s: 10 }, { max_keyset_age_s: 5 }, { max_keyset_age_s: 4 }]) {
    await mut(`keysets/${name}/${JSON.stringify(acc)}`, (b) => { b.accumulator.sequencer_keys = s; if (at !== undefined) b.accumulator.receipts = [reserve(w.session, w.subject, w.seqKey, at)]; }, tr(acc ? { acc } : {}));
  }
  for (const [name, issuedAt] of [['fresh', w.subject.iat - 200], ['stale', w.subject.iat - 1_000_000], ['stale2', w.subject.iat - 700_000], ['future', w.subject.iat + 120_000]] as any[]) await mut(`receipt/${name}`, (b) => { b.accumulator.receipts = [reserve(w.session, w.subject, w.seqKey, issuedAt)]; });
  await mut('receipt/unlisted key', (b) => { b.accumulator.receipts = [reserve(w.session, w.subject, seeded(99), w.subject.iat - 100)]; });
  await mut('receipt/not sequenced', (b) => { b.accumulator.receipts = [{ v: 1, kind: 'pca-acc-receipt', session: w.session, acc: 'trip_spend', seq: 1, pre: 0, delta: 77800, post: 77800, pcactn_digest: C.hashCanonical('x'), aud: AUD, issued_at: T0, expires_at: T0 + 60_000, kid: 'g', ledger: { index: 0, head: C.hashCanonical('h') }, signer: C.encodeKey(w.site.publicKey), sig: 'AA' }]; });
  await mut('receipt/withheld params', (b) => { for (const e of b.effects) delete e.params; });
  // a PCActn whose signed intent_session names another session / a wrong seq / unmatched claim
  const task = C.delegate(w.D1, C.encodeKey(w.agent.publicKey), [], w.ana.secretKey);
  const plan = [{ id: 'n1', verb: 'air.book', resource: 'skyair.example/bookings', params_digest: C.paramsDigest(PARAMS_OK), reversibility_class: 'irreversible' }];
  const sessionP = (intentSession: any, counter: number) => C.buildPCActn({ grant: w.D1, chain: [w.D1, task], plan, nodeId: 'n1', params: PARAMS_OK, counter, signerSecret: w.agent.secretKey, aud: AUD, iat: T0 + 5500, exp: T0 + 600_000, intentSession });
  const sch = w.S.schema.digest;
  const isv: [string, any][] = [['other session', { session: C.hashCanonical('other'), root: w.sRef, seq: 1, schema: sch }], ['other root', { session: w.session, root: C.hashCanonical('r'), seq: 1, schema: sch }],
    ['other schema', { session: w.session, root: w.sRef, seq: 1, schema: C.hashCanonical('s') }], ['wrong seq', { session: w.session, root: w.sRef, seq: 0, schema: sch }], ['ok', { session: w.session, root: w.sRef, seq: 1, schema: sch }],
    ['acc claim', { session: w.session, root: w.sRef, seq: 1, schema: sch, acc: [{ id: 'trip_spend', post: 77800 }] }]];
  for (const [name, is] of isv) await mut(`intent_session/${name}`, (b) => { b.pcactns = [...b.pcactns, clone(sessionP(is, 4))]; });
  // the subject carrying an intent_session claim bound to the accumulator event
  const subj2 = sessionP({ session: w.session, root: w.sRef, seq: 1, schema: sch, acc: [{ id: 'trip_spend', post: 77800 }] }, 5);
  await mut('intent_session/subject', (b) => { b.pcactns = [subj2]; b.subject.pcactn_digest = C.pcactnDigest(subj2); b.accumulator.events[0].pcactn_digest = C.pcactnDigest(subj2); b.effects[0].pcactn_digest = C.pcactnDigest(subj2); b.accumulator.receipts = [reserve(w.session, subj2, w.seqKey, T0 + 5400)]; });
  // an overspend that stays arithmetically consistent
  for (const post of [40001, 60000, 80000, 80001, 120000]) await mut(`overspend/${post}`, (b) => { b.accumulator.events[0].post = post; b.effects[0].params = { ...PARAMS_OK, total: post }; });
  // a fabricated, self-consistent bundle against the real pins and without pins
  const fake = walkthrough(77);
  await add('fabricated/no pins', clone(fake.bundle), (({ principals, ...r }) => r)(clone(fake.trust)));
  await add('fabricated/real pins', clone(fake.bundle), tr());
  await add('fabricated/own pins', clone(fake.bundle), clone(fake.trust));
  await add('malformed/null bundle', null, tr());
  await add('malformed/string bundle', 'x', tr());
  await add('malformed/array bundle', [], tr());
}
console.log('cases', o.cases.length);
refWrite(o, 'evidence-bundle-py');
