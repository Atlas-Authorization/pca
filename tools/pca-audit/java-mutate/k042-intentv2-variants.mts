// Targeted variants for k042-intentv2-oracle.mts: one case per branch / reason of decideIntentV2 that the conformance
// vectors leave uncovered or only cover through the check boolean. Edits never re-sign the PCActn or the admitting grant
// (decideIntentV2 does not verify them); session roots, receipts, key sets, epochs and session grants are signed with
// the conformance keys (seed = sha256("atlas-pca-conformance/<label>")).
export default async function (h: any) {
  const { vary, add, base, ABSENT, clone, pca, seed } = h;
  const mk = (l: string) => { const sk = seed(l); return { sk, pub: pca.b64u(pca.publicKeyOf(sk)) }; };
  const principal = mk('v2/principal'), agent = mk('v2/agent'), sequencer2 = mk('v2/sequencer-2'), seqRoot = mk('v2/sequencer-root'), stranger = mk('v2/stranger'), revAuth = mk('v2/revocation-authority');
  const NOW = 1_800_000_000_000;
  const MAP0 = pca.b64u(seed('v2/map0')), MAP1 = pca.b64u(seed('v2/map1')), OTHER = pca.b64u(seed('v2/k042-other'));
  const g0 = base['session-g0'];
  const S0 = g0.ctx.session.root;
  const SESSION = S0.session;
  const R0 = g0.p.intent_session.root;
  const G0 = g0.grant;
  const D1 = base['session-d1'].grant;
  const sessCav = (g: any) => g.caveats.find((c: any) => c && c.type === 'intent_session');
  const bodyOf = (S: any) => { const { signer: _a, sig: _b, alg: _c, pq_pk: _d, pq_sig: _e, ...b } = S; return b; };
  const rootOf = (over: any) => { const S = pca.signSessionRoot({ ...bodyOf(S0), ...over }, principal.sk); return { S, R: pca.sessionRootDigest(S) }; };
  const cap = [{ verb: 'air.book', resource: '*' }];
  const mint = (seq: number, prev: string | undefined, root: string, salt = 'k042') =>
    pca.mintSessionGrant({ principalSecret: principal.sk, principalPublic: principal.pub, holder: agent.pub, session: SESSION, seq, ...(prev !== undefined ? { prev } : {}), root, mapDigest: seq === 0 ? MAP0 : MAP1, predicates: cap, salt }).grant;
  /** Move a case onto another session root (ctx root, intent_session.root, the admitting grant's caveat root). */
  const onRoot = (v: any, S: any, R: string) => { v.ctx.session.root = S; v.p.intent_session.root = R; sessCav(v.grant).root = R; };

  // ---------------------------------------------------------------- the context: absent, not an object
  for (const [n, from] of [['g0', 'session-g0'], ['plain', 'session-backcompat'], ['commit', 'map-commit-ok'], ['require-plain', 'map-require-plain'], ['d1', 'session-d1']])
    vary(`ctx-absent/${n}`, from, (v: any) => { v.ctx = ABSENT; });
  for (const [n, c] of [['string', 'x'], ['null', null], ['array', []], ['number', 7]] as const)
    for (const [m, from] of [['g0', 'session-g0'], ['plain', 'session-backcompat'], ['commit', 'map-commit-ok'], ['require-false', 'map-require-false']])
      vary(`ctx-not-object/${n}/${m}`, from, (v: any) => { v.ctx = c; });
  vary('ctx-empty/g0', 'session-g0', (v: any) => { v.ctx = {}; });
  vary('ctx-empty/plain', 'session-backcompat', (v: any) => { v.ctx = {}; });

  // ---------------------------------------------------------------- contextError: every reason, and the valid forms
  const ctxEdits: [string, (c: any) => void][] = [
    ['policy-string', (c) => { c.policy = 'x'; }],
    ['policy-unknown', (c) => { c.policy = { session: {}, foo: 1 }; }],
    ['policy-session-string', (c) => { c.policy = { session: 'x' }; }],
    ['policy-session-unknown', (c) => { c.policy = { session: { require: false, x: 1 } }; }],
    ['policy-session-require-string', (c) => { c.policy = { session: { require: 'true' } }; }],
    ['policy-session-age-neg', (c) => { c.policy = { session: { max_revocation_age_s: -1 } }; }],
    ['policy-session-age-frac', (c) => { c.policy = { session: { max_revocation_age_s: 1.5 } }; }],
    ['policy-session-valid', (c) => { c.policy = { session: { require: false, max_revocation_age_s: 100 } }; }],
    ['policy-session-require-true', (c) => { c.policy = { session: { require: true } }; }],
    ['policy-schema-string', (c) => { c.policy = { schema: 'x' }; }],
    ['policy-schema-unknown', (c) => { c.policy = { schema: { closed: true } }; }],
    ['policy-schema-cw-number', (c) => { c.policy = { schema: { closed_world: 1 } }; }],
    ['policy-schema-cw-false', (c) => { c.policy = { schema: { closed_world: false } }; }],
    ['policy-schema-cw-true', (c) => { c.policy = { schema: { closed_world: true } }; }],
    ['policy-acc-string', (c) => { c.policy = { acc: 'x' }; }],
    ['policy-acc-unknown', (c) => { c.policy = { acc: { max_receipt_age_s: 1, other: 1 } }; }],
    ['policy-acc-receipt-age-string', (c) => { c.policy = { acc: { max_receipt_age_s: '1' } }; }],
    ['policy-acc-keyset-age-neg', (c) => { c.policy = { acc: { max_keyset_age_s: -1 } }; }],
    ['policy-acc-keyset-age-only', (c) => { c.policy = { acc: { max_keyset_age_s: 60 } }; }],
    ['policy-acc-valid', (c) => { c.policy = { acc: { max_receipt_age_s: 900, max_keyset_age_s: 3600 } }; }],
    ['policy-map-string', (c) => { c.policy = { map: 'x' }; }],
    ['policy-map-unknown', (c) => { c.policy = { map: { require: false, eps: 1 } }; }],
    ['policy-map-require-number', (c) => { c.policy = { map: { require: 1 } }; }],
    ['policy-map-eps-neg', (c) => { c.policy = { map: { max_residual_risk_ppm: -1 } }; }],
    ['policy-map-valid', (c) => { c.policy = { map: { require: false, max_residual_risk_ppm: 5 } }; }],
    ['policy-map-require-true', (c) => { c.policy = { map: { require: true } }; }],
    ['policy-all-valid', (c) => { c.policy = { session: { require: false }, schema: { closed_world: false }, acc: {}, map: {} }; }],
    ['params-string', (c) => { c.params = 'x'; }],
    ['params-array', (c) => { c.params = []; }],
    ['schema-string', (c) => { c.schema = 'x'; }],
    ['schema-null', (c) => { c.schema = null; }],
    ['session-string', (c) => { c.session = 'x'; }],
    ['acc-string', (c) => { c.acc = 'x'; }],
    ['acc-array', (c) => { c.acc = []; }],
    ['map-string', (c) => { c.map = 'x'; }],
    ['map-unknown', (c) => { c.map = { disclosure: {}, extra: 1 }; }],
    ['map-empty', (c) => { c.map = {}; }],
    ['layers-string', (c) => { c.layers = 'x'; }],
    ['layers-unknown', (c) => { c.layers = { org: { predicates: [] }, team: { predicates: [] } }; }],
    ['layers-org-string', (c) => { c.layers = { org: 'x' }; }],
    ['layers-std-predicates-string', (c) => { c.layers = { std: { predicates: 'x' } }; }],
    ['layers-site-no-predicates', (c) => { c.layers = { site: {} }; }],
    ['wb-string', (c) => { c.wb = 'x'; }],
    ['wb-empty', (c) => { c.wb = {}; }],
    ['wb-artifacts-string', (c) => { c.wb = { artifacts: 'x' }; }],
    ['wb-artifacts-facts-string', (c) => { c.wb = { artifacts: { facts: 'x' } }; }],
    ['wb-artifacts-labels-string', (c) => { c.wb = { artifacts: { labels: {} } }; }],
    ['wb-artifacts-verdicts-string', (c) => { c.wb = { artifacts: { verdicts: 1 } }; }],
    ['wb-artifacts-offer-set-array', (c) => { c.wb = { artifacts: { offer_set: [] } }; }],
    ['wb-artifacts-valid', (c) => { c.wb = { artifacts: { facts: [], labels: [], verdicts: [] } }; }],
    ['wb-policy-string', (c) => { c.wb = { policy: 'x' }; }],
    ['wb-policy-world-string', (c) => { c.wb = { policy: { world: 'x' } }; }],
    ['wb-policy-provenance-array', (c) => { c.wb = { policy: { provenance: [] } }; }],
    ['wb-policy-classifiers-string', (c) => { c.wb = { policy: { classifiers: 'x' } }; }],
    ['wb-policy-classifiers-string-with-artifacts', (c) => { c.wb = { artifacts: {}, policy: { classifiers: 'x' } }; }],
    ['wb-policy-empty', (c) => { c.wb = { policy: {} }; }],
    ['wb-both-empty', (c) => { c.wb = { artifacts: {}, policy: {} }; }],
    ['acc-state-string', (c) => { c.acc.state = 'x'; }],
    ['acc-monitors-array', (c) => { c.acc.monitors = []; }],
    ['acc-last-seq-string', (c) => { c.acc.last_seq = 'x'; }],
    ['acc-keyset-versions-string', (c) => { c.acc.keyset_versions = 'x'; }],
    ['acc-receipts-object', (c) => { c.acc.receipts = {}; }],
    ['acc-sequencer-keys-string', (c) => { c.acc.sequencer_keys = 'x'; }],
    ['acc-last-seq-neg', (c) => { c.acc.last_seq = { trip_spend: -1 }; }],
    ['acc-last-seq-ok', (c) => { c.acc.last_seq = { trip_spend: 1, other: 0 }; }],
    ['acc-empty', (c) => { c.acc = {}; }],
    ['acc-absent', (c) => { delete c.acc; }],
    ['schema-docs-string', (c) => { c.schema.docs = 'x'; }],
    ['schema-keys-absent', (c) => { delete c.schema.keys; }],
    ['schema-docs-absent', (c) => { delete c.schema.docs; }],
    ['schema-absent', (c) => { delete c.schema; }],
    ['schema-docs-empty', (c) => { c.schema.docs = []; }],
    ['session-grants-string', (c) => { c.session.grants = 'x'; }],
    ['session-revocation-array', (c) => { c.session.revocation = []; }],
    ['session-revocation-last-string', (c) => { c.session.revocation_last = 'x'; }],
    ['session-absent', (c) => { delete c.session; }],
    ['session-root-absent', (c) => { delete c.session.root; }],
    ['session-grants-absent', (c) => { delete c.session.grants; }],
    ['params-absent', (c) => { delete c.params; }],
  ];
  for (const [n, f] of ctxEdits)
    for (const [m, from] of [['g0', 'session-g0'], ['plain', 'session-backcompat'], ['commit', 'map-commit-ok']])
      vary(`ctx/${n}/${m}`, from, (v: any) => { f(v.ctx); });

  // ---------------------------------------------------------------- the clock
  for (const now of [9007199254740991, 9007199254740992, -9007199254740991, -9007199254740992, 0, NOW + 86_400_000 - 1, NOW + 86_400_000])
    for (const [m, from] of [['g0', 'session-g0'], ['commit', 'map-commit-ok'], ['require-plain', 'map-require-plain'], ['closed-world', 'schema-closed-world-policy']])
      vary(`clock/${now}/${m}`, from, (v: any) => { v.now = now; });

  // ---------------------------------------------------------------- schema (rule 14)
  const BIG = { x: 1e300 }; // actionSchemaDigest / accReceiptDigest throw on it (integer outside the safe range)
  vary('schema/docs-throwing-first', 'session-g0', (v: any) => { v.ctx.schema.docs = [BIG, ...v.ctx.schema.docs]; });
  vary('schema/docs-other-first', 'session-g0', (v: any) => { v.ctx.schema.docs = [{ v: 1 }, ...v.ctx.schema.docs]; });
  vary('schema/closed-world-docs-throwing-first', 'schema-closed-world-policy', (v: any) => { v.ctx.schema.docs = [BIG, ...v.ctx.schema.docs]; });
  vary('schema/closed-world-ok', 'schema-closed-world-policy', (v: any) => { v.p = clone(g0.p); delete v.p.intent_session; v.ctx = { ...clone(g0.ctx), policy: { schema: { closed_world: true } } }; });
  vary('schema/aud-other', 'session-g0', (v: any) => { v.p.aud = 'hotel.example'; });
  vary('schema/aud-absent', 'session-g0', (v: any) => { delete v.p.aud; });
  vary('schema/params-absent', 'session-g0', (v: any) => { delete v.ctx.params; });
  vary('schema/action-absent', 'session-g0', (v: any) => { delete v.p.action; });
  vary('schema/verb-other', 'session-g0', (v: any) => { v.p.action.verb = 'air.search'; });
  vary('schema/resource-absent', 'session-g0', (v: any) => { delete v.p.action.resource; });

  // ---------------------------------------------------------------- the bound root and rule 13
  vary('root/is-root-other', 'session-g0', (v: any) => { v.p.intent_session.root = OTHER; });
  {
    const X = rootOf({ session: OTHER });
    vary('root/other-session', 'session-g0', (v: any) => { v.ctx.session.root = X.S; v.p.intent_session.root = X.R; sessCav(v.grant).root = X.R; });
    const bad = clone(S0); bad.expires_at = 5;
    vary('root/unsigned-edit', 'session-g0', (v: any) => { v.ctx.session.root = bad; });
    vary('root/root-string', 'session-g0', (v: any) => { v.ctx.session.root = 'x'; });
  }
  vary('session/intent-absent', 'session-g0', (v: any) => { delete v.p.intent; });
  vary('session/is-schema-other', 'session-g0', (v: any) => { v.p.intent_session.schema = OTHER; });
  vary('session/map-other-seq0', 'session-g0', (v: any) => { v.p.intent.map_digest = OTHER; });
  vary('session/map-other-seq1', 'session-d1', (v: any) => { v.p.intent.map_digest = OTHER; });
  vary('session/grant-no-session-caveat', 'session-g0', (v: any) => { v.grant.caveats = v.grant.caveats.filter((c: any) => c.type !== 'intent_session'); });
  vary('session/grant-caveat-bad', 'session-g0', (v: any) => { sessCav(v.grant).seq = -1; });
  vary('session/grant-caveat-session', 'session-g0', (v: any) => { sessCav(v.grant).session = OTHER; });
  vary('session/grant-caveat-root', 'session-g0', (v: any) => { sessCav(v.grant).root = OTHER; });
  vary('session/grant-caveat-seq', 'session-g0', (v: any) => { sessCav(v.grant).seq = 1; });
  vary('session/grant-issuer-stranger', 'session-g0', (v: any) => { v.grant.issuer = stranger.pub; });
  vary('session/grant-issuer-absent', 'session-g0', (v: any) => { delete v.grant.issuer; });
  // the delta chain at seq 2: G0 -> D1 -> D2
  const D2 = mint(2, D1.id, R0, 'salt2');
  const seq2 = (v: any) => {
    v.grant = clone(D2);
    v.p.intent_session.seq = 2;
    v.p.intent_session.acc = [{ id: 'trip_spend', post: 116_700 }];
    v.p.intent.map_digest = MAP1;
    v.ctx.session.grants = [clone(G0), clone(D1)];
    v.ctx.acc.state = { trip_spend: { sum: 77_800 } };
  };
  vary('chain2/ok', 'session-d1', (v: any) => { seq2(v); });
  vary('chain2/unheld-one', 'session-d1', (v: any) => { seq2(v); v.ctx.session.grants = [clone(G0)]; });
  vary('chain2/three-held', 'session-d1', (v: any) => { seq2(v); v.ctx.session.grants.push(clone(D2)); });
  const chainEdits: [string, (gs: any[]) => void][] = [
    ['g1-string', (gs) => { gs[1] = 'x'; }],
    ['g0-string', (gs) => { gs[0] = 'x'; }],
    ['g1-id-number', (gs) => { gs[1].id = 1; }],
    ['g1-issuer-absent', (gs) => { delete gs[1].issuer; }],
    ['g0-alg-bogus', (gs) => { gs[0].alg = 'rot13'; }],
    ['g1-alg-number', (gs) => { gs[1].alg = 5; }],
    ['g1-alg-ed25519', (gs) => { gs[1].alg = 'ed25519'; }],
    ['g1-alg-ml-dsa', (gs) => { gs[1].alg = 'ml-dsa-65'; }],
    ['g1-no-caveat', (gs) => { gs[1].caveats = gs[1].caveats.filter((c: any) => c.type !== 'intent_session'); }],
    ['g1-caveat-bad', (gs) => { sessCav(gs[1]).root = 'short'; }],
    ['g1-caveat-session', (gs) => { sessCav(gs[1]).session = OTHER; }],
    ['g1-caveat-root', (gs) => { sessCav(gs[1]).root = OTHER; }],
    ['g1-caveat-seq0', (gs) => { sessCav(gs[1]).seq = 0; }],
    ['g1-caveat-seq2', (gs) => { sessCav(gs[1]).seq = 2; }],
    ['g0-caveat-seq1', (gs) => { sessCav(gs[0]).seq = 1; }],
    ['g0-caveat-session', (gs) => { sessCav(gs[0]).session = OTHER; }],
    ['g0-caveat-root', (gs) => { sessCav(gs[0]).root = OTHER; }],
    ['g1-issuer-stranger', (gs) => { gs[1].issuer = stranger.pub; }],
    ['g0-issuer-stranger', (gs) => { gs[0].issuer = stranger.pub; }],
    ['g1-prev-other', (gs) => { sessCav(gs[1]).prev = OTHER; }],
    ['g1-prev-absent', (gs) => { delete sessCav(gs[1]).prev; }],
    ['g0-id-other', (gs) => { gs[0].id = OTHER; }],
    ['g1-id-other', (gs) => { gs[1].id = OTHER; }],
  ];
  for (const [n, f] of chainEdits) vary(`chain2/${n}`, 'session-d1', (v: any) => { seq2(v); f(v.ctx.session.grants); });
  vary('chain2/admitting-prev-g0', 'session-d1', (v: any) => { seq2(v); sessCav(v.grant).prev = G0.id; });
  vary('chain2/admitting-prev-absent', 'session-d1', (v: any) => { seq2(v); delete sessCav(v.grant).prev; });
  vary('chain1/prev-absent', 'session-d1', (v: any) => { delete sessCav(v.grant).prev; });
  vary('chain1/g0-alg-bogus', 'session-d1', (v: any) => { v.ctx.session.grants[0].alg = 'rot13'; });

  // ---------------------------------------------------------------- revocation (rule 13 step 7)
  {
    const REV = { epoch_uri: 'https://atlas.example/rev', max_age_s: 60, key: revAuth.pub };
    const STD = { profile: 'skyair-standing', version: 3, digest: pca.b64u(seed('v2/k042-std')) };
    const RV = rootOf({ revocation: REV });
    const RVS = rootOf({ revocation: REV, layers: { task: { map_digest: MAP0 }, std: STD } });
    const RNS = rootOf({ layers: { task: { map_digest: MAP0 }, std: STD } });
    const ev = (revoked: string[], issued: number) => {
      const set = new pca.RevocationSet(revoked);
      const epoch = pca.signRevocationEpoch(revAuth.sk, { instance_id: 'ana', grant_ref: pca.sessionRevocationScope(SESSION), epoch: set.size, set_size: set.size, root: set.root, issued_at: issued, not_after: issued + 300_000 });
      return { epoch, revoked: set.list() };
    };
    const g0r = (R: string) => mint(0, undefined, R, 'r0');
    for (const [n, RT] of [['rev', RV], ['rev-std', RVS], ['std-only', RNS]] as const) {
      const G = g0r(RT.R), Dx1 = mint(1, G.id, RT.R, 'r1'), Dx2 = mint(2, Dx1.id, RT.R, 'r2');
      const at = (v: any, seq: number) => {
        onRoot(v, RT.S, RT.R);
        if (seq === 0) v.grant = clone(G);
        else {
          v.grant = clone(Dx2);
          v.p.intent_session.seq = 2;
          v.p.intent_session.acc = [{ id: 'trip_spend', post: 116_700 }];
          v.p.intent.map_digest = MAP1;
          v.ctx.session.grants = [clone(G), clone(Dx1)];
          v.ctx.acc.state = { trip_spend: { sum: 77_800 } };
        }
      };
      const ids0 = [pca.sessionRevocationId(SESSION), pca.mapRevocationId(MAP0), pca.deltaRevocationId(G.id)];
      const ids2 = [pca.mapRevocationId(MAP1), pca.deltaRevocationId(G.id), pca.deltaRevocationId(Dx1.id), pca.deltaRevocationId(Dx2.id)];
      const prof = pca.profileRevocationId(STD.profile, STD.version);
      vary(`rev/${n}/seq0-fresh`, 'session-g0', (v: any) => { at(v, 0); v.ctx.session.revocation = ev([], NOW - 1_000); });
      vary(`rev/${n}/seq0-none`, 'session-g0', (v: any) => { at(v, 0); });
      vary(`rev/${n}/seq2-fresh`, 'session-g0', (v: any) => { at(v, 2); v.ctx.session.revocation = ev([], NOW - 1_000); });
      vary(`rev/${n}/seq2-none`, 'session-g0', (v: any) => { at(v, 2); });
      for (const [i, id] of ids0.entries()) vary(`rev/${n}/seq0-revoked-${i}`, 'session-g0', (v: any) => { at(v, 0); v.ctx.session.revocation = ev([id], NOW - 1_000); });
      for (const [i, id] of ids2.entries()) vary(`rev/${n}/seq2-revoked-${i}`, 'session-g0', (v: any) => { at(v, 2); v.ctx.session.revocation = ev([id], NOW - 1_000); });
      vary(`rev/${n}/seq0-profile-revoked`, 'session-g0', (v: any) => { at(v, 0); v.ctx.session.revocation = ev([prof], NOW - 1_000); });
      vary(`rev/${n}/seq0-stale-61`, 'session-g0', (v: any) => { at(v, 0); v.ctx.session.revocation = ev([], NOW - 61_000); });
      vary(`rev/${n}/seq0-age-60`, 'session-g0', (v: any) => { at(v, 0); v.ctx.session.revocation = ev([], NOW - 60_000); });
      for (const pol of [0, 30, 59, 60, 61, 3600]) {
        vary(`rev/${n}/seq0-policy-${pol}-age-45`, 'session-g0', (v: any) => { at(v, 0); v.ctx.policy = { session: { max_revocation_age_s: pol } }; v.ctx.session.revocation = ev([], NOW - 45_000); });
        vary(`rev/${n}/seq0-policy-${pol}-age-61`, 'session-g0', (v: any) => { at(v, 0); v.ctx.policy = { session: { max_revocation_age_s: pol } }; v.ctx.session.revocation = ev([], NOW - 61_000); });
      }
      vary(`rev/${n}/seq0-last-present`, 'session-g0', (v: any) => { at(v, 0); v.ctx.session.revocation = ev(['pca-intent:session:zz'], NOW - 1_000); v.ctx.session.revocation_last = ev(['pca-intent:session:zz'], NOW - 2_000); });
      vary(`rev/${n}/seq0-last-rollback`, 'session-g0', (v: any) => { at(v, 0); v.ctx.session.revocation = ev([], NOW - 1_000); v.ctx.session.revocation_last = ev(['pca-intent:session:zz'], NOW - 2_000); });
    }
  }

  // ---------------------------------------------------------------- accumulators (rule 15)
  vary('acc/is-acc-absent', 'session-g0', (v: any) => { delete v.p.intent_session.acc; });
  vary('acc/is-acc-empty', 'session-g0', (v: any) => { v.p.intent_session.acc = []; });
  vary('acc/is-acc-absent-monitor', 'acc-monitor-state', (v: any) => { delete v.p.intent_session.acc; });
  vary('acc/schema-absent', 'session-g0', (v: any) => { delete v.ctx.schema; });
  vary('acc/schema-docs-throwing-first', 'session-g0', (v: any) => { v.ctx.schema.docs = [BIG, ...v.ctx.schema.docs]; v.ctx.schema.keys = v.ctx.schema.keys; });
  vary('acc/params-absent', 'session-g0', (v: any) => { delete v.ctx.params; });
  vary('acc/params-total-string', 'session-g0', (v: any) => { v.ctx.params.total = 'x'; });
  vary('acc/params-total-absent', 'session-g0', (v: any) => { delete v.ctx.params.total; });
  vary('acc/state-absent', 'session-g0', (v: any) => { delete v.ctx.acc.state; });
  vary('acc/receipt-on-site-local', 'session-g0', (v: any) => { v.p.intent_session.acc[0].receipt = OTHER; });
  vary('acc/overflow', 'session-g0', (v: any) => { v.ctx.acc.state.trip_spend.sum = 9007199254740991 - 100; });
  vary('acc/at-max-safe', 'session-g0', (v: any) => { v.ctx.acc.state.trip_spend.sum = 9007199254740991 - 38_900; v.p.intent_session.acc[0].post = 9007199254740991; });
  vary('acc/claim-post-low', 'session-g0', (v: any) => { v.p.intent_session.acc[0].post = 38_899; });
  vary('acc/monitors-absent', 'acc-monitor-state', (v: any) => { delete v.ctx.acc.monitors; });
  vary('acc/monitors-absent-g0', 'session-g0', (v: any) => { delete v.ctx.acc.monitors; });
  vary('acc/monitor-state-number', 'acc-monitor-state', (v: any) => { v.ctx.acc.monitors = { hotel_after_flight: 1 }; });
  vary('acc/monitor-other-id', 'acc-monitor-state', (v: any) => { v.ctx.acc.monitors = { other: 'unmet' }; });
  {
    // a root with an unselected site-local accumulator, an unselected sequenced one, a wallet one and a keyed count
    const SEARCHES = { id: 'searches', agg: 'count', sel: { verbs: ['air.search'] }, win: { kind: 'task' }, key: null, holder: { kind: 'site_local' } };
    const SEQS = { id: 'seq_search', agg: 'count', sel: { verbs: ['air.search'] }, win: { kind: 'task' }, key: null, holder: { kind: 'sequenced', uri: 'https://atlas.example/seq', root: seqRoot.pub } };
    const BYVERB = { id: 'books', agg: 'count', sel: { verbs: ['air.book'] }, win: { kind: 'task' }, key: null, domain_max: 10, holder: { kind: 'site_local' } };
    const BYNOTE = { id: 'per_note', agg: 'count', sel: { verbs: ['air.book'] }, win: { kind: 'task' }, key: 'action.params.note', holder: { kind: 'site_local' } };
    const BYOFFER = { id: 'per_offer', agg: 'count', sel: { verbs: ['air.book'] }, win: { kind: 'task' }, key: 'action.params.offer_id', holder: { kind: 'site_local' } };
    const CANCEL = { id: 'cancels', agg: 'count', sel: { verbs: ['air.cancel'] }, win: { kind: 'task' }, key: 'action.params.offer_id', holder: { kind: 'site_local' } };
    const trip = S0.accumulators[0], questions = S0.accumulators[1];
    const RA = rootOf({ accumulators: [trip, SEARCHES, SEQS, questions] });
    const RB = rootOf({ accumulators: [BYVERB] });
    const RN = rootOf({ accumulators: [BYNOTE] });
    const RO = rootOf({ accumulators: [BYOFFER] });
    const RC = rootOf({ accumulators: [CANCEL] });
    const onA = (v: any) => onRoot(v, RA.S, RA.R);
    vary('acc-un/plain', 'session-g0', (v: any) => { onA(v); });
    vary('acc-un/state-searches', 'session-g0', (v: any) => { onA(v); v.ctx.acc.state.searches = { count: 4 }; });
    vary('acc-un/state-searches-bad', 'session-g0', (v: any) => { onA(v); v.ctx.acc.state.searches = { sum: 4 }; });
    vary('acc-un/state-searches-string', 'session-g0', (v: any) => { onA(v); v.ctx.acc.state.searches = 'x'; });
    vary('acc-un/state-seq-search', 'session-g0', (v: any) => { onA(v); v.ctx.acc.state.seq_search = { count: 2 }; });
    vary('acc-un/state-questions', 'session-g0', (v: any) => { onA(v); v.ctx.acc.state.questions = { count: 2 }; });
    vary('acc-un/claim-searches', 'session-g0', (v: any) => { onA(v); v.p.intent_session.acc.push({ id: 'searches', post: 5 }); });
    vary('acc-un/claim-seq-search', 'session-g0', (v: any) => { onA(v); v.p.intent_session.acc.push({ id: 'seq_search', post: 1 }); });
    vary('acc-un/verb-search', 'session-g0', (v: any) => { onA(v); v.p.action.verb = 'air.search'; v.ctx.acc.state.searches = { count: 4 }; v.p.intent_session.acc = [{ id: 'searches', post: 5 }]; });
    vary('acc-un/verb-search-no-schema', 'session-g0', (v: any) => { onA(v); delete v.ctx.schema; });
    const onB = (v: any, R: any) => { onRoot(v, R.S, R.R); };
    vary('acc-verb/ok', 'session-g0', (v: any) => { onB(v, RB); v.ctx.acc.state = { books: { count: 2 } }; v.p.intent_session.acc = [{ id: 'books', post: 3 }]; });
    vary('acc-verb/no-schema', 'session-g0', (v: any) => { onB(v, RB); delete v.ctx.schema; v.ctx.acc.state = { books: { count: 2 } }; v.p.intent_session.acc = [{ id: 'books', post: 3 }]; });
    vary('acc-verb/domain-at', 'session-g0', (v: any) => { onB(v, RB); v.ctx.acc.state = { books: { count: 9 } }; v.p.intent_session.acc = [{ id: 'books', post: 10 }]; });
    vary('acc-verb/domain-over', 'session-g0', (v: any) => { onB(v, RB); v.ctx.acc.state = { books: { count: 10 } }; v.p.intent_session.acc = [{ id: 'books', post: 11 }]; });
    vary('acc-key/note', 'session-g0', (v: any) => { onB(v, RN); v.ctx.params.note = 'hi'; v.ctx.acc.state = { per_note: { count: 0 } }; v.p.intent_session.acc = [{ id: 'per_note', post: 1 }]; });
    vary('acc-key/note-missing', 'session-g0', (v: any) => { onB(v, RN); v.ctx.acc.state = { per_note: { count: 0 } }; v.p.intent_session.acc = [{ id: 'per_note', post: 1 }]; });
    vary('acc-key/offer', 'session-g0', (v: any) => { onB(v, RO); v.ctx.acc.state = { per_offer: { count: 0 } }; v.p.intent_session.acc = [{ id: 'per_offer', post: 1 }]; });
    vary('acc-key/offer-missing', 'session-g0', (v: any) => { onB(v, RO); delete v.ctx.params.offer_id; v.ctx.acc.state = { per_offer: { count: 0 } }; v.p.intent_session.acc = [{ id: 'per_offer', post: 1 }]; });
    vary('acc-key/offer-no-schema', 'session-g0', (v: any) => { onB(v, RO); delete v.ctx.schema; v.ctx.acc.state = { per_offer: { count: 0 } }; v.p.intent_session.acc = [{ id: 'per_offer', post: 1 }]; });
    vary('acc-key/offer-schema-mismatch', 'session-g0', (v: any) => { onB(v, RO); v.p.intent_session.schema = OTHER; v.ctx.acc.state = { per_offer: { count: 0 } }; v.p.intent_session.acc = [{ id: 'per_offer', post: 1 }]; });
    vary('acc-key/cancel-verb', 'session-g0', (v: any) => { onB(v, RC); v.p.action.verb = 'air.cancel'; v.ctx.acc.state = { cancels: { count: 0 } }; v.p.intent_session.acc = [{ id: 'cancels', post: 1 }]; });
  }
  // sequenced receipts
  {
    const rcv = base['acc-receipt'];
    const rc = rcv.ctx.acc.receipts[0];
    const { signer: _s, sig: _g, alg: _a, pq_pk: _p, pq_sig: _q, ...rcBody } = rc;
    const resign = (over: any) => pca.signAccReceipt({ ...rcBody, ...over }, sequencer2.sk);
    const withRc = (v: any, r: any, post = r.post) => { v.ctx.acc.receipts = [r]; v.p.intent_session.acc = [{ id: 'trip_spend', post, receipt: pca.accReceiptDigest(r) }]; };
    vary('seq/no-receipt-in-claim', 'acc-receipt', (v: any) => { delete v.p.intent_session.acc[0].receipt; });
    vary('seq/receipts-absent', 'acc-receipt', (v: any) => { delete v.ctx.acc.receipts; });
    vary('seq/receipts-throwing-first', 'acc-receipt', (v: any) => { v.ctx.acc.receipts = [BIG, ...v.ctx.acc.receipts]; });
    vary('seq/receipts-other-first', 'acc-receipt', (v: any) => { v.ctx.acc.receipts = [resign({ seq: 4 }), ...v.ctx.acc.receipts]; });
    vary('seq/receipts-dup', 'acc-receipt', (v: any) => { v.ctx.acc.receipts = [...v.ctx.acc.receipts, ...clone(v.ctx.acc.receipts)]; });
    vary('seq/receipts-string-first', 'acc-receipt', (v: any) => { v.ctx.acc.receipts = ['x', 3, null, ...v.ctx.acc.receipts]; });
    vary('seq/keys-absent', 'acc-receipt', (v: any) => { delete v.ctx.acc.sequencer_keys; });
    vary('seq/other-session', 'acc-receipt', (v: any) => { withRc(v, resign({ session: OTHER })); });
    vary('seq/other-acc', 'acc-receipt', (v: any) => { withRc(v, resign({ acc: 'other_acc' })); });
    vary('seq/other-aud', 'acc-receipt', (v: any) => { withRc(v, resign({ aud: 'hotel.example' })); });
    vary('seq/expires-now', 'acc-receipt', (v: any) => { withRc(v, resign({ expires_at: NOW })); });
    vary('seq/expires-now-minus-1', 'acc-receipt', (v: any) => { withRc(v, resign({ issued_at: NOW - 1_000, expires_at: NOW - 1 })); });
    for (const last of [0, 2, 3, 4]) vary(`seq/last-${last}`, 'acc-receipt', (v: any) => { v.ctx.acc.last_seq = { trip_spend: last }; });
    vary('seq/last-other-id', 'acc-receipt', (v: any) => { v.ctx.acc.last_seq = { other: 9 }; });
    vary('seq/post-mismatch', 'acc-receipt', (v: any) => { v.p.intent_session.acc[0].post = 48_901; });
    vary('seq/over-domain', 'acc-receipt', (v: any) => { withRc(v, resign({ pre: 461_200, delta: 38_900, post: 500_100 })); });
    vary('seq/at-domain', 'acc-receipt', (v: any) => { withRc(v, resign({ pre: 461_100, delta: 38_900, post: 500_000 })); });
    vary('seq/policy-receipt-age', 'acc-receipt', (v: any) => { v.ctx.policy = { acc: { max_receipt_age_s: 0 } }; });
    vary('seq/policy-keyset-age-0', 'acc-receipt', (v: any) => { v.ctx.policy = { acc: { max_keyset_age_s: 0 } }; });
    vary('seq/policy-keyset-age-1', 'acc-receipt', (v: any) => { v.ctx.policy = { acc: { max_keyset_age_s: 1 } }; });
  }

  // ---------------------------------------------------------------- layers (V5)
  {
    const L = (preds: any) => ({ predicates: preds });
    const layerSets: [string, any][] = [
      ['resource-match', { org: L([{ verb: 'air.book', resource: 'skyair.example/bookings' }]) }],
      ['resource-other', { org: L([{ verb: 'air.book', resource: 'skyair.example/other' }]) }],
      ['resource-undefined', { org: L([{ verb: 'air.book', resource: 'undefined' }]) }],
      ['verb-other', { site: L([{ verb: 'air.search' }]) }],
      ['std-fail', { org: L([{ verb: 'air.book' }]), site: L([{ verb: 'air.book' }]), std: L([{ verb: 'air.search' }]) }],
      ['site-fail-std-pass', { site: L([{ verb: 'air.search' }]), std: L([{ verb: 'air.book' }]) }],
      ['all-pass', { org: L([{ verb: 'air.book' }]), site: L([{ verb: 'air.book' }]), std: L([{ verb: 'air.book' }]) }],
      ['extra-member', { org: { predicates: [{ verb: 'air.book' }], x: 1 } }],
      ['empty', {}],
      ['params-total', { org: L([{ verb: 'air.book', where: [{ field: 'action.params.total', op: 'lte', value: 40_000 }] }]) }],
      ['params-total-low', { org: L([{ verb: 'air.book', where: [{ field: 'action.params.total', op: 'lte', value: 100 }] }]) }],
      ['canon-refundable', { site: L([{ verb: 'air.book', where: [{ field: 'env.canon.refundable', op: 'eq', value: 'false' }] }]) }],
      ['env-acc', { site: L([{ verb: 'air.book', where: [{ field: 'env.acc.trip_spend.post', op: 'lte', value: 40_000 }] }]) }],
    ];
    for (const [n, layers] of layerSets) {
      vary(`layers/${n}`, 'session-g0', (v: any) => { v.ctx.layers = layers; });
      vary(`layers/${n}/no-params`, 'session-g0', (v: any) => { v.ctx.layers = layers; delete v.ctx.params; });
      vary(`layers/${n}/schema-fails`, 'session-g0', (v: any) => { v.ctx.layers = layers; v.p.intent_session.schema = OTHER; });
      vary(`layers/${n}/plain`, 'session-backcompat', (v: any) => { v.ctx.layers = layers; });
    }
    vary('layers/resource-absent-undefined', 'session-g0', (v: any) => { delete v.p.action.resource; v.ctx.layers = { org: L([{ verb: 'air.book', resource: 'undefined' }]) }; });
    vary('layers/action-absent', 'session-g0', (v: any) => { delete v.p.action; v.ctx.layers = { org: L([{ verb: 'undefined' }]) }; });
  }

  // ---------------------------------------------------------------- map (rule 19)
  vary('map/require-no-form', 'session-g0', (v: any) => { v.ctx.policy = { map: { require: true } }; });
  vary('map/commit-intent-absent', 'map-commit-ok', (v: any) => { delete v.p.intent; });
  vary('map/commit-no-map-ctx', 'map-commit-ok', (v: any) => { delete v.ctx.map; });
  vary('map/commit-map-empty', 'map-commit-ok', (v: any) => { v.ctx.map = {}; });
  vary('map/commit-action-absent', 'map-commit-ok', (v: any) => { delete v.p.action; });
  vary('map/commit-params-absent', 'map-commit-ok', (v: any) => { delete v.ctx.params; });
  vary('map/commit-eps-0', 'map-commit-ok', (v: any) => { v.ctx.policy = { map: { max_residual_risk_ppm: 0 } }; });
  vary('map/commit-eps-big', 'map-commit-ok', (v: any) => { v.ctx.policy = { map: { max_residual_risk_ppm: 1_000_000 } }; });
  vary('map/commit-require', 'map-commit-ok', (v: any) => { v.ctx.policy = { map: { require: true } }; });
  vary('map/plain-require-ctx-absent', 'map-require-plain', (v: any) => { v.ctx = { policy: { map: { require: true } } }; });
  vary('map/plain-require-false', 'map-require-plain', (v: any) => { v.ctx.policy = { map: { require: false } }; });
  vary('map/form-other', 'map-commit-ok', (v: any) => { v.p.intent_session.map_form = 'plain'; });
  vary('map/form-other-require', 'map-commit-ok', (v: any) => { v.p.intent_session.map_form = 'plain'; v.ctx.policy = { map: { require: true } }; });
  for (const [n, c] of [['string', 'x'], ['null', null]] as const) {
    vary(`map/ctx-${n}-form-plain`, 'map-commit-ok', (v: any) => { v.ctx = c; v.p.intent_session.map_form = 'plain'; });
    vary(`map/ctx-${n}-no-form`, 'map-commit-ok', (v: any) => { v.ctx = c; delete v.p.intent_session.map_form; });
  }

  // ---------------------------------------------------------------- W-B (rules 16-18) through the pipeline
  {
    const core = JSON.parse((await import('node:fs')).readFileSync(new URL('../../../packages/pca/conformance/vectors.json', import.meta.url), 'utf8'));
    const P = core.primitives;
    const wbCase = (name: string, f: (v: any) => void) => vary(name, 'session-g0', (v: any) => { v.ctx.wb = {}; f(v); });
    for (const w of P.intent_world) {
      const i = w.input;
      if (i.now !== undefined && !Number.isSafeInteger(i.now)) continue; // the Java API clock is a long
      wbCase(`wb16/${w.name}`, (v: any) => {
        v.now = i.now ?? v.now;
        v.p.aud = i.aud;
        v.p.intent_session.session = i.session;
        if (i.action?.verb !== undefined) v.p.action.verb = i.action.verb;
        if (i.action?.resource !== undefined) v.p.action.resource = i.action.resource;
        v.ctx.params = i.action?.params ?? {};
        for (const k of ['facts', 'offer_set']) if (i.committed?.[k] !== undefined) v.p.intent_session[k] = i.committed[k];
        const art: any = {};
        if (i.facts !== undefined) art.facts = i.facts;
        if (i.offer_set !== undefined) art.offer_set = i.offer_set;
        v.ctx.wb = { artifacts: art, ...(i.policy !== undefined ? { policy: { world: i.policy } } : {}) };
      });
    }
    for (const w of P.intent_provenance) {
      const i = w.input;
      wbCase(`wb17/${w.name}`, (v: any) => {
        v.p.aud = i.aud;
        v.p.intent_session.session = i.session;
        v.ctx.params = i.action?.params ?? {};
        if (i.prov !== undefined) v.p.intent_session.prov = i.prov;
        if (i.committed_labels !== undefined) v.p.intent_session.labels = i.committed_labels;
        v.ctx.wb = { ...(i.labels !== undefined ? { artifacts: { labels: i.labels } } : {}), ...(i.policy !== undefined ? { policy: { provenance: i.policy } } : {}) };
      });
    }
    for (const w of P.intent_classifier) {
      const i = w.input;
      wbCase(`wb18/${w.name}`, (v: any) => {
        v.p.intent_session.session = i.session;
        v.ctx.params = i.action?.params ?? {};
        if (i.committed !== undefined) v.p.intent_session.classes = i.committed;
        v.ctx.wb = { ...(i.verdicts !== undefined ? { artifacts: { verdicts: i.verdicts } } : {}), policy: { classifiers: i.policy?.classifiers ?? [] } };
      });
    }
    // all three at once: a passing world + provenance question + classes, in one pipeline
    const pw = P.intent_world.find((w: any) => w.expect?.ok === true && Object.keys(w.expect.world ?? {}).length > 0);
    const pq = P.intent_provenance.find((w: any) => w.expect?.outcome === 'question');
    const pp = P.intent_provenance.find((w: any) => w.expect?.outcome === 'pass' && Object.keys(w.expect.labels ?? {}).length > 0);
    const pc = P.intent_classifier.find((w: any) => w.expect?.ok === true);
    for (const [n, prov] of [['question', pq], ['pass', pp]] as const) {
      if (!pw || !prov || !pc) throw new Error('W-B combo inputs missing');
      wbCase(`wb-combo/${n}`, (v: any) => {
        const i = pw.input;
        v.now = i.now;
        v.p.aud = i.aud;
        v.p.intent_session.session = i.session;
        v.ctx.params = { ...(i.action?.params ?? {}), ...(prov.input.action?.params ?? {}), ...(pc.input.action?.params ?? {}) };
        for (const k of ['facts', 'offer_set']) if (i.committed?.[k] !== undefined) v.p.intent_session[k] = i.committed[k];
        const art: any = {};
        if (i.facts !== undefined) art.facts = i.facts;
        if (i.offer_set !== undefined) art.offer_set = i.offer_set;
        if (prov.input.prov !== undefined) v.p.intent_session.prov = prov.input.prov;
        if (prov.input.labels !== undefined) art.labels = prov.input.labels;
        if (pc.input.committed !== undefined) v.p.intent_session.classes = pc.input.committed;
        if (pc.input.verdicts !== undefined) art.verdicts = pc.input.verdicts;
        v.ctx.wb = { artifacts: art, policy: { world: i.policy ?? {}, provenance: prov.input.policy, classifiers: pc.input.policy?.classifiers ?? [] } };
      });
    }
  }

  // ---------------------------------------------------------------- JSON.parse number semantics: Context.fromJson / withParams
  const { ser } = h;
  const expo = (t: string) => t.replace(/"expires_at":1800086400000/g, '"expires_at":1.8000864e12').replace(/"total":38900/g, '"total":3.89e4');
  for (const from of ['session-g0', 'map-commit-ok', 'acc-receipt']) {
    vary(`json/exponent-forms/${from}`, from, () => {}, (v: any) => ({ ctxText: expo(ser(v.ctx)) }));
    const params = JSON.stringify(base[from].ctx.params);
    for (const [n, wp] of [['plain', params], ['exponent', params.replace(/"total":38900/g, '"total":3.89e4')], ['empty', '{}'], ['other', '{"offer_id":"OF-2"}']] as const) {
      vary(`with-params/${n}/${from}`, from, (v: any) => { delete v.ctx.params; }, () => ({ wp }));
      vary(`with-params/${n}/over/${from}`, from, (v: any) => { v.ctx.params = { offer_id: 'nope' }; }, () => ({ wp }));
    }
  }
}
