// k05 differential oracle: the action-kit REGISTRY layer (Java ActionRegistry.java and every native port of it).
// TS reference: packages/pca/src/action-pin.ts (actionPinError, evolutionRecordError, evolutionDiffDigest, verifyRegistrySig,
// verifyEvolutionRecord, reapprovalValid, decidePin) and packages/pca-actions/src/pack.ts + registry.ts + rule22.ts + digest.ts
// (compareVersions, packShapeError, packDefs, verifyPack, PackTracker, RULE22_ENGINE.decide, verifyPackProof).
// Seeds are real, deterministically signed artifacts (Ed25519 and ML-DSA-65 / hybrid keys from fixed labels; ML-DSA here is the
// deterministic variant), then generated structural variants (lib.mjs variants()), every limit ±1, every refusal string, and
// tampered / re-signed documents so the deep branches past the signature are reached.
//   packages/pca/node_modules/tsx/dist/cli.mjs --tsconfig tools/pca-audit/k05-oracles/tsconfig.json tools/pca-audit/k05-oracles/actionregistry-oracle.mts
// writes tools/pca-audit/k05-oracles/out/k05-actionregistry.json.gz (see README.md for the porting notes).
import { Oracle, variants, around, rng, reparse, seed, clone, DEL, setAt } from './lib.mjs';
import * as _m0NS from '@atlasauth/pca';
const _m0: any = { ...(_m0NS as any).default, ..._m0NS };
const b64u = _m0.b64u;
const publicKeyOf = _m0.publicKeyOf;
const mlDsa65Keygen = _m0.mlDsa65Keygen;
const hashCanonical = _m0.hashCanonical;
import * as _m1NS from '@atlasauth/pca/ext/intent';
const _m1: any = { ...(_m1NS as any).default, ..._m1NS };
const actionPinError = _m1.actionPinError;
const evolutionRecordError = _m1.evolutionRecordError;
const evolutionDiffDigest = _m1.evolutionDiffDigest;
const verifyRegistrySig = _m1.verifyRegistrySig;
const verifyEvolutionRecord = _m1.verifyEvolutionRecord;
const reapprovalValid = _m1.reapprovalValid;
const decidePin = _m1.decidePin;
const signEvolutionRecord = _m1.signEvolutionRecord;
const signReapproval = _m1.signReapproval;
const registryKeyOf = _m1.registryKeyOf;
const signRegistryDoc = _m1.signRegistryDoc;
const EVOLUTION_DOMAIN = _m1.EVOLUTION_DOMAIN;
const EVOLUTION_RECORD_KIND = _m1.EVOLUTION_RECORD_KIND;
const REAPPROVAL_DOMAIN = _m1.REAPPROVAL_DOMAIN;
import * as _m2NS from '@atlasauth/pca-actions';
const _m2: any = { ...(_m2NS as any).default, ..._m2NS };
const BUILTIN_DEFS = _m2.BUILTIN_DEFS;
const PackTracker = _m2.PackTracker;
const RULE22_ENGINE = _m2.RULE22_ENGINE;
const buildPack = _m2.buildPack;
const compareVersions = _m2.compareVersions;
const defDigest = _m2.defDigest;
const packDefs = _m2.packDefs;
const packDigest = _m2.packDigest;
const packProof = _m2.packProof;
const packRoot = _m2.packRoot;
const packShapeError = _m2.packShapeError;
const shardDigest = _m2.shardDigest;
const verifyPack = _m2.verifyActionPack;
const verifyPackProof = _m2.verifyPackProof;
const PACK_SIG_DOMAIN = _m2.PACK_SIG_DOMAIN;
const MAX_PACK_DEFS = _m2.MAX_PACK_DEFS;
const CAVEAT_KINDS = _m2.CAVEAT_KINDS;
const CONTEXT_KEYS = _m2.CONTEXT_KEYS;
const profile = _m2.profile;

const o = new Oracle('actionregistry', 'tools/pca-audit/k05-oracles/actionregistry-oracle.mts',
  'TS-reference differential oracle for the native ActionRegistry (evolution records, registry signatures, re-approvals, the grant pin, signed packs + shards, the rollback tracker, rule 22 decide, pack proofs).');
const R = rng(0x05ac7e9);
const pending: Promise<unknown>[] = [];
const used = new Map<string, number>();
// generated labels can collide (two variants with the same printable label): suffix #n, deterministic in call order
const run = (fn: string, name: string, ref: any, args: unknown[]) => {
  const k = fn + '/' + name;
  const n = used.get(k) ?? 0;
  used.set(k, n + 1);
  pending.push(o.run(fn, n ? `${name} #${n}` : name, ref, args));
};

// ---- keys -------------------------------------------------------------------------------------------------------------------------
const REG = seed('k05/actreg/registry');
const OTHER = seed('k05/actreg/other');
const PRINCIPAL = seed('k05/actreg/principal');
const ML = mlDsa65Keygen(seed('k05/actreg/mldsa'));
const ML_SUITE = { alg: 'ml-dsa-65', mlDsa: ML } as any;
const HY_SUITE = { alg: 'hybrid-ed25519-ml-dsa-65', mlDsa: ML } as any;
const KEY = registryKeyOf('reg-1', REG);
const KEY_OTHER = registryKeyOf('reg-1', OTHER);
const KEY_ML = registryKeyOf('reg-ml', REG, ML_SUITE);
const KEY_HY = registryKeyOf('reg-hy', REG, HY_SUITE);
const KEYS = [KEY];
const ALLKEYS = [KEY, KEY_ML, KEY_HY];
const D = (l: string) => b64u(seed('k05/actreg/d/' + l));
const flip = (s: string, i = 0) => s.slice(0, i) + (s[i] === 'A' ? 'B' : 'A') + s.slice(i + 1);

// ---- evolution records --------------------------------------------------------------------------------------------------------------
const A = D('A'), B = D('B'), C = D('C'), E = D('E');
const NS = 'stripe', VERB = 'stripe.refund';
const urec = (over: Record<string, unknown> = {}) => ({ v: 1, kind: EVOLUTION_RECORD_KIND, ns: NS, verb: VERB, from: A, to: B, class: 'narrow', reasons: ['amount max lowered'], ...over }) as any;
const srec = (over: Record<string, unknown> = {}, secret = REG, kid = 'reg-1', suite?: any) => signEvolutionRecord(urec(over), kid, secret, suite);
const REC = srec();
const REC_ML = srec({}, REG, 'reg-ml', ML_SUITE);
const REC_HY = srec({}, REG, 'reg-hy', HY_SUITE);
const REC_ADD = srec({ from: null, to: A, class: 'added', reasons: [] });
const REC_DEL = srec({ from: A, to: null, class: 'removed', reasons: [] });

const ere = (name: string, x: unknown, signed = true) => run('evolutionRecordError', name, (a: any, s: any) => evolutionRecordError(a, { signed: s }), [x, signed]);
for (const [n, r] of [['narrow', REC], ['ml', REC_ML], ['hybrid', REC_HY], ['added', REC_ADD], ['removed', REC_DEL]] as const) {
  ere(`seed ${n}`, r);
  ere(`seed ${n} unsigned-mode`, r, false);
  const { sig: _s, ...body } = r as any;
  ere(`seed ${n} body unsigned`, body, false);
  ere(`seed ${n} body signed-mode`, body, true);
  for (const [l, v] of variants(r, { lens: [127, 128, 129, 512, 513] })) {
    ere(`${n}${l}`, v);
    if (n === 'narrow') ere(`${n}${l} unsigned-mode`, v, false);
  }
}
// hand boundaries
for (const cls of ['equal', 'narrow', 'widen', 'incomparable', 'added', 'removed', 'Narrow', '', 'sideways'])
  for (const [fl, from, to] of [['both', A, B], ['nofrom', null, B], ['noto', A, null], ['neither', null, null]] as const) ere(`class ${cls} ${fl}`, { ...REC, class: cls, from, to });
for (const n of [0, 1, 63, 64, 65]) ere(`reasons count ${n}`, { ...REC, reasons: Array.from({ length: n }, (_, i) => `r${i}`) });
for (const s of around(512)) ere(`reason len ${s.length} ${/é/.test(s) ? 'mb' : 'ascii'}`, { ...REC, reasons: [s] });
ere('reason astral 256 code points (512 utf16)', { ...REC, reasons: ['\u{1F600}'.repeat(256)] });
ere('reason astral 257 code points (514 utf16)', { ...REC, reasons: ['\u{1F600}'.repeat(257)] });
for (const s of around(128, 'k')) ere(`kid len ${s.length}${/é/.test(s) ? ' mb' : ''}`, { ...REC, sig: { ...REC.sig, kid: s } });
for (const ns of ['a', 'a.b.c.d.e.f', 'a.b.c.d.e.f.g', 'A', 'a..b', '.a', 'a.', 'a-b', 'a_b', '0', 'a b', 'é'])
  ere(`ns ${JSON.stringify(ns)}`, { ...REC, ns });
for (const verb of ['a', 'a.b', 'a.b.c.d.e.f', 'a.b.c.d.e.f.g', 'A.b', 'a..b', 'a.b.', 'a-b.c', 'a.b\n'])
  ere(`verb ${JSON.stringify(verb)}`, { ...REC, verb });
for (const d of ['A'.repeat(42), 'A'.repeat(43), 'A'.repeat(44), 'A'.repeat(42) + '=', 'A'.repeat(42) + '+', 'A'.repeat(42) + '/', 'A'.repeat(42) + '-', 'A'.repeat(42) + '_'])
  { ere(`from ${d.length} ${d.slice(-1)}`, { ...REC, from: d }); ere(`to ${d.length} ${d.slice(-1)}`, { ...REC, to: d }); }
// member ABSENT vs null (TS: absent `from`/`to` is NOT null -> 'bad from' / 'bad to')
{ const r = { ...REC_ADD }; delete (r as any).from; ere('added from member absent', r); }
{ const r = { ...REC_DEL }; delete (r as any).to; ere('removed to member absent', r); }
ere('pq_value null', { ...REC, sig: { ...REC.sig, pq_value: null } });
ere('pq_value string', { ...REC, sig: { ...REC.sig, pq_value: 'AA' } });
ere('v 1.0 (number 1)', { ...REC, v: 1.0 });
ere('reasons non-canonical number inside string ok', { ...REC, reasons: ['1e21'] });
ere('lone surrogate in reasons (canonical refuses)', { ...REC, reasons: ['\ud800'] });
ere('NFD reason (canonical refuses?)', { ...REC, reasons: ['é'] });

// ---- evolutionDiffDigest (only complete records: the reference never sees an absent member here) ------------------------------------
const edd = (name: string, r: unknown) => run('evolutionDiffDigest', name, (x: any) => evolutionDiffDigest(x), [r]);
for (const [n, r] of [['narrow', REC], ['added', REC_ADD], ['removed', REC_DEL], ['ml', REC_ML]] as const) edd(n, r);
for (let i = 0; i < 40; i++)
  edd(`random ${i}`, urec({ ns: R.pick(['stripe', 'a', 'a.b']), verb: R.pick(['stripe.refund', 'a.b', 'x.y.z']), from: R.pick([A, B, null]), to: R.pick([B, C, null]), class: R.pick(['equal', 'narrow', 'widen', 'incomparable', 'added', 'removed']), reasons: R.sub(['r1', 'r2', 'é', '', 'long '.repeat(20)]) }));

// ---- verifyRegistrySig ------------------------------------------------------------------------------------------------------------
const vrs = (name: string, domain: string, body: unknown, sig: unknown, keys: unknown) =>
  run('verifyRegistrySig', name, (d: any, b: any, s: any, k: any) => { const r = verifyRegistrySig(d, b, s, k); return r.ok ? null : r.reason; }, [domain, body, sig, keys]);
{
  const { sig, ...body } = REC as any;
  const { sig: sigM, ...bodyM } = REC_ML as any;
  const { sig: sigH, ...bodyH } = REC_HY as any;
  vrs('ed ok', EVOLUTION_DOMAIN, body, sig, KEYS);
  vrs('ml ok', EVOLUTION_DOMAIN, bodyM, sigM, ALLKEYS);
  vrs('hybrid ok', EVOLUTION_DOMAIN, bodyH, sigH, ALLKEYS);
  vrs('wrong domain', REAPPROVAL_DOMAIN, body, sig, KEYS);
  vrs('domain without NUL', EVOLUTION_DOMAIN.slice(0, -1), body, sig, KEYS);
  vrs('pack domain', PACK_SIG_DOMAIN, body, sig, KEYS);
  vrs('keys not array obj', EVOLUTION_DOMAIN, body, sig, {});
  vrs('keys null', EVOLUTION_DOMAIN, body, sig, null);
  vrs('keys string', EVOLUTION_DOMAIN, body, sig, 'x');
  vrs('keys empty', EVOLUTION_DOMAIN, body, sig, []);
  vrs('keys junk then key', EVOLUTION_DOMAIN, body, sig, [null, 5, 'reg-1', [], { kid: 'reg-2', pk: KEY.pk }, KEY]);
  vrs('first matching kid wins (other key first)', EVOLUTION_DOMAIN, body, sig, [KEY_OTHER, KEY]);
  vrs('first matching kid wins (right key first)', EVOLUTION_DOMAIN, body, sig, [KEY, KEY_OTHER]);
  vrs('wrong key', EVOLUTION_DOMAIN, body, sig, [KEY_OTHER]);
  vrs('kid number vs string', EVOLUTION_DOMAIN, body, { ...sig, kid: 1 }, [{ ...KEY, kid: 1 }]);
  // a missing (or null) kid matches no key, not even a key entry without a kid (fixed in 0.5)
  { const { kid: _k, ...noKid } = sig; const { kid: _kk, ...keyNoKid } = KEY as any;
    vrs('sig no kid, key no kid', EVOLUTION_DOMAIN, body, noKid, [keyNoKid]);
    vrs('sig kid null, key kid null', EVOLUTION_DOMAIN, body, { ...sig, kid: null }, [{ ...KEY, kid: null }]);
    vrs('sig no kid, key kid null', EVOLUTION_DOMAIN, body, noKid, [{ ...KEY, kid: null }]); }
  vrs('kid case', EVOLUTION_DOMAIN, body, { ...sig, kid: 'REG-1' }, KEYS);
  vrs('pq_pk number', EVOLUTION_DOMAIN, body, sig, [{ ...KEY, pq_pk: 5 }]);
  vrs('pq_pk null', EVOLUTION_DOMAIN, body, sig, [{ ...KEY, pq_pk: null }]);
  vrs('pq_pk on ed key', EVOLUTION_DOMAIN, body, sig, [{ ...KEY, pq_pk: KEY_ML.pq_pk }]);
  for (const pk of [KEY.pk.slice(0, 42), KEY.pk + 'A', KEY.pk.slice(0, 42) + '=', null, 5, '', 'A'.repeat(43), KEY.pk.slice(0, 42) + 'B'])
    vrs(`key pk #${String(pk).length} ${JSON.stringify(pk)?.slice(-6)}`, EVOLUTION_DOMAIN, body, sig, [{ ...KEY, pk }]);
  // non-canonical last char: 43 chars whose final sextet has low bits set
  vrs('key pk non-canonical tail', EVOLUTION_DOMAIN, body, sig, [{ ...KEY, pk: KEY.pk.slice(0, 42) + String.fromCharCode(KEY.pk.charCodeAt(42) ^ 1) }]);
  for (const alg of [undefined, 'ed25519', 'ml-dsa-65', 'hybrid-ed25519-ml-dsa-65', 'rsa', '', null, 7, 'ED25519']) {
    vrs(`sig alg ${String(alg)} ed key`, EVOLUTION_DOMAIN, body, { ...sig, alg }, KEYS);
    vrs(`key alg ${String(alg)}`, EVOLUTION_DOMAIN, body, sig, [{ ...KEY, alg }]);
  }
  vrs('ml sig claimed ed', EVOLUTION_DOMAIN, bodyM, { ...sigM, alg: 'ed25519' }, ALLKEYS);
  vrs('hybrid sig claimed ml', EVOLUTION_DOMAIN, bodyH, { ...sigH, alg: 'ml-dsa-65' }, ALLKEYS);
  vrs('hybrid without pq_value', EVOLUTION_DOMAIN, bodyH, (({ pq_value: _p, ...s }) => s)(sigH), ALLKEYS);
  vrs('hybrid pq_value flipped', EVOLUTION_DOMAIN, bodyH, { ...sigH, pq_value: flip(sigH.pq_value, 10) }, ALLKEYS);
  vrs('hybrid ed value flipped', EVOLUTION_DOMAIN, bodyH, { ...sigH, value: flip(sigH.value, 10) }, ALLKEYS);
  vrs('hybrid key pq_pk swapped', EVOLUTION_DOMAIN, bodyH, sigH, [{ ...KEY_HY, pq_pk: registryKeyOf('x', REG, { alg: 'ml-dsa-65', mlDsa: mlDsa65Keygen(seed('k05/actreg/ml2')) } as any).pq_pk }]);
  vrs('ml key without pq_pk', EVOLUTION_DOMAIN, bodyM, sigM, [(({ pq_pk: _p, ...k }) => k)(KEY_ML)]);
  vrs('ml value flipped', EVOLUTION_DOMAIN, bodyM, { ...sigM, value: flip(sigM.value, 50) }, ALLKEYS);
  vrs('ml sig with extra pq_value', EVOLUTION_DOMAIN, bodyM, { ...sigM, pq_value: sigM.value }, ALLKEYS);
  for (let i of [0, 1, 42, 43, 84, 85]) vrs(`ed value flip @${i}`, EVOLUTION_DOMAIN, body, { ...sig, value: flip(sig.value, i) }, KEYS);
  vrs('ed value number', EVOLUTION_DOMAIN, body, { ...sig, value: 5 }, KEYS);
  vrs('ed value padded', EVOLUTION_DOMAIN, body, { ...sig, value: sig.value + '==' }, KEYS);
  vrs('ed value short', EVOLUTION_DOMAIN, body, { ...sig, value: sig.value.slice(0, 85) }, KEYS);
  vrs('ed with pq_value', EVOLUTION_DOMAIN, body, { ...sig, pq_value: 'AA' }, KEYS);
  vrs('body changed', EVOLUTION_DOMAIN, { ...body, reasons: [] }, sig, KEYS);
  vrs('body key order irrelevant', EVOLUTION_DOMAIN, Object.fromEntries(Object.entries(body).reverse()), sig, KEYS);
  vrs('body non-canonical (float)', EVOLUTION_DOMAIN, { ...body, v: 1.5 }, sig, KEYS);
  vrs('body lone surrogate', EVOLUTION_DOMAIN, { ...body, reasons: ['\udc00'] }, sig, KEYS);
  vrs('body null', EVOLUTION_DOMAIN, null, sig, KEYS);
  vrs('body string', EVOLUTION_DOMAIN, 'x', sig, KEYS);
  vrs('sig empty obj', EVOLUTION_DOMAIN, body, {}, KEYS);
}

// ---- verifyEvolutionRecord --------------------------------------------------------------------------------------------------------
const ver = (name: string, r: unknown, keys: unknown = KEYS) => run('verifyEvolutionRecord', name, (x: any, k: any) => { const v = verifyEvolutionRecord(x, k); return v.ok ? null : v.reason; }, [r, keys]);
for (const [n, r] of [['narrow', REC], ['ml', REC_ML], ['hybrid', REC_HY], ['added', REC_ADD], ['removed', REC_DEL]] as const) {
  ver(`seed ${n}`, r, ALLKEYS);
  ver(`seed ${n} other key`, r, [registryKeyOf((r as any).sig.kid, OTHER)]);
  ver(`seed ${n} no keys`, r, []);
  for (const [l, v] of variants(r, { maxPaths: 40 })) ver(`${n}${l}`, v, ALLKEYS);
}
ver('re-signed widen', srec({ class: 'widen' }));
ver('signed record, class changed after', { ...REC, class: 'equal' });
ver('wrong-key signature', srec({}, OTHER));

// ---- reapprovalValid ----------------------------------------------------------------------------------------------------------------
const GRANT = { id: D('grant'), issuer: b64u(publicKeyOf(PRINCIPAL)) };
const WIDEN = srec({ to: C, class: 'widen' });
const DIFF = evolutionDiffDigest(WIDEN);
const RA = signReapproval({ grantId: GRANT.id, record: WIDEN, principalSecret: PRINCIPAL });
const rav = (name: string, r: unknown, gid: unknown = GRANT.id, iss: unknown = GRANT.issuer, verb: unknown = VERB, diff: unknown = DIFF) =>
  run('reapprovalValid', name, (a: any, b: any, c: any, d: any, e: any) => reapprovalValid(a, b, c, d, e), [r, gid, iss, verb, diff]);
rav('honest', RA);
for (const [l, v] of variants(RA)) rav(`ra${l}`, v);
rav('other grant', RA, D('other-grant'));
rav('other issuer', RA, GRANT.id, b64u(publicKeyOf(OTHER)));
rav('issuer malformed', RA, GRANT.id, 'xx');
rav('issuer null', RA, GRANT.id, null);
rav('issuer padded', RA, GRANT.id, GRANT.issuer + '=');
rav('other verb', RA, GRANT.id, GRANT.issuer, 'stripe.charge');
rav('other diff', RA, GRANT.id, GRANT.issuer, VERB, evolutionDiffDigest(REC));
rav('grant id null + ra grant null', { ...RA, grant: null }, null);
rav('signed by other key', signReapproval({ grantId: GRANT.id, record: WIDEN, principalSecret: OTHER }));
rav('re-signed after edit (other grant, valid sig)', signReapproval({ grantId: D('other-grant'), record: WIDEN, principalSecret: PRINCIPAL }), D('other-grant'));
for (let i of [0, 1, 42, 43, 84, 85]) rav(`sig flip @${i}`, { ...RA, sig: { ...RA.sig, value: flip(RA.sig.value, i) } });

// ---- actionPinError ----------------------------------------------------------------------------------------------------------------
const PIN = { pack: { ns: NS, root: D('root') }, defs: { [VERB]: A, 'stripe.charge': B }, on_new_action: 'deny', max_esc: 3, preauth_esc: 1, caveats: ['amount_cap', 'window'] };
const ape = (name: string, x: unknown) => run('actionPinError', name, (a: any) => actionPinError(a), [x]);
ape('seed', PIN);
for (const [l, v] of variants(PIN)) ape(l, v);
for (const m of [-1, 0, 1, 2, 3, 4, 1.5, -0, '1', null]) for (const p of [-1, 0, 1, 2, 3, 4, 1.5, -0, null, undefined])
  ape(`max_esc ${String(m)} preauth ${String(p)}`, { ...PIN, max_esc: m, preauth_esc: p });
ape('max_esc absent preauth 3', (() => { const x: any = { ...PIN, preauth_esc: 3 }; delete x.max_esc; return x; })());
ape('preauth absent', (() => { const x: any = { ...PIN }; delete x.preauth_esc; return x; })());
for (const k of [...CAVEAT_KINDS, 'other', '']) ape(`caveat ${k}`, { ...PIN, caveats: [k] });
ape('caveats all kinds', { ...PIN, caveats: [...CAVEAT_KINDS] });
ape('caveats empty', { ...PIN, caveats: [] });
ape('caveats dup', { ...PIN, caveats: ['window', 'window'] });
ape('caveats not array', { ...PIN, caveats: 'window' });
ape('defs empty', { ...PIN, defs: {} });
ape('defs array', { ...PIN, defs: [] });
ape('defs null', { ...PIN, defs: null });
for (const verb of ['a', 'a.b', 'a.b.c.d.e.f', 'a.b.c.d.e.f.g', 'A.b', 'a..b', 'a.b.', '__proto__', 'constructor.x'])
  ape(`defs verb ${verb}`, { ...PIN, defs: { [verb]: A } });
ape('defs second verb bad', { ...PIN, defs: { [VERB]: A, BAD: A } });
ape('defs second digest bad', { ...PIN, defs: { [VERB]: A, 'x.y': 'A' } });
for (const ns of ['a', 'a.b.c.d.e.f', 'a.b.c.d.e.f.g', 'A', '', 'a-b']) ape(`pack ns ${ns}`, { ...PIN, pack: { ns, root: PIN.pack.root } });
ape('pack extra member', { ...PIN, pack: { ...PIN.pack, x: 1 } });
for (const v of ['deny', 'escalate', 'Deny', 'allow', '', null]) ape(`on_new ${String(v)}`, { ...PIN, on_new_action: v });
ape('minimal', { pack: PIN.pack, on_new_action: 'escalate' });

// ---- decidePin ----------------------------------------------------------------------------------------------------------------------
const rec = (from: string, to: string, cls: string, over: Record<string, unknown> = {}, key = REG) =>
  signEvolutionRecord({ v: 1, kind: EVOLUTION_RECORD_KIND, ns: NS, verb: VERB, from, to, class: cls as never, reasons: [], ...over }, 'reg-1', key);
const doc = (def: unknown, pack: unknown = { ns: NS, root: PIN.pack.root }) => ({ pack, verbs: [{ verb: 'stripe.other', def: E }, { verb: VERB, def }] });
const PINP = { pack: PIN.pack, defs: { [VERB]: A }, on_new_action: 'deny' };
const dpin = (name: string, over: Record<string, unknown>) =>
  run('decidePin', name, (i: any) => decidePin(i), [{ pin: PINP, doc: doc(A), verb: VERB, records: [], keys: KEYS, reapprovals: [], grant: GRANT, ...over }]);
const raOf = (r: any, gid = GRANT.id, key = PRINCIPAL) => signReapproval({ grantId: gid, record: r, principalSecret: key });
dpin('exact', {});
dpin('changed no chain', { doc: doc(B) });
for (const cls of ['equal', 'narrow', 'widen', 'incomparable']) {
  const r = rec(A, B, cls);
  dpin(`one hop ${cls}`, { doc: doc(B), records: [r] });
  dpin(`one hop ${cls} reapproved`, { doc: doc(B), records: [r], reapprovals: [raOf(r)] });
  dpin(`one hop ${cls} reapproval other grant`, { doc: doc(B), records: [r], reapprovals: [raOf(r, D('g2'))] });
  dpin(`one hop ${cls} reapproval other key`, { doc: doc(B), records: [r], reapprovals: [raOf(r, GRANT.id, OTHER)] });
  dpin(`one hop ${cls} reapproval junk then good`, { doc: doc(B), records: [r], reapprovals: [null, 5, {}, raOf(r)] });
}
const W1 = rec(A, B, 'widen'), W2 = rec(B, C, 'incomparable'), N1 = rec(A, B, 'narrow'), N2 = rec(B, C, 'equal');
dpin('two hops free', { doc: doc(C), records: [N1, N2] });
dpin('two hops second blocked', { doc: doc(C), records: [N1, W2] });
dpin('two hops first blocked', { doc: doc(C), records: [W1, N2] });
dpin('two hops both blocked (needs = first on path from presented back = earliest)', { doc: doc(C), records: [W1, W2] });
dpin('two hops both blocked, first reapproved', { doc: doc(C), records: [W1, W2], reapprovals: [raOf(W1)] });
dpin('two hops both blocked, both reapproved', { doc: doc(C), records: [W1, W2], reapprovals: [raOf(W1), raOf(W2)] });
dpin('unblocked path preferred', { doc: doc(C), records: [rec(A, C, 'widen'), N1, N2] });
dpin('blocked direct, records order reversed', { doc: doc(C), records: [N2, N1, rec(A, C, 'widen')] });
dpin('missing hop', { doc: doc(C), records: [N1] });
dpin('backwards', { doc: doc(B), records: [rec(B, A, 'narrow')] });
dpin('cycle', { doc: doc(C), records: [rec(A, B, 'equal'), rec(B, A, 'equal')] });
dpin('self loop', { doc: doc(B), records: [rec(A, A, 'equal'), N1] });
dpin('record wrong key', { doc: doc(B), records: [rec(A, B, 'narrow', {}, OTHER)] });
dpin('record other verb', { doc: doc(B), records: [rec(A, B, 'narrow', { verb: 'stripe.charge' })] });
dpin('record other ns', { doc: doc(B), records: [rec(A, B, 'narrow', { ns: 'other' })] });
dpin('record added', { doc: doc(B), records: [signEvolutionRecord(urec({ from: null, to: B, class: 'added', reasons: [] }), 'reg-1', REG)] });
dpin('record malformed', { doc: doc(B), records: [{ ...N1, x: 1 }, null, 'x', 5] });
dpin('records not array', { doc: doc(B), records: { 0: N1 } });
dpin('records null', { doc: doc(B), records: null });
dpin('keys null', { doc: doc(B), records: [N1], keys: null });
dpin('keys absent', { doc: doc(B), records: [N1], keys: undefined });
dpin('keys ml + hybrid only', { doc: doc(B), records: [N1], keys: [KEY_ML, KEY_HY] });
dpin('ml record chain', { doc: doc(B), records: [signEvolutionRecord(urec({ class: 'narrow', reasons: [] }), 'reg-ml', REG, ML_SUITE)], keys: ALLKEYS });
dpin('reapprovals not array', { doc: doc(B), records: [W1], reapprovals: { 0: raOf(W1) } });
dpin('reapprovals null', { doc: doc(B), records: [W1], reapprovals: null });
// chain length around MAX_EVOLUTION_STEPS = 32
const chain = (n: number) => { const ds = Array.from({ length: n + 1 }, (_, i) => (i === 0 ? A : D('c' + i))); return { ds, recs: ds.slice(1).map((d, i) => rec(ds[i]!, d, 'equal')) }; };
for (const n of [31, 32, 33]) {
  const { ds, recs } = chain(n);
  dpin(`chain length ${n}`, { doc: doc(ds[n]), records: recs });
  dpin(`chain length ${n} reversed records`, { doc: doc(ds[n]), records: [...recs].reverse() });
  const blocked = [...recs]; blocked[0] = rec(ds[0]!, ds[1]!, 'widen');
  dpin(`chain length ${n} first widen`, { doc: doc(ds[n]), records: blocked });
}
// pin/doc shapes
dpin('pin malformed', { pin: { ...PINP, on_new_action: 'maybe' } });
dpin('pin unknown member', { pin: { ...PINP, x: 1 } });
dpin('pin null', { pin: null });
dpin('new verb deny', { pin: { ...PINP, defs: { 'stripe.x': A } } });
dpin('new verb escalate', { pin: { ...PINP, defs: { 'stripe.x': A }, on_new_action: 'escalate' } });
dpin('defs empty', { pin: { ...PINP, defs: {} } });
dpin('pack-only exact', { pin: { pack: PIN.pack, on_new_action: 'deny' } });
dpin('pack-only root differs', { pin: { pack: PIN.pack, on_new_action: 'deny' }, doc: doc(A, { ns: NS, root: D('other-root') }) });
dpin('pack-only root missing', { pin: { pack: PIN.pack, on_new_action: 'deny' }, doc: doc(A, { ns: NS }) });
dpin('pack ns differs', { doc: doc(A, { ns: 'other', root: PIN.pack.root }) });
dpin('pack null', { doc: doc(A, null) });
dpin('pack array', { doc: doc(A, []) });
dpin('pack string', { doc: doc(A, 'stripe') });
dpin('def missing', { doc: doc(undefined) });
dpin('def null', { doc: doc(null) });
dpin('def number', { doc: doc(5) });
dpin('verb undeclared', { doc: { pack: PIN.pack, verbs: [] } });
dpin('verbs not array', { doc: { pack: PIN.pack, verbs: { [VERB]: { verb: VERB, def: A } } } });
dpin('verbs junk then verb', { doc: { pack: PIN.pack, verbs: [null, 5, 'x', [], { verb: VERB, def: A }] } });
dpin('verbs duplicate (first wins)', { doc: { pack: PIN.pack, verbs: [{ verb: VERB, def: B }, { verb: VERB, def: A }] } });
dpin('doc null', { doc: null });
dpin('doc no verbs', { doc: { pack: PIN.pack } });
dpin('verb is a prototype key', { verb: 'constructor', pin: { ...PINP, defs: { 'a.b': A } }, doc: { pack: PIN.pack, verbs: [{ verb: 'constructor', def: A }] } });
dpin('grant null with chain', { doc: doc(B), records: [W1], reapprovals: [raOf(W1)], grant: null });
// seeded random pin worlds
{
  const ds = [A, B, C, E, D('x1'), D('x2')];
  for (let i = 0; i < 300; i++) {
    const recs: any[] = [];
    const ras: any[] = [];
    for (let k = R.int(0, 6); k > 0; k--) {
      const r = rec(R.pick(ds), R.pick(ds), R.pick(['equal', 'narrow', 'widen', 'incomparable']), R.next() < 0.1 ? { verb: 'stripe.charge' } : {}, R.next() < 0.1 ? OTHER : REG);
      recs.push(r);
      if (R.next() < 0.3) ras.push(raOf(r, R.next() < 0.8 ? GRANT.id : D('g2')));
    }
    dpin(`random ${i}`, { doc: doc(R.pick(ds)), records: recs, reapprovals: ras, ...(R.next() < 0.15 ? { pin: { ...PINP, on_new_action: 'escalate', defs: { [R.pick([VERB, 'stripe.zz'])]: R.pick(ds) } } } : {}) });
  }
}

// ---- compareVersions --------------------------------------------------------------------------------------------------------------
const cv = (a: string, b: string) => run('compareVersions', `${a} ? ${b}`, (x: any, y: any) => Math.sign(compareVersions(x, y)), [a, b]);
const VS = ['0.0.0', '0.0.1', '0.1.0', '1.0.0', '1.2.3', '1.10.0', '1.9.9', '2.0.0', '999999999.0.0', '0.999999999.0', '0.0.999999999', '10.0.0', '9.99.99'];
for (const a of VS) for (const b of VS) cv(a, b);
for (const bad of ['1.0', '1.0.0-rc1', '01.0.0', '1.00.0', '1.0.00', '1000000000.0.0', '0.1000000000.0', ' 1.0.0', '1.0.0 ', '1..0', 'a.b.c', '', '-1.0.0', '+1.0.0', '1.0.0\n', '１.0.0']) {
  cv(bad, '1.0.0');
  cv('1.0.0', bad);
}
cv('1.0', '2.0'); // both bad: names the first

// ---- packs --------------------------------------------------------------------------------------------------------------------------
const SRC = { kind: 'hand', uri: 'internal://k05', spec_digest: 'A'.repeat(43), licence: 'Apache-2.0', licence_notes: 'k05 oracle' };
const small = BUILTIN_DEFS.filter((d: any) => d.verb.startsWith('stripe.')).map((d: any) => [JSON.stringify(d).length, d] as const).sort((a, b) => a[0] - b[0]).map((x) => x[1]);
const DEFS3 = small.slice(0, 3);
const patch = (d: any, f: (x: any) => void) => { const c = clone(d); f(c); return c; };
const mkPack = (defs: any[], version: string, extra: Record<string, unknown> = {}) =>
  buildPack({ ns: NS, version, stability: 'stable', defs, source: SRC, kid: 'reg-1', secret: REG, ...extra } as any);
const P1 = mkPack(DEFS3, '1.0.0');
const DEFS3b = [patch(DEFS3[0], (x) => { x.title = (x.title ?? 'T') + ' v2'; }), DEFS3[1], DEFS3[2]];
const P2 = mkPack(DEFS3b, '1.1.0', { prev: { pack: P1.pack } });
const PS = mkPack(small.slice(0, 4), '1.0.0', { shard: { max: 2 } });
const PML = mkPack(DEFS3, '1.0.0', { kid: 'reg-ml', suite: ML_SUITE });
const PHY = mkPack(DEFS3, '1.0.0', { kid: 'reg-hy', suite: HY_SUITE });
const resign = (p: any, kid = 'reg-1', secret = REG, suite?: any) => { const { sig: _s, ...body } = p; return { ...body, sig: signRegistryDoc(PACK_SIG_DOMAIN, body, kid, secret, suite) }; };

const pse = (name: string, x: unknown, signed = true) => run('packShapeError', name, (a: any, s: any) => packShapeError(a, { signed: s }), [x, signed]);
for (const [n, p] of [['p1', P1.pack], ['p2', P2.pack], ['sharded', PS.pack], ['ml', PML.pack]] as const) {
  pse(`seed ${n}`, p);
  pse(`seed ${n} unsigned-mode`, p, false);
  const { sig: _s, ...body } = p as any;
  pse(`seed ${n} body unsigned`, body, false);
  pse(`seed ${n} body signed-mode`, body, true);
  // structural variants; defs internals are the Actions oracle's job (depth 3 stops at defs[i] members)
  for (const [l, v] of variants(p, { depth: n === 'p2' ? 5 : 3, lens: [0, 1, 2048, 2049] })) pse(`${n}${l}`, v);
}
for (const s of around(2048)) for (const k of ['kind', 'uri', 'spec_digest', 'licence', 'licence_notes']) pse(`source.${k} len ${s.length}${/é/.test(s) ? ' mb' : ''}`, { ...P1.pack, source: { ...SRC, [k]: s } });
for (const k of ['kind', 'uri', 'spec_digest', 'licence', 'licence_notes']) pse(`source.${k} empty`, { ...P1.pack, source: { ...SRC, [k]: '' } });
for (const v of ['0.0.0', '999999999.999999999.999999999', '1000000000.0.0', '1.0', '01.0.0', '1.0.0-rc'] ) pse(`version ${v}`, { ...P1.pack, version: v });
for (const st of ['draft', 'beta', 'stable', 'Stable', 'deprecated', null]) pse(`stability ${String(st)}`, { ...P1.pack, stability: st });
for (const k of ['traits_digest', 'roles_digest', 'rules_digest', 'root', 'prev']) for (const d of ['A'.repeat(42), 'A'.repeat(44), 'A'.repeat(42) + '=', 5, null])
  pse(`${k} ${JSON.stringify(d).slice(-4)} ${String(d).length}`, { ...P1.pack, [k]: d });
{ const x: any = { ...P1.pack }; delete x.prev; pse('prev member absent', x); }
pse('defs empty', { ...P1.pack, defs: [] });
pse('defs unsorted', { ...P1.pack, defs: [...DEFS3].reverse() });
pse('defs dup', { ...P1.pack, defs: [DEFS3[0], DEFS3[0], DEFS3[1]] });
pse('defs second invalid', { ...P1.pack, defs: [DEFS3[0], patch(DEFS3[1], (x) => { x.verb = 'BAD'; }), DEFS3[2]] });
pse(`defs ${MAX_PACK_DEFS} (count boundary, dummy verbs)`, { ...P1.pack, defs: Array.from({ length: MAX_PACK_DEFS }, (_, i) => patch(DEFS3[0], (x) => { x.verb = `stripe.v${String(i).padStart(5, '0')}`; })) });
pse(`defs ${MAX_PACK_DEFS + 1}`, { ...P1.pack, defs: Array.from({ length: MAX_PACK_DEFS + 1 }, () => DEFS3[0]) });
const SH = (PS.pack as any).defs.shards;
pse('shards empty', { ...PS.pack, defs: { shards: [] } });
pse('shards 4096', { ...PS.pack, defs: { shards: Array.from({ length: 4096 }, (_, i) => ({ name: `s${i}`, digest: A, uri: 'u' })) } });
pse('shards 4097', { ...PS.pack, defs: { shards: Array.from({ length: 4097 }, (_, i) => ({ name: `s${i}`, digest: A, uri: 'u' })) } });
pse('shards dup name', { ...PS.pack, defs: { shards: [SH[0], SH[0]] } });
for (const nm of ['a', 'a.b', 'a-b', 'a.b.c.d.e.f.g.h', 'a.b.c.d.e.f.g.h.i', 'A', 'a..b', 'a-', '-a', 'a b', ''])
  pse(`shard name ${JSON.stringify(nm)}`, { ...PS.pack, defs: { shards: [{ ...SH[0], name: nm }] } });
for (const s of around(2048, 'u')) pse(`shard uri len ${s.length}${/é/.test(s) ? ' mb' : ''}`, { ...PS.pack, defs: { shards: [{ ...SH[0], uri: s }] } });
pse('shard uri empty', { ...PS.pack, defs: { shards: [{ ...SH[0], uri: '' }] } });
pse('shard extra member', { ...PS.pack, defs: { shards: [{ ...SH[0], x: 1 }] } });
pse('defs object extra member', { ...PS.pack, defs: { shards: SH, x: 1 } });
pse('evolution 0', { ...P1.pack, evolution: [] });
pse('evolution not array', { ...P1.pack, evolution: {} });
pse('evolution bad record', { ...P1.pack, evolution: [REC, { ...REC, x: 1 }] });
pse('evolution unsigned record', { ...P1.pack, evolution: [(({ sig: _s, ...b }) => b)(REC)] });
pse('evolution 65536 (boundary; shared record)', { ...P1.pack, evolution: Array.from({ length: 65536 }, () => REC_ADD) });
pse('evolution 65537', { ...P1.pack, evolution: Array.from({ length: 65537 }, () => REC_ADD) });
for (const g of [null, {}, { alg: 'ed25519', kid: 'k', value: 'v' }, { alg: 'ed25519', kid: 'k' }, { alg: 1, kid: 'k', value: 'v' }, { alg: 'x', kid: '', value: '' }, { alg: 'ed25519', kid: 'k', value: 'v', pq_value: 1 }, { alg: 'ed25519', kid: 'k', value: 'v', z: 1 }])
  pse(`sig ${JSON.stringify(g)}`, { ...P1.pack, sig: g });
pse('non-canonical body (float in source? no: float in defs)', { ...P1.pack, defs: [patch(DEFS3[0], (x) => { x.zz = 1.5; }), DEFS3[1], DEFS3[2]] });
pse('NFD in source notes', { ...P1.pack, source: { ...SRC, licence_notes: 'é' } });
pse('lone surrogate in source notes', { ...P1.pack, source: { ...SRC, licence_notes: '\ud800' } });

// packDefs (gathered verbs, or the thrown message)
const pdefs = (name: string, p: unknown, shards: unknown) => run('packDefs', name, (a: any, s: any) => packDefs(a, s ?? undefined).map((d: any) => d.verb), [p, shards]);
const SHARDS = PS.shards as Record<string, any>;
const shardNames = Object.keys(SHARDS);
pdefs('inline', P1.pack, {});
pdefs('inline with shards arg', P1.pack, SHARDS);
pdefs('sharded ok', PS.pack, SHARDS);
pdefs('sharded no shards', PS.pack, {});
pdefs('sharded shards null', PS.pack, null);
pdefs('sharded one missing', PS.pack, { [shardNames[0]!]: SHARDS[shardNames[0]!] });
pdefs('sharded extra shard', PS.pack, { ...SHARDS, extra: SHARDS[shardNames[0]!] });
pdefs('sharded swapped', PS.pack, { [shardNames[0]!]: SHARDS[shardNames[1]!], [shardNames[1]!]: SHARDS[shardNames[0]!] });
for (const n of shardNames) {
  for (const [l, v] of variants(SHARDS[n], { depth: 2 })) pdefs(`shard ${n}${l}`, PS.pack, { ...SHARDS, [n]: v });
  // re-point the ref at the mutated shard, so the content checks after the digest are reached
  for (const [f, mut] of [['v 2', { v: 2 }], ['kind', { kind: 'pca-action-pack' }], ['ns', { ns: 'other' }], ['version', { version: '9.9.9' }], ['name', { name: 'other' }], ['defs obj', { defs: {} }], ['defs empty', { defs: [] }], ['v 1.0', { v: 1.0 }]] as const) {
    const s2 = { ...SHARDS[n], ...mut };
    const pk = clone(PS.pack); (pk as any).defs.shards = (pk as any).defs.shards.map((r: any) => (r.name === n ? { ...r, digest: shardDigest(s2) } : r));
    pdefs(`shard ${n} repointed ${f}`, pk, { ...SHARDS, [n]: s2 });
  }
}
pdefs('shard named __proto__', (() => { const pk = clone(PS.pack) as any; pk.defs.shards = [{ ...pk.defs.shards[0], name: '__proto__' }]; return pk; })(), {});

// verifyPack
const vp = (name: string, p: unknown, keys: unknown = ALLKEYS, shards: unknown = null) =>
  run('verifyPack', name, (a: any, k: any, s: any) => { const r = verifyPack(a, k, s ? { shards: s } : {}); return r.ok ? { ok: true, digest: r.digest, verbs: r.defs.map((d: any) => d.verb) } : r; }, [p, keys, shards]);
vp('p1', P1.pack);
vp('p2 (evolution)', P2.pack);
vp('sharded', PS.pack, ALLKEYS, SHARDS);
vp('sharded no shards', PS.pack);
vp('ml', PML.pack);
vp('hybrid', PHY.pack);
vp('ml with ed-only keys', PML.pack, KEYS);
vp('p1 other key', P1.pack, [KEY_OTHER]);
vp('p1 keys empty', P1.pack, []);
vp('p1 keys not array', P1.pack, {});
vp('p1 re-signed by other', resign(P1.pack, 'reg-1', OTHER));
for (const [l, v] of variants(P1.pack, { depth: 2 })) vp(`raw${l}`, v);
// edit the body THEN re-sign: reaches the vocabulary digests, defs, root and evolution checks
const rsv = (name: string, f: (p: any) => void, base: any = P1.pack, shards: unknown = null) => { const p = clone(base); f(p); vp(`resigned ${name}`, resign(p), ALLKEYS, shards); };
for (const k of ['traits_digest', 'roles_digest', 'rules_digest', 'root']) rsv(`${k} changed`, (p) => { p[k] = D('x' + k); });
rsv('def title changed (root mismatch)', (p) => { p.defs[0].title = 'Tampered'; });
rsv('def dropped (root mismatch)', (p) => { p.defs.pop(); });
rsv('root recomputed after drop', (p) => { p.defs.pop(); p.root = packRoot(p.defs.map(defDigest)); });
rsv('defs reversed', (p) => { p.defs.reverse(); });
rsv('evolution foreign ns', (p) => { p.evolution = [signEvolutionRecord(urec({ ns: 'other', from: null, to: defDigest(DEFS3[0]), class: 'added', reasons: [] }), 'reg-1', REG)]; });
rsv('evolution to not in pack', (p) => { p.evolution = [signEvolutionRecord(urec({ from: null, to: D('nope'), class: 'added', reasons: [] }), 'reg-1', REG)]; });
rsv('evolution removed (to null) ok', (p) => { p.evolution = [signEvolutionRecord(urec({ from: D('gone'), to: null, class: 'removed', reasons: [] }), 'reg-1', REG)]; });
rsv('evolution wrong key', (p) => { p.evolution = [signEvolutionRecord(urec({ from: null, to: defDigest(DEFS3[0]), class: 'added', reasons: [] }), 'reg-1', OTHER)]; });
rsv('evolution second bad', (p) => { p.evolution = [...p.evolution, signEvolutionRecord(urec({ from: null, to: D('nope2'), class: 'added', reasons: [] }), 'reg-1', REG)]; });
rsv('p2 evolution class lie (narrow), signature valid', (p) => { p.evolution = p.evolution.map((r: any) => signEvolutionRecord({ ...(({ sig: _s, ...b }) => b)(r), class: r.from && r.to ? 'narrow' : r.class }, 'reg-1', REG)); }, P2.pack);
rsv('sharded shard ref digest changed', (p) => { p.defs.shards[0].digest = D('sd'); }, PS.pack, SHARDS);
rsv('sharded unsorted across shards ok', (p) => { p.defs.shards.reverse(); }, PS.pack, SHARDS);
rsv('version changed', (p) => { p.version = '9.9.9'; });
rsv('stability draft', (p) => { p.stability = 'draft'; });
rsv('source changed', (p) => { p.source = { ...SRC, uri: 'internal://other' }; });
rsv('prev set', (p) => { p.prev = D('prev'); });
// sharded: replace shard contents, re-point the refs, re-sign (reaches the post-gather checks)
const reshard = (name: string, f: (sh: Record<string, any>) => void) => {
  const sh = clone(SHARDS); f(sh);
  const p = clone(PS.pack) as any;
  p.defs.shards = p.defs.shards.map((r: any) => ({ ...r, digest: shardDigest(sh[r.name]) }));
  vp(`resharded ${name}`, resign(p), ALLKEYS, sh);
};
reshard('all shards empty (no defs)', (sh) => { for (const k of Object.keys(sh)) sh[k].defs = []; });
reshard('one shard empty (root mismatch)', (sh) => { sh[shardNames[0]!].defs = []; });
reshard('duplicate def across shards', (sh) => { sh[shardNames[1]!].defs = [...sh[shardNames[1]!].defs, sh[shardNames[0]!].defs[0]]; });
reshard('invalid def in shard', (sh) => { sh[shardNames[0]!].defs[0].verb = 'BAD'; });
reshard('def moved between shards (same set)', (sh) => { const d = sh[shardNames[0]!].defs.pop(); sh[shardNames[1]!].defs.unshift(d); });
// seeded random re-signed edits
for (let i = 0; i < 80; i++) {
  const base = R.pick([P1.pack, P2.pack]);
  const ps = [['traits_digest'], ['roles_digest'], ['rules_digest'], ['root'], ['prev'], ['version'], ['stability'], ['defs', 0, 'title'], ['defs', 1, 'verb'], ['defs', 2, 'effects'], ['evolution', 0, 'to'], ['evolution', 0, 'class'], ['source', 'licence']];
  const p = R.pick(ps);
  const val = R.pick([D('r' + i), '2.0.0', 'beta', null, 'x', 'stripe.zzz', [], ['read'], 'narrow']);
  vp(`resigned random ${i} ${p.join('.')}`, resign(setAt(base, p, () => val)));
}

// PackTracker (keepContent:false: natives do not recompute the semantic upgrade diff). Comparison: ok/status/code, reason only when code=bad_pack.
const tr = (name: string, steps: Array<[unknown, unknown]>) =>
  run('packTracker', name, (st: any) => { const t = new PackTracker(ALLKEYS, { keepContent: false }); return st.map(([p, s]: any) => t.accept(p, s ?? undefined)); }, [steps]);
const P0b = mkPack(DEFS3.slice(0, 2), '1.0.0');
const P3 = mkPack(DEFS3, '1.2.0', { prev: { pack: P2.pack } });
const P2gap = mkPack(DEFS3b, '1.1.0');
const P2fork = mkPack(DEFS3.slice(0, 2), '1.1.0', { prev: { pack: P1.pack } });
tr('first', [[P1.pack, null]]);
tr('same twice', [[P1.pack, null], [P1.pack, null]]);
tr('upgrade', [[P1.pack, null], [P2.pack, null]]);
tr('upgrade twice', [[P1.pack, null], [P2.pack, null], [P3.pack, null]]);
tr('skip a version (chain gap)', [[P1.pack, null], [P3.pack, null]]);
tr('rollback', [[P2.pack, null], [P1.pack, null]]);
tr('fork', [[P1.pack, null], [P0b.pack, null]]);
tr('fork after upgrade', [[P1.pack, null], [P2.pack, null], [P2fork.pack, null]]);
tr('gap (prev null)', [[P1.pack, null], [P2gap.pack, null]]);
tr('bad then good', [[{ ...P1.pack, x: 1 }, null], [P1.pack, null]]);
tr('first is v2 then v1', [[P2.pack, null], [P1.pack, null], [P2.pack, null]]);
tr('sharded first', [[PS.pack, SHARDS]]);
tr('sharded missing shards', [[PS.pack, null]]);
tr('two namespaces', [[P1.pack, null], [mkPack(DEFS3, '0.0.1', { ns: 'stripe2' }).pack, null], [P2.pack, null]]);
tr('ml then ed same content (fork)', [[PML.pack, null], [P1.pack, null]]);

// ---- rule22Decide (RULE22_ENGINE.decide) ---------------------------------------------------------------------------------------------
const FL = (over: Record<string, unknown> = {}) => ({ risk: 2, rev: 'irreversible', blast_ppm: 0, esc: 2, caveats: ['amount_cap'], context: ['idempotency'], prules: [], ...over });
const r22 = (name: string, doc: unknown, verb: unknown, grant: unknown, context: unknown) =>
  run('rule22Decide', name, (d: any, v: any, g: any, c: any) => RULE22_ENGINE.decide({ doc: d, verb: v, grant: g, context: c }), [doc, verb, grant, context]);
const G = { caveats: ['amount_cap'], max_esc: 3, preauth_esc: 2 };
const doc22 = (floors: unknown) => ({ verbs: [{ verb: 'a.other', floors: FL({ esc: 0 }) }, { verb: VERB, floors }] });
r22('allow', doc22(FL()), VERB, G, ['idempotency']);
for (const esc of [0, 1, 2, 3]) for (const mx of [0, 1, 2, 3]) for (const pre of [0, 1, 2, 3]) r22(`esc ${esc} max ${mx} pre ${pre}`, doc22(FL({ esc })), VERB, { ...G, max_esc: mx, preauth_esc: pre }, ['idempotency']);
r22('caveat missing', doc22(FL()), VERB, { ...G, caveats: [] }, ['idempotency']);
r22('caveat unknown kind filtered', doc22(FL({ caveats: ['window'] })), VERB, { ...G, caveats: ['windowx', 'Window'] }, ['idempotency']);
r22('caveats superset', doc22(FL()), VERB, { ...G, caveats: [...CAVEAT_KINDS] }, ['idempotency']);
r22('context missing', doc22(FL()), VERB, G, []);
r22('context unknown filtered', doc22(FL()), VERB, G, ['Idempotency', 'x']);
r22('context all keys', doc22(FL({ context: [...CONTEXT_KEYS] })), VERB, G, [...CONTEXT_KEYS]);
r22('taint context key', doc22(FL({ context: ['taint:web'] })), VERB, G, ['taint:web']);
r22('verb absent', doc22(FL()), 'x.y', G, ['idempotency']);
r22('verbs not array', { verbs: {} }, VERB, G, []);
r22('verbs missing', {}, VERB, G, []);
r22('floors missing', { verbs: [{ verb: VERB }] }, VERB, G, []);
for (const [l, v] of variants(FL(), { depth: 2 })) r22(`floors${l}`, doc22(v), VERB, G, ['idempotency']);
for (const [l, v] of variants(G, { depth: 2 })) r22(`grant${l}`, doc22(FL()), VERB, v, ['idempotency']);
r22('grant caveats null', doc22(FL()), VERB, { ...G, caveats: null }, ['idempotency']);
r22('context null', doc22(FL()), VERB, G, null);
r22('first match wins', { verbs: [{ verb: VERB, floors: FL({ esc: 0, caveats: [], context: [] }) }, { verb: VERB, floors: FL({ esc: 3 }) }] }, VERB, { ...G, caveats: [] }, []);
r22('profile helper floors', doc22(profile ? (() => { try { return { ...FL() }; } catch { return FL(); } })() : FL()), VERB, G, ['idempotency']);

// ---- verifyPackProof -----------------------------------------------------------------------------------------------------------------
{
  const ds = DEFS3.map(defDigest);
  const root = packRoot(ds);
  const vpp = (name: string, r: unknown, proof: unknown, d: unknown) => run('verifyPackProof', name, (a: any, b: any, c: any) => verifyPackProof(a, b, c), [r, proof, d]);
  for (const d of ds) {
    const pr = packProof(ds, d);
    vpp(`ok ${d.slice(0, 6)}`, root, pr, d);
    vpp(`other digest ${d.slice(0, 6)}`, root, pr, D('nope'));
    for (const [l, v] of variants(pr, { depth: 3 })) vpp(`${d.slice(0, 6)}${l}`, root, v, d);
  }
  vpp('root flipped', flip(root), packProof(ds, ds[0]!), ds[0]);
  vpp('root null', null, packProof(ds, ds[0]!), ds[0]);
  vpp('proof null', root, null, ds[0]);
  const one = [ds[0]!];
  vpp('single leaf', packRoot(one), packProof(one, ds[0]!), ds[0]);
  const many = Array.from({ length: 9 }, (_, i) => D('leaf' + i));
  for (const i of [0, 4, 7, 8]) vpp(`nine leaves @${i}`, packRoot(many), packProof(many, many[i]!), many[i]);
}

await Promise.all(pending);
// Engine- or canonicalizer-specific message tails (JS TypeError text, each native's canonicalizer wording) are not portable:
// such a case carries `textPrefix`, and a native must produce the same decision with a message that STARTS WITH it.
const MARKERS = ['pin evaluation error (fail closed): ', 'pack verification error: ', 'verification error: ', 'canonicalize: '];
for (const c of o.cases as any[]) {
  const t = JSON.stringify(c.out);
  for (const m of MARKERS) {
    const i = t.indexOf(m);
    if (i < 0) continue;
    // the prefix = the message text up to and including the marker
    const msg = (typeof c.out === 'string' ? c.out : c.out?.reason ?? c.out?.$throws ?? JSON.stringify(c.out)) as string;
    const j = msg.indexOf(m);
    if (j >= 0) c.textPrefix = msg.slice(0, j + m.length);
    break;
  }
}
o.write();
void reparse; void DEL; void hashCanonical; void packDigest; void KEY_HY;
