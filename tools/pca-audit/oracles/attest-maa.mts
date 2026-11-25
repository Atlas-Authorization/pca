// Oracle: packages/pca/src/attest-maa-keys.ts (Azure MAA token-signing key trust: guarded certs fetch, JWKS evaluation, the rotation-safe trust store,
// multi-vantage corroboration) and attest-maa-pins.ts (the release-signed built-in pins), TS reference. Writes out/ref-attest-maa.json.gz.
// Inputs are the REAL public Azure MAA certificate sets (fixtures/real-azure-maa), the shipped release-signed pin manifest and synthetic certificates
// forged under fixed seeds (public certificates only). Deterministic: every clock is an argument, fetches are scripted.
//
// PORTING (fn(args) -> native entry point; JSON values; a reference throw ({"$throws"}) only requires the native to refuse)
//   NOTE: a rejection `reason` that starts with 'error:' (OpenSSL text), 'The first argument' (a Node type error) or names an ASN.1 library schema is library text: compare presence only.
//   NOTE: a certificate with trailing bytes after its DER (syn-cert-trailing-byte) is ACCEPTED by the reference (OpenSSL tolerance); a strict-DER native may refuse: record the decision.
//   jwks = {keys:[{kid?, kty?, alg?, x5c:[base64 DER]}]}; policy = MaaKeyPolicy (builtinPins may be false | true | a BuiltinMaaPinsSource object)
//   constants []                                              -> {BUILTIN_CHAIN_LEAF_CN, BUILTIN_MAA_PINS_ISSUER_ID, BUILTIN_MAA_PINS_ISSUER_KEYS}
//   evaluateMaaJwks [jwks, issuer, policy, nowMs]             -> {accepted:[{spki, kind, notBeforeMs, notAfterMs}], rejected:[{kid, reason}]}  (reason strings are compared by prefix up to ':' ... exact where the reference text is a fixed string)
//   loadBuiltinMaaPins [{nowMs, source?}]                     -> BuiltinMaaPinsResult  (source = {manifest, issuerKeys, minVersion?}; absent = the shipped pins)
//   corroborate [sets, k, {issuer, nowMs, policy?}]           -> MaaCorroborationResult
//   fetchCerts [{issuer, response, opts?}]                    -> {ok, jwks} | {ok:false, error}; response = {status?, url?, contentLength?, body: json | {$text}, bodyBytes?: {$bytes}} | {$throws}
//   trust [scenario]                                          -> {results, store, fetches}; scenario = {policy, initial?: {issuer: state}, fetches: [response | {$throws} | jwks...],
//        calls: [{issuer, nowMs, repin?: {manifest, verify}}]}; the scripted fetch returns fetches[min(i, last)]; store = the final in-memory snapshot;
//        fetches = the URLs requested. The durable store is covered by the same logic (durableMaaKeyStateStore is a thin kv adapter, see kvStore).
//   kvStore [{steps}]                                         -> durableMaaKeyStateStore over an in-memory kv: steps = [{set: [issuer, state]} | {get: issuer}] -> [result]
//   buildTrust [{policy, noFetch?}]                           -> {built:true} | {$throws}
const PKGSRC = '../../../packages/pca/src/';
import { readFileSync } from 'node:fs';
import { Oracle, refWrite, seed } from './lib.mjs';
import { b64u, fx, fxt, sd, chr, flip, unb, T0, suiteKey, secretsOfSpec, refWriteBlobs } from './attest-roots-kit.mts';

const K: any = await import('../../../packages/pca/src/attest-maa-keys.ts');
const P: any = await import('../../../packages/pca/src/attest-maa-pins.ts');
const D: any = await import('../../../packages/pca/src/attest-maa-pins.data.ts');
const AL: any = await import('../../../packages/pca/src/attest-allowlist.ts');
const X: any = await import('../../../packages/pca/src/test-support/forge-x509.ts');
const { createMemoryDurableKv }: any = await import('../../../packages/pca/src/durable-state.ts');
const o = new Oracle('attest-maa', 'tools/pca-audit/oracles/attest-maa.mts', 'TS-reference oracle for the Azure MAA key trust store and the release-signed pins.');
const J = (x: any) => JSON.parse(JSON.stringify(x, (_k, v) => (v instanceof Uint8Array ? { $bytes: b64u(v) } : v)));
const run = (fn: () => any) => { try { return J(fn()); } catch (e: any) { return { $throws: e instanceof Error ? e.message : String(e) }; } };
const add = (fn: string, name: string, args: any[], out: any) => o.add(fn, name, args, out);

const HOUR = 3_600_000, DAY = 24 * HOUR;
const WUS = 'https://sharedwus.wus.attest.azure.net', EUS = 'https://sharedeus.eus.attest.azure.net';
const JW = JSON.parse(fxt('real-azure-maa', 'maa-signing-certs.json'));
const JE = JSON.parse(fxt('real-azure-maa', 'maa-signing-certs-eus.json'));
const bound = JSON.parse(Buffer.from(fxt('real-azure-maa', 'pcabound-tdxvm-token.jwt').trim().split('.')[1]!, 'base64url').toString());
const NOW = (bound.iat + 3600) * 1000;
const SPKI_A = 'fe4fa28d5b2e89f088d484f260363a12bcab53d9a9e0d6725507336fc8b6a71e', SPKI_B = '97cda3af47e762fb8673d1664066082ad7a9e82120eb9523da1a39f6a84de3cc';
const MS_ROOT = '02376d0908ac23041cc7d666d9daf192554f7fc36317aa9cb800908616b28af8', MS_PCA = '9ab67a5d1926476a794bcb4fa6cd74faa1486cd05931010aa7bbf1f57f1a8f58';
const LEAF_CN = 'Microsoft Azure Attestation 2020';
const BP = (over: any = {}) => ({ trustedIssuers: [WUS], allowTrustOnFirstUse: true, builtinPins: false, ...over });

add('constants', 'all', [], J({ BUILTIN_CHAIN_LEAF_CN: P.BUILTIN_CHAIN_LEAF_CN, BUILTIN_MAA_PINS_ISSUER_ID: D.BUILTIN_PINS_ISSUER_ID, BUILTIN_MAA_PINS_ISSUER_KEYS: P.BUILTIN_MAA_PINS_ISSUER_KEYS }));

// ---- synthetic certificates (public) ----
const names = (cn: string, extra: any[] = []) => [['CN', cn], ...extra] as any;
const selfSigned = (label: string, cn: string, o2: { curve?: any; from?: string; to?: string; signer?: any; issuerCn?: string; sub?: any } = {}) => {
  const key = X.forgeKey('maa/' + label, o2.curve ?? 'P-256');
  const c = X.forgeCert({ subject: o2.sub ?? names(cn), issuer: names(o2.issuerCn ?? cn), subjectKey: key, signer: o2.signer ?? key, serial: X.serialFor('maa/' + label), notBefore: new Date(o2.from ?? '2026-09-01T00:00:00Z'), notAfter: new Date(o2.to ?? '2027-09-01T00:00:00Z'), extensions: [] });
  return { der: Buffer.from(c.der).toString('base64'), key };
};
const jw = (...certs: string[][]) => ({ keys: certs.map((x5c, i) => ({ kid: 'k' + i, kty: 'RSA', x5c })) });
const syn = {
  ok: selfSigned('ok', WUS),
  ok384: selfSigned('ok384', WUS, { curve: 'P-384' }),
  other: selfSigned('other', EUS),
  wildcard: selfSigned('wild', 'https://*.wus.attest.azure.net'),
  expired: selfSigned('exp', WUS, { from: '2024-01-01T00:00:00Z', to: '2025-01-01T00:00:00Z' }),
  future: selfSigned('fut', WUS, { from: '2030-01-01T00:00:00Z', to: '2031-01-01T00:00:00Z' }),
  old: selfSigned('old', WUS, { from: '2020-01-01T00:00:00Z', to: '2032-01-01T00:00:00Z' }),
  multiRdn: selfSigned('rdn', WUS, { sub: names(WUS, [['O', 'Contoso']]) }),
  notSelfSigned: (() => { const k = X.forgeKey('maa/signer', 'P-256'); return selfSigned('nss', WUS, { signer: k }); })(),
  issuerDiffers: selfSigned('idiff', WUS, { issuerCn: EUS }),
};
const SNOW = Date.parse('2027-01-01T00:00:00Z');
const ev = (nm: string, jwks: any, issuer: string, policy: any, now: number) => add('evaluateMaaJwks', nm, [jwks, issuer, policy, now], run(() => K.evaluateMaaJwks(jwks, issuer, policy, now)));
for (const [nm, c] of Object.entries(syn)) ev('syn-' + nm, jw([c.der]), WUS, BP(), SNOW);
ev('syn-ok-two-keys', jw([syn.ok.der], [syn.ok384.der]), WUS, BP(), SNOW);
ev('syn-ok-duplicate-key', jw([syn.ok.der], [syn.ok.der]), WUS, BP(), SNOW);
ev('syn-ok-skew-before', jw([syn.ok.der]), WUS, BP(), Date.parse('2026-08-31T23:59:30Z'));
ev('syn-ok-skew-before-short', jw([syn.ok.der]), WUS, BP(), Date.parse('2026-08-31T23:58:00Z'));
ev('syn-ok-skew-zero', jw([syn.ok.der]), WUS, BP({ clockSkewMs: 0 }), Date.parse('2026-08-31T23:59:30Z'));
ev('syn-ok-skew-after', jw([syn.ok.der]), WUS, BP(), Date.parse('2027-09-01T00:00:30Z'));
ev('syn-ok-age-limit-equal', jw([syn.ok.der]), WUS, BP({ maxKeyAgeMs: SNOW - Date.parse('2026-09-01T00:00:00Z') }), SNOW);
ev('syn-ok-age-limit-less', jw([syn.ok.der]), WUS, BP({ maxKeyAgeMs: SNOW - Date.parse('2026-09-01T00:00:00Z') - 1 }), SNOW);
ev('syn-old-age-default', jw([syn.old.der]), WUS, BP(), SNOW);
ev('syn-old-age-long', jw([syn.old.der]), WUS, BP({ maxKeyAgeMs: 4000 * DAY }), SNOW);
ev('syn-other-issuer', jw([syn.other.der]), EUS, BP({ trustedIssuers: [EUS] }), SNOW);
ev('syn-empty-keys', { keys: [] }, WUS, BP(), SNOW);
ev('syn-no-keys-member', {}, WUS, BP(), SNOW);
ev('syn-null-jwks', null, WUS, BP(), SNOW);
ev('syn-key-no-kid', { keys: [{ x5c: [syn.ok.der] }, { x5c: [syn.wildcard.der] }] }, WUS, BP(), SNOW);
ev('syn-x5c-empty', { keys: [{ kid: 'a', x5c: [] }] }, WUS, BP(), SNOW);
ev('syn-x5c-missing', { keys: [{ kid: 'a' }] }, WUS, BP(), SNOW);
ev('syn-x5c-not-cert', { keys: [{ kid: 'a', x5c: ['AAAA'] }] }, WUS, BP(), SNOW);
ev('syn-x5c-not-base64', { keys: [{ kid: 'a', x5c: ['!!!'] }] }, WUS, BP(), SNOW);
ev('syn-x5c-number', { keys: [{ kid: 'a', x5c: [5] }] }, WUS, BP(), SNOW);
ev('syn-cert-flipped', jw([b64u(Buffer.from(syn.ok.der, 'base64')).length ? Buffer.from(flip(Buffer.from(syn.ok.der, 'base64'), 100)).toString('base64') : '']), WUS, BP(), SNOW);
ev('syn-cert-trailing-byte', jw([Buffer.concat([Buffer.from(syn.ok.der, 'base64'), Buffer.from([0])]).toString('base64')]), WUS, BP(), SNOW);
// real certificates
const spkiSets = (j: any) => j.keys.map((k: any) => k.kid);
for (const [jn, j, iss] of [['wus', JW, WUS], ['eus', JE, EUS]] as any[]) {
  ev(`real-${jn}-default`, j, iss, BP({ trustedIssuers: [iss] }), NOW);
  ev(`real-${jn}-root-pinned`, j, iss, BP({ trustedIssuers: [iss], chainRootSpkiSha256: [MS_ROOT], chainLeafCn: [LEAF_CN] }), NOW);
  ev(`real-${jn}-root-and-intermediate`, j, iss, BP({ trustedIssuers: [iss], chainRootSpkiSha256: [MS_ROOT], chainIntermediateSpkiSha256: [MS_PCA], chainLeafCn: [LEAF_CN] }), NOW);
  ev(`real-${jn}-root-upper-case-pin`, j, iss, BP({ trustedIssuers: [iss], chainRootSpkiSha256: [MS_ROOT.toUpperCase()], chainLeafCn: [LEAF_CN] }), NOW);
  ev(`real-${jn}-wrong-root`, j, iss, BP({ trustedIssuers: [iss], chainRootSpkiSha256: ['00'.repeat(32)] }), NOW);
  ev(`real-${jn}-intermediate-not-in-chain`, j, iss, BP({ trustedIssuers: [iss], chainRootSpkiSha256: [MS_ROOT], chainIntermediateSpkiSha256: ['11'.repeat(32)] }), NOW);
  ev(`real-${jn}-leaf-cn-other`, j, iss, BP({ trustedIssuers: [iss], chainRootSpkiSha256: [MS_ROOT], chainLeafCn: ['Something Else'] }), NOW);
  ev(`real-${jn}-leaf-cn-empty-list`, j, iss, BP({ trustedIssuers: [iss], chainRootSpkiSha256: [MS_ROOT], chainLeafCn: [] }), NOW);
  ev(`real-${jn}-other-issuer`, j, jn === 'wus' ? EUS : WUS, BP({ trustedIssuers: [jn === 'wus' ? EUS : WUS] }), NOW);
  ev(`real-${jn}-max-age-1s`, j, iss, BP({ trustedIssuers: [iss], maxKeyAgeMs: 1000, chainRootSpkiSha256: [MS_ROOT] }), NOW);
  ev(`real-${jn}-far-future`, j, iss, BP({ trustedIssuers: [iss], chainRootSpkiSha256: [MS_ROOT] }), Date.parse('2030-01-01T00:00:00Z'));
  ev(`real-${jn}-long-ago`, j, iss, BP({ trustedIssuers: [iss], chainRootSpkiSha256: [MS_ROOT] }), Date.parse('2019-01-01T00:00:00Z'));
  for (const [i, k] of j.keys.entries()) {
    ev(`real-${jn}-key${i}-only`, { keys: [k] }, iss, BP({ trustedIssuers: [iss], chainRootSpkiSha256: [MS_ROOT], chainIntermediateSpkiSha256: [MS_PCA] }), NOW);
    if (k.x5c.length > 1) {
      ev(`real-${jn}-key${i}-chain-reordered`, { keys: [{ ...k, x5c: [...k.x5c].reverse() }] }, iss, BP({ trustedIssuers: [iss], chainRootSpkiSha256: [MS_ROOT] }), NOW);
      ev(`real-${jn}-key${i}-root-dropped`, { keys: [{ ...k, x5c: k.x5c.slice(0, -1) }] }, iss, BP({ trustedIssuers: [iss], chainRootSpkiSha256: [MS_ROOT] }), NOW);
      ev(`real-${jn}-key${i}-leaf-only`, { keys: [{ ...k, x5c: k.x5c.slice(0, 1) }] }, iss, BP({ trustedIssuers: [iss], chainRootSpkiSha256: [MS_ROOT] }), NOW);
      ev(`real-${jn}-key${i}-intermediate-dropped`, { keys: [{ ...k, x5c: [k.x5c[0], k.x5c[2]] }] }, iss, BP({ trustedIssuers: [iss], chainRootSpkiSha256: [MS_ROOT], chainIntermediateSpkiSha256: [MS_PCA] }), NOW);
      for (const at of [60, 400]) {
        const raw = Buffer.from(k.x5c[0], 'base64');
        ev(`real-${jn}-key${i}-leaf-byte${at}-flipped`, { keys: [{ ...k, x5c: [Buffer.from(flip(raw, at)).toString('base64'), ...k.x5c.slice(1)] }] }, iss, BP({ trustedIssuers: [iss], chainRootSpkiSha256: [MS_ROOT] }), NOW);
      }
      ev(`real-${jn}-key${i}-leaf-signature-flipped`, { keys: [{ ...k, x5c: [Buffer.from(flip(Buffer.from(k.x5c[0], 'base64'), Buffer.from(k.x5c[0], 'base64').length - 5)).toString('base64'), ...k.x5c.slice(1)] }] }, iss, BP({ trustedIssuers: [iss], chainRootSpkiSha256: [MS_ROOT] }), NOW);
    }
  }
}
ev('real-mixed-with-synthetic', { keys: [JW.keys[0], { kid: 'syn', x5c: [syn.ok.der] }, JW.keys[1]] }, WUS, BP({ chainRootSpkiSha256: [MS_ROOT] }), NOW);
void spkiSets;

// ---- the release-signed pins ----
const lb = (nm: string, a: any) => add('loadBuiltinMaaPins', nm, [a], run(() => P.loadBuiltinMaaPins(a)));
const shipped = D.BUILTIN_PINS_MANIFEST.body;
lb('shipped-in-window', { nowMs: NOW });
lb('shipped-at-not-before', { nowMs: shipped.notBefore });
lb('shipped-before-not-before', { nowMs: shipped.notBefore - 1 });
lb('shipped-at-expiry', { nowMs: shipped.expiresAt });
lb('shipped-after-expiry', { nowMs: shipped.expiresAt + 1 });
lb('shipped-now-fraction', { nowMs: NOW + 0.5 });
lb('shipped-now-string', { nowMs: String(NOW) });
const relKey = suiteKey('maa/release', 'hybrid-ed25519-ml-dsa-65');
const REL = { rel: { alg: 'hybrid-ed25519-ml-dsa-65', keys: relKey.pub } };
const entries = (v = 3, over: any[] = []) => [
  { kind: 'maa-signing-spki', value: SPKI_A, label: WUS }, { kind: 'maa-signing-spki', value: SPKI_B, label: WUS },
  { kind: 'maa-chain-root-spki', value: MS_ROOT, label: 'Microsoft Root Certificate Authority 2011' }, { kind: 'maa-chain-intermediate-spki', value: MS_PCA, label: 'Microsoft Azure Attestation PCA 2019' },
  { kind: 'attest-corroboration', value: 'ab'.repeat(32), label: `vantages=${v};method=test` }, ...over,
];
const mk = (over: any = {}) => AL.signAllowlistManifest({ version: over.version ?? 1, issuedAt: over.notBefore ?? NOW - DAY, notBefore: over.notBefore ?? NOW - DAY, expiresAt: over.expiresAt ?? NOW + 100 * DAY, entries: over.entries ?? entries() }, { issuer: 'rel', alg: 'hybrid-ed25519-ml-dsa-65', secrets: relKey.secrets });
const cs = (nm: string, manifest: any, over: any = {}, nowMs = NOW) => lb('custom-' + nm, { nowMs, source: { manifest, issuerKeys: REL, ...over } });
cs('ok', mk());
cs('ok-vantages-exactly-3', mk({ entries: entries(3) }));
cs('ok-vantages-many', mk({ entries: entries(250) }));
cs('ok-revoked-signing-key-listed', mk({ entries: entries(3, [{ kind: 'maa-signing-spki', value: '22'.repeat(32), label: EUS, revoked: true }]) }));
cs('ok-two-issuers', mk({ entries: entries(3, [{ kind: 'maa-signing-spki', value: SPKI_A, label: EUS }]) }));
cs('ok-min-version-equal', mk({ version: 5 }), { minVersion: 5 });
cs('ok-lifetime-400-days', mk({ notBefore: NOW - DAY, expiresAt: NOW - DAY + 400 * DAY }));
cs('vantages-2', mk({ entries: entries(2) }));
cs('vantages-1', mk({ entries: entries(1) }));
cs('vantages-0-label-refused-by-manifest', mk({ entries: entries(3).slice(0, 4).concat([{ kind: 'attest-corroboration', value: 'ab'.repeat(32), label: 'vantages=1;method=x' }]) }));
cs('no-corroboration', mk({ entries: entries(3).slice(0, 4) }));
cs('two-corroborations', mk({ entries: entries(3, [{ kind: 'attest-corroboration', value: 'cd'.repeat(32), label: 'vantages=3;method=other' }]) }));
cs('no-signing-key', mk({ entries: entries(3).filter((e) => e.kind !== 'maa-signing-spki') }));
cs('no-chain-root', mk({ entries: entries(3).filter((e) => e.kind !== 'maa-chain-root-spki') }));
cs('no-chain-intermediate', mk({ entries: entries(3).filter((e) => e.kind !== 'maa-chain-intermediate-spki') }));
cs('lifetime-401-days', mk({ notBefore: NOW - DAY, expiresAt: NOW - DAY + 401 * DAY }));
cs('below-min-version', mk({ version: 1 }), { minVersion: 2 });
cs('not-yet-valid', mk({ notBefore: NOW + 1 }));
cs('expired', mk({ expiresAt: NOW - 1 }));
cs('tampered-body', { ...mk(), body: { ...mk().body, version: 9 } });
cs('tampered-signature', { ...mk(), sig: chr(mk().sig, 4) });
cs('tampered-pq-signature', { ...mk(), pq_sig: chr(mk().pq_sig, 400) });
cs('unknown-issuer', { ...mk(), issuer: 'other' });
cs('not-an-object', null);
cs('empty-source-keys', mk(), { issuerKeys: {} });
cs('wrong-issuer-key', mk(), { issuerKeys: { rel: { alg: 'hybrid-ed25519-ml-dsa-65', keys: suiteKey('maa/other', 'hybrid-ed25519-ml-dsa-65').pub } } });

// ---- corroboration ----
const co = (nm: string, sets: any, k: any, opts: any) => add('corroborate', nm, [sets, k, opts], run(() => K.corroborateMaaKeySets(sets, k, opts)));
const obs = (v: string, j: any, issuer = WUS) => ({ vantage: v, issuer, jwks: j });
const COPT = { issuer: WUS, nowMs: NOW };
co('three-agree', [obs('gcb', JW), obs('aci', JW), obs('local', JW)], 3, COPT);
co('two-of-two', [obs('a', JW), obs('b', JW)], 2, COPT);
co('k-below-vantages', [obs('a', JW), obs('b', JW), obs('c', JW)], 2, COPT);
co('one-vantage-k2', [obs('a', JW)], 2, COPT);
co('k-one', [obs('a', JW), obs('b', JW)], 1, COPT);
co('k-fraction', [obs('a', JW), obs('b', JW)], 2.5, COPT);
co('k-string', [obs('a', JW), obs('b', JW)], '2', COPT);
co('same-label-twice-counts-once', [obs('a', JW), obs('a', JW), obs('b', JW)], 3, COPT);
co('same-label-different-sets', [obs('a', JW), obs('a', { keys: [JW.keys[0]] })], 2, COPT);
co('disagree-one-key-missing', [obs('a', JW), obs('b', { keys: [JW.keys[0]] })], 2, COPT);
co('disagree-third-vantage', [obs('a', JW), obs('b', JW), obs('c', { keys: [JW.keys[3]] })], 2, COPT);
co('vantage-sees-no-valid-key', [obs('a', JW), obs('b', { keys: [{ kid: 'x', x5c: [syn.wildcard.der] }] })], 2, COPT);
co('empty-jwks', [obs('a', JW), obs('b', { keys: [] })], 2, COPT);
co('wrong-issuer-observation', [obs('a', JW), obs('b', JW, EUS)], 2, COPT);
co('issuer-invalid', [obs('a', JW), obs('b', JW)], 2, { issuer: WUS + '/', nowMs: NOW });
co('now-fraction', [obs('a', JW), obs('b', JW)], 2, { issuer: WUS, nowMs: NOW + 0.5 });
co('sets-not-array', 'x', 2, COPT);
co('label-empty', [obs('', JW), obs('b', JW)], 2, COPT);
co('label-100', [obs('a'.repeat(100), JW), obs('b', JW)], 2, COPT);
co('label-101', [obs('a'.repeat(101), JW), obs('b', JW)], 2, COPT);
co('label-number', [{ vantage: 5, issuer: WUS, jwks: JW }, obs('b', JW)], 2, COPT);
co('observation-null', [null, obs('b', JW)], 2, COPT);
co('policy-chain-root', [obs('a', JW), obs('b', JW)], 2, { ...COPT, policy: { chainRootSpkiSha256: [MS_ROOT] } });
co('policy-max-age', [obs('a', JW), obs('b', JW)], 2, { ...COPT, policy: { maxKeyAgeMs: 1000 } });
co('far-future-no-valid-keys', [obs('a', JW), obs('b', JW)], 2, { issuer: WUS, nowMs: Date.parse('2031-01-01T00:00:00Z') });
for (const v of ['aci', 'gcb', 'local']) {
  // the shipped vantage observations of the pin ceremony list the chain per key; here the live sets are what matter
  void v;
}
co('eus-three-agree', [obs('a', JE, EUS), obs('b', JE, EUS), obs('c', JE, EUS)], 3, { issuer: EUS, nowMs: NOW });

// ---- scripted fetch ----
const respOf = (r: any) => {
  if (r.$throws) throw new Error(r.$throws);
  const text = r.body && typeof r.body === 'object' && '$text' in r.body ? r.body.$text : r.bodyBytes ? null : JSON.stringify(r.body);
  const body = r.bodyBytes ? Buffer.from(r.bodyBytes.$bytes, 'base64url') : text;
  const res: any = new Response(body, { status: r.status ?? 200, headers: { 'content-type': 'application/json', ...(r.contentLength !== undefined ? { 'content-length': String(r.contentLength) } : {}) } });
  if (r.url !== undefined) Object.defineProperty(res, 'url', { value: r.url });
  return res;
};
const jwksResp = (j: any) => ({ body: j });
const seqFetch = (steps: any[], log: string[]) => { let i = 0; return (async (url: any, init: any) => { log.push(String(url) + (init?.redirect === 'error' ? ' [redirect:error]' : '')); const s = steps[Math.min(i++, steps.length - 1)]; return respOf('keys' in s && !('body' in s) ? jwksResp(s) : s); }) as any; };
const fc = async (nm: string, issuer: string, response: any, opts: any = {}) => {
  const log: string[] = [];
  let out: any;
  try { out = { ok: true, jwks: J(await K.fetchMaaCerts(issuer, { fetch: seqFetch([response], log), ...opts })) }; } catch (e: any) { out = { ok: false, error: e instanceof Error ? e.message : String(e) }; }
  out.requests = log;
  add('fetchCerts', nm, [{ issuer, response, ...(Object.keys(opts).length ? { opts } : {}) }], out);
};
const KEYS1 = { keys: [{ kid: 'a', kty: 'RSA', alg: 'RS256', x5c: [syn.ok.der], extra: 1 }] };
await fc('ok', WUS, jwksResp(KEYS1));
await fc('ok-real', WUS, jwksResp(JW));
await fc('http-404', WUS, { status: 404, body: {} });
await fc('http-500', WUS, { status: 500, body: {} });
await fc('url-redirect', WUS, { ...jwksResp(KEYS1), url: WUS + '/other' });
await fc('url-same', WUS, { ...jwksResp(KEYS1), url: WUS + '/certs' });
await fc('content-length-over', WUS, { ...jwksResp(KEYS1), contentLength: 2_000_000 });
await fc('content-length-at-limit-body-small', WUS, { ...jwksResp(KEYS1), contentLength: 1_048_576 });
await fc('body-over-limit', WUS, jwksResp(KEYS1), { maxBytes: 20 });
await fc('body-exactly-limit', WUS, { body: { $text: '{"keys":[]}' } }, { maxBytes: 11 });
await fc('body-one-over-limit', WUS, { body: { $text: '{"keys":[]}' } }, { maxBytes: 10 });
await fc('body-not-json', WUS, { body: { $text: 'nope' } });
await fc('body-invalid-utf8', WUS, { bodyBytes: B8(Buffer.from([0x7b, 0xff, 0x7d])) });
await fc('body-bom', WUS, { bodyBytes: B8(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from('{"keys":[]}')])) });
await fc('keys-missing', WUS, { body: {} });
await fc('keys-not-array', WUS, { body: { keys: {} } });
await fc('json-null', WUS, { body: null });
await fc('too-many-keys', WUS, jwksResp({ keys: Array.from({ length: 33 }, () => ({ x5c: [syn.ok.der] })) }));
await fc('exactly-32-keys', WUS, jwksResp({ keys: Array.from({ length: 32 }, () => ({ x5c: [syn.ok.der] })) }));
await fc('key-not-object', WUS, jwksResp({ keys: [5] }));
await fc('key-null', WUS, jwksResp({ keys: [null] }));
await fc('x5c-missing', WUS, jwksResp({ keys: [{ kid: 'a' }] }));
await fc('x5c-empty', WUS, jwksResp({ keys: [{ x5c: [] }] }));
await fc('x5c-9-certs', WUS, jwksResp({ keys: [{ x5c: Array.from({ length: 9 }, () => 'AAAA') }] }));
await fc('x5c-8-certs', WUS, jwksResp({ keys: [{ x5c: Array.from({ length: 8 }, () => 'AAAA') }] }));
await fc('x5c-entry-number', WUS, jwksResp({ keys: [{ x5c: [5] }] }));
await fc('x5c-entry-empty', WUS, jwksResp({ keys: [{ x5c: [''] }] }));
await fc('x5c-entry-131073', WUS, jwksResp({ keys: [{ x5c: ['A'.repeat(131_073)] }] }), { maxBytes: 4_000_000 });
await fc('kid-number-dropped', WUS, jwksResp({ keys: [{ kid: 5, kty: 6, alg: 7, x5c: ['AAAA'] }] }));
await fc('fetch-throws', WUS, { $throws: 'network down' });
await fc('issuer-http', 'http://sharedwus.wus.attest.azure.net', jwksResp(KEYS1));
await fc('issuer-path', WUS + '/path', jwksResp(KEYS1));
await fc('issuer-trailing-slash', WUS + '/', jwksResp(KEYS1));
await fc('issuer-port', 'https://a.example.net:8443', jwksResp(KEYS1));
await fc('issuer-uppercase', 'https://A.example.net', jwksResp(KEYS1));
await fc('issuer-empty', '', jwksResp(KEYS1));
function B8(b: Buffer) { return { $bytes: b64u(b) }; }

// ---- trust store ----
const stateOf = (issuer: string, fetchedAtMs: number, anchors: any[]) => ({ v: 1, issuer, fetchedAtMs, anchors });
const anc = (spki: string, o2: any = {}) => ({ spki, kind: 'self-signed', notBeforeMs: NOW - 10 * DAY, notAfterMs: NOW + 300 * DAY, firstSeenMs: NOW - 5 * DAY, ...o2 });
const trustRun = async (nm: string, sc: any) => {
  sc = JSON.parse(JSON.stringify(sc));
  const store = (() => { const m = new Map<string, any>(); for (const [k, v] of Object.entries(sc.initial ?? {})) m.set(k, JSON.parse(JSON.stringify(v))); return { get: (i: string) => m.get(i), set: (i: string, s: any) => void m.set(i, JSON.parse(JSON.stringify(s))), snap: () => Object.fromEntries(m) }; })();
  const log: string[] = [];
  const results: any[] = [];
  let out: any;
  try {
    const t = K.createMaaKeyTrust({ policy: sc.policy, store, fetch: seqFetch(sc.fetches, log) });
    for (const c of sc.calls) results.push(J(await t.getTrustAnchors(c.issuer, { nowMs: c.nowMs, ...(c.repin ? { repin: c.repin } : {}) })));
    out = { results, store: J(store.snap()), fetches: log };
  } catch (e: any) { out = { $throws: e instanceof Error ? e.message : String(e) }; }
  add('trust', nm, [sc], out);
};
const CALL = (nowMs = NOW, issuer = WUS, extra: any = {}) => ({ issuer, nowMs, ...extra });
const tp = (over: any = {}) => ({ trustedIssuers: [WUS], allowTrustOnFirstUse: true, builtinPins: false, ...over });
const A1 = { keys: [JW.keys[0]] }, A2 = { keys: [JW.keys[3]] }, AB = { keys: [JW.keys[0], JW.keys[3]] };
await trustRun('tofu-first-fetch', { policy: tp(), fetches: [AB], calls: [CALL()] });
await trustRun('tofu-off-refuses', { policy: tp({ allowTrustOnFirstUse: false }), fetches: [AB], calls: [CALL()] });
await trustRun('initial-pins-baseline', { policy: tp({ allowTrustOnFirstUse: false, initialPins: { [WUS]: [SPKI_A.toUpperCase()] } }), fetches: [AB], calls: [CALL()] });
await trustRun('initial-pins-no-overlap', { policy: tp({ allowTrustOnFirstUse: false, initialPins: { [WUS]: ['00'.repeat(32)] } }), fetches: [AB], calls: [CALL()] });
await trustRun('cache-hit-within-ttl', { policy: tp(), fetches: [AB, A1], calls: [CALL(), CALL(NOW + 30 * 60_000)] });
await trustRun('cache-expired-refetch', { policy: tp(), fetches: [AB, A1], calls: [CALL(), CALL(NOW + 2 * HOUR)] });
await trustRun('ttl-custom', { policy: tp({ ttlMs: 1000 }), fetches: [AB, AB], calls: [CALL(), CALL(NOW + 1000)] });
await trustRun('rotation-one-new-key', { policy: tp(), fetches: [A1, AB], calls: [CALL(), CALL(NOW + 2 * HOUR)] });
await trustRun('rotation-no-overlap', { policy: tp(), fetches: [A1, A2], calls: [CALL(), CALL(NOW + 2 * HOUR)] });
await trustRun('rotation-no-overlap-not-required', { policy: tp({ requireOverlap: false }), fetches: [A1, A2], calls: [CALL(), CALL(NOW + 2 * HOUR)] });
await trustRun('too-many-new-keys', { policy: tp({ maxNewKeysPerFetch: 0 }), fetches: [A1, AB], calls: [CALL(), CALL(NOW + 2 * HOUR)] });
await trustRun('initial-too-many', { policy: tp({ maxInitialKeys: 1 }), fetches: [AB], calls: [CALL()] });
await trustRun('fetch-fails-no-state', { policy: tp(), fetches: [{ $throws: 'down' }], calls: [CALL()] });
await trustRun('fetch-fails-stale-cache', { policy: tp(), fetches: [AB, { $throws: 'down' }], calls: [CALL(), CALL(NOW + 3 * HOUR)] });
await trustRun('fetch-fails-stale-exceeded', { policy: tp(), fetches: [AB, { $throws: 'down' }], calls: [CALL(), CALL(NOW + 30 * HOUR)] });
await trustRun('fetch-fails-stale-custom-limit', { policy: tp({ maxStaleMs: 2 * HOUR }), fetches: [AB, { $throws: 'down' }], calls: [CALL(), CALL(NOW + 3 * HOUR)] });
await trustRun('fetch-http-500-stale', { policy: tp(), fetches: [AB, { status: 500, body: {} }], calls: [CALL(), CALL(NOW + 3 * HOUR)] });
await trustRun('untrusted-issuer', { policy: tp(), fetches: [AB], calls: [CALL(NOW, EUS)] });
await trustRun('now-fraction', { policy: tp(), fetches: [AB], calls: [CALL(NOW + 0.5)] });
await trustRun('no-valid-keys-empty-jwks', { policy: tp(), fetches: [{ keys: [] }], calls: [CALL()] });
await trustRun('no-valid-keys-all-expired', { policy: tp(), fetches: [AB], calls: [CALL(Date.parse('2030-01-01T00:00:00Z'))] });
await trustRun('state-clock-regression', { policy: tp(), initial: { [WUS]: stateOf(WUS, NOW, [anc(SPKI_A)]) }, fetches: [AB], calls: [CALL(NOW - 10 * 60_000)] });
await trustRun('state-clock-within-skew', { policy: tp(), initial: { [WUS]: stateOf(WUS, NOW, [anc(SPKI_A)]) }, fetches: [AB], calls: [CALL(NOW - 30_000)] });
for (const [nm, st] of [['not-object', 5], ['wrong-version', { ...stateOf(WUS, NOW, []), v: 2 }], ['wrong-issuer', stateOf(EUS, NOW, [])], ['fetched-fraction', stateOf(WUS, NOW + 0.5, [])], ['anchors-not-array', { ...stateOf(WUS, NOW, []), anchors: {} }], ['anchor-bad-spki', stateOf(WUS, NOW, [anc('xyz')])], ['anchor-upper-spki', stateOf(WUS, NOW, [anc(SPKI_A.toUpperCase())])], ['anchor-bad-kind', stateOf(WUS, NOW, [anc(SPKI_A, { kind: 'x' })])], ['anchor-bad-time', stateOf(WUS, NOW, [anc(SPKI_A, { notAfterMs: 1.5 })])]] as any[]) await trustRun('corrupt-state-' + nm, { policy: tp(), initial: { [WUS]: st }, fetches: [AB], calls: [CALL()] });
await trustRun('state-anchor-expired-refetches', { policy: tp(), initial: { [WUS]: stateOf(WUS, NOW - 10 * HOUR, [anc(SPKI_A, { notAfterMs: NOW - 5 * HOUR })]) }, fetches: [AB], calls: [CALL()] });
await trustRun('state-fresh-cache-uses-state', { policy: tp(), initial: { [WUS]: stateOf(WUS, NOW - 10 * 60_000, [anc(SPKI_A), anc(SPKI_B)]) }, fetches: [{ $throws: 'must not be called' }], calls: [CALL()] });
await trustRun('state-firstseen-kept', { policy: tp(), initial: { [WUS]: stateOf(WUS, NOW - 2 * HOUR, [anc(SPKI_A, { firstSeenMs: 123 })]) }, fetches: [AB], calls: [CALL()] });
await trustRun('state-fetchedat-monotone', { policy: tp(), initial: { [WUS]: stateOf(WUS, NOW + 30_000, [anc(SPKI_A)]) }, fetches: [AB], calls: [CALL(NOW + 2 * HOUR)] });
// the release-signed repin and the built-in pins
const OPKEY = suiteKey('maa/repin', 'ed25519');
const OPK = { rel: { alg: 'ed25519', keys: OPKEY.pub } };
const repinMan = (entries2: any[], over: any = {}) => AL.signAllowlistManifest({ version: over.version ?? 1, issuedAt: NOW, notBefore: NOW - DAY, expiresAt: NOW + 30 * DAY, entries: entries2 }, { issuer: 'rel', alg: 'ed25519', secrets: OPKEY.secrets });
const rp = (entries2: any[], over: any = {}, verify: any = {}) => ({ manifest: repinMan(entries2, over), verify: { issuerKeys: OPK, ...verify } });
await trustRun('repin-approves-disjoint-set', { policy: tp({ allowTrustOnFirstUse: false }), fetches: [AB], calls: [CALL(NOW, WUS, { repin: rp([{ kind: 'maa-signing-spki', value: SPKI_A, label: WUS }]) })] });
await trustRun('repin-wrong-issuer-label', { policy: tp({ allowTrustOnFirstUse: false }), fetches: [AB], calls: [CALL(NOW, WUS, { repin: rp([{ kind: 'maa-signing-spki', value: SPKI_A, label: EUS }]) })] });
await trustRun('repin-revokes-key', { policy: tp(), fetches: [AB], calls: [CALL(NOW, WUS, { repin: rp([{ kind: 'maa-signing-spki', value: SPKI_A, label: WUS, revoked: true }]) })] });
await trustRun('repin-revokes-all', { policy: tp(), fetches: [AB], calls: [CALL(NOW, WUS, { repin: rp([{ kind: 'maa-signing-spki', value: SPKI_A, label: WUS, revoked: true }, { kind: 'maa-signing-spki', value: SPKI_B, label: WUS, revoked: true }]) })] });
await trustRun('repin-bad-signature', { policy: tp(), fetches: [AB], calls: [CALL(NOW, WUS, { repin: { manifest: { ...repinMan([]), sig: chr(repinMan([]).sig, 3) }, verify: { issuerKeys: OPK } } })] });
await trustRun('repin-expired', { policy: tp(), fetches: [AB], calls: [CALL(NOW + 60 * DAY, WUS, { repin: rp([]) })] });
await trustRun('repin-min-version', { policy: tp(), fetches: [AB], calls: [CALL(NOW, WUS, { repin: rp([], {}, { minVersion: 2 }) })] });
await trustRun('repin-denies-cached-key', { policy: tp(), initial: { [WUS]: stateOf(WUS, NOW - 10 * 60_000, [anc(SPKI_A), anc(SPKI_B)]) }, fetches: [AB], calls: [CALL(NOW, WUS, { repin: rp([{ kind: 'maa-signing-spki', value: SPKI_A, label: WUS, revoked: true }]) })] });
const BUILTIN_TRUST = (over: any = {}) => ({ trustedIssuers: [WUS, EUS], ...over });
await trustRun('builtin-default-first-use', { policy: BUILTIN_TRUST(), fetches: [JW], calls: [CALL(NOW, WUS)] });
await trustRun('builtin-default-eus', { policy: BUILTIN_TRUST(), fetches: [JE], calls: [CALL(NOW, EUS)] });
await trustRun('builtin-with-chain-roots-from-pins', { policy: BUILTIN_TRUST(), fetches: [JW], calls: [CALL(NOW, WUS)] });
await trustRun('builtin-explicit-true', { policy: BUILTIN_TRUST({ builtinPins: true }), fetches: [JW], calls: [CALL(NOW, WUS)] });
await trustRun('builtin-off-no-baseline', { policy: BUILTIN_TRUST({ builtinPins: false }), fetches: [JW], calls: [CALL(NOW, WUS)] });
await trustRun('builtin-expired-refuses', { policy: BUILTIN_TRUST(), fetches: [JW], calls: [CALL(shipped.expiresAt + 1, WUS)] });
await trustRun('builtin-expired-with-tofu', { policy: BUILTIN_TRUST({ allowTrustOnFirstUse: true }), fetches: [JW], calls: [CALL(shipped.expiresAt + 1, WUS)] });
await trustRun('builtin-unknown-issuer-for-pins', { policy: BUILTIN_TRUST({ trustedIssuers: ['https://other.attest.azure.net'] }), fetches: [JW], calls: [CALL(NOW, 'https://other.attest.azure.net')] });
await trustRun('builtin-rotation-unknown-key-only', { policy: BUILTIN_TRUST(), fetches: [{ keys: [{ kid: 'x', x5c: [syn.ok.der] }] }], calls: [CALL(Date.parse('2026-12-01T00:00:00Z'), WUS)] });
await trustRun('builtin-custom-source', { policy: BUILTIN_TRUST({ builtinPins: { manifest: mk(), issuerKeys: REL } }), fetches: [JW], calls: [CALL(NOW, WUS)] });
await trustRun('builtin-custom-source-revoked-key', { policy: BUILTIN_TRUST({ builtinPins: { manifest: mk({ entries: entries(3).filter((e) => e.value !== SPKI_B).concat([{ kind: 'maa-signing-spki', value: SPKI_B, label: WUS, revoked: true } as any]) }), issuerKeys: REL } }), fetches: [JW], calls: [CALL(NOW, WUS)] });
await trustRun('builtin-custom-source-invalid', { policy: BUILTIN_TRUST({ builtinPins: { manifest: mk({ entries: entries(1) }), issuerKeys: REL } }), fetches: [JW], calls: [CALL(NOW, WUS)] });
await trustRun('builtin-explicit-initial-pins-win', { policy: BUILTIN_TRUST({ initialPins: { [WUS]: [SPKI_A] } }), fetches: [JW], calls: [CALL(NOW, WUS)] });
await trustRun('chain-root-pinned-by-policy', { policy: tp({ chainRootSpkiSha256: [MS_ROOT], chainLeafCn: [LEAF_CN] }), fetches: [JW], calls: [CALL(NOW, WUS)] });
await trustRun('chain-intermediate-pinned-by-policy', { policy: tp({ chainRootSpkiSha256: [MS_ROOT], chainIntermediateSpkiSha256: [MS_PCA], chainLeafCn: [LEAF_CN] }), fetches: [JW], calls: [CALL(NOW, WUS)] });
await trustRun('two-issuers-independent', { policy: tp({ trustedIssuers: [WUS, EUS] }), fetches: [JW, JE], calls: [CALL(NOW, WUS), CALL(NOW, EUS), CALL(NOW + 60_000, WUS)] });
await trustRun('policy-snapshot-clock-skew', { policy: tp({ clockSkewMs: 0 }), fetches: [AB], calls: [CALL(Date.parse('2026-09-30T00:00:00Z'))] });

// ---- durable store adapter ----
{
  const kvs = async (nm: string, steps: any[]) => {
    const kv = createMemoryDurableKv();
    const st = K.durableMaaKeyStateStore(kv);
    const out: any[] = [];
    for (const s of steps) {
      if ('set' in s) { await st.set(s.set[0], s.set[1]); out.push(null); } else out.push(J((await st.get(s.get)) ?? null));
    }
    add('kvStore', nm, [{ steps }], { results: out, kv: J(Object.fromEntries([...kv.snapshot()])) });
  };
  const S = (t: number, spki = SPKI_A) => stateOf(WUS, t, [anc(spki)]);
  await kvs('set-get', [{ set: [WUS, S(100)] }, { get: WUS }, { get: EUS }]);
  await kvs('monotone-older-ignored', [{ set: [WUS, S(200)] }, { set: [WUS, S(100, SPKI_B)] }, { get: WUS }]);
  await kvs('monotone-equal-replaces', [{ set: [WUS, S(200)] }, { set: [WUS, S(200, SPKI_B)] }, { get: WUS }]);
  await kvs('newer-replaces', [{ set: [WUS, S(100)] }, { set: [WUS, S(300, SPKI_B)] }, { get: WUS }]);
  await kvs('corrupt-previous-overwritten', [{ set: [WUS, 'junk'] }, { set: [WUS, S(100)] }, { get: WUS }]);
}
// ---- construction ----
const bt = (nm: string, c: any) => add('buildTrust', nm, [c], run(() => { K.createMaaKeyTrust({ policy: c.policy, store: K.createMemoryMaaKeyStateStore(), fetch: c.noFetch ? undefined : async () => new Response('{}') }); return { built: true }; }));
bt('ok', { policy: tp() });
bt('no-fetch', { policy: tp(), noFetch: true });
bt('no-issuers', { policy: tp({ trustedIssuers: [] }) });
bt('issuers-missing', { policy: { builtinPins: false } });
bt('issuer-http', { policy: tp({ trustedIssuers: ['http://a.example.net'] }) });
bt('issuer-path', { policy: tp({ trustedIssuers: [WUS + '/x'] }) });
bt('issuer-trailing-slash', { policy: tp({ trustedIssuers: [WUS + '/'] }) });
bt('issuer-port-ok', { policy: tp({ trustedIssuers: ['https://a.example.net:8443'] }) });
bt('one-bad-of-two', { policy: tp({ trustedIssuers: [WUS, 'https://A.example.net'] }) });
void seed; void sd; void unb; void T0; void secretsOfSpec; void readFileSync; void fx; void PKGSRC;

refWriteBlobs(o, 'attest-maa');
