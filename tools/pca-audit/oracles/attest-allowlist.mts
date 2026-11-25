// Oracle: packages/pca/src/attest-allowlist.ts (signed, versioned, expiring measurement-allowlist manifests: verify / durable verify / create / sign /
// revoke / project / policy fields) and attest-allowlist-anchor.ts (the transparency anchor: commit, operator log, anchor + refresh head, evidence,
// verifyAllowlistAnchored, anchorEntryOf), TS reference. Writes out/ref-attest-allowlist.json.gz. Deterministic: every suite signs deterministically,
// keys derive from seed labels (the strip tool rewrites `seed` / `edSecret` / `secret` members to {"$seed": label}), every time is an argument.
// The anchor corpus replays the committed conformance vectors (conformance/allowlist-anchor-vectors.json, 74 rows) and adds the operator side.
//
// PORTING (fn(args) -> native entry point; JSON values; a reference throw ({"$throws"}) only requires the native to refuse; {"$num": "NaN"|"Infinity"|
// "-Infinity"} anywhere in args is that non-finite double)
//   issuerKeys = {<issuerId>: {alg, keys: {edPub?, mlDsaPub?, slhDsaPub?, mlDsa87Pub?, slhDsa256sPub?}, notAfter?}}   (public keys, base64url)
//   keySpec    = {alg, edSecret?, seed?}  secrets of a SIGN case: edSecret = Ed25519 secret, seed = the ML-DSA keygen seed (ml-dsa-65 / ml-dsa-87 suites)
//   constants []                                              -> {ALLOWLIST_KINDS, DOMAIN: "pca-attest-allowlist/v1\n"}
//   verifyAllowlistManifest [manifest, opts]                  -> {ok, body, issuer, alg, version, digest} | {ok:false, code, reason (not compared beyond code)}
//   verifyAllowlistDurable [{opts, initial?, steps}]          -> {results: [...], kv}  steps run in order against ONE in-memory kv (key "allowlist/<issuer>"
//                                                                holds {version, digest}); initial = {key: value} pre-seeded raw state; kv = final state
//   createAllowlistManifest [body]                            -> body (throws on any violation)
//   signAllowlistManifest [body, {issuer, alg, keySpec}]      -> {body, issuer, alg, sig, pq_sig?}   exact bytes (all signing suites here are deterministic)
//   revokeAllowlistEntry [prevBody, rev, times]               -> body (throws)
//   driverVersionSlotHex [v]                                  -> string | throws
//   projectAllowlist [verifiedOk, {nowMs}]                    -> AllowlistProjection; verifiedOk = the {ok:true, body, issuer, alg, version, digest} result
//   policyFields [fn, projection]                             -> azureMaaPolicyFields | intelDcapPolicyFields | sevSnpPolicyFields | gcpCsPolicyFields | nvidiaCcPolicyFields
//   anchorCommit [entry]                                      -> string (allowlistAnchorCommit)
//   anchorEntryOf [verifiedOk]                                -> {issuer, version, digest}
//   anchorOps [{instanceId, principal, secret, ops}]          -> [result per op]; secret = the log guardian's Ed25519 secret; ops run on ONE log:
//        {anchor: entryOrVerifiedOk, nowMs} -> evidence | {$throws}; {refresh: nowMs} -> head | {$throws}; {evidenceFor: index, cached?: {size}} -> evidence | {$throws};
//        {latest: true} -> head | null; {entries: true} -> [entry]
//   verifyAnchored [{verified, evidence, opts}]               -> {ok, issuer, version, digest, highestAnchoredVersion, head} | {ok:false, code}
//        verified = {issuer, version, digest} (the entry of a verified manifest); opts = {trust, nowMs, maxHeadAgeMs?, clockSkewMs?, cachedHead?}
import { createHash } from 'node:crypto';
import { Oracle, refWrite, seed, variants } from './lib.mjs';
import { b64u, B, unb, sd, suiteKey, secretsOfSpec, chr, T0 } from './attest-roots-kit.mts';
const { publicKeyOf }: any = await import('../../../packages/pca/src/keys.ts');
const { createMemoryDurableKv }: any = await import('../../../packages/pca/src/durable-state.ts');
const { buildAnchorVectors }: any = await import('../../../packages/pca/src/test-support/anchor-vectors.ts');

const A: any = await import('../../../packages/pca/src/attest-allowlist.ts');
const N: any = await import('../../../packages/pca/src/attest-allowlist-anchor.ts');
const o = new Oracle('attest-allowlist', 'tools/pca-audit/oracles/attest-allowlist.mts', 'TS-reference oracle for the signed measurement-allowlist manifests and their transparency anchor.');
const J = (x: any) => JSON.parse(JSON.stringify(x, (_k, v) => (v instanceof Uint8Array ? { $bytes: b64u(v) } : v)));
const num = (v: any): any => (v && typeof v === 'object' && !Array.isArray(v) && typeof v.$num === 'string' && Object.keys(v).length === 1 ? Number(v.$num) : Array.isArray(v) ? v.map(num) : v && typeof v === 'object' ? Object.fromEntries(Object.keys(v).map((k) => [k, num(v[k])])) : v);
const run = (fn: () => any) => { try { return J(fn()); } catch (e: any) { return { $throws: e instanceof Error ? e.message : String(e) }; } };
const arun = async (fn: () => Promise<any>) => { try { return J(await fn()); } catch (e: any) { return { $throws: e instanceof Error ? e.message : String(e) }; } };
const add = (fn: string, name: string, args: any[], out: any) => o.add(fn, name, args, out);

const H96 = (n: number) => n.toString(16).padStart(2, '0').repeat(48);
const H64 = (n: number) => n.toString(16).padStart(2, '0').repeat(32);
const ISS = 'https://sharedwus.wus.attest.azure.net';
const T = T0;
const E = (kind: string, value: string, label = 'l', extra: any = {}) => ({ kind, value, label, ...extra });
const BODY = (over: any = {}) => ({ version: 3, issuedAt: T - 1000, notBefore: T - 1000, expiresAt: T + 86_400_000, entries: [E('tdx-mrtd', H96(1)), E('sev-snp-measurement', H96(2), 'snp'), E('gcp-image-digest', 'sha256:' + H64(3), 'img'), E('maa-signing-spki', H64(4), ISS)], ...over });

// issuer keys, one per suite
const ALGS = ['ed25519', 'ml-dsa-65', 'hybrid-ed25519-ml-dsa-65', 'hybrid-nested-ed25519-ml-dsa-65', 'ml-dsa-87', 'hybrid-ed25519-ml-dsa-87', 'slh-dsa-sha2-128f', 'hybrid-ed25519-slh-dsa-sha2-128f', 'slh-dsa-sha2-256s'];
const KEYS: Record<string, ReturnType<typeof suiteKey>> = {};
for (const a of ALGS) KEYS[a] = suiteKey('allowlist/issuer/' + a, a);
const ed = KEYS['ed25519']!;
const reg = (alg: string, over: any = {}) => ({ alg, keys: KEYS[alg]!.pub, ...over });
const ik = (id = 'ops', alg = 'ed25519', over: any = {}) => ({ [id]: reg(alg, over) });
const sign = (body: any, alg = 'ed25519', issuer = 'ops') => A.signAllowlistManifest(body, { issuer, alg, secrets: KEYS[alg]!.secrets });
const OPTS = (over: any = {}) => ({ issuerKeys: ik(), nowMs: T, ...over });
const ver = (nm: string, manifest: any, opts: any) => add('verifyAllowlistManifest', nm, [manifest, opts], run(() => A.verifyAllowlistManifest(num(manifest), num(opts))));

add('constants', 'all', [], J({ ALLOWLIST_KINDS: A.ALLOWLIST_KINDS, DOMAIN: 'pca-attest-allowlist/v1\n' }));

// ---- verify: every suite ----
for (const a of ALGS) ver('ok-' + a, sign(BODY(), a), OPTS({ issuerKeys: ik('ops', a) }));
const M0 = sign(BODY());
const D0 = A.verifyAllowlistManifest(M0, OPTS()).digest;
ver('ok-opts-min-version-equal', M0, OPTS({ minVersion: 3 }));
ver('ok-last-seen-equal-same-digest', M0, OPTS({ lastSeenVersion: 3, lastSeenDigest: D0 }));
ver('ok-last-seen-equal-no-digest', M0, OPTS({ lastSeenVersion: 3 }));
ver('ok-last-seen-older', M0, OPTS({ lastSeenVersion: 2, lastSeenDigest: 'whatever' }));
ver('ok-max-lifetime-equal', M0, OPTS({ maxLifetimeMs: 86_401_000 }));
ver('ok-skew-covers-not-yet-valid', M0, OPTS({ nowMs: T - 1000 - 500, clockSkewMs: 500 }));
ver('ok-skew-covers-expired', M0, OPTS({ nowMs: T + 86_400_000 + 500, clockSkewMs: 500 }));
ver('ok-negative-skew-is-zero', M0, OPTS({ clockSkewMs: -5000 }));
ver('ok-not-before-boundary', M0, OPTS({ nowMs: T - 1000 }));
ver('ok-expires-boundary', M0, OPTS({ nowMs: T + 86_400_000 }));
ver('ok-issuer-not-after-equal', M0, OPTS({ issuerKeys: ik('ops', 'ed25519', { notAfter: T }) }));
ver('ok-all-kinds', sign(BODY({ entries: [E('tdx-mrtd', H96(1)), E('tdx-rtmr', H96(2)), E('sev-snp-measurement', H96(3)), E('gcp-image-digest', 'sha256:' + H64(4), 'i'), E('nvidia-measurement', H96(5)), E('nvidia-driver-version', '595.71.05'), E('maa-signing-spki', H64(6), ISS), E('maa-chain-root-spki', H64(7)), E('maa-chain-intermediate-spki', H64(8)), E('attest-corroboration', H64(9), 'vantages=3;method=three clouds'), E('tdx-mrtd', H96(1), 'second-label-same-kind-dup-value-different')].slice(0, 10) })), OPTS());
ver('ok-empty-entries', sign(BODY({ entries: [] })), OPTS());
ver('ok-entry-not-after-and-revoked', sign(BODY({ entries: [E('tdx-mrtd', H96(1), 'l', { notAfter: 5, revoked: true })] })), OPTS());
ver('ok-same-maa-spki-two-issuers', sign(BODY({ entries: [E('maa-signing-spki', H64(4), ISS), E('maa-signing-spki', H64(4), 'https://other.example.net')] })), OPTS());
// codes
ver('unknown-issuer', M0, OPTS({ issuerKeys: ik('other') }));
ver('unknown-issuer-proto-key', { ...M0, issuer: 'constructor' }, OPTS());
ver('issuer-expired', M0, OPTS({ issuerKeys: ik('ops', 'ed25519', { notAfter: T - 1 }) }));
ver('alg-mismatch', M0, OPTS({ issuerKeys: ik('ops', 'ml-dsa-65') }));
ver('bad-signature-flipped', { ...M0, sig: chr(M0.sig, 4) }, OPTS());
ver('bad-signature-other-key', M0, OPTS({ issuerKeys: { ops: { alg: 'ed25519', keys: { edPub: b64u(publicKeyOf(seed('allowlist/other-key'))) } } } }));
ver('bad-signature-body-edited', { ...M0, body: { ...M0.body, version: 4 } }, OPTS());
ver('bad-signature-entry-added', { ...M0, body: { ...M0.body, entries: [...M0.body.entries, E('tdx-rtmr', H96(9))] } }, OPTS());
ver('bad-signature-entry-order', { ...M0, body: { ...M0.body, entries: [...M0.body.entries].reverse() } }, OPTS());
ver('bad-signature-empty', { ...M0, sig: '' }, OPTS());
ver('bad-signature-wrong-domain-alg', sign(BODY(), 'ml-dsa-65'), OPTS({ issuerKeys: { ops: { alg: 'ml-dsa-65', keys: KEYS['ed25519']!.pub } } }));
ver('bad-signature-hybrid-pq-flipped', (() => { const m = sign(BODY(), 'hybrid-ed25519-ml-dsa-65'); return { ...m, pq_sig: chr(m.pq_sig, 100) }; })(), OPTS({ issuerKeys: ik('ops', 'hybrid-ed25519-ml-dsa-65') }));
ver('bad-signature-hybrid-ed-flipped', (() => { const m = sign(BODY(), 'hybrid-ed25519-ml-dsa-65'); return { ...m, sig: chr(m.sig, 5) }; })(), OPTS({ issuerKeys: ik('ops', 'hybrid-ed25519-ml-dsa-65') }));
ver('bad-signature-hybrid-missing-pq-key', sign(BODY(), 'hybrid-ed25519-ml-dsa-65'), OPTS({ issuerKeys: { ops: { alg: 'hybrid-ed25519-ml-dsa-65', keys: { edPub: KEYS['hybrid-ed25519-ml-dsa-65']!.pub.edPub } } } }));
ver('not-yet-valid', M0, OPTS({ nowMs: T - 1001 }));
ver('not-yet-valid-skew-short', M0, OPTS({ nowMs: T - 1501, clockSkewMs: 500 }));
ver('expired', M0, OPTS({ nowMs: T + 86_400_001 }));
ver('expired-skew-short', M0, OPTS({ nowMs: T + 86_400_501, clockSkewMs: 500 }));
ver('rollback', M0, OPTS({ lastSeenVersion: 4 }));
ver('below-min-version', M0, OPTS({ minVersion: 4 }));
ver('conflict', M0, OPTS({ lastSeenVersion: 3, lastSeenDigest: 'x'.repeat(43) }));
ver('lifetime-too-long', M0, OPTS({ maxLifetimeMs: 86_400_999 }));
ver('lifetime-negative-limit', M0, OPTS({ maxLifetimeMs: -1 }));
// precedence: several faults at once
ver('precedence-expired-over-rollback', M0, OPTS({ nowMs: T + 86_400_001, lastSeenVersion: 9 }));
ver('precedence-lifetime-over-min-version', M0, OPTS({ maxLifetimeMs: 1, minVersion: 9 }));
ver('precedence-min-version-over-rollback', M0, OPTS({ minVersion: 9, lastSeenVersion: 9 }));
ver('precedence-rollback-over-conflict', M0, OPTS({ lastSeenVersion: 4, lastSeenDigest: 'x' }));
ver('precedence-bad-signature-over-expired', { ...M0, sig: chr(M0.sig, 4) }, OPTS({ nowMs: T + 86_400_001 }));
ver('precedence-unknown-issuer-over-signature', { ...M0, sig: chr(M0.sig, 4) }, OPTS({ issuerKeys: ik('other') }));
ver('precedence-alg-mismatch-over-issuer-expired', M0, OPTS({ issuerKeys: ik('ops', 'ml-dsa-65', { notAfter: 1 }) }));
// non-finite / mistyped options
for (const [i, [k, v]] of ([['clockSkewMs', { $num: 'NaN' }], ['clockSkewMs', { $num: 'Infinity' }], ['clockSkewMs', '5'], ['maxLifetimeMs', { $num: 'NaN' }], ['maxLifetimeMs', { $num: 'Infinity' }], ['maxLifetimeMs', null], ['minVersion', { $num: 'NaN' }], ['minVersion', 1.5], ['minVersion', null], ['lastSeenVersion', { $num: 'NaN' }], ['lastSeenVersion', 2.5], ['lastSeenVersion', '3']] as any[]).entries()) ver(`opt-${k}-${i}`, M0, OPTS({ [k]: v }));
ver('opt-nowMs-fraction', M0, OPTS({ nowMs: T + 0.5 }));
ver('opt-nowMs-nan', M0, OPTS({ nowMs: { $num: 'NaN' } }));
ver('opt-nowMs-string', M0, OPTS({ nowMs: String(T) }));
ver('opt-nowMs-unsafe', M0, OPTS({ nowMs: 2 ** 53 }));
// manifest shapes
for (const [nm, m] of [['null', null], ['array', []], ['string', 'x'], ['number', 5], ['empty-object', {}], ['extra-member', { ...M0, extra: 1 }], ['no-sig', { ...M0, sig: undefined }], ['sig-number', { ...M0, sig: 5 }], ['issuer-empty', { ...M0, issuer: '' }], ['issuer-201', { ...M0, issuer: 'a'.repeat(201) }], ['issuer-number', { ...M0, issuer: 5 }], ['alg-unknown', { ...M0, alg: 'rsa' }], ['alg-number', { ...M0, alg: 5 }], ['alg-missing', { ...M0, alg: undefined }], ['pq-sig-on-pure', { ...M0, pq_sig: 'AAAA' }], ['pq-sig-number', { ...M0, pq_sig: 7 }], ['body-missing', { ...M0, body: undefined }], ['body-null', { ...M0, body: null }], ['body-array', { ...M0, body: [] }]] as any[]) ver('shape-' + nm, m, OPTS());
ver('shape-hybrid-without-pq-sig', (() => { const m = sign(BODY(), 'hybrid-ed25519-ml-dsa-65'); return { ...m, pq_sig: undefined }; })(), OPTS({ issuerKeys: ik('ops', 'hybrid-ed25519-ml-dsa-65') }));
ver('shape-issuer-200', sign(BODY(), 'ed25519', 'a'.repeat(200)), OPTS({ issuerKeys: ik('a'.repeat(200)) }));
ver('shape-opts-issuerkeys-empty', M0, { issuerKeys: {}, nowMs: T });
// body faults (the manifest is signed AFTER the fault is built so only the body validation can fail): unsigned form is enough since parse precedes the signature
const bad = (nm: string, body: any) => ver('body-' + nm, { body, issuer: 'ops', alg: 'ed25519', sig: M0.sig }, OPTS());
const B1 = BODY();
bad('extra-key', { ...B1, extra: 1 });
for (const k of ['version', 'issuedAt', 'notBefore', 'expiresAt', 'entries']) bad('missing-' + k, { ...B1, [k]: undefined });
for (const [i, v] of [0, -1, 1.5, '3', null, 2 ** 53, { $num: 'NaN' }].entries()) bad('version-' + i, { ...B1, version: v });
for (const k of ['issuedAt', 'notBefore', 'expiresAt']) for (const [i, v] of [-1, 1.5, '1', { $num: 'Infinity' }, 2 ** 53, -0].entries()) bad(`${k}-${i}`, { ...B1, [k]: v });
bad('not-before-equals-expires', { ...B1, notBefore: B1.expiresAt });
bad('not-before-after-expires', { ...B1, notBefore: B1.expiresAt + 1 });
bad('issued-after-expires', { ...B1, issuedAt: B1.expiresAt + 1 });
bad('issued-equals-expires', { ...B1, issuedAt: B1.expiresAt });
bad('issued-before-not-before-ok', { ...B1, issuedAt: B1.notBefore - 1 });
bad('entries-object', { ...B1, entries: {} });
bad('entries-10001', { ...B1, entries: Array.from({ length: 10_001 }, () => null) });
bad('entries-10000-null', { ...B1, entries: Array.from({ length: 10_000 }, () => null) });
bad('entry-null', { ...B1, entries: [null] });
bad('entry-array', { ...B1, entries: [[]] });
bad('entry-extra-key', { ...B1, entries: [{ ...E('tdx-mrtd', H96(1)), x: 1 }] });
bad('entry-kind-unknown', { ...B1, entries: [E('nope', H96(1))] });
bad('entry-kind-proto', { ...B1, entries: [E('constructor', H96(1))] });
bad('entry-kind-number', { ...B1, entries: [E(5 as any, H96(1))] });
bad('entry-value-number', { ...B1, entries: [E('tdx-mrtd', 5 as any)] });
bad('entry-label-number', { ...B1, entries: [E('tdx-mrtd', H96(1), 5 as any)] });
bad('entry-label-empty', { ...B1, entries: [E('tdx-mrtd', H96(1), '')] });
bad('entry-label-200', { ...B1, entries: [E('tdx-mrtd', H96(1), 'a'.repeat(200))] });
bad('entry-label-201', { ...B1, entries: [E('tdx-mrtd', H96(1), 'a'.repeat(201))] });
for (const c of ['\u0000', '\u001f', '\u007f', '\n', '\t']) bad('entry-label-control-' + c.charCodeAt(0), { ...B1, entries: [E('tdx-mrtd', H96(1), 'a' + c + 'b')] });
bad('entry-label-unicode-ok', { ...B1, entries: [E('tdx-mrtd', H96(1), 'é x')] });
bad('entry-not-after-negative', { ...B1, entries: [E('tdx-mrtd', H96(1), 'l', { notAfter: -1 })] });
bad('entry-not-after-fraction', { ...B1, entries: [E('tdx-mrtd', H96(1), 'l', { notAfter: 1.5 })] });
bad('entry-not-after-string', { ...B1, entries: [E('tdx-mrtd', H96(1), 'l', { notAfter: '5' })] });
bad('entry-revoked-false', { ...B1, entries: [E('tdx-mrtd', H96(1), 'l', { revoked: false })] });
bad('entry-revoked-string', { ...B1, entries: [E('tdx-mrtd', H96(1), 'l', { revoked: 'true' })] });
bad('entry-duplicate', { ...B1, entries: [E('tdx-mrtd', H96(1), 'a'), E('tdx-mrtd', H96(1), 'b')] });
bad('entry-same-value-different-kind-ok', { ...B1, entries: [E('tdx-mrtd', H96(1)), E('tdx-rtmr', H96(1))] });
bad('entry-maa-same-value-different-label-ok', { ...B1, entries: [E('maa-signing-spki', H64(1), ISS), E('maa-signing-spki', H64(1), 'https://b.example.net')] });
bad('entry-maa-duplicate-same-label', { ...B1, entries: [E('maa-signing-spki', H64(1), ISS), E('maa-signing-spki', H64(1), ISS)] });
// value grid per kind: the valid form, then each deviation
const KV: Record<string, [string, string][]> = {
  'tdx-mrtd': [['ok', H96(1)], ['upper', H96(1).toUpperCase()], ['95', H96(1).slice(1)], ['97', H96(1) + 'a'], ['nonhex', 'g' + H96(1).slice(1)], ['0x', '0x' + H96(1).slice(2)], ['empty', ''], ['space', H96(1).slice(0, 95) + ' ']],
  'tdx-rtmr': [['ok', H96(2)], ['upper', H96(2).toUpperCase()], ['short', H96(2).slice(2)]],
  'sev-snp-measurement': [['ok', H96(3)], ['upper', H96(3).toUpperCase()], ['short', H96(3).slice(2)]],
  'nvidia-measurement': [['ok', H96(4)], ['upper', H96(4).toUpperCase()], ['short', H96(4).slice(2)]],
  'gcp-image-digest': [['ok', 'sha256:' + H64(5)], ['no-prefix', H64(5)], ['upper-hex', 'sha256:' + H64(5).toUpperCase()], ['upper-prefix', 'SHA256:' + H64(5)], ['sha512', 'sha512:' + H64(5)], ['short', 'sha256:' + H64(5).slice(1)], ['long', 'sha256:' + H64(5) + '0']],
  'nvidia-driver-version': [['ok', '595.71.05'], ['two', '595.71'], ['one', '595'], ['four', '1.2.3.4'], ['five', '1.2.3.4.5'], ['16-chars', '123456.123456.1'], ['17-chars', '123456.123456.12'], ['7-digit', '1234567.1'], ['leading-zero', '0595.071'], ['alpha', '595.7a'], ['trailing-dot', '595.71.'], ['leading-dot', '.595.71'], ['empty', ''], ['space', '595. 71']],
  'maa-signing-spki': [['ok', H64(6)], ['upper', H64(6).toUpperCase()], ['short', H64(6).slice(1)]],
  'maa-chain-root-spki': [['ok', H64(7)], ['upper', H64(7).toUpperCase()], ['long', H64(7) + '0']],
  'maa-chain-intermediate-spki': [['ok', H64(8)], ['upper', H64(8).toUpperCase()], ['nonhex', 'z' + H64(8).slice(1)]],
  'attest-corroboration': [['ok', H64(9)], ['upper', H64(9).toUpperCase()], ['short', H64(9).slice(1)]],
};
for (const [kind, vals] of Object.entries(KV)) for (const [nm, v] of vals) bad(`value-${kind}-${nm}`, { ...B1, entries: [E(kind, v, kind === 'maa-signing-spki' ? ISS : kind === 'attest-corroboration' ? 'vantages=3;method=m' : 'l')] });
// label rules of maa-signing-spki and attest-corroboration
for (const [nm, l] of [['ok', ISS], ['http', 'http://x.example.net'], ['path', ISS + '/'], ['upper', 'https://SHARED.example.net'], ['port', 'https://a.example.net:8443'], ['port-6-digit', 'https://a.example.net:123456'], ['underscore', 'https://a_b.example.net'], ['trailing-dot', 'https://a.example.net.'], ['leading-hyphen', 'https://-a.example.net'], ['single-char', 'https://a'], ['query', ISS + '?x=1'], ['userinfo', 'https://u@a.example.net'], ['plain', 'label']] as any[]) bad('label-maa-' + nm, { ...B1, entries: [E('maa-signing-spki', H64(6), l)] });
for (const [nm, l] of [['ok', 'vantages=3;method=three clouds'], ['one', 'vantages=1;method=x'], ['zero', 'vantages=0;method=x'], ['leading-zero', 'vantages=03;method=x'], ['999', 'vantages=999;method=x'], ['1000', 'vantages=1000;method=x'], ['no-method', 'vantages=3;method='], ['method-150', 'vantages=3;method=' + 'a'.repeat(150)], ['method-151', 'vantages=3;method=' + 'a'.repeat(151)], ['non-ascii', 'vantages=3;method=é'], ['tab', 'vantages=3;method=a\tb'], ['spaces', 'vantages=3; method=x'], ['plain', 'label'], ['upper', 'Vantages=3;method=x']] as any[]) bad('label-corroboration-' + nm, { ...B1, entries: [E('attest-corroboration', H64(9), l)] });
// structural variants of a signed small manifest (every path: delete / hostile / boundary)
{
  const small = sign(BODY({ entries: [E('tdx-mrtd', H96(1)), E('maa-signing-spki', H64(4), ISS)] }));
  let n = 0;
  for (const [lab, v] of variants(small, { maxPaths: 80 })) { if (n++ > 700) break; ver('variant-' + lab.replace(/[^A-Za-z0-9/ =#+._-]/g, '?'), v, OPTS()); }
}

// ---- durable ----
{
  const dur = async (nm: string, opts: any, steps: any[], initial?: Record<string, unknown>) => {
    const kv = createMemoryDurableKv();
    for (const [k, v] of Object.entries(initial ?? {})) await kv.set(k, v);
    const results: any[] = [];
    for (const s of steps) results.push(J(await A.verifyAllowlistDurable(num(s), num(opts), kv)));
    const kvOut = Object.fromEntries([...kv.snapshot()]);
    add('verifyAllowlistDurable', nm, [{ opts, ...(initial ? { initial } : {}), steps }], { results, kv: J(kvOut) });
  };
  const m = (v: number, over: any = {}) => sign(BODY({ version: v, ...over }));
  const m3b = sign(BODY({ entries: [E('tdx-mrtd', H96(77))] }));
  await dur('first-accept', OPTS(), [m(3)]);
  await dur('ascending', OPTS(), [m(1), m(2), m(5)]);
  await dur('rollback-after-newer', OPTS(), [m(5), m(3)]);
  await dur('same-version-same-body-again', OPTS(), [m(3), m(3)]);
  await dur('same-version-different-body-conflict', OPTS(), [m(3), m3b]);
  await dur('rejected-does-not-advance', OPTS(), [{ ...m(9), sig: chr(m(9).sig, 3) }, m(1)]);
  await dur('expired-does-not-advance', OPTS(), [m(9, { expiresAt: T - 1, notBefore: T - 100 }), m(1)]);
  await dur('two-issuers-independent', { issuerKeys: { ...ik('ops'), ...ik('ops2') }, nowMs: T }, [m(5), sign(BODY({ version: 2 }), 'ed25519', 'ops2'), m(4)]);
  await dur('initial-higher-rolls-back', OPTS(), [m(3)], { 'allowlist/ops': { version: 7, digest: 'd'.repeat(43) } });
  await dur('initial-equal-conflict', OPTS(), [m(3)], { 'allowlist/ops': { version: 3, digest: 'd'.repeat(43) } });
  await dur('initial-equal-same-digest', OPTS(), [m(3)], { 'allowlist/ops': { version: 3, digest: D0 } });
  await dur('initial-lower-accepts-and-advances', OPTS(), [m(3)], { 'allowlist/ops': { version: 1, digest: 'd'.repeat(43) } });
  for (const [nm, v] of [['string', 'x'], ['null', null], ['no-digest', { version: 1 }], ['version-string', { version: '1', digest: 'x' }], ['version-zero', { version: 0, digest: 'x' }], ['version-fraction', { version: 1.5, digest: 'x' }], ['extra', { version: 1, digest: 'x', extra: 1 }]] as any[]) await dur('corrupt-state-' + nm, OPTS(), [m(3)], { 'allowlist/ops': v });
  await dur('manifest-not-object', OPTS(), [null, 5]);
  await dur('issuer-missing', OPTS(), [{ body: BODY() }]);
  await dur('issuer-too-long', OPTS(), [{ ...m(3), issuer: 'a'.repeat(201) }]);
  await dur('opts-min-version', OPTS({ minVersion: 4 }), [m(3), m(4)]);
}

// ---- create / sign / revoke ----
for (const [nm, b] of [['ok', BODY()], ['unordered-keys', { entries: BODY().entries, expiresAt: BODY().expiresAt, version: 3, notBefore: BODY().notBefore, issuedAt: BODY().issuedAt }], ['bad-version', BODY({ version: 0 })], ['extra', { ...BODY(), x: 1 }], ['bad-entry', BODY({ entries: [E('tdx-mrtd', 'zz')] })], ['non-object', null]] as any[]) add('createAllowlistManifest', nm, [b], run(() => A.createAllowlistManifest(b)));
for (const a of ALGS) {
  const k = KEYS[a]!;
  if (!k.spec) continue;
  add('signAllowlistManifest', a, [BODY(), { issuer: 'ops', alg: a, keySpec: k.spec }], run(() => A.signAllowlistManifest(BODY(), { issuer: 'ops', alg: a, secrets: secretsOfSpec(k.spec) })));
}
add('signAllowlistManifest', 'invalid-body', [BODY({ version: -1 }), { issuer: 'ops', alg: 'ed25519', keySpec: ed.spec }], run(() => A.signAllowlistManifest(BODY({ version: -1 }), { issuer: 'ops', alg: 'ed25519', secrets: secretsOfSpec(ed.spec) })));
add('signAllowlistManifest', 'missing-key-material', [BODY(), { issuer: 'ops', alg: 'ml-dsa-65', keySpec: { alg: 'ml-dsa-65' } }], run(() => A.signAllowlistManifest(BODY(), { issuer: 'ops', alg: 'ml-dsa-65', secrets: {} })));
add('signAllowlistManifest', 'unknown-alg', [BODY(), { issuer: 'ops', alg: 'rsa', keySpec: ed.spec }], run(() => A.signAllowlistManifest(BODY(), { issuer: 'ops', alg: 'rsa', secrets: secretsOfSpec(ed.spec) })));
add('signAllowlistManifest', 'hybrid-missing-ed', [BODY(), { issuer: 'ops', alg: 'hybrid-ed25519-ml-dsa-65', keySpec: { alg: 'hybrid-ed25519-ml-dsa-65', seed: KEYS['ml-dsa-65']!.spec!.seed } }], run(() => A.signAllowlistManifest(BODY(), { issuer: 'ops', alg: 'hybrid-ed25519-ml-dsa-65', secrets: secretsOfSpec({ alg: 'ml-dsa-65', seed: KEYS['ml-dsa-65']!.spec!.seed }) })));
{
  const prev = BODY({ entries: [E('tdx-mrtd', H96(1), 'a'), E('maa-signing-spki', H64(4), ISS), E('maa-signing-spki', H64(4), 'https://b.example.net')] });
  const tm = { issuedAt: T + 10, notBefore: T + 10, expiresAt: T + 1000 };
  const rv = (nm: string, p: any, r: any, t: any = tm) => add('revokeAllowlistEntry', nm, [p, r, t], run(() => A.revokeAllowlistEntry(p, r, t)));
  rv('flip-existing', prev, { kind: 'tdx-mrtd', value: H96(1) });
  rv('add-tombstone', prev, { kind: 'tdx-mrtd', value: H96(2) });
  rv('add-tombstone-label', prev, { kind: 'tdx-rtmr', value: H96(2), label: 'bad-rtmr' });
  rv('maa-matches-label', prev, { kind: 'maa-signing-spki', value: H64(4), label: 'https://b.example.net' });
  rv('maa-other-label-adds', prev, { kind: 'maa-signing-spki', value: H64(4), label: 'https://c.example.net' });
  rv('maa-no-label-adds-revoked-label', prev, { kind: 'maa-signing-spki', value: H64(4) });
  rv('invalid-value', prev, { kind: 'tdx-mrtd', value: 'zz' });
  rv('unknown-kind', prev, { kind: 'nope', value: H96(1) });
  rv('bad-times', prev, { kind: 'tdx-mrtd', value: H96(1) }, { issuedAt: T, notBefore: T + 5, expiresAt: T + 1 });
  rv('twice-same', BODY({ entries: [E('tdx-mrtd', H96(1), 'a', { revoked: true })] }), { kind: 'tdx-mrtd', value: H96(1) });
  rv('previous-not-after-kept', BODY({ entries: [E('tdx-mrtd', H96(1), 'a', { notAfter: 99 })] }), { kind: 'tdx-mrtd', value: H96(1) });
}
for (const v of ['595.71.05', '1.2', '1.2.3.4', '535.1', '0.0', '595', '1.2.3.4.5', '123456.123456.1', '123456.123456.12', 'a.b', '', '1..2', '595.071.5']) add('driverVersionSlotHex', JSON.stringify(v), [v], run(() => A.driverVersionSlotHex(v)));

// ---- projection ----
const ok = (m: any, opts: any = OPTS()) => A.verifyAllowlistManifest(m, opts);
const PRJ: Array<[string, any, number]> = [];
const prj = (nm: string, body: any, now: number = T) => PRJ.push([nm, ok(sign(body)), now]);
prj('all-kinds', BODY({ entries: [E('tdx-mrtd', H96(1)), E('tdx-rtmr', H96(2)), E('sev-snp-measurement', H96(3)), E('gcp-image-digest', 'sha256:' + H64(4), 'i'), E('nvidia-measurement', H96(5)), E('nvidia-driver-version', '595.71.05'), E('nvidia-driver-version', '535.1'), E('maa-signing-spki', H64(6), ISS), E('maa-signing-spki', H64(7), 'https://b.example.net'), E('maa-chain-root-spki', H64(8)), E('maa-chain-intermediate-spki', H64(9)), E('attest-corroboration', H64(10), 'vantages=3;method=x')] }));
prj('empty', BODY({ entries: [] }));
prj('revoked-and-live-values', BODY({ entries: [E('tdx-mrtd', H96(1), 'a', { revoked: true }), E('tdx-mrtd', H96(2))] }));
prj('revoked-across-kinds-independent', BODY({ entries: [E('tdx-mrtd', H96(1), 'a', { revoked: true }), E('tdx-rtmr', H96(1))] }));
prj('maa-revoked-any-label-kills-value', BODY({ entries: [E('maa-signing-spki', H64(6), ISS), E('maa-signing-spki', H64(6), 'https://b.example.net', { revoked: true }), E('maa-signing-spki', H64(7), ISS)] }));
prj('entry-expired', BODY({ entries: [E('tdx-mrtd', H96(1), 'a', { notAfter: T - 1 }), E('tdx-mrtd', H96(2), 'b', { notAfter: T }), E('tdx-mrtd', H96(3), 'c', { notAfter: T + 1 })] }));
prj('entry-expired-revoked-tombstone-no-expiry-listing', BODY({ entries: [E('tdx-mrtd', H96(1), 'a', { notAfter: T - 1, revoked: true })] }));
prj('driver-version-slots', BODY({ entries: [E('nvidia-driver-version', '1.2'), E('nvidia-driver-version', '123456.123456.1')] }));
prj('later-time-expires-entries', BODY({ entries: [E('tdx-mrtd', H96(1), 'a', { notAfter: T + 5 })] }), T + 10);
const projections: any[] = [];
for (const [nm, v, now] of PRJ) {
  const out = run(() => A.projectAllowlist(v, { nowMs: now }));
  add('projectAllowlist', nm, [J(v), { nowMs: now }], out);
  projections.push([nm, out]);
}
for (const [nm, p] of projections) for (const f of ['azureMaaPolicyFields', 'intelDcapPolicyFields', 'sevSnpPolicyFields', 'gcpCsPolicyFields', 'nvidiaCcPolicyFields']) add('policyFields', `${f}-${nm}`, [f, p], run(() => A[f](p)));

// ---- anchor ----
const AE = (issuer: string, version: number, n = version) => ({ issuer, version, digest: createHash('sha256').update('allowlist-anchor-oracle-digest/' + n).digest('base64url') });
add('anchorCommit', 'basic', [AE('ops', 1)], N.allowlistAnchorCommit(AE('ops', 1)));
add('anchorCommit', 'other-issuer', [AE('ops2', 1)], N.allowlistAnchorCommit(AE('ops2', 1)));
add('anchorCommit', 'version-2', [AE('ops', 2)], N.allowlistAnchorCommit(AE('ops', 2)));
add('anchorCommit', 'unicode-issuer', [AE('é "', 1)], N.allowlistAnchorCommit(AE('é "', 1)));
add('anchorEntryOf', 'basic', [J(ok(M0))], J(N.anchorEntryOf(ok(M0))));
{
  const GUARD = { secret: sd('allowlist/anchor/guardian') };
  const gsec = seed('allowlist/anchor/guardian');
  const mkOps = async (nm: string, ops: any[], init = { instanceId: 'inst-anchor-a', principal: 'allowlist-anchor-log' }) => {
    const log: any = N.createAllowlistAnchorLog(init);
    const outs: any[] = [];
    for (const op of ops) {
      if ('anchor' in op) outs.push(run(() => N.anchorAllowlistHead(log, op.anchor, { guardianSecret: gsec, nowMs: op.nowMs })));
      else if ('refresh' in op) outs.push(run(() => N.refreshAnchorHead(log, { guardianSecret: gsec, nowMs: op.refresh })));
      else if ('evidenceFor' in op) outs.push(run(() => N.evidenceFor(log, op.evidenceFor, op.cached)));
      else if ('latest' in op) outs.push(J(log.latest() ?? null));
      else outs.push(J(log.entries()));
    }
    add('anchorOps', nm, [{ ...init, ...GUARD, ops }], outs);
  };
  const v = (iss: string, ver: number, dig = ver) => ({ ok: true, body: {}, ...AE(iss, ver, dig), alg: 'ed25519' });
  await mkOps('first-anchor', [{ anchor: AE('ops', 1), nowMs: T }]);
  await mkOps('anchor-verified-result', [{ anchor: ok(M0), nowMs: T }]);
  await mkOps('three-versions-evidence', [{ anchor: AE('ops', 1), nowMs: T }, { anchor: AE('ops', 2), nowMs: T + 1 }, { anchor: AE('ops', 3), nowMs: T + 2 }, { evidenceFor: 0 }, { evidenceFor: 1, cached: { size: 1 } }, { evidenceFor: 2, cached: { size: 1 } }, { evidenceFor: 2, cached: { size: 3 } }, { evidenceFor: 2, cached: { size: 0 } }, { latest: true }, { entries: true }]);
  await mkOps('idempotent-reanchor', [{ anchor: AE('ops', 1), nowMs: T }, { anchor: AE('ops', 1), nowMs: T + 99 }, { entries: true }, { latest: true }]);
  await mkOps('same-version-other-digest', [{ anchor: AE('ops', 1), nowMs: T }, { anchor: AE('ops', 1, 9), nowMs: T }]);
  await mkOps('lower-version-refused', [{ anchor: AE('ops', 3), nowMs: T }, { anchor: AE('ops', 2), nowMs: T }]);
  await mkOps('lower-version-other-issuer-ok', [{ anchor: AE('ops', 3), nowMs: T }, { anchor: AE('ops2', 1), nowMs: T }, { entries: true }]);
  await mkOps('gap-in-versions-ok', [{ anchor: AE('ops', 1), nowMs: T }, { anchor: AE('ops', 9), nowMs: T }]);
  await mkOps('refresh', [{ anchor: AE('ops', 1), nowMs: T }, { refresh: T + 1000 }, { refresh: T + 2000 }, { latest: true }]);
  await mkOps('refresh-empty', [{ refresh: T }]);
  await mkOps('evidence-empty', [{ evidenceFor: 0 }]);
  await mkOps('evidence-bad-index', [{ anchor: AE('ops', 1), nowMs: T }, { evidenceFor: 1 }, { evidenceFor: -1 }]);
  for (const [nm, e] of [['digest-short', { issuer: 'ops', version: 1, digest: 'abc' }], ['digest-padded', { issuer: 'ops', version: 1, digest: AE('ops', 1).digest + '=' }], ['version-zero', { issuer: 'ops', version: 0, digest: AE('ops', 1).digest }], ['version-fraction', { issuer: 'ops', version: 1.5, digest: AE('ops', 1).digest }], ['issuer-empty', { issuer: '', version: 1, digest: AE('ops', 1).digest }], ['issuer-201', { issuer: 'a'.repeat(201), version: 1, digest: AE('ops', 1).digest }], ['extra-key', { issuer: 'ops', version: 1, digest: AE('ops', 1).digest, x: 1 }], ['null', null]] as any[]) await mkOps('malformed-' + nm, [{ anchor: e, nowMs: T }]);
  void v;
}
{
  const doc: any = buildAnchorVectors();
  for (const r of doc.allowlist_anchor) {
    const verified = { ...r.manifest, alg: 'ed25519', ok: true, body: {} };
    const evidence = r.evidence;
    const res = N.verifyAllowlistAnchored(verified, evidence === null ? undefined : evidence, { trust: doc.trust, nowMs: r.now, ...(r.maxHeadAgeMs !== undefined ? { maxHeadAgeMs: r.maxHeadAgeMs } : {}), ...(r.clockSkewMs !== undefined ? { clockSkewMs: r.clockSkewMs } : {}), ...(r.cachedHead ? { cachedHead: r.cachedHead } : {}) });
    add('verifyAnchored', r.name, [{ verified: r.manifest, evidence, opts: { trust: doc.trust, nowMs: r.now, ...(r.maxHeadAgeMs !== undefined ? { maxHeadAgeMs: r.maxHeadAgeMs } : {}), ...(r.clockSkewMs !== undefined ? { clockSkewMs: r.clockSkewMs } : {}), ...(r.cachedHead ? { cachedHead: r.cachedHead } : {}) } }], J(res));
  }
}

refWrite(o, 'attest-allowlist');
