// Oracle: every export of packages/pca/src/attest-puf.ts (the PUF unclonable attestation root: repetition-code fuzzy extractor, simulated PUF,
// TPM-EK PUF provider over an injectable tpm2-tools runner, enrollment, device attestor, enrollment registry, the PUF verifier), TS reference.
// Writes out/ref-attest-puf.json.gz. Deterministic: Ed25519 and ML-DSA sign deterministically, randomness is passed in, keys come from seed labels.
//
// PORTING (fn(args) -> native entry point; results compared by JSON value; a reference throw ({"$throws"}) only requires the native to refuse)
//   bytes are {"$bytes": b64u}; a PUF response / bit vector is a byte array with ONE 0/1 value per bit.
//   pufSpec = {id, seed, length, flip?[]}   seed: the 32-byte simulated-PUF seed (the strip tool rewrites it to {"$seed": label}: the native derives
//                                            sha256("atlas-pca-conformance/" + label)); a base64url string of 32 bytes otherwise.
//   rand    = [r1, r2]                       the randomBytes callback: its 1st call (n = messageBits) returns r1, its 2nd (n = 32) returns r2.
//   constants []                                         -> {PUF_EXTRACT_INFO, PUF_ATTEST_DOMAIN, PUF_KEY_BYTES, TPM_EK_PUF_DOMAIN}
//   repetitionCorrectionBound [rep]                      -> number
//   fuzzyEnroll [bits, {rep, messageBits}, rand]         -> {keySha256 (hex of sha256 of the 32-byte key: the key is the device's signing seed, so the corpus carries its digest only), helper}
//   fuzzyReproduce [bits, helper]                        -> {keySha256}
//   simulatedPufResponse [pufSpec, challenge]            -> bits (createSimulatedPuf(spec).response(challenge))
//   tpmEk [{opts, run, op, challenge?}]                  -> {ok, value} | {ok:false, error}; op = "readEkPublic" | "response"; opts = TpmEkPufProviderOptions
//                                                           without run (id, length, tool?, ekHandle?, args?, minEkBytes?); run = a TpmCommandResult
//                                                           {status|null, stdout, stderr?, error?}, or {"$throws": msg} (the runner throws), or
//                                                           "undefined" (returns undefined); out.calls = [[command, args]] the runner saw
//   enrollPuf [pufSpec, challenge, {rep, messageBits, alg?}, rand] -> PufEnrollment
//   pufAttest [pufSpec, enrollment, claims]              -> PufAttestationStatement   (createPufAttestor(createSimulatedPuf(spec), enrollment).attest)
//   registry [{enrollments, ops}]                        -> [result per op]; op = {register|lookup|revoke|isRevoked: ...}
//   verifyPuf [scenario]                                 -> HardwareAttestationResult. scenario = {config, enrollments, revoked?, evidence, input}
//        config {policy:{measurements, weightsMeasurements?, identity?: "custom"}, requirePq?, noResolveEnrollment?, noEvidenceSeam?}; "custom" identity =
//        deriveIdentity returning {model_id:"m-custom", weights_digest:<statement weights_digest or "">, weights_measured:true, runtime_measurement:<measurement>, operator:<enrolled providerId>}
//        enrollments: resolveEnrollment looks the id up (last wins); revoked: when present isRevoked = id in that list; evidence: the statement the
//        evidence seam returns (null = returns undefined); input = {nowMs, expected}; the document / ctx the verifier only forwards are {}
//   buildVerifier [{policy?, noResolveEnrollment?}]      -> {ok:true, value:{built:true}} | {$throws} (construction; the resolver, when present, returns undefined)
import { createHash } from 'node:crypto';
import { Oracle, refWrite, seed } from './lib.mjs';
const rb = (l: string) => Buffer.from(createHash('sha256').update('attest-puf-oracle-randomness/' + l).digest());
import { b64u, B, unb, sd, flip, chr, EXPECTED, T0 } from './attest-roots-kit.mts';

const M: any = await import('../../../packages/pca/src/attest-puf.ts');
const o = new Oracle('attest-puf', 'tools/pca-audit/oracles/attest-puf.mts', 'TS-reference oracle for the PUF attestation root (fuzzy extractor, TPM-EK provider, enrollment, attestor, registry, verifier).');
const J = (x: any) => JSON.parse(JSON.stringify(x, (_k, v) => (v instanceof Uint8Array ? { $bytes: b64u(v) } : v)));
const rev = (v: any): any => (v && typeof v === 'object' && !Array.isArray(v) && typeof v.$bytes === 'string' && Object.keys(v).length === 1 ? unb(v.$bytes) : Array.isArray(v) ? v.map(rev) : v && typeof v === 'object' ? Object.fromEntries(Object.keys(v).map((k) => [k, rev(v[k])])) : v);
const sha = (u: Uint8Array) => createHash('sha256').update(u).digest('hex');
const run = (fn: () => any) => { try { return { ok: true, value: J(fn()) }; } catch (e: any) { return { $throws: e instanceof Error ? e.message : String(e) }; } };
const add = (fn: string, name: string, args: any[], out: any) => o.add(fn, name, args, out);
const rnd = (a: any, b: any) => { let i = 0; return (n: number) => (i++ === 0 ? a : b).subarray(0, n); };
const rands = (label: string, messageBits: number) => {
  const m = Buffer.concat([...Array(Math.ceil(messageBits / 32))].map((_, i) => rb(`${label}/r1/${i}`))).subarray(0, messageBits);
  return [m, rb(label + '/r2')];
};
const spec = (label: string, length: number, id = 'puf-' + label, fl?: number[]) => ({ id, seed: sd('puf/' + label), length, ...(fl ? { flip: fl } : {}) });
const mkPuf = (s: any) => M.createSimulatedPuf({ id: s.id, seed: unb(s.seed), length: s.length, ...(s.flip ? { flip: s.flip } : {}) });
const CH = rb('challenge');

// ---- constants / bound ----
add('constants', 'all', [], J({ PUF_EXTRACT_INFO: M.PUF_EXTRACT_INFO, PUF_ATTEST_DOMAIN: M.PUF_ATTEST_DOMAIN, PUF_KEY_BYTES: M.PUF_KEY_BYTES, TPM_EK_PUF_DOMAIN: M.TPM_EK_PUF_DOMAIN }));
for (const rep of [1, 2, 3, 4, 5, 7, 9, 15, 0, -1, 1.5, 3.9]) add('repetitionCorrectionBound', `rep-${rep}`, [rep], M.repetitionCorrectionBound(rep));

// ---- simulated PUF ----
for (const [label, len, fl] of [['a', 8, undefined], ['a', 64, undefined], ['a', 65, undefined], ['b', 64, undefined], ['a', 64, [0, 5, 63]], ['a', 64, [-1, 64, 1000]], ['a', 64, [3, 3]], ['a', 256, undefined], ['a', 1, undefined], ['a', 33, [32]]] as any[]) {
  const s = spec(label, len, 'sim', fl);
  for (const ch of [CH, new Uint8Array(0), Buffer.from('x')]) add('simulatedPufResponse', `${label}-${len}-${fl ? fl.join('_') : 'noflip'}-ch${ch.length}`, [s, B(ch)], J(mkPuf(s).response(ch)));
}

// ---- fuzzy extractor ----
const PARAMS: Array<[number, number]> = [[1, 8], [3, 8], [3, 64], [5, 32], [7, 16], [9, 5], [15, 3], [3, 1], [3, 33], [11, 128]];
const enrolled: Array<{ label: string; rep: number; mb: number; bits: Uint8Array; helper: any; key: Uint8Array }> = [];
for (const [rep, mb] of PARAMS) {
  const n = rep * mb;
  const s = spec(`fe-${rep}-${mb}`, n);
  const bits = mkPuf(s).response(CH);
  const [r1, r2] = rands(`fe/${rep}/${mb}`, mb);
  const args = [B(bits), { rep, messageBits: mb }, [B(r1), B(r2)]];
  const raw = M.fuzzyEnroll(bits, { rep, messageBits: mb }, rnd(r1, r2));
  add('fuzzyEnroll', `rep${rep}-mb${mb}`, args, J({ keySha256: sha(raw.key), helper: raw.helper }));
  const helper = J(raw.helper);
  enrolled.push({ label: `${rep}-${mb}`, rep, mb, bits, helper, key: raw.key });
}
// refusals
const bits24 = mkPuf(spec('fe-bad', 24)).response(CH);
const [rb1, rb2] = rands('fe/bad', 8);
const feBad: Array<[string, any, any]> = [
  ['rep-even', bits24, { rep: 2, messageBits: 12 }], ['rep-zero', bits24, { rep: 0, messageBits: 24 }], ['rep-negative', bits24, { rep: -3, messageBits: 8 }], ['rep-fraction', bits24, { rep: 1.5, messageBits: 16 }],
  ['mb-zero', bits24, { rep: 3, messageBits: 0 }], ['mb-fraction', bits24, { rep: 3, messageBits: 8.5 }], ['len-short', bits24.subarray(0, 23), { rep: 3, messageBits: 8 }], ['len-long', Buffer.concat([bits24, Buffer.from([0])]), { rep: 3, messageBits: 8 }],
  ['bit-2', Buffer.from(bits24.map((b, i) => (i === 5 ? 2 : b))), { rep: 3, messageBits: 8 }], ['bit-255', Buffer.from(bits24.map((b, i) => (i === 23 ? 255 : b))), { rep: 3, messageBits: 8 }], ['empty', new Uint8Array(0), { rep: 3, messageBits: 8 }],
];
for (const [nm, bits, p] of feBad) add('fuzzyEnroll', nm, [B(bits), p, [B(rb1), B(rb2)]], run(() => { const r = M.fuzzyEnroll(bits, p, rnd(rb1, rb2)); return { keySha256: sha(r.key), helper: r.helper }; }));
// the random codeword message is masked to its low bit: a message byte 0xff == 0x01
{
  const bits = mkPuf(spec('fe-mask', 24)).response(CH);
  const hi = Buffer.from(Array.from({ length: 8 }, (_, i) => (i % 2 ? 0xff : 0x02)));
  const lo = Buffer.from(Array.from({ length: 8 }, (_, i) => (i % 2 ? 0x01 : 0x00)));
  const r2 = rb('fe/mask/r2');
  add('fuzzyEnroll', 'message-masked-hi', [B(bits), { rep: 3, messageBits: 8 }, [B(hi), B(r2)]], run(() => { const r = M.fuzzyEnroll(bits, { rep: 3, messageBits: 8 }, rnd(hi, r2)); return { keySha256: sha(r.key), helper: r.helper }; }));
  add('fuzzyEnroll', 'message-masked-lo', [B(bits), { rep: 3, messageBits: 8 }, [B(lo), B(r2)]], run(() => { const r = M.fuzzyEnroll(bits, { rep: 3, messageBits: 8 }, rnd(lo, r2)); return { keySha256: sha(r.key), helper: r.helper }; }));
}
// reproduce: every enrolled response at distances 0 .. beyond the bound, per block and spread
for (const e of enrolled) {
  const bound = M.repetitionCorrectionBound(e.rep);
  const noisy = (positions: number[]) => { const c = Uint8Array.from(e.bits); for (const p of positions) c[p] ^= 1; return c; };
  const tests: Array<[string, Uint8Array]> = [['exact', e.bits]];
  if (bound > 0) {
    tests.push(['bound-block0', noisy(Array.from({ length: bound }, (_, i) => i))]);
    tests.push(['bound-every-block', noisy(Array.from({ length: e.mb }, (_, b) => b * e.rep))]);
    tests.push(['over-bound-block0', noisy(Array.from({ length: bound + 1 }, (_, i) => i))]);
    tests.push(['all-flipped', noisy(Array.from({ length: e.bits.length }, (_, i) => i))]);
  } else tests.push(['one-flip', noisy([0])]);
  tests.push(['last-bit', noisy([e.bits.length - 1])]);
  for (const [nm, r] of tests) add('fuzzyReproduce', `${e.label}-${nm}`, [B(r), e.helper], run(() => ({ keySha256: sha(M.fuzzyReproduce(r, e.helper)) })));
}
// reproduce refusals: helper and response malformations
{
  const e = enrolled.find((x) => x.label === '3-8')!;
  const h = e.helper;
  const bad: Array<[string, any, Uint8Array]> = [
    ['helper-null', null, e.bits], ['helper-rep-even', { ...h, rep: 2, n: 16 }, e.bits], ['helper-rep-zero', { ...h, rep: 0, n: 0 }, e.bits], ['helper-rep-fraction', { ...h, rep: 1.5 }, e.bits], ['helper-mb-fraction', { ...h, messageBits: 8.5 }, e.bits],
    ['helper-n-wrong', { ...h, n: 25 }, e.bits], ['helper-n-missing', { rep: h.rep, messageBits: h.messageBits, sketch: h.sketch, salt: h.salt }, e.bits],
    ['sketch-missing', { rep: h.rep, messageBits: h.messageBits, n: h.n, salt: h.salt }, e.bits], ['salt-missing', { rep: h.rep, messageBits: h.messageBits, n: h.n, sketch: h.sketch }, e.bits],
    ['sketch-number', { ...h, sketch: 5 }, e.bits], ['sketch-padded', { ...h, sketch: h.sketch + '=' }, e.bits], ['sketch-standard-alphabet', { ...h, sketch: 'AA+/' + h.sketch.slice(4) }, e.bits], ['sketch-short', { ...h, sketch: h.sketch.slice(0, 2) }, e.bits],
    ['sketch-long', { ...h, sketch: h.sketch + 'AAAA' }, e.bits], ['sketch-empty', { ...h, sketch: '' }, e.bits], ['salt-short', { ...h, salt: h.salt.slice(0, 40) }, e.bits], ['salt-empty', { ...h, salt: '' }, e.bits], ['salt-long', { ...h, salt: h.salt + 'AAAA' }, e.bits],
    ['response-short', h, e.bits.subarray(0, 23)], ['response-long', h, Buffer.concat([e.bits, Buffer.from([1])])], ['response-bit-2', h, Buffer.from(e.bits.map((b, i) => (i === 0 ? 2 : b)))], ['response-empty', h, new Uint8Array(0)],
    ['unknown-member', { ...h, extra: 1 }, e.bits],
  ];
  for (const [nm, hh, r] of bad) add('fuzzyReproduce', 'bad-' + nm, [B(r), hh], run(() => ({ keySha256: sha(M.fuzzyReproduce(r, hh)) })));
  // a sketch with the trailing pad bits set (16 sketch bits are 24 bits packed to 3 bytes; the high bits of the last byte beyond n are ignored)
  const sk = unb(h.sketch);
  const t = Uint8Array.from(sk); t[t.length - 1] |= 0x80;
  add('fuzzyReproduce', 'sketch-pad-bits', [B(e.bits), { ...h, sketch: b64u(t) }], run(() => ({ keySha256: sha(M.fuzzyReproduce(e.bits, { ...h, sketch: b64u(t) })) })));
}

// ---- TPM EK provider ----
const EK = Buffer.from(Array.from({ length: 80 }, (_, i) => (i * 37 + 11) & 0xff));
const EK2 = Buffer.from(Array.from({ length: 80 }, (_, i) => (i * 41 + 3) & 0xff));
const tpmCase = (nm: string, opts: any, runSpec: any, op: string, challenge?: Uint8Array) => {
  const calls: any[] = [];
  const runner = (cmd: string, args: readonly string[]) => {
    calls.push([cmd, [...args]]);
    if (runSpec === 'undefined') return undefined;
    if (runSpec && typeof runSpec === 'object' && '$throws' in runSpec) throw new Error(runSpec.$throws);
    return rev(runSpec);
  };
  let out: any;
  try {
    const p = new M.TpmEkPufProvider({ ...opts, run: runner });
    out = { ok: true, value: J(op === 'readEkPublic' ? p.readEkPublic() : p.response(challenge ?? CH)) };
  } catch (e: any) {
    out = { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
  out.calls = calls;
  add('tpmEk', nm, [{ opts, run: runSpec, op, ...(challenge ? { challenge: B(challenge) } : {}) }], out);
};
const OKRUN = { status: 0, stdout: B(EK) };
tpmCase('read-default', { id: 'tpm1', length: 64 }, OKRUN, 'readEkPublic');
tpmCase('read-tool-handle', { id: 'tpm1', length: 64, tool: 'my_readpublic', ekHandle: '0x81010002' }, OKRUN, 'readEkPublic');
tpmCase('read-args-override', { id: 'tpm1', length: 64, args: ['-x', 'y'] }, OKRUN, 'readEkPublic');
tpmCase('read-empty-tool-falls-back', { id: 'tpm1', length: 64, tool: '', ekHandle: '' }, OKRUN, 'readEkPublic');
tpmCase('read-min-bytes-ok', { id: 'tpm1', length: 64, minEkBytes: 80 }, OKRUN, 'readEkPublic');
tpmCase('read-min-bytes-short', { id: 'tpm1', length: 64, minEkBytes: 81 }, OKRUN, 'readEkPublic');
tpmCase('read-default-min-63', { id: 'tpm1', length: 64 }, { status: 0, stdout: B(EK.subarray(0, 63)) }, 'readEkPublic');
tpmCase('read-default-min-64', { id: 'tpm1', length: 64 }, { status: 0, stdout: B(EK.subarray(0, 64)) }, 'readEkPublic');
tpmCase('read-nonzero-status', { id: 'tpm1', length: 64 }, { status: 1, stdout: B(EK), stderr: ' tpm error \n' }, 'readEkPublic');
tpmCase('read-nonzero-status-no-stderr', { id: 'tpm1', length: 64 }, { status: 2, stdout: B(EK) }, 'readEkPublic');
tpmCase('read-null-status', { id: 'tpm1', length: 64 }, { status: null, stdout: B(EK) }, 'readEkPublic');
tpmCase('read-spawn-error', { id: 'tpm1', length: 64 }, { status: null, stdout: B(new Uint8Array(0)), error: 'tpm2_readpublic: ENOENT' }, 'readEkPublic');
tpmCase('read-empty-error-string-ignored', { id: 'tpm1', length: 64 }, { status: 0, stdout: B(EK), error: '' }, 'readEkPublic');
tpmCase('read-runner-throws', { id: 'tpm1', length: 64 }, { $throws: 'boom' }, 'readEkPublic');
tpmCase('read-runner-undefined', { id: 'tpm1', length: 64 }, 'undefined', 'readEkPublic');
tpmCase('read-stdout-not-bytes', { id: 'tpm1', length: 64 }, { status: 0, stdout: 'x' }, 'readEkPublic');
tpmCase('response-64', { id: 'tpm1', length: 64 }, OKRUN, 'response');
tpmCase('response-64-other-ek', { id: 'tpm1', length: 64 }, { status: 0, stdout: B(EK2) }, 'response');
tpmCase('response-256-challenge-x', { id: 'tpm1', length: 256 }, OKRUN, 'response', Buffer.from('x'));
tpmCase('response-65', { id: 'tpm1', length: 65 }, OKRUN, 'response');
tpmCase('response-300-empty-challenge', { id: 'tpm1', length: 300 }, OKRUN, 'response', new Uint8Array(0));
tpmCase('response-fails', { id: 'tpm1', length: 64 }, { status: 1, stdout: B(new Uint8Array(0)) }, 'response');
for (const [nm, opts] of [['id-empty', { id: '', length: 64 }], ['id-number', { id: 5, length: 64 }], ['length-zero', { id: 'a', length: 0 }], ['length-fraction', { id: 'a', length: 6.5 }], ['length-missing', { id: 'a' }], ['min-zero', { id: 'a', length: 8, minEkBytes: 0 }], ['min-fraction', { id: 'a', length: 8, minEkBytes: 1.5 }], ['opts-null', null]] as any[]) tpmCase('ctor-' + nm, opts, OKRUN, 'readEkPublic');

// ---- enrollment, attestor ----
const claims = (over: any = {}) => ({ measurement: 'm'.repeat(8), holder_pub: EXPECTED.holderPub, grant_ref: EXPECTED.grantRef, epoch: EXPECTED.epoch, nonce: EXPECTED.nonce, ...over });
interface Dev { name: string; spec: any; challenge: Uint8Array; opts: any; enr: any }
const devs: Dev[] = [];
for (const [name, label, len, rep, mb, alg] of [['ed', 'd1', 96, 3, 32, 'ed25519'], ['ml65', 'd2', 160, 5, 32, 'ml-dsa-65'], ['ml87', 'd3', 96, 3, 32, 'ml-dsa-87'], ['default', 'd4', 96, 3, 32, undefined], ['noisy', 'd5', 96, 3, 32, 'ed25519']] as any[]) {
  const s = spec(label, len);
  const ch = rb('ch/' + name);
  const opts = { rep, messageBits: mb, ...(alg ? { alg } : {}) };
  const [r1, r2] = rands('enr/' + name, mb);
  const out = run(() => M.enrollPuf(mkPuf(s), ch, { ...opts, randomBytes: rnd(r1, r2) }));
  add('enrollPuf', name, [s, B(ch), opts, [B(r1), B(r2)]], out);
  devs.push({ name, spec: s, challenge: ch, opts, enr: out.value });
}
{
  const s = spec('d1', 96); const ch = CH; const [r1, r2] = rands('enr/ed', 32);
  for (const [nm, opts] of [['alg-slh', { rep: 3, messageBits: 32, alg: 'slh-dsa-sha2-128f' }], ['alg-hybrid', { rep: 3, messageBits: 32, alg: 'hybrid-ed25519-ml-dsa-65' }], ['alg-unknown', { rep: 3, messageBits: 32, alg: 'rsa' }], ['rep-even', { rep: 2, messageBits: 48 }], ['mb-mismatch', { rep: 3, messageBits: 31 }], ['rep-zero', { rep: 0, messageBits: 96 }]] as any[]) add('enrollPuf', 'bad-' + nm, [s, B(ch), opts, [B(r1), B(r2)]], run(() => M.enrollPuf(mkPuf(s), ch, { ...opts, randomBytes: rnd(r1, r2) })));
  // a provider whose length differs from rep*messageBits
  const s2 = spec('d1', 95);
  add('enrollPuf', 'bad-provider-length', [s2, B(ch), { rep: 3, messageBits: 32 }, [B(r1), B(r2)]], run(() => M.enrollPuf(mkPuf(s2), ch, { rep: 3, messageBits: 32, randomBytes: rnd(r1, r2) })));
  add('enrollPuf', 'challenge-empty', [s, B(new Uint8Array(0)), { rep: 3, messageBits: 32 }, [B(r1), B(r2)]], run(() => M.enrollPuf(mkPuf(s), new Uint8Array(0), { rep: 3, messageBits: 32, randomBytes: rnd(r1, r2) })));
}
const attest = (nm: string, d: Dev, enr: any, c: any, specOverride?: any) => {
  const s = specOverride ?? d.spec;
  add('pufAttest', nm, [s, enr, c], run(() => M.createPufAttestor(mkPuf(s), enr).attest(c)));
};
for (const d of devs) {
  attest(`${d.name}-basic`, d, d.enr, claims());
  attest(`${d.name}-weights`, d, d.enr, claims({ weights_digest: 'w'.repeat(8) }));
}
{
  const d = devs.find((x) => x.name === 'noisy')!;
  attest('noisy-1-flip', d, d.enr, claims(), { ...d.spec, flip: [4] });
  attest('noisy-1-flip-per-block', d, d.enr, claims(), { ...d.spec, flip: [0, 3, 6, 9, 12, 15, 18, 21] });
  attest('noisy-over-bound', d, d.enr, claims(), { ...d.spec, flip: [0, 1, 3, 4] });
  attest('other-device', d, d.enr, claims(), spec('d-other', 96, d.spec.id));
  attest('other-id', d, d.enr, claims(), { ...d.spec, id: 'renamed' });
  attest('bad-enr-alg', d, { ...d.enr, alg: 'slh-dsa-sha2-128f' }, claims());
  attest('bad-enr-challenge', d, { ...d.enr, challenge: '!!' }, claims());
  attest('bad-enr-helper', d, { ...d.enr, helper: { ...d.enr.helper, rep: 2 } }, claims());
  attest('bad-claims-holder-empty', d, d.enr, claims({ holder_pub: '' }));
  attest('bad-claims-epoch-negative', d, d.enr, claims({ epoch: -1 }));
  attest('bad-claims-epoch-fraction', d, d.enr, claims({ epoch: 1.5 }));
  attest('bad-claims-nonce-empty', d, d.enr, claims({ nonce: '' }));
}

// ---- registry ----
{
  const [a, b] = [devs[0]!.enr, devs[1]!.enr];
  const a2 = { ...a, publicKey: devs[2]!.enr.publicKey };
  const reg = (enrs: any[], ops: any[]) => {
    const r = M.createPufEnrollmentRegistry(enrs);
    return ops.map((op) => {
      const k = Object.keys(op)[0]!;
      if (k === 'register') { r.register(op.register); return null; }
      if (k === 'lookup') return J(r.lookup(op.lookup) ?? null);
      if (k === 'revoke') { r.revoke(op.revoke); return null; }
      return r.isRevoked(op.isRevoked);
    });
  };
  const sc = (nm: string, enrs: any, ops: any[]) => add('registry', nm, [{ enrollments: enrs, ops }], run(() => reg(enrs, ops)));
  sc('init-lookup', [a, b], [{ lookup: a.providerId }, { lookup: b.providerId }, { lookup: 'nobody' }]);
  sc('init-duplicate-last-wins', [a, a2], [{ lookup: a.providerId }]);
  sc('register-overwrites', [a], [{ register: a2 }, { lookup: a.providerId }]);
  sc('revoke-hides', [a], [{ revoke: a.providerId }, { isRevoked: a.providerId }, { lookup: a.providerId }]);
  sc('re-register-does-not-unrevoke', [a], [{ revoke: a.providerId }, { register: a }, { lookup: a.providerId }, { isRevoked: a.providerId }]);
  sc('revoke-unknown', [a], [{ revoke: 'ghost' }, { isRevoked: 'ghost' }, { isRevoked: a.providerId }, { lookup: a.providerId }]);
  sc('non-array-init', 5 as any, [{ lookup: 'x' }]);
  sc('null-init', null as any, [{ lookup: 'x' }]);
  sc('malformed-entries-skipped', [null, 5, { providerId: 7 }, a] as any, [{ lookup: a.providerId }, { lookup: '7' }]);
  sc('register-malformed-ignored', [a], [{ register: { providerId: 3 } }, { register: null }, { lookup: a.providerId }]);
}

// ---- verifier ----
const buildCfg = (sc: any) => {
  const policy: any = { measurements: sc.config.policy.measurements, ...(sc.config.policy.weightsMeasurements ? { weightsMeasurements: sc.config.policy.weightsMeasurements } : {}) };
  if (sc.config.policy.identity === 'custom') policy.deriveIdentity = (st: any, enr: any) => ({ model_id: 'm-custom', weights_digest: st.weights_digest ?? '', weights_measured: true, runtime_measurement: st.measurement, operator: enr.providerId });
  const byId = new Map<string, any>();
  for (const e of sc.enrollments ?? []) byId.set(e.providerId, e);
  const cfg: any = { policy, ...(sc.config.requirePq !== undefined ? { requirePq: sc.config.requirePq } : {}) };
  if (!sc.config.noResolveEnrollment) cfg.resolveEnrollment = (id: string) => byId.get(id);
  if (!sc.config.noEvidenceSeam) cfg.resolveEvidence = () => (sc.evidence === null ? undefined : sc.evidence);
  if (sc.revoked) cfg.isRevoked = (id: string) => sc.revoked.includes(id);
  return cfg;
};
const vp = async (nm: string, sc: any) => {
  sc = JSON.parse(JSON.stringify(sc));
  let out: any;
  try { out = J(await M.createPufVerifier(buildCfg(sc)).verify({ document: {}, ctx: {}, nowMs: sc.input.nowMs, expected: sc.input.expected })); } catch (e: any) { out = { $throws: e instanceof Error ? e.message : String(e) }; }
  add('verifyPuf', nm, [sc], out);
};
const dEd = devs[0]!, dMl = devs[1]!, dMl87 = devs[2]!;
const stmt = (d: Dev, c: any = claims(), over: any = {}) => ({ ...M.createPufAttestor(mkPuf(d.spec), d.enr).attest(c), ...over });
const INPUT = { nowMs: T0, expected: EXPECTED };
const CFG = { policy: { measurements: ['m'.repeat(8)] } };
const base = (d: Dev, over: any = {}) => ({ config: CFG, enrollments: [d.enr], evidence: stmt(d), input: INPUT, ...over });
await vp('ok-ed25519', base(dEd));
await vp('ok-ml-dsa-65', base(dMl));
await vp('ok-ml-dsa-87', base(dMl87));
await vp('ok-weights-gated', base(dEd, { config: { policy: { measurements: ['m'.repeat(8)], weightsMeasurements: ['w'.repeat(8)] } }, evidence: stmt(dEd, claims({ weights_digest: 'w'.repeat(8) })) }));
await vp('ok-weights-list-empty-not-gated', base(dEd, { config: { policy: { measurements: ['m'.repeat(8)], weightsMeasurements: [] } } }));
await vp('ok-custom-identity', base(dEd, { config: { policy: { measurements: ['m'.repeat(8)], identity: 'custom' } }, evidence: stmt(dEd, claims({ weights_digest: 'w'.repeat(8) })) }));
await vp('ok-default-identity-weights', base(dEd, { evidence: stmt(dEd, claims({ weights_digest: 'w'.repeat(8) })) }));
await vp('ok-require-pq-ml', base(dMl, { config: { ...CFG, requirePq: true } }));
await vp('ok-enrollment-not-after-future', base(dEd, { enrollments: [{ ...dEd.enr, notAfter: T0 + 1 }] }));
await vp('ok-revoked-list-other', base(dEd, { revoked: ['someone-else'] }));
await vp('deny-require-pq-classical', base(dEd, { config: { ...CFG, requirePq: true } }));
await vp('deny-enrollment-expired-equal', base(dEd, { enrollments: [{ ...dEd.enr, notAfter: T0 }] }));
await vp('deny-enrollment-expired-past', base(dEd, { enrollments: [{ ...dEd.enr, notAfter: T0 - 1 }] }));
await vp('deny-revoked', base(dEd, { revoked: [dEd.enr.providerId] }));
await vp('deny-revoked-before-unknown', base(dEd, { enrollments: [], revoked: [dEd.enr.providerId] }));
await vp('deny-unknown-enrollment', base(dEd, { enrollments: [] }));
await vp('deny-no-evidence-seam', base(dEd, { config: { ...CFG, noEvidenceSeam: true } }));
await vp('deny-evidence-undefined', base(dEd, { evidence: null }));
await vp('deny-evidence-not-object', base(dEd, { evidence: 5 }));
await vp('deny-evidence-no-provider', base(dEd, { evidence: { ...stmt(dEd), provider_id: undefined } }));
await vp('deny-evidence-no-alg', base(dEd, { evidence: { ...stmt(dEd), alg: undefined } }));
await vp('throws-no-resolve-enrollment', base(dEd, { config: { ...CFG, noResolveEnrollment: true } }));
await vp('deny-helper-tampered-sketch', base(dEd, { enrollments: [{ ...dEd.enr, helper: { ...dEd.enr.helper, sketch: chr(dEd.enr.helper.sketch, 2) } }] }));
await vp('deny-helper-commitment-missing', base(dEd, { enrollments: [{ ...dEd.enr, helperCommitment: undefined }] }));
await vp('deny-helper-commitment-wrong', base(dEd, { enrollments: [{ ...dEd.enr, helperCommitment: chr(dEd.enr.helperCommitment, 1) }] }));
await vp('deny-alg-mismatch', base(dEd, { evidence: stmt(dEd, claims(), { alg: 'ml-dsa-65' }) }));
await vp('deny-alg-unknown', base(dEd, { evidence: stmt(dEd, claims(), { alg: 'rsa' }), enrollments: [{ ...dEd.enr, alg: 'rsa' }] }));
await vp('deny-alg-hybrid-not-supported', base(dEd, { evidence: stmt(dEd, claims(), { alg: 'hybrid-ed25519-ml-dsa-65' }), enrollments: [{ ...dEd.enr, alg: 'hybrid-ed25519-ml-dsa-65' }] }));
await vp('deny-wrong-public-key', base(dEd, { enrollments: [{ ...dEd.enr, publicKey: dMl.enr.publicKey, alg: 'ed25519' }] }));
await vp('deny-ml-wrong-public-key', base(dMl, { enrollments: [{ ...dMl.enr, publicKey: dMl87.enr.publicKey }] }));
await vp('deny-signature-flipped', base(dEd, { evidence: stmt(dEd, claims(), { sig: b64u(flip(unb(stmt(dEd).sig), 3)) }) }));
await vp('deny-ml-signature-flipped', base(dMl, { evidence: stmt(dMl, claims(), { sig: b64u(flip(unb(stmt(dMl).sig), 100)) }) }));
await vp('deny-signature-empty', base(dEd, { evidence: stmt(dEd, claims(), { sig: '' }) }));
await vp('deny-signature-missing', base(dEd, { evidence: stmt(dEd, claims(), { sig: undefined }) }));
await vp('deny-measurement-swapped-after-signing', base(dEd, { evidence: stmt(dEd, claims(), { measurement: 'x'.repeat(8) }), config: { policy: { measurements: ['x'.repeat(8)] } } }));
await vp('deny-weights-swapped-after-signing', base(dEd, { evidence: stmt(dEd, claims({ weights_digest: 'w'.repeat(8) }), { weights_digest: 'v'.repeat(8) }) }));
await vp('deny-provider-swapped-after-signing', base(dEd, { evidence: stmt(dEd, claims(), { provider_id: 'other' }), enrollments: [{ ...dEd.enr, providerId: 'other' }] }));
await vp('ok-pq-sig-ignored-on-pure-suite', base(dEd, { evidence: stmt(dEd, claims(), { pq_sig: 'AAAA' }) }));
await vp('deny-extra-member-signed-body', base(dEd, { evidence: stmt(dEd, claims(), { extra: 1 }) }));
await vp('deny-other-device-signature', base(dEd, { evidence: M.createPufAttestor(mkPuf(spec('d-other', 96, dEd.spec.id)), dEd.enr).attest(claims()) }));
await vp('deny-binding-holder', base(dEd, { input: { nowMs: T0, expected: { ...EXPECTED, holderPub: 'someone-else' } } }));
await vp('deny-binding-grant', base(dEd, { input: { nowMs: T0, expected: { ...EXPECTED, grantRef: 'g2' } } }));
await vp('deny-binding-epoch', base(dEd, { input: { nowMs: T0, expected: { ...EXPECTED, epoch: 8 } } }));
await vp('deny-binding-nonce', base(dEd, { input: { nowMs: T0, expected: { ...EXPECTED, nonce: 'n2' } } }));
await vp('deny-binding-missing-expected', base(dEd, { input: { nowMs: T0 } }));
await vp('deny-binding-not-constructible-epoch', base(dEd, { input: { nowMs: T0, expected: { ...EXPECTED, epoch: -1 } } }));
await vp('deny-binding-not-constructible-holder', base(dEd, { input: { nowMs: T0, expected: { ...EXPECTED, holderPub: '' } } }));
await vp('deny-binding-empty-in-statement', base(dEd, { evidence: stmt(dEd, claims(), { binding: '' }) }));
await vp('deny-policy-measurement', base(dEd, { config: { policy: { measurements: ['z'.repeat(8)] } } }));
await vp('deny-policy-weights-absent', base(dEd, { config: { policy: { measurements: ['m'.repeat(8)], weightsMeasurements: ['w'.repeat(8)] } } }));
await vp('deny-policy-weights-wrong', base(dEd, { config: { policy: { measurements: ['m'.repeat(8)], weightsMeasurements: ['w'.repeat(8)] } }, evidence: stmt(dEd, claims({ weights_digest: 'q'.repeat(8) })) }));
await vp('deny-device-noise-beyond-bound-statement-fails', base(dEd, { evidence: M.createPufAttestor(mkPuf({ ...dEd.spec, flip: [0, 1, 3, 4, 6, 7] }), dEd.enr).attest(claims()) }));
// construction refusals (config: {policy?, noResolveEnrollment?}; the resolver, when present, returns undefined)
for (const [nm, cfg] of [['policy-empty', { policy: { measurements: [] } }], ['policy-missing', {}], ['policy-measurements-not-array', { policy: { measurements: 'x' } }], ['no-resolve-enrollment', { policy: { measurements: ['a'] }, noResolveEnrollment: true }], ['ok', { policy: { measurements: ['a'] } }]] as any[]) {
  const live = { ...(cfg.policy !== undefined ? { policy: cfg.policy } : {}), ...(cfg.noResolveEnrollment ? {} : { resolveEnrollment: () => undefined }) };
  add('buildVerifier', nm, [cfg], run(() => { M.createPufVerifier(live); return { built: true }; }));
}

refWrite(o, 'attest-puf');
