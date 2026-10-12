#!/usr/bin/env node
// N-version primitives harness. Run: node --import tsx tools/pca-trustbase/primitives/run.mjs [--suite a,b,..] [--n-hash N] [--n-ed N] [--n-pq N] [--seed S] [--out DIR]
//   suites: vectors (Wycheproof/RFC8032/ACVP) hash hmac edsign edadv edrand pq     (default: all)
// External voters are enabled by env: PRIM_RUST PRIM_SLH PRIM_GO PRIM_PY (see cloud.sh). Without them only in-process voters run.
// Exit code: 0 = no UNEXPECTED divergence; 1 = at least one finding with severity BUG (see report.findings).
import fs from 'node:fs';
import path from 'node:path';
import { buildVoters, runAll } from './lib/voters.mjs';
import { Prng, hex, unhex, cat, BOUNDARY_LENGTHS, patterned, Report } from './lib/util.mjs';
import { edAdversarial, L, fromLE, toLE } from './lib/ed-cases.mjs';

const argv = Object.fromEntries(process.argv.slice(2).map((a, i, all) => (a.startsWith('--') ? [a.slice(2), all[i + 1] && !all[i + 1].startsWith('--') ? all[i + 1] : '1'] : null)).filter(Boolean));
const HERE = path.dirname(new URL(import.meta.url).pathname);
const SUITES = (argv.suite ?? 'vectors,hash,hmac,edsign,edadv,edrand,pq').split(',');
const SEED = +(argv.seed ?? 20261009), N_HASH = +(argv['n-hash'] ?? 20000), N_ED = +(argv['n-ed'] ?? 20000), N_PQ = +(argv['n-pq'] ?? 200);
const OUT = argv.out ?? path.join(process.cwd(), 'prim-out'); fs.mkdirSync(OUT, { recursive: true });
const ACVP = argv.acvp ?? path.join(HERE, 'vectors', 'acvp');
const rep = new Report(); const findings = []; // findings: {sev: BUG|FINDING|INFO, ...}
const finding = (sev, id, text, extra = {}) => { findings.push({ sev, id, text, ...extra }); };
const T0 = Date.now(); const log = (...a) => console.log(`[${((Date.now() - T0) / 1000).toFixed(0)}s]`, ...a);

const V = await buildVoters({ withPca: argv['no-pca'] === undefined });
const ALL = V.list;
const names = ALL.map((v) => v.name);
log('voters:', names.join(', '), JSON.stringify(V.N.versions));
const has = (n) => !!V.byName[n];
const pick = (...ns) => ALL.filter((v) => ns.includes(v.name));
const byOp = (...ns) => ns; // readability

/** All non-abstaining voters must return the identical string. Records divergences; returns number found. */
function agree(suite, reqs, res, voters, label = (r) => r.join(' ').slice(0, 160), norm = (x) => x) {
  let bad = 0;
  for (let i = 0; i < reqs.length; i++) {
    const got = {}; for (const v of voters) { const r = res[v.name]?.[i]; if (r !== null && r !== undefined) got[v.name] = norm(r); }
    const vals = Object.values(got); if (vals.length === 0) continue;
    rep.count(suite, 'checks'); for (const v of Object.keys(got)) rep.count(suite, 'votes:' + v);
    const errs = Object.entries(got).filter(([, r]) => typeof r === 'string' && r.startsWith('ERR'));
    const set = new Set(vals);
    if (set.size > 1) { bad++; rep.diverge(suite, errs.length ? 'voter-error' : 'mismatch', { req: label(reqs[i]), votes: Object.fromEntries(Object.entries(got).map(([k, x]) => [k, String(x).slice(0, 80)])) }); }
  }
  return bad;
}
async function batched(reqs, voters, cb, size = 1500) { for (let i = 0; i < reqs.length; i += size) { const part = reqs.slice(i, i + size); await cb(part, await runAll(voters, part), i); } }
const HASHES = ['sha256', 'sha384', 'sha512', 'sha3-256', 'sha3-512', 'shake128:32', 'shake128:200', 'shake256:32', 'shake256:136', 'shake256:300'];
const BLOCK = { sha256: 64, sha384: 128, sha512: 128 };

// ======================================================= vectors
async function suiteVectors() {
  const S = 'vectors';
  // --- Ed25519: Wycheproof + RFC 8032
  const edVoters = ALL.filter((v) => v.name !== 'noble-zip215' || true);
  const wp = JSON.parse(fs.readFileSync(path.join(HERE, 'vectors', 'ed25519_test.json'), 'utf8'));
  const tcs = []; for (const g of wp.testGroups) for (const t of g.tests) tcs.push({ pk: g.publicKey.pk, ...t });
  const reqs = tcs.map((t) => ['EV', t.pk, t.msg, t.sig]);
  const res = await runAll(ALL, reqs);
  const tally = {}; // voter -> {validRejected, invalidAccepted:[...]}
  for (const v of ALL) tally[v.name] = { validRejected: [], invalidAccepted: [], n: 0 };
  tcs.forEach((t, i) => { for (const v of ALL) { const r = res[v.name][i]; if (r === null) continue; const T = tally[v.name]; T.n++; if (t.result === 'valid' && r !== '1') T.validRejected.push(t.tcId); if (t.result === 'invalid' && r === '1') T.invalidAccepted.push({ tcId: t.tcId, comment: t.comment, flags: t.flags }); } });
  rep.suites['wycheproof-ed25519'] = { vectors: tcs.length, algorithm: wp.algorithm, version: wp.generatorVersion, perVoter: Object.fromEntries(Object.entries(tally).map(([k, T]) => [k, { n: T.n, validRejected: T.validRejected.length, invalidAccepted: T.invalidAccepted.length }])) };
  for (const [vn, T] of Object.entries(tally)) {
    if (T.validRejected.length) finding(vn === 'pca-prod' || vn === 'noble-strict' ? 'BUG' : 'FINDING', 'wycheproof-ed25519-valid-rejected', `${vn} rejects ${T.validRejected.length} Wycheproof VALID vectors`, { tcIds: T.validRejected.slice(0, 20) });
    if (T.invalidAccepted.length) finding(vn === 'pca-prod' ? 'BUG' : vn === 'noble-strict' ? 'FINDING' : 'INFO', 'wycheproof-ed25519-invalid-accepted', `${vn} accepts ${T.invalidAccepted.length} Wycheproof INVALID vectors`, { sample: T.invalidAccepted.slice(0, 12) });
  }
  log('wycheproof ed25519', tcs.length, 'vectors', JSON.stringify(rep.suites['wycheproof-ed25519'].perVoter));
  // RFC 8032 section 7.1 TEST 1 / TEST 2
  const rfc = [
    { sk: '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60', pk: 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a', msg: '', sig: 'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b' },
    { sk: '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb', pk: '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c', msg: '72', sig: '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00' },
  ];
  for (const t of rfc) {
    const rq = [['EP', t.sk], ['ES', t.sk, t.msg], ['EV', t.pk, t.msg, t.sig]]; const rs = await runAll(ALL, rq);
    for (let i = 0; i < 3; i++) for (const v of ALL) { const r = rs[v.name][i]; if (r === null) continue; const exp = [t.pk, t.sig, '1'][i]; rep.count('rfc8032', 'checks'); if (r !== exp) rep.diverge('rfc8032', 'wrong-vs-RFC', { voter: v.name, req: rq[i].join(' ').slice(0, 100), got: r.slice(0, 40), exp: exp.slice(0, 40) }); }
  }
  // --- Wycheproof HMAC
  for (const [file, algo] of [['hmac_sha256_test.json', 'sha256'], ['hmac_sha512_test.json', 'sha512']]) {
    const j = JSON.parse(fs.readFileSync(path.join(HERE, 'vectors', file), 'utf8')); const t2 = [];
    for (const g of j.testGroups) for (const t of g.tests) t2.push({ ...t, tagSize: g.tagSize });
    const rq = t2.map((t) => ['M', algo, t.key, t.msg]); const rs = await runAll(ALL, rq); let wrong = 0, n = 0;
    t2.forEach((t, i) => { for (const v of ALL) { const r = rs[v.name][i]; if (r === null) continue; n++; const match = r.startsWith(t.tag) && t.tag.length === t.tagSize / 4; const ok = t.result === 'valid' ? match : !match; if (!ok && t.result === 'valid') { wrong++; rep.diverge('wycheproof-hmac', 'wrong', { algo, voter: v.name, tcId: t.tcId }); } } });
    rep.suites['wycheproof-hmac-' + algo] = { vectors: t2.length, votes: n, valid_mismatch: wrong };
  }
  // --- ACVP
  if (!fs.existsSync(ACVP)) { finding('INFO', 'acvp-missing', 'ACVP vectors not present (run fetch-vectors.sh); ACVP suites skipped'); return; }
  const ld = (d) => { const j = JSON.parse(fs.readFileSync(path.join(ACVP, d, 'internalProjection.json'), 'utf8')); return Array.isArray(j) ? j.find((x) => x.testGroups) : j; };
  const cap = (+argv['acvp-cap']) || 1e9;
  for (const [dir, algo] of [['SHA2-256-1.0', 'sha256'], ['SHA2-384-1.0', 'sha384'], ['SHA2-512-1.0', 'sha512'], ['SHA3-256-2.0', 'sha3-256'], ['SHA3-512-2.0', 'sha3-512'], ['SHAKE-128-1.0', 'shake128'], ['SHAKE-256-1.0', 'shake256']]) {
    if (!fs.existsSync(path.join(ACVP, dir))) continue;
    const j = ld(dir); const cases = [];
    for (const g of j.testGroups) { if (g.testType !== 'AFT') continue; for (const t of g.tests) { const bits = +t.len; if (bits % 8) continue; cases.push({ a: algo.startsWith('shake') ? `${algo}:${(+t.outLen) / 8}` : algo, m: t.msg.slice(0, (bits / 8) * 2), md: t.md.toLowerCase().slice(0, algo.startsWith('shake') ? (+t.outLen / 4) : 1e9) }); } }
    const rq = cases.slice(0, cap).map((c) => ['H', c.a, c.m]); const rs = await runAll(ALL, rq); let n = 0, bad = 0;
    rq.forEach((r, i) => { for (const v of ALL) { const g = rs[v.name][i]; if (g === null) continue; n++; if (g !== cases[i].md) { bad++; rep.diverge('acvp-' + algo, 'wrong-vs-NIST', { voter: v.name, len: r[2].length / 2 }); } } });
    rep.suites['acvp-' + algo] = { tests: rq.length, votes: n, wrong: bad }; log('acvp', algo, rq.length, 'tests', bad, 'wrong');
  }
  for (const [dir, algo] of [['HMAC-SHA2-256-1.0', 'sha256'], ['HMAC-SHA2-512-1.0', 'sha512']]) {
    if (!fs.existsSync(path.join(ACVP, dir))) continue;
    const j = ld(dir); const cases = []; for (const g of j.testGroups) for (const t of g.tests) cases.push({ k: t.key.slice(0, (g.keyLen / 8) * 2), m: t.msg.slice(0, (g.msgLen / 8) * 2), mac: t.mac.toLowerCase() });
    const rq = cases.map((c) => ['M', algo, c.k, c.m]); const rs = await runAll(ALL, rq); let n = 0, bad = 0;
    rq.forEach((r, i) => { for (const v of ALL) { const g = rs[v.name][i]; if (g === null) continue; n++; if (!g.startsWith(cases[i].mac)) { bad++; rep.diverge('acvp-hmac-' + algo, 'wrong-vs-NIST', { voter: v.name }); } } });
    rep.suites['acvp-hmac-' + algo] = { tests: rq.length, votes: n, wrong: bad };
  }
  // ML-DSA keyGen + sigVer (pure/external only; the interface pca uses)
  const MLP = { 'ML-DSA-65': '65', 'ML-DSA-87': '87' };
  if (fs.existsSync(path.join(ACVP, 'ML-DSA-keyGen-FIPS204'))) {
    const j = ld('ML-DSA-keyGen-FIPS204'); const rq = [], exp = [];
    for (const g of j.testGroups) if (MLP[g.parameterSet]) for (const t of g.tests) { rq.push(['MK', MLP[g.parameterSet], t.seed.toLowerCase()]); exp.push(t.pk.toLowerCase() + '\t' + t.sk.toLowerCase()); }
    const rs = await runAll(ALL, rq); let bad = 0, n = 0;
    rq.forEach((r, i) => { for (const v of ALL) { const g = rs[v.name][i]; if (g === null) continue; n++; const [gp, gs] = g.split('\t'); const [ep, es] = exp[i].split('\t'); if (gp !== ep || (gs !== 'N/A' && gs !== es)) { bad++; rep.diverge('acvp-mldsa-keygen', 'wrong-vs-NIST', { voter: v.name, param: r[1] }); } } });
    rep.suites['acvp-mldsa-keygen'] = { tests: rq.length, votes: n, wrong: bad };
  }
  if (fs.existsSync(path.join(ACVP, 'ML-DSA-sigVer-FIPS204'))) {
    const j = ld('ML-DSA-sigVer-FIPS204'); const rq = [], exp = [];
    for (const g of j.testGroups) if (MLP[g.parameterSet] && g.signatureInterface === 'external' && g.preHash === 'pure') for (const t of g.tests) { rq.push(['MV', MLP[g.parameterSet], t.pk.toLowerCase(), t.message.toLowerCase(), t.signature.toLowerCase(), t.context.toLowerCase()]); exp.push(t.testPassed === true || t.testPassed === 'True' ? '1' : '0'); }
    const rs = await runAll(ALL, rq); const per = {};
    rq.forEach((r, i) => { for (const v of ALL) { const g = rs[v.name][i]; if (g === null) continue; const p = (per[v.name] ??= { n: 0, wrong: 0 }); p.n++; if (g !== exp[i]) { p.wrong++; rep.diverge('acvp-mldsa-sigver', 'wrong-vs-NIST', { voter: v.name, param: r[1], exp: exp[i], got: g, pk: r[2].slice(0, 16) }); } } });
    rep.suites['acvp-mldsa-sigver'] = { tests: rq.length, perVoter: per }; log('acvp ml-dsa sigVer', rq.length, JSON.stringify(per));
  }
  const SLP = { 'SLH-DSA-SHA2-128f': 'sha2-128f', 'SLH-DSA-SHA2-256s': 'sha2-256s' };
  if (fs.existsSync(path.join(ACVP, 'SLH-DSA-keyGen-FIPS205'))) {
    const j = ld('SLH-DSA-keyGen-FIPS205'); const rq = [], exp = [];
    for (const g of j.testGroups) if (SLP[g.parameterSet]) for (const t of g.tests) { rq.push(['SK', SLP[g.parameterSet], (t.skSeed + t.skPrf + t.pkSeed).toLowerCase()]); exp.push(t.pk.toLowerCase() + '\t' + t.sk.toLowerCase()); }
    const rs = await runAll(ALL, rq); let bad = 0, n = 0;
    rq.forEach((r, i) => { for (const v of ALL) { const g = rs[v.name][i]; if (g === null) continue; n++; if (g !== exp[i]) { bad++; rep.diverge('acvp-slh-keygen', 'wrong-vs-NIST', { voter: v.name, param: r[1] }); } } });
    rep.suites['acvp-slh-keygen'] = { tests: rq.length, votes: n, wrong: bad };
  }
  if (fs.existsSync(path.join(ACVP, 'SLH-DSA-sigVer-FIPS205'))) {
    const j = ld('SLH-DSA-sigVer-FIPS205'); const rq = [], exp = [];
    for (const g of j.testGroups) if (SLP[g.parameterSet] && g.signatureInterface === 'external' && g.preHash === 'pure') for (const t of g.tests) { rq.push(['SV', SLP[g.parameterSet], t.pk.toLowerCase(), t.message.toLowerCase(), t.signature.toLowerCase(), t.context.toLowerCase()]); exp.push(t.testPassed === true || t.testPassed === 'True' ? '1' : '0'); }
    const rs = await runAll(ALL, rq); const per = {};
    rq.forEach((r, i) => { for (const v of ALL) { const g = rs[v.name][i]; if (g === null) continue; const p = (per[v.name] ??= { n: 0, wrong: 0 }); p.n++; if (g !== exp[i]) { p.wrong++; rep.diverge('acvp-slh-sigver', 'wrong-vs-NIST', { voter: v.name, param: r[1], exp: exp[i], got: g }); } } });
    rep.suites['acvp-slh-sigver'] = { tests: rq.length, perVoter: per }; log('acvp slh sigVer', rq.length, JSON.stringify(per));
  }
}

// ======================================================= hash / hmac
async function suiteHash() {
  const S = 'hash'; const rng = new Prng(SEED); const hv = ALL.filter((v) => !['noble-zip215', 'pca-prod', 'rust-dalek-strict', 'py-cryptography'].includes(v.name));
  // exhaustive boundary x pattern
  const reqs = [];
  for (const n of BOUNDARY_LENGTHS) for (const k of [0, 1, 2, 3]) for (const a of HASHES) { if (n >= 1 << 20 && k === 3 && !a.endsWith('32') && a !== 'sha256') continue; reqs.push(['H', a, hex(patterned(n, k, rng))]); }
  for (let n = 0; n <= 300; n++) for (const a of HASHES) reqs.push(['H', a, hex(rng.bytes(n))]);
  let bad = 0; await batched(reqs, hv, async (p, r) => { bad += agree(S, p, r, hv, (x) => `${x[1]} len=${x[2].length / 2}`); }, 200);
  log('hash boundary/structured', reqs.length, 'reqs ->', bad, 'divergences');
  // random
  let done = 0; const BATCH = 4000;
  while (done < N_HASH) {
    const rq = []; for (let i = 0; i < BATCH && done + i < N_HASH; i++) { const n = rng.int(10) === 0 ? rng.int(5000) : rng.int(300); rq.push(['H', rng.pick(HASHES), hex(rng.bytes(n))]); }
    const rs = await runAll(hv, rq); bad += agree(S, rq, rs, hv, (x) => `${x[1]} ${x[2].slice(0, 80)}`); done += rq.length;
    if ((done / BATCH) % 50 === 0) log('hash random', done, '/', N_HASH, 'div', bad);
  }
  rep.count(S, 'random-cases', N_HASH);
}
async function suiteHmac() {
  const S = 'hmac'; const rng = new Prng(SEED + 1); const hv = ALL.filter((v) => !['noble-zip215', 'pca-prod', 'rust-dalek-strict', 'py-cryptography'].includes(v.name));
  let bad = 0; const reqs = [];
  for (const algo of ['sha256', 'sha512']) { const b = algo === 'sha256' ? 64 : 128;
    for (const kl of [0, 1, b - 1, b, b + 1, 2 * b, 3 * b + 5, 1000]) for (const ml of [0, 1, 55, 56, 63, 64, 111, 112, 127, 128, 129, 1000, 70000]) for (const kind of [0, 1, 3]) reqs.push(['M', algo, hex(patterned(kl, kind, rng)), hex(patterned(ml, kind, rng))]); }
  await batched(reqs, hv, async (p, r) => { bad += agree(S, p, r, hv, (x) => `${x[1]} k=${x[2].length / 2} m=${x[3].length / 2}`); });
  let done = 0; while (done < N_HASH) { const rq = []; for (let i = 0; i < 4000 && done + i < N_HASH; i++) rq.push(['M', rng.pick(['sha256', 'sha512']), hex(rng.bytes(rng.int(300))), hex(rng.bytes(rng.int(400)))]); const rs = await runAll(hv, rq); bad += agree(S, rq, rs, hv); done += rq.length; }
  rep.count(S, 'random-cases', N_HASH); log('hmac', reqs.length, '+', N_HASH, '->', bad);
}

// ======================================================= ed25519
const ED_STRICT_REF = ['pca-prod', 'noble-strict']; // production configuration
async function suiteEdSign() {
  const S = 'edsign'; const rng = new Prng(SEED + 2); const sv = ALL.filter((v) => !['noble-zip215', 'rust-dalek-strict'].includes(v.name)); let bad = 0;
  const reqs = []; for (let i = 0; i < Math.max(2000, N_ED / 10); i++) { const sk = hex(rng.bytes(32)); const m = hex(rng.bytes(rng.pick([0, 1, 32, 64, 100, 1000]))); reqs.push(['EP', sk], ['ES', sk, m]); }
  await batched(reqs, sv, async (p, r) => { bad += agree(S, p, r, sv, (x) => `${x[0]} ${x[1].slice(0, 16)}`); });
  // every voter verifies the (agreed) signatures
  const vq = []; const sigs = await runAll([V.byName['noble-strict']], reqs.filter((r) => r[0] === 'ES')); const pks = await runAll([V.byName['noble-strict']], reqs.filter((r) => r[0] === 'EP'));
  const esr = reqs.filter((r) => r[0] === 'ES'); const epr = reqs.filter((r) => r[0] === 'EP');
  esr.forEach((r, i) => vq.push(['EV', pks['noble-strict'][i], r[2], sigs['noble-strict'][i]]));
  let v1 = 0; await batched(vq, ALL, async (p, r) => { for (let i = 0; i < p.length; i++) for (const v of ALL) { const x = r[v.name][i]; if (x === null) continue; rep.count(S, 'verify-honest-votes'); if (x !== '1') { v1++; rep.diverge(S, 'honest-sig-rejected', { voter: v.name, req: p[i].join(' ').slice(0, 120) }); } } });
  if (bad || v1) finding('BUG', 'ed25519-sign/derive-divergence', `${bad} sign/pubkey divergences, ${v1} honest signatures rejected`);
  log('edsign', reqs.length / 2, 'keys,', bad, 'sign divergences', v1, 'honest rejected');
}

const EDV = (cs, voters) => cs.map((c) => ['EV', hex(c.pk), hex(c.msg), hex(c.sig)]);
async function suiteEdAdv() {
  const S = 'edadv'; const ev = ALL.filter((v) => v.name !== 'pca-prod' || true);
  const cases = [...edAdversarial({ seed: SEED + 3, perCat: +(argv['adv-per-cat'] ?? 200) })];
  log('ed adversarial cases:', cases.length);
  const table = {}; // cat -> voter -> accepts
  const pat = {}; // cat|pattern -> {n, sample}
  let pcaBad = 0, validRej = 0;
  const CH = 300;
  for (let i = 0; i < cases.length; i += CH) {
    const part = cases.slice(i, i + CH); const rq = EDV(part); const rs = await runAll(ev, rq);
    part.forEach((c, j) => {
      const t = (table[c.cat] ??= { n: 0 }); t.n++;
      const verdict = {}; for (const v of ev) { const r = rs[v.name][j]; if (r === null) continue; verdict[v.name] = r; if (r === '1') t[v.name] = (t[v.name] ?? 0) + 1; if (r.startsWith('ERR')) rep.diverge(S, 'voter-error', { voter: v.name, cat: c.cat, r }); }
      const key = c.cat + '|' + Object.entries(verdict).map(([k, x]) => k + '=' + x).join(',');
      const P = (pat[key] ??= { cat: c.cat, expect: c.expect, n: 0, sample: null, verdict }); P.n++; if (!P.sample) P.sample = { label: c.label, pk: hex(c.pk), msg: hex(c.msg).slice(0, 200), sig: hex(c.sig) };
      const prod = verdict['pca-prod'] ?? verdict['noble-strict'];
      if (c.expect === 'valid') { for (const [vn, x] of Object.entries(verdict)) if (x !== '1') { validRej++; rep.diverge(S, 'valid-rejected', { voter: vn, cat: c.cat, label: c.label }); } }
      else if (prod === '1' && c.expect !== 'mixed-order-cofactorless-valid') { pcaBad++; rep.diverge(S, 'PCA-ACCEPTS-INVALID', { cat: c.cat, label: c.label, pk: hex(c.pk), sig: hex(c.sig), msg: hex(c.msg).slice(0, 100) }); }
    });
  }
  // classification of voter-accept vs pca-reject
  const classes = [];
  for (const P of Object.values(pat)) {
    const acc = Object.entries(P.verdict).filter(([, x]) => x === '1').map(([k]) => k); const rej = Object.entries(P.verdict).filter(([, x]) => x === '0').map(([k]) => k);
    if (acc.length && rej.length) classes.push({ cat: P.cat, expect: P.expect, count: P.n, accept: acc, reject: rej, sample: P.sample });
  }
  classes.sort((a, b) => b.count - a.count);
  rep.suites[S] = { cases: cases.length, table, pcaAcceptsInvalid: pcaBad, validRejected: validRej };
  fs.writeFileSync(path.join(OUT, 'ed25519-divergence-classes.json'), JSON.stringify(classes, null, 1));
  // S>=L must be rejected by EVERY conforming verifier (RFC 8032 5.1.7, ZIP-215 too)
  for (const c of classes) if (/^S>=L|^S-high/.test(c.cat)) finding('BUG', 'ed25519-noncanonical-S-accepted', `S>=L accepted by ${c.accept.join(',')} (cat ${c.cat})`, c);
  if (pcaBad) finding('BUG', 'pca-accepts-rfc-invalid-ed25519', `production configuration accepted ${pcaBad} RFC-8032-invalid signatures`);
  if (validRej) finding('BUG', 'ed25519-valid-rejected', `${validRej} honest signatures rejected by some voter`);
  log('edadv done: pca accepts-invalid', pcaBad, 'valid rejected', validRej, 'divergence classes', classes.length);
}

async function suiteEdRand() {
  const S = 'edrand'; const rng = new Prng(SEED + 4); const nob = V.N.ed25519; let done = 0, bad = 0, cons = { acc: 0, rej: 0 };
  const voters = ALL; const BATCH = 2000;
  while (done < N_ED) {
    const rq = [], kind = [];
    for (let i = 0; i < BATCH && done + i < N_ED; i++) {
      const sk = rng.bytes(32), msg = rng.bytes(rng.pick([0, 1, 7, 32, 63, 64, 65, 111, 112, 127, 128, 135, 136, 200, 500])); const pk = nob.getPublicKey(sk); let sig = nob.sign(msg, sk); let m = msg, p = pk; const r = rng.int(10);
      if (r === 1) { sig = sig.slice(); sig[rng.int(64)] ^= 1 << rng.int(8); } else if (r === 2) { p = pk.slice(); p[rng.int(32)] ^= 1 << rng.int(8); } else if (r === 3 && msg.length) { m = msg.slice(); m[rng.int(m.length)] ^= 1 << rng.int(8); }
      else if (r === 4) { sig = cat(sig.subarray(0, 32), toLE(fromLE(sig.subarray(32)) + L)); } else if (r === 5) { sig = rng.bytes(64); } else if (r === 6) { p = rng.bytes(32); } else if (r === 7) { sig = sig.slice(); sig[63] |= 0xe0; }
      else if (r === 8) { sig = sig.slice(); sig[32 + rng.int(32)] = rng.pick([0, 255]); }
      rq.push(['EV', hex(p), hex(m), hex(sig)]);
    }
    const rs = await runAll(voters, rq);
    for (let i = 0; i < rq.length; i++) {
      const got = {}; for (const v of voters) if (rs[v.name][i] !== null) got[v.name] = rs[v.name][i];
      const set = new Set(Object.values(got)); rep.count(S, 'cases');
      if (set.has('1')) cons.acc++; else cons.rej++;
      if (set.size > 1) { bad++; rep.diverge(S, 'verdict-mismatch', { req: rq[i].slice(1).map((x) => x.slice(0, 140)), votes: got }); }
    }
    done += rq.length; if ((done / BATCH) % 25 === 0) log('edrand', done, '/', N_ED, 'mismatch', bad);
  }
  rep.suites[S].summary = { voters: voters.map((v) => v.name), accepted: cons.acc, rejected: cons.rej, mismatches: bad };
  if (bad) finding('FINDING', 'ed25519-random-verdict-mismatch', `${bad} random/mutated cases where voters disagree (see report divergences)`);
  log('edrand done', N_ED, 'cases', bad, 'mismatches');
}

// ======================================================= post-quantum
async function suitePq() {
  const S = 'pq'; const rng = new Prng(SEED + 5);
  const mlv = ALL.filter((v) => ['noble-strict', 'node-openssl', 'pca-prod', 'rust-dalek'].includes(v.name)); // rust-dalek proc = rust-voter (fips204)
  const slv = ALL.filter((v) => ['noble-strict', 'node-openssl', 'pca-prod', 'rust-slh'].includes(v.name));
  const nob = V.byName['noble-strict'];
  const rust = V.byName['rust-dalek'], node = V.byName['node-openssl'];
  const flips = (sig, pk, msg, r, kind) => { const s = sig.slice(), p = pk.slice(), m = msg.slice(); const k = r.int(7);
    if (k === 0) s[r.int(s.length)] ^= 1 << r.int(8); else if (k === 1) p[r.int(p.length)] ^= 1 << r.int(8); else if (k === 2 && m.length) m[r.int(m.length)] ^= 1 << r.int(8);
    else if (k === 3) s[s.length - 1 - r.int(kind.tail)] ^= 1 << r.int(8); // hint / auth-path tail region
    else if (k === 4) return { sig: s.subarray(0, s.length - 1 - r.int(3)), pk, msg };
    else if (k === 5) return { sig: cat(s, new Uint8Array(1 + r.int(2))), pk, msg };
    else { for (let i = 0; i < 4; i++) s[r.int(s.length)] = r.pick([0, 255]); }
    return { sig: s, pk: p, msg: m }; };
  // ---- ML-DSA
  for (const lvl of ['65', '87']) {
    let div = 0, nver = 0, n = 0; const tail = { 65: 55 + 6, 87: 75 + 8 }[lvl];
    for (let i = 0; i < N_PQ; i++) {
      const seed = hex(rng.bytes(32)), msg = hex(rng.bytes(rng.pick([0, 1, 32, 100, 300]))); const rnd = hex(rng.bytes(32));
      const kg = await runAll(mlv, [['MK', lvl, seed]]); // keygen equality (pk exactly; sk where provided)
      const kk = {}; for (const v of mlv) if (kg[v.name][0] !== null) kk[v.name] = kg[v.name][0];
      const pks = new Set(Object.values(kk).map((x) => x.split('\t')[0])); const sks = new Set(Object.values(kk).map((x) => x.split('\t')[1]).filter((x) => x !== 'N/A'));
      if (pks.size > 1 || sks.size > 1) { div++; rep.diverge(S, `mldsa${lvl}-keygen`, { seed, votes: Object.fromEntries(Object.entries(kk).map(([k, x]) => [k, x.slice(0, 40)])) }); }
      const pk = [...pks][0];
      const sg = await runAll(mlv, [['MS', lvl, seed, msg, ''], ['MS', lvl, seed, msg, rnd], ['MSR', lvl, seed, msg]]);
      for (let j = 0; j < 2; j++) { const got = {}; for (const v of mlv) if (sg[v.name][j] !== null) got[v.name] = sg[v.name][j]; if (new Set(Object.values(got)).size > 1) { div++; rep.diverge(S, `mldsa${lvl}-${j ? 'rnd' : 'det'}-sign-mismatch`, { seed, msg: msg.slice(0, 40), votes: Object.fromEntries(Object.entries(got).map(([k, x]) => [k, x.slice(0, 40)])) }); } rep.count(S, `mldsa${lvl}-sign-checks`); }
      const sigs = [...new Set([sg['noble-strict'][0], sg['noble-strict'][1], sg['node-openssl']?.[2], sg['rust-dalek']?.[0]].filter(Boolean))]; // incl. OpenSSL hedged sig
      const pkb = unhex(pk), mb = unhex(msg);
      const rq = [];
      for (const sgx of sigs) rq.push(['MV', lvl, pk, msg, sgx]);
      for (const sgx of sigs.slice(0, 2)) for (let t = 0; t < 14; t++) { const f = flips(unhex(sgx), pkb, mb, rng, { tail }); rq.push(['MV', lvl, hex(f.pk), hex(f.msg), hex(f.sig)]); }
      const rs = await runAll(mlv, rq);
      for (let j = 0; j < rq.length; j++) { const got = {}; for (const v of mlv) if (rs[v.name][j] !== null) got[v.name] = rs[v.name][j]; nver++; const set = new Set(Object.values(got)); if (set.size > 1 || (j < sigs.length && !set.has('1'))) { div++; rep.diverge(S, j < sigs.length ? `mldsa${lvl}-valid-sig-rejected` : `mldsa${lvl}-tamper-mismatch`, { pk: rq[j][2].slice(0, 24), sig: rq[j][4].slice(0, 24), votes: got }); } }
      n++; if (n % 50 === 0) log(`pq ml-dsa-${lvl}`, n, '/', N_PQ, 'verifies', nver, 'div', div);
    }
    rep.count(S, `mldsa${lvl}-iterations`, n); rep.count(S, `mldsa${lvl}-verifies-per-voter`, nver); log(`ml-dsa-${lvl}: ${n} keys, ${nver} verifications per voter, ${div} divergences`);
    if (div) finding('BUG', `mldsa${lvl}-divergence`, `${div} divergences between ML-DSA-${lvl} implementations`);
  }
  // ---- SLH-DSA (slow: few signatures, many tampered verifications)
  for (const [par, nsign, n3] of [['sha2-128f', Math.max(4, Math.floor(N_PQ / 8)), 48], ['sha2-256s', Math.max(2, Math.floor(N_PQ / 60)), 96]]) {
    let div = 0, nver = 0; const tail = par === 'sha2-128f' ? 400 : 700;
    for (let i = 0; i < nsign; i++) {
      const seed = hex(rng.bytes(n3)), msg = hex(rng.bytes(rng.pick([0, 1, 32, 100]))); const opt = hex(rng.bytes(n3 / 3));
      const kg = await runAll(slv, [['SK', par, seed]]); const kk = {}; for (const v of slv) if (kg[v.name][0] !== null) kk[v.name] = kg[v.name][0];
      if (new Set(Object.values(kk)).size > 1) { div++; rep.diverge(S, `slh-${par}-keygen`, { seed, votes: kk }); }
      const [pk, sk] = Object.values(kk)[0].split('\t');
      const sg = await runAll(slv, [['SS', par, sk, msg, ''], ['SS', par, sk, msg, opt], ['SSR', par, sk, msg]]);
      for (let j = 0; j < 2; j++) { const got = {}; for (const v of slv) if (sg[v.name][j] !== null) got[v.name] = sg[v.name][j]; if (new Set(Object.values(got)).size > 1) { div++; rep.diverge(S, `slh-${par}-sign-mismatch`, { j, votes: Object.fromEntries(Object.entries(got).map(([k, x]) => [k, x.slice(0, 40)])) }); } }
      const sigs = [...new Set([sg['noble-strict'][0], sg['noble-strict'][1], sg['node-openssl']?.[2], sg['rust-slh']?.[0]].filter(Boolean))];
      const rq = []; for (const sgx of sigs) rq.push(['SV', par, pk, msg, sgx]);
      for (const sgx of sigs.slice(0, 2)) for (let t = 0; t < 20; t++) { const f = flips(unhex(sgx), unhex(pk), unhex(msg), rng, { tail }); rq.push(['SV', par, hex(f.pk), hex(f.msg), hex(f.sig)]); }
      const rs = await runAll(slv, rq);
      for (let j = 0; j < rq.length; j++) { const got = {}; for (const v of slv) if (rs[v.name][j] !== null) got[v.name] = rs[v.name][j]; nver++; const set = new Set(Object.values(got)); if (set.size > 1 || (j < sigs.length && !set.has('1'))) { div++; rep.diverge(S, j < sigs.length ? `slh-${par}-valid-sig-rejected` : `slh-${par}-tamper-mismatch`, { votes: got }); } }
    }
    rep.count(S, `slh-${par}-signatures`, nsign); rep.count(S, `slh-${par}-verifies-per-voter`, nver); log(`slh-dsa-${par}: ${nsign} sigs, ${nver} verifications per voter, ${div} divergences`);
    if (div) finding('BUG', `slh-${par}-divergence`, `${div} divergences between SLH-DSA ${par} implementations`);
  }
}

// ======================================================= replay (traffic captured from the production glue by the contract monitor)
async function suiteReplay() {
  const S = 'replay'; const file = argv.replay; if (!file || !fs.existsSync(file)) { finding('INFO', 'replay-missing', 'no --replay file'); return; }
  const lines = fs.readFileSync(file, 'utf8').split('\n').filter(Boolean).map((l) => l.split('\t'));
  const ed = lines.filter((l) => l[0] === 'EV'), mv = lines.filter((l) => l[0] === 'MV'), sv = lines.filter((l) => l[0] === 'SV');
  const votersEd = ALL, votersMl = ALL.filter((v) => ['noble-strict', 'node-openssl', 'pca-prod', 'rust-dalek'].includes(v.name)), votersSl = ALL.filter((v) => ['noble-strict', 'node-openssl', 'pca-prod', 'rust-slh'].includes(v.name));
  const stat = {};
  for (const [name, reqs, voters, strictRef] of [['EV', ed, votersEd, true], ['MV', mv, votersMl, false], ['SV', sv, votersSl, false]]) {
    let acc = 0, rej = 0, mism = 0; const classes = {};
    await batched(reqs, voters, async (p, r) => {
      for (let i = 0; i < p.length; i++) {
        const got = {}; for (const v of voters) if (r[v.name][i] !== null) got[v.name] = r[v.name][i];
        const set = new Set(Object.values(got)); if (set.has('1')) acc++; else rej++;
        if (set.size > 1) {
          mism++; const key = Object.entries(got).map(([k, x]) => k + '=' + x).join(',');
          // Ed25519: only pca-prod/noble-strict stricter-than-the-rest is the documented, intended divergence; anything else is flagged
          classes[key] = (classes[key] ?? 0) + 1;
          if (mism <= 10) rep.diverge(S, name + '-verdict-mismatch', { req: p[i].map((x) => x.slice(0, 100)), votes: got });
        }
      }
    }, 300);
    stat[name] = { n: reqs.length, accepted: acc, rejected: rej, mismatches: mism, classes };
  }
  rep.suites[S] = stat; log('replay', JSON.stringify(stat).slice(0, 600));
  if (Object.values(stat).some((x) => x.mismatches)) finding('FINDING', 'replay-mismatch', 'implementations disagree on traffic captured from the production glue (see report.divergences)');
}

const RUN = { replay: suiteReplay, vectors: suiteVectors, hash: suiteHash, hmac: suiteHmac, edsign: suiteEdSign, edadv: suiteEdAdv, edrand: suiteEdRand, pq: suitePq };
for (const s of SUITES) { if (!RUN[s]) { console.error('unknown suite', s); continue; } log('=== suite', s); try { await RUN[s](); } catch (e) { console.error('suite', s, 'crashed:', e); finding('BUG', 'suite-crash:' + s, String(e && e.stack || e).slice(0, 600)); } }
await V.close();
const div = Object.entries(rep.counts).map(([k, n]) => ({ key: k, count: n }));
const nonEmpty = div.filter((d) => !/^(edadv)\|/.test(d.key));
for (const d of nonEmpty) finding(/PCA-ACCEPTS|valid-rejected|wrong-vs-|mismatch|keygen|honest-sig|voter-error|wrong$/.test(d.key) ? 'BUG' : 'FINDING', 'divergence:' + d.key, `${d.count} occurrences`);
const report = { when: new Date().toISOString(), seed: SEED, args: argv, voters: names, versions: V.N.versions, durationSec: (Date.now() - T0) / 1000, suites: rep.suites, divergenceCounts: rep.counts, divergences: rep.divergences, findings };
fs.writeFileSync(path.join(OUT, 'report.json'), JSON.stringify(report, null, 1));
const bugs = findings.filter((f) => f.sev === 'BUG');
console.log('\n=== SUMMARY ==='); console.log(JSON.stringify(rep.suites, null, 0).slice(0, 4000));
console.log('findings:', findings.map((f) => `${f.sev}:${f.id}`).join(' | ') || 'none');
console.log(`report: ${path.join(OUT, 'report.json')}  BUG=${bugs.length}`);
process.exit(bugs.length ? 1 : 0);
