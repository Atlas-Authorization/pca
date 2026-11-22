// Oracle: @atlasauth/pca-siem (OCSF / CEF / ECS event mapping, formatDecision, scrubError, httpSink / consoleSink, exportBatch).
// Deterministic: every record carries a fixed `now`; a record with no `now` is not generated (it would read the wall clock).
// Records are plain JSON (pcactn / verify / decision / now / session); the proof digest is the reference's own hash of the pcactn.
// PORTING (fn(args) -> native entry point, compared by JSON value; a throw requires the native to throw):
//   toOcsfEvent(record, opts?)   Siem.toOcsfEvent(record, opts)            (Map in, Map out)
//   toCef(record, opts?)         Siem.toCef(record, opts)                  (string)
//   toEcs(record, opts?)         Siem.toEcs(record, opts)                  (Map)
//   formatDecision(rec, fmt, o)  Siem.formatDecision(...).toMap()          ({format, object?, line}; a format other than cef / ocsf yields ECS)
//   scrubError(s)                Siem.scrubError(s)
//   httpSinkScenario(spec)       Siem.httpSink(url, options).deliver(events): spec {url, format, headers?, contentType?, name?, timeoutMs?, mode, events: [record]}
//                                mode: ok | st:<code>[:<text>] | throws:<msg> | hang; result {name, format, result, request?}
//   consoleSinkScenario(spec)    Siem.consoleSink: spec {format?, name?, throws?, records: [record]} -> {name, format, result, lines}
//   exportScenario(spec)         Siem.exportBatch(records, sink, {onError, serialize}): spec {format, sinkMode: ok | fail | failNoError | throws | throwsOnError,
//                                records, serialize?, badRecordIdx?}: result + the onError calls [{message, sink, count}] + the delivered lines
import * as S0 from '@atlasauth/pca-siem';
import { Oracle, refWrite, variants } from './lib.mjs';

const S: any = (S0 as any).default ?? S0;
const o = new Oracle('siem', 'tools/pca-audit/oracles/siem.mts', 'TS-reference oracle for the SIEM event mapping.');
const T0 = 1_800_000_000_000;
let n = 0;
const nm = (s: string) => `${s}#${n++}`;
const add = (fn: string, name: string, ref: Function, args: any[]) => o.run(fn, nm(name), ref, args);

const K = (c: string) => c.repeat(43);
const cap = (issuer: string, holder: string, caveats: any[]) => ({ issuer, holder, caveats, sig: 's'.repeat(86) });
const pcactn = (over: any = {}) => ({
  ver: 2, alg: 'ed25519', grant_ref: 'grant-1', counter: 7, nonce: 'n-0001', iat: T0 - 1000, exp: T0 + 60_000, caution: 3,
  action: { verb: 'payments.transfer', resource: 'acct:123', params_digest: K('p'), reversibility_class: 'irreversible' },
  plan: { root: K('r') }, bond_ref: 'bond-9',
  cap_chain: [cap(K('A'), K('B'), [{ t: 'x' }]), cap(K('B'), K('C'), [{ t: 'x' }, { t: 'y' }, { t: 'z' }])],
  sig: 'q'.repeat(86), ...over,
});
const PASS = { wire: 'pass', version: 'pass', audience: 'pass', validity: 'pass', cap_chain: 'pass', plan_inclusion: 'pass', leaf_signature: 'pass', counter_format: 'pass', replay: 'pass' };
const verifyOk = (over: any = {}) => ({ allow: true, checks: { ...PASS, ...over } });
const verifyBad = (k: string, reason = 'bad ' + k) => ({ allow: false, reason, checks: { ...PASS, [k]: 'fail' } });
const dec = (over: any = {}) => ({ admit: true, releaseGuardianShare: false, reasons: ['within policy'], r: 0.25, requiredThreshold: { t: 1, proof: 'passkey' }, ...over });
const rec = (over: any = {}) => ({ pcactn: pcactn(), verify: verifyOk(), decision: dec(), now: T0, ...over });
const thresholdP = { shares: [{ role: 'principal', publicKey: K('P') }, { role: 'guardian', publicKey: K('G') }, { role: 'principal', publicKey: K('A') }, { role: 'agent' }, null, { role: 5 }] };

const RECS: [string, any][] = [
  ['allow tier1', rec()],
  ['allow no decision', rec({ decision: undefined })],
  ['allow tier2', rec({ decision: dec({ requiredThreshold: { t: 2, proof: 'webauthn' } }) })],
  ['allow tier3', rec({ decision: dec({ requiredThreshold: { t: 3, proof: 'multi' } }) })],
  ['step-up', rec({ decision: dec({ admit: false, releaseGuardianShare: true, reasons: ['needs guardian'], requiredThreshold: { t: 3, proof: 'multi' } }) })],
  ['step-up no reasons', rec({ decision: dec({ admit: false, releaseGuardianShare: true, reasons: [] }) })],
  ['policy deny', rec({ decision: dec({ admit: false, releaseGuardianShare: false, reasons: ['over budget'] }) })],
  ['policy deny no reason', rec({ decision: dec({ admit: false, reasons: undefined }) })],
  ['allow reasons empty-first', rec({ decision: dec({ reasons: ['', 'x'] }) })],
  ['verify fail wire', rec({ verify: verifyBad('wire') })],
  ['verify fail replay', rec({ verify: verifyBad('replay', 'replayed') })],
  ['verify fail non-security', rec({ verify: { allow: false, reason: 'policy veto', checks: { ...PASS, threshold: 'fail' } } })],
  ['verify fail no reason', rec({ verify: { allow: false, checks: PASS } })],
  ['verify missing', rec({ verify: undefined })],
  ['verify null', rec({ verify: null })],
  ['verify no checks', rec({ verify: { allow: true } })],
  ['threshold pass', rec({ pcactn: pcactn({ threshold: thresholdP }), verify: verifyOk({ threshold: 'pass' }), decision: dec({ requiredThreshold: { t: 3, proof: 'multi' } }) })],
  ['threshold unverified', rec({ pcactn: pcactn({ threshold: thresholdP }), verify: verifyOk({ threshold: 'fail' }) })],
  ['threshold absent check', rec({ pcactn: pcactn({ threshold: thresholdP }) })],
  ['session given', rec({ session: 'sess-42' })],
  ['empty chain', rec({ pcactn: pcactn({ cap_chain: [] }) })],
  ['one hop', rec({ pcactn: pcactn({ cap_chain: [cap(K('A'), K('B'), [])] }) })],
  ['hops with holes', rec({ pcactn: pcactn({ cap_chain: [cap(K('A'), K('B'), [1, 2]), null, cap(K('C'), K('D'), [1]), 0, 'x', { issuer: '', holder: 5 }] }) })],
  ['short and long keys', rec({ pcactn: pcactn({ cap_chain: [cap('short', 'exactly13char', []), cap('exactly13char', 'a-key-that-is-much-longer-than-twelve', [])] }) })],
  ['unicode keys', rec({ pcactn: pcactn({ cap_chain: [cap('é'.repeat(20), '😀'.repeat(8), [])] }) })],
  ['no pcactn fields', rec({ pcactn: {} })],
  ['pcactn null', rec({ pcactn: null })],
  ['pcactn missing', rec({ pcactn: undefined })],
  ['pcactn string', rec({ pcactn: 'x' })],
  ['version 3', rec({ pcactn: pcactn({ ver: 3 }) })],
  ['version fractional', rec({ pcactn: pcactn({ ver: 2.5 }) })],
  ['version string', rec({ pcactn: pcactn({ ver: '2' }) })],
  ['alg pq', rec({ pcactn: pcactn({ alg: 'ml-dsa-65' }) })],
  ['no nonce', rec({ pcactn: pcactn({ nonce: undefined }) })],
  ['nonce special chars', rec({ pcactn: pcactn({ nonce: 'a=b\\c\nd\r\ne|f' }) })],
  ['verb resource special', rec({ pcactn: pcactn({ action: { verb: 'a|b\\c', resource: 'r=1\n2', params_digest: 'pd', reversibility_class: 'x' } }) })],
  ['reason special', rec({ verify: { allow: false, reason: 'x=1|y\\z\r\nw', checks: PASS } })],
  ['reason very long', rec({ verify: { allow: false, reason: 'z'.repeat(400), checks: PASS } })],
  ['counter negative', rec({ pcactn: pcactn({ counter: -5, nonce: undefined }) })],
  ['counter fractional', rec({ pcactn: pcactn({ counter: 1.5, nonce: undefined }) })],
  ['counter huge', rec({ pcactn: pcactn({ counter: 2 ** 53, nonce: undefined }) })],
  ['counter string', rec({ pcactn: pcactn({ counter: '7', nonce: undefined }) })],
  ['iat exp absent', rec({ pcactn: pcactn({ iat: undefined, exp: undefined }) })],
  ['iat fractional', rec({ pcactn: pcactn({ iat: 1_800_000_000_123.7 }) })],
  ['iat zero', rec({ pcactn: pcactn({ iat: 0 }) })],
  ['iat negative', rec({ pcactn: pcactn({ iat: -86_400_000 }) })],
  ['iat year 10000', rec({ pcactn: pcactn({ iat: 253_402_300_800_000 }) })],
  ['iat year -1', rec({ pcactn: pcactn({ iat: -62_198_755_200_000 }) })],
  ['iat max date', rec({ pcactn: pcactn({ iat: 8_640_000_000_000_000 }) })],
  ['iat out of range', rec({ pcactn: pcactn({ iat: 8_640_000_000_000_001 }) })],
  ['iat string', rec({ pcactn: pcactn({ iat: 'x' }) })],
  ['now fractional', rec({ now: T0 + 0.5 })],
  ['risk scores', rec({ decision: dec({ r: 0 }) })],
  ['risk fractional', rec({ decision: dec({ r: 0.123456789 }) })],
  ['risk string', rec({ decision: dec({ r: 'high' }) })],
  ['tier odd', rec({ decision: dec({ requiredThreshold: { t: 4, proof: 5 } }) })],
  ['tier object', rec({ decision: dec({ requiredThreshold: { t: { a: 1 }, proof: ['x', null, [1, 2]] } }) })],
  ['tier null', rec({ decision: dec({ requiredThreshold: { t: null, proof: null } }) })],
  ['no requiredThreshold', rec({ decision: dec({ requiredThreshold: undefined }) })],
  ['caution absent', rec({ pcactn: pcactn({ caution: undefined, bond_ref: undefined }) })],
  ['bond not string', rec({ pcactn: pcactn({ bond_ref: 5 }) })],
  ['checks mixed', rec({ verify: { allow: true, checks: { wire: 'pass', leaf_signature: 'fail', extra: 'skip', '10': 'pass', '2': 'pass' } } })],
  ['wire fail leaf pass', rec({ verify: { allow: true, checks: { wire: 'fail', leaf_signature: 'pass' } } })],
  ['decision truthy admit', rec({ decision: { admit: 1, reasons: ['r'] } })],
  ['decision string', rec({ decision: 'x' })],
  ['decision empty', rec({ decision: {} })],
  ['verify allow truthy', rec({ verify: { allow: 1, checks: PASS } })],
  ['grant_ref empty', rec({ pcactn: pcactn({ grant_ref: '' }) })],
  ['unicode everywhere', rec({ pcactn: pcactn({ action: { verb: 'é\u2028\ud800x', resource: '\u0000\u001f"\\/', params_digest: '😀', reversibility_class: '\u007f' } }), verify: { allow: false, reason: 'é😀', checks: PASS } })],
  ['signature long', rec({ pcactn: pcactn({ sig: 'x'.repeat(200) }) })],
  ['signature exactly 16', rec({ pcactn: pcactn({ sig: 'x'.repeat(16) }) })],
  ['signature 17', rec({ pcactn: pcactn({ sig: 'x'.repeat(17) }) })],
  ['unsigned', rec({ pcactn: pcactn({ sig: undefined }) })],
];

const OPTS: any[] = [undefined, {}, { signature: 'full' }, { signature: 'prefix' }, { signature: 'omit' }, { signature: 'bogus' }];
for (const [ri, [label, r]] of RECS.entries()) {
  for (const op of ri < 4 ? OPTS : ri % 3 === 0 ? [undefined, { signature: 'omit' }] : [undefined]) {
    await add('toOcsfEvent', `${label}/${JSON.stringify(op)}`, S.toOcsfEvent, [r, op]);
    await add('toCef', `${label}/${JSON.stringify(op)}`, S.toCef, [r, op]);
    await add('toEcs', `${label}/${JSON.stringify(op)}`, S.toEcs, [r, op]);
  }
  for (const f of ['ocsf', 'cef', 'ecs', 'bogus']) await add('formatDecision', `${label}/${f}`, S.formatDecision, [r, f, { signature: 'full' }]);
}
// structural variants of a few seeds
const seeds: [string, any][] = [['allow', rec()], ['threshold', RECS.find((x) => x[0] === 'threshold pass')![1]], ['deny', rec({ verify: verifyBad('wire') })]];
for (const [label, sd] of seeds) {
  let vi = 0;
  for (const [vl, v] of variants(sd, { depth: 5 })) {
    if (typeof v?.now !== 'number') continue; // no wall-clock reads
    if (vi++ % 30 !== 0) continue; // every thirtieth variant keeps the corpus under the size cap
    await add('toOcsfEvent', `var ${label} ${vl}`, S.toOcsfEvent, [v, undefined]);
    await add('toCef', `var ${label} ${vl}`, S.toCef, [v, undefined]);
    await add('toEcs', `var ${label} ${vl}`, S.toEcs, [v, undefined]);
  }
}

// ---- scrubError --------------------------------------------------------------------------------------------------------------------------
const SCRUB = [
  '', 'plain message', 'connect ECONNREFUSED 127.0.0.1:443', 'fetch failed',
  'GET https://user:pa55word@host.example/path failed', 'ftp://u:p@h/x', 'HTTPS://A:B@C.D/E', 'https://nopass@host/x', 'https://:@host/x', 'x://a:b@c x://d:e@f',
  'Authorization: Basic dXNlcjpwYXNz', 'authorization=Bearer abcdef123456', 'AUTHORIZATION": "secret value here', "authorization'  :  x\nnext line",
  'Authorization:', 'authorizations: x',
  'Bearer abcdef', 'Bearer abcde', 'bearer ABCDEF123456 and Basic abcdefgh', 'Splunk 12345678-aaaa-bbbb', 'Token abc.def~ghi+jkl/mno=pqr-stu', 'Tokenx abcdefgh', 'Token\tabcdefgh',
  'token=abc123', 'Token: abc', 'secret="a b c"', "password='p w'", 'passwd = x', 'pwd:y', 'api_key=KEY', 'api-key: KEY', 'apikey=KEY', 'API_KEY=KEY', 'dd-api-key=abc', 'key=1&other=2', 'signature=zzz;rest',
  'sig=abc,def', 'credential : cc', 'mykey=1', 'a.key=1', 'monkey=1', 'keys=1', 'token="unterminated', "token='x y",
  'A'.repeat(31), 'A'.repeat(32), 'A'.repeat(33), 'a-b_'.repeat(10), 'x' + 'A'.repeat(40) + 'y', 'é' + 'A'.repeat(40),
  'z'.repeat(299), 'z'.repeat(300), 'z'.repeat(301), 'z '.repeat(200), ('error with token=abc ' + 'w '.repeat(200)),
  'Éauthorization: s', 'éBearer abcdefgh', '\u00a0token=abc', 'token=\u00a0abc', 'token\u2028=x', 'token=a\u3000b', 'key =\n x', 'key:\r\nv', '\ud800 token=x', 'token=😀😀😀',
  'k1=v key=secretvalue password: hunter2 Bearer abcdefghij https://u:p@h A'.repeat(1) + 'B'.repeat(40),
];
for (const s of SCRUB) await add('scrubError', JSON.stringify(s).slice(0, 60), S.scrubError, [s]);

// ---- sinks -------------------------------------------------------------------------------------------------------------------------------
const ev = (r: any, f: string) => S.formatDecision(r, f, undefined);
const errMsg = (e: any) => (e instanceof Error ? e.message : String(e));
async function httpScenario(spec: any) {
  const calls: any[] = [];
  const m: string = spec.mode;
  const fetchFn = async (url: string, init: any) => {
    calls.push({ url, method: init.method, headers: init.headers, body: init.body });
    if (m === 'ok') return { ok: true, status: 200 };
    if (m.startsWith('st:')) { const [, code, ...t] = m.split(':'); return { ok: false, status: Number(code), ...(t.length ? { statusText: t.join(':') } : {}) }; }
    if (m.startsWith('throws:')) throw new Error(m.slice(7));
    if (m === 'okStatus') return { ok: true, status: 204 };
    return new Promise(() => {}); // hang
  };
  const sink = S.httpSink(spec.url, { format: spec.format, headers: spec.headers, contentType: spec.contentType, name: spec.name, timeoutMs: spec.timeoutMs, fetch: fetchFn });
  const events = spec.events.map((r: any) => ev(r, spec.format));
  const result = await sink.deliver(events);
  return { name: sink.name, format: sink.format, result, request: calls[0] };
}
const HTTP: any[] = [];
for (const f of ['ocsf', 'ecs', 'cef']) {
  for (const m of ['ok', 'st:500', 'st:403:Forbidden', 'st:502:Bad Gateway token=abc123', 'throws:boom', 'throws:connect https://u:secret@h/x failed', 'throws:Authorization: Splunk abcdef0123456789', 'throws:' + 'q'.repeat(400), 'hang'])
    HTTP.push({ url: 'https://siem.example/ingest?token=1', format: f, mode: m, timeoutMs: m === 'hang' ? 30 : undefined, events: [RECS[0][1], RECS[4][1]] });
}
HTTP.push({ url: 'https://x/', format: 'ocsf', mode: 'ok', headers: { Authorization: 'Splunk abc', 'content-type': 'application/json' }, events: [] });
HTTP.push({ url: 'https://x/', format: 'ecs', mode: 'ok', contentType: 'text/x', name: 'custom', headers: { 'X-A': '1' }, events: [RECS[0][1]] });
HTTP.push({ url: 'https://x/', format: 'cef', mode: 'ok', name: '', events: [RECS[0][1]] });
HTTP.push({ url: 'https://x/', format: 'bogus', mode: 'ok', events: [RECS[0][1]] });
HTTP.push({ url: 'https://x/', format: 'ocsf', mode: 'hang', timeoutMs: 0 + 25, events: [RECS[0][1]] });
for (const [i, sp] of HTTP.entries()) await add('httpSinkScenario', `${i} ${sp.format} ${sp.mode}`, httpScenario, [sp]);

async function consoleScenario(spec: any) {
  const lines: string[] = [];
  const sink = S.consoleSink({ ...(spec.format !== undefined ? { format: spec.format } : {}), ...(spec.name !== undefined ? { name: spec.name } : {}), logger: (l: string) => { if (spec.throws) throw new Error(spec.throws); lines.push(l); } });
  const events = spec.records.map((r: any) => ev(r, sink.format));
  const result = await sink.deliver(events);
  return { name: sink.name, format: sink.format, result, lines };
}
const CONS: any[] = [
  { records: [RECS[0][1], RECS[9][1]] }, { format: 'cef', records: [RECS[0][1]] }, { format: 'ecs', name: 'mine', records: [RECS[4][1]] }, { records: [] },
  { records: [RECS[0][1]], throws: 'log failed' }, { format: 'cef', records: [RECS[0][1], RECS[1][1]], throws: 'token=abc12345' },
];
for (const [i, sp] of CONS.entries()) await add('consoleSinkScenario', `${i}`, consoleScenario, [sp]);

async function exportScenario(spec: any) {
  const errors: any[] = [];
  const delivered: string[] = [];
  const m: string = spec.sinkMode;
  const sink: any = {
    name: 's1', format: spec.format,
    deliver: (events: any[]) => {
      for (const e of events) delivered.push(e.line);
      if (m === 'ok') return { ok: true };
      if (m === 'fail') return { ok: false, error: 'collector said no token=abcdef123' };
      if (m === 'failNoError') return { ok: false };
      throw new Error('deliver exploded Bearer abcdefghij');
    },
  };
  const result = await S.exportBatch(spec.records, sink, { serialize: spec.serialize, onError: (e: Error, ctx: any) => { errors.push({ message: e.message, sink: ctx.sink, count: ctx.count }); if (m === 'throwsOnError' || spec.onErrorThrows) throw new Error('cb'); } });
  return { result, errors, delivered };
}
// a record whose serialization throws: a getter is not JSON, so use a value whose canonical form the digest rejects is NOT a throw (safeDigest) — the
// serializers are total over JSON data; a record that throws is therefore only produced by a non-JSON value, which a native cannot receive.
const EXP: any[] = [];
for (const f of ['ocsf', 'ecs', 'cef'])
  for (const m of ['ok', 'fail', 'failNoError', 'throws', 'throwsOnError'])
    EXP.push({ format: f, sinkMode: m, records: [RECS[0][1], RECS[4][1], RECS[9][1]] });
EXP.push({ format: 'ocsf', sinkMode: 'ok', records: [] });
EXP.push({ format: 'cef', sinkMode: 'ok', records: [RECS[0][1]], serialize: { signature: 'full' } });
EXP.push({ format: 'ecs', sinkMode: 'fail', records: [], onErrorThrows: true });
for (const [i, sp] of EXP.entries()) await add('exportScenario', `${i} ${sp.format} ${sp.sinkMode}`, exportScenario, [sp]);

refWrite(o, "siem");
