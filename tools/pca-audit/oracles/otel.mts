// Oracle: @atlasauth/pca-otel (redactSecrets, pcaSpanAttributes, instrumentGuard over scripted tracers / meters / guards).
// PORTING (fn(args) -> native entry point, compared by JSON value; a throw requires the native to throw):
//   redactSecrets(text)                   Otel.redactSecrets(text)
//   pcaSpanAttributes(result, mode)       Otel.pcaSpanAttributes(result, redact): mode default (null) | identity | upper (String.toUpperCase) | brackets (s => `<${s}>`)
//   instrumentScenario(spec)              Otel.instrumentGuard(guard, opts) then one call; spec {tracer, meter, tracerMode, meterMode, redact, spanName?, guard}
//                                         guard {result} | {throws: msg}; modes (tracer): ok | startThrows | attrThrows | statusThrows | recordThrows | endThrows;
//                                         (meter): ok | createThrows | addThrows | recordThrows. Output {wrap?: <message when the wrap throws>, outcome, events}
//                                         events: startSpan / setAttribute / setStatus / recordException {message} / end / createCounter / createHistogram / add / record,
//                                         in call order. The error NAME of a recorded exception is not compared (a Java class has no settable name).
import * as O0 from '@atlasauth/pca-otel';
import { Oracle, refWrite, variants } from './lib.mjs';

const O: any = (O0 as any).default ?? O0;
const o = new Oracle('otel', 'tools/pca-audit/oracles/otel.mts', 'TS-reference oracle for the OpenTelemetry instrumentation.');
let n = 0;
const nm = (s: string) => `${s}#${n++}`;
const add = (fn: string, name: string, ref: Function, args: any[]) => o.run(fn, nm(name), ref, args);

const REDACT = [
  '', 'plain text', 'transfer funds', 'acct:12345', 'https://user:pass@example.com/x', 'ftp://a:b@c', 'HTTP://U:P@H/', 'https://host/path',
  'eyJhbGciOi.eyJzdWIiOiIx.c2ln', 'eyJabcde.abcdefgh.', 'xeyJabcde.abcdefgh.sig', 'eyJabcd.abcdefgh.sig', 'eyJ-_-_-_.-_-_-_.-_',
  'authorization: x', 'Authorization="abc def"\nnext', "AUTHORIZATION':  v", 'authorizations: z',
  'Bearer abcdef', 'Bearer abcde', 'bearer ABCDEFG.h~i+j/k=l-m', 'Basic dXNlcjpwYXNz', 'Token abcdefgh', 'Tokens abcdefgh', 'Splunk abcdefgh',
  'token=abc', 'token: "a b"', "secret='x y'", 'password=hunter2', 'passwd = p', 'pwd:1', 'api_key=K', 'api-key: K', 'apikey=K', 'key=v', 'signature=s', 'sig=s', 'credential=c', 'auth=a', 'author=x', 'mykey=1', 'a.key = b',
  'k="unterminated', "k='", 'token="a"&key=b,sig=c;x', 'token=""', "secret=''",
  'A'.repeat(31), 'A'.repeat(32), 'a1_-'.repeat(12), 'Z'.repeat(64) + ' tail', 'é' + 'Z'.repeat(40), 'x'.repeat(255), 'x '.repeat(130), 'y'.repeat(300),
  'a b '.repeat(70), 'token=' + 'v'.repeat(300),
  ' token=x', 'token= x', 'key　:　v', 'key:\r\nv', 'Éauthorization: s', 'éBearer abcdefgh', '😀 token=😀', '\ud800 key=1',
  'verb with token=abc and Bearer abcdefghijkl and https://u:p@h/ and ' + 'Q'.repeat(40),
];
for (const s of REDACT) await add('redactSecrets', JSON.stringify(s).slice(0, 60), O.redactSecrets, [s]);

const MODES: any = { identity: (s: string) => s, upper: (s: string) => s.toUpperCase(), brackets: (s: string) => `<${s}>` };
const res = (over: any = {}) => ({ ok: true, status: 200, verdict: { allow: true, r: 0.25, requiredThreshold: { t: 2 }, checks: { wire: 'pass' }, reasons: ['fine'] }, pcactn: { action: { verb: 'payments.transfer', resource: 'acct:123' } }, ...over });
const RES: [string, any][] = [
  ['allow', res()], ['deny', res({ ok: false, status: 403, verdict: { allow: false, r: 0.9, requiredThreshold: { t: 3 }, reasons: ['over budget', 'second'] } })],
  ['deny no reasons', res({ ok: false, verdict: { allow: false } })], ['deny empty reasons', res({ ok: false, verdict: { reasons: [] } })],
  ['deny reason non-string', res({ ok: false, verdict: { reasons: [5] } })], ['deny reasons string', res({ ok: false, verdict: { reasons: 'abc' } })],
  ['deny reasons empty string', res({ ok: false, verdict: { reasons: '' } })], ['deny reasons object', res({ ok: false, verdict: { reasons: { 0: 'zero', 1: 'one' } } })],
  ['deny reasons number', res({ ok: false, verdict: { reasons: 7 } })],
  ['ok string', res({ ok: 'true' })], ['ok 1', res({ ok: 1 })], ['ok missing', res({ ok: undefined })],
  ['no verdict', { ok: true }], ['empty', {}], ['null', null], ['string', 'x'], ['array', [1]],
  ['status float', res({ status: 1.5 })], ['status string', res({ status: '200' })], ['status neg zero', res({ status: -0 })], ['status huge', res({ status: 2 ** 53 })],
  ['tier odd', res({ verdict: { requiredThreshold: { t: 'high' }, r: 'x' } })], ['tier zero', res({ verdict: { requiredThreshold: { t: 0 }, r: 0 } })],
  ['risk float', res({ verdict: { r: 0.123456789, requiredThreshold: { t: 1 } } })], ['risk 1e21', res({ verdict: { r: 1e21 } })],
  ['verb secret', res({ pcactn: { action: { verb: 'token=abc123', resource: 'https://u:p@h/' } } })], ['verb not string', res({ pcactn: { action: { verb: 5, resource: null } } })],
  ['no action', res({ pcactn: {} })], ['action string', res({ pcactn: { action: 'x' } })],
  ['long resource', res({ pcactn: { action: { verb: 'v', resource: 'r'.repeat(400) } } })],
];
for (const [label, r] of RES) for (const m of [undefined, 'identity', 'upper', 'brackets']) {
  await add('pcaSpanAttributes', `${label}/${m}`, (x: any, mode: any) => O.pcaSpanAttributes(x, mode ? MODES[mode] : undefined), [r, m]);
}
for (const [label, sd] of [['allow', res()], ['deny', RES[1][1]]] as [string, any][]) {
  for (const [vl, v] of variants(sd, { depth: 4 })) await add('pcaSpanAttributes', `var ${label} ${vl}`, (x: any, mode: any) => O.pcaSpanAttributes(x, mode ? MODES[mode] : undefined), [v, null]);
}

// ---- instrumentGuard ---------------------------------------------------------------------------------------------------------------------
async function scenario(spec: any) {
  const events: any[] = [];
  const tm = spec.tracerMode ?? 'ok', mm = spec.meterMode ?? 'ok';
  const throwIf = (cond: boolean) => { if (cond) throw new Error('exporter boom'); };
  const span = {
    setAttribute: (k: string, v: any) => { events.push({ ev: 'setAttribute', k, v }); throwIf(tm === 'attrThrows'); },
    setStatus: (s: any) => { events.push({ ev: 'setStatus', code: s.code, ...(s.message !== undefined ? { message: s.message } : {}) }); throwIf(tm === 'statusThrows'); },
    recordException: (e: any) => { events.push({ ev: 'recordException', message: e.message, noStack: e.stack === undefined }); throwIf(tm === 'recordThrows'); },
    end: () => { events.push({ ev: 'end' }); throwIf(tm === 'endThrows'); },
  };
  const tracer = { startSpan: (name: string) => { events.push({ ev: 'startSpan', name }); throwIf(tm === 'startThrows'); return span; } };
  const meter = {
    createCounter: (name: string) => { events.push({ ev: 'createCounter', name }); throwIf(mm === 'createThrows'); return { add: (v: number, a: any) => { events.push({ ev: 'add', v, a }); throwIf(mm === 'addThrows'); } }; },
    createHistogram: (name: string) => { events.push({ ev: 'createHistogram', name }); return { record: (v: number, a: any) => { events.push({ ev: 'record', v, a }); throwIf(mm === 'recordThrows'); } }; },
  };
  const guard = async (_req: any) => { if (spec.guard.throws !== undefined) throw new Error(spec.guard.throws); return spec.guard.result; };
  let wrapped: any;
  try {
    wrapped = O.instrumentGuard(guard, { ...(spec.tracer ? { tracer } : {}), ...(spec.meter ? { meter } : {}), ...(spec.spanName !== undefined ? { spanName: spec.spanName } : {}), ...(spec.redact ? { redact: MODES[spec.redact] } : {}) });
  } catch (e: any) { return { wrap: e.message, events }; }
  let outcome: any;
  try { outcome = { result: await wrapped('req') }; } catch (e: any) { outcome = { threw: e.message }; }
  return { outcome, events };
}
const SCN: any[] = [];
const GUARDS: any[] = [
  { result: RES[0][1] }, { result: RES[1][1] }, { result: RES[2][1] }, { result: null }, { result: { ok: false, verdict: { r: 'x' } } },
  { throws: 'guard failed' }, { throws: 'guard failed token=abc123 Bearer abcdefghij' }, { throws: '' }, { result: res({ verdict: { r: 5, requiredThreshold: { t: 1 }, reasons: ['token=zz'] }, ok: false }) },
];
for (const g of GUARDS) for (const t of [false, true]) for (const m of [false, true]) {
  if (!t && !m && GUARDS.indexOf(g) > 1) continue;
  SCN.push({ tracer: t, meter: m, guard: g });
}
for (const tm of ['startThrows', 'attrThrows', 'statusThrows', 'recordThrows', 'endThrows']) for (const g of [GUARDS[1], GUARDS[5]]) SCN.push({ tracer: true, meter: true, tracerMode: tm, guard: g });
for (const mm of ['createThrows', 'addThrows', 'recordThrows']) for (const g of [GUARDS[0], GUARDS[5]]) SCN.push({ tracer: true, meter: true, meterMode: mm, guard: g });
for (const rd of ['identity', 'upper', 'brackets']) for (const g of [GUARDS[1], GUARDS[6]]) SCN.push({ tracer: true, meter: true, redact: rd, guard: g });
SCN.push({ tracer: true, meter: false, spanName: 'custom.span', guard: GUARDS[0] }, { tracer: true, meter: false, spanName: '', guard: GUARDS[0] });
for (const [i, sp] of SCN.entries()) await add('instrumentScenario', `${i}`, scenario, [sp]);

refWrite(o, 'otel');
