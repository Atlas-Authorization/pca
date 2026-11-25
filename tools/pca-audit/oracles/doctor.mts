// Oracle: @atlasauth/pca-doctor (deployment checks: clock, proxy, suites, root caveats, enforcement; scrubbing, results formatting, config, CLI).
// Deterministic: fake fetch / clock / @atlasauth/pca stand-ins are named tables replayed identically natively; "rand" is mulberry32(seed).
// The replay-store checks (checkStore) need an adapter and the conformance kit: they are covered by the store-conformance oracle.
// PORTING (net.atlasauth.pca.doctor.Doctor):
//   consts                       -> the constants (USAGE, *_REMEDIATION, CHECK_GROUPS, DEFAULT_REQUIRED, ROOT_CAVEAT_MIN_VERSION, DEFAULT_REFERENCE_URL); out = {name: value}
//   scrubText(s) / scrubDeep(v)  -> Doctor.scrubText / scrubDeep; exact strings
//   checkAllowedSuites(cfg) / checkPqBinding(cfg) / checkProxyConfig(cfg) / checkEnforcement(cfg) -> same names; CheckResult as {id,status,detail,remediation?,observed?}
//   testNetIp(seed) / forgedHeaders(seed) -> with rand = mulberry32(seed) (Doctor.mulberry32)
//   readDate/checkClock/checkProxyProbe(cfg, env) -> env = {now, responses:{url:[{date?, rl?, rtt?, throw?}]}}: each fetch pops the next entry of its url (the last one repeats),
//        advances the fake clock by rtt ms BEFORE answering, throws Error(throw) when set; header 'date' / 'ratelimit-remaining' come from date / rl. rand = mulberry32(7).
//   compareVersion(a,b)          -> Doctor.compareVersion
//   checkRootCaveats(cfg, spec)  -> spec = {throws?, version, path, behavior} (named fake @atlasauth/pca stand-in: enforce | ignore-max | ignore-unknown | deny-all | throws | nonarray-reasons | allow-all)
//   configProblems / verdictOf / formatResults / configFromEnv / mergeConfig / parseDoctorArgs / main / runDoctor -> same names
import { Oracle, rng, variants, refWrite } from './lib.mjs';

const D: any = await import('../../../packages/pca-doctor/src/index.ts');
const Sc: any = await import('../../../packages/pca-doctor/src/scrub.ts');
const o = new Oracle('doctor', 'tools/pca-audit/oracles/doctor.mts', 'TS-reference oracle for pca-doctor.');
const T0 = 1_800_000_000_000;

// ---- consts -------------------------------------------------------------------------------------------------------------
await o.run('consts', 'all', () => ({
  USAGE: D.USAGE, CHECK_GROUPS: [...D.CHECK_GROUPS], DEFAULT_REQUIRED: D.DEFAULT_REQUIRED, ROOT_CAVEAT_MIN_VERSION: D.ROOT_CAVEAT_MIN_VERSION, DEFAULT_REFERENCE_URL: D.DEFAULT_REFERENCE_URL,
  SUITES_REMEDIATION: D.SUITES_REMEDIATION, PQ_REMEDIATION: D.PQ_REMEDIATION, CLOCK_REMEDIATION: D.CLOCK_REMEDIATION, PROXY_REMEDIATION: D.PROXY_REMEDIATION,
  ATOMICITY_REMEDIATION: D.ATOMICITY_REMEDIATION, DURABILITY_REMEDIATION: D.DURABILITY_REMEDIATION, CAVEAT_REMEDIATION: D.CAVEAT_REMEDIATION,
}), []);

// ---- scrub --------------------------------------------------------------------------------------------------------------
const JWT = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk';
const frags = [JWT, 'Authorization: Bearer abc123def456', 'authorization="Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="', 'Bearer abcdef', 'bearer ab', 'Token xyz123456', 'Basic dXNlcjpwYXNz',
  'https://user:pass@host.example/path', 'postgres://u:p@db:5432/x', 'ftp://anon@host', 'http://a:b:c@h', 'token=abc123', 'password: "hunter two"', "secret='s3 cret'", 'api_key=AKIA1234', 'api-key: k',
  'KEY=1', 'sig=abc&x=1', 'credential=zz;', 'auth:1', 'sslpassword=pw', 'pwd = a,b', 'passwd=x', 'x'.repeat(39), 'x'.repeat(40), 'A'.repeat(41) + '-_' + 'b'.repeat(5), 'plain text', '', ' ', 'é\u00a0secret=é', 'token\u00a0=\u00a0tok',
  'tokenx=1', 'mytoken=1', 'a.token=1', 'eyJabcd.abcde.fghij', 'eyJabcde.abcde.', 'eyJabcde.abcde.f', '\ud800token=a', 'line1\nauthorization: foo\nline3', 'AUTHORIZATION=Bearer x', 'Cookie: a=b; token=c',
  'x://u:p@h', '1x://u:p@h', 'a+b-c.d://u:p@h/', '://u:p@h', 'secret:', 'secret=', '"token":"abc"', "'password':'p w'", 'Token: abc', 'Basic  twospaces123', 'key=1 key=2'];
let n = 0;
for (const f of frags) await o.run('scrubText', `frag ${n++}`, (s: any) => Sc.scrubText(s), [f]);
const r = rng(11);
for (let i = 0; i < 400; i++) {
  const parts = Array.from({ length: r.int(1, 5) }, () => r.pick(frags));
  await o.run('scrubText', `mix ${i}`, (s: any) => Sc.scrubText(s), [parts.join(r.pick([' ', ', ', '\n', ' & ', '']))]);
}
await o.run('scrubText', 'long-600', (s: any) => Sc.scrubText(s), ['a '.repeat(300)]);
await o.run('scrubText', 'long-601', (s: any) => Sc.scrubText(s), ['a '.repeat(300) + 'b']);
await o.run('scrubText', 'long-emoji', (s: any) => Sc.scrubText(s), ['\ud83d\ude00'.repeat(299)]);
await o.run('scrubText', 'long-split-pair', (s: any) => Sc.scrubText(s), ['a'.repeat(599) + '\ud83d\ude00']);
for (const v of [null, 5, true, 1.5, -0, ['a'], { a: 1 }]) await o.run('scrubText', `nonstring ${JSON.stringify(v)}`, (s: any) => Sc.scrubText(s), [v]);
const nest = (d: number): any => (d === 0 ? { s: 'token=abc', n: 1, a: ['password=x', null, 2, [JWT]] } : { k: nest(d - 1), s: 'Bearer abcdefg' });
for (const d of [0, 1, 4, 7, 8, 9, 10]) await o.run('scrubDeep', `depth ${d}`, (v: any) => Sc.scrubDeep(v), [nest(d)]);
for (const v of [null, 5, 'secret=x', [], {}, [[['token=1']]], { a: undefined, b: null, c: true }]) await o.run('scrubDeep', `v ${JSON.stringify(v)}`, (x: any) => Sc.scrubDeep(x), [v]);

// ---- suites -------------------------------------------------------------------------------------------------------------
const known = Object.keys((await import('@atlasauth/pca') as any).SIG_SUITES);
const sv: any[] = [undefined, {}, { allowedSuites: [] }, { allowedSuites: ['ed25519'] }, { allowedSuites: ['ed25519', 'ml-dsa-65'] }, { allowedSuites: ['hybrid-ed25519-ml-dsa-65'] }, { allowedSuites: ['nope'] },
  { allowedSuites: ['ed25519', 5] }, { allowedSuites: 'ed25519' }, { allowedSuites: null }, { allowedSuites: [null] }, { allowedSuites: ['__proto__'] }, { allowedSuites: ['toString'] }, { allowedSuites: ['hasOwnProperty'] },
  { allowedSuites: known }, { allowedSuites: ['fn-dsa-512'] }, { allowedSuites: ['less-cat1', 'ed25519'] }, { allowedSuites: {} }, { allowedSuites: 0 }];
n = 0;
for (const v of sv) await o.run('checkAllowedSuites', `v ${n++}`, (c: any) => D.checkAllowedSuites(c), [v === undefined ? {} : { verifier: v }]);
await o.run('checkAllowedSuites', 'verifier-null', (c: any) => D.checkAllowedSuites(c), [{ verifier: null }]);
await o.run('checkAllowedSuites', 'verifier-0', (c: any) => D.checkAllowedSuites(c), [{ verifier: 0 }]);
const ID = 'A'.repeat(43);
const PK = 'abc-_123';
const pv: any[] = [undefined, {}, { allowUnboundPq: true }, { allowUnboundPq: 'true' }, { allowUnboundPq: false }, { pqPins: {} }, { pqPins: { [ID]: PK } }, { pqPins: { [ID]: PK }, allowedSuites: ['ed25519'] },
  { pqPins: { short: PK } }, { pqPins: { [ID]: 5 } }, { pqPins: { [ID]: 'bad pk' } }, { pqPins: { [ID]: '' } }, { pqPins: [] }, { pqPins: null }, { pqPins: 'x' }, { pqPins: 5 }, { pqPins: { [ID + 'A']: PK } },
  { pqPins: { [ID]: PK, other: PK } }, { trustedRoot: true }, { trustedRoot: true, allowedSuites: ['ml-dsa-65'] }, { trustedRoot: 'yes' }, { allowedSuites: ['ed25519'] }, { allowedSuites: ['ml-dsa-65'] },
  { allowedSuites: ['ml-dsa-65'], trustedRoot: true }, { allowedSuites: ['ml-dsa-65'], pqPins: { [ID]: PK } }, { allowedSuites: ['ml-dsa-65'], pqPins: {} }, { allowedSuites: [], trustedRoot: true }, { allowedSuites: ['nope'] },
  { allowedSuites: ['ed25519', 'hybrid-ed25519-ml-dsa-65'], pqPins: { [ID]: PK, [ID.replace(/A/g, 'B')]: PK } }, { allowedSuites: [5] }, { allowUnboundPq: true, pqPins: 5 }];
n = 0;
for (const v of pv) await o.run('checkPqBinding', `v ${n++}`, (c: any) => D.checkPqBinding(c), [v === undefined ? {} : { verifier: v }]);

// ---- proxy config -------------------------------------------------------------------------------------------------------
const counts: any[] = [undefined, 0, 1, 2, 16, 17, -1, -0, 1.5, '1', null, NaN, 1e21];
const hdrs: any[] = [undefined, 'x-forwarded-for', 'forwarded', 'x-real-ip', 'other'];
const hops: any[] = [undefined, 0, 1, 2, 3];
n = 0;
for (const c of counts) for (const h of hdrs) for (const p of hops) {
  const proxy: any = {};
  if (c !== undefined && !(typeof c === 'number' && Number.isNaN(c))) proxy.trustedProxyCount = c;
  if (h !== undefined) proxy.header = h;
  if (p !== undefined) proxy.hops = p;
  await o.run('checkProxyConfig', `m ${n++}`, (cc: any) => D.checkProxyConfig(cc), [{ proxy }]);
}
await o.run('checkProxyConfig', 'no-proxy', (c: any) => D.checkProxyConfig(c), [{}]);
await o.run('checkProxyConfig', 'proxy-null', (c: any) => D.checkProxyConfig(c), [{ proxy: null }]);
for (const seed of [1, 2, 3, 7, 42, 99, 12345, 4294967295, 0]) {
  await o.run('testNetIp', `s${seed}`, (s: any) => D.testNetIp(rng(s).next), [seed]);
  await o.run('forgedHeaders', `s${seed}`, (s: any) => D.forgedHeaders(rng(s).next), [seed]);
}

// ---- fake environment ---------------------------------------------------------------------------------------------------
const mkEnv = (spec: any) => {
  let t = spec.now;
  const idx: Record<string, number> = {};
  const fetch = async (url: string) => {
    const lst = spec.responses[url];
    if (!lst) throw new Error('no route ' + url);
    const i = idx[url] ?? 0;
    idx[url] = i + 1;
    const rsp = lst[Math.min(i, lst.length - 1)];
    t += rsp.rtt ?? 0;
    if (rsp.throw) throw new Error(rsp.throw);
    return { status: 200, headers: { get: (nm: string) => (nm === 'date' ? rsp.date ?? null : nm === 'ratelimit-remaining' ? rsp.rl ?? null : null) }, arrayBuffer: async () => new ArrayBuffer(0) };
  };
  return { fetch, now: () => t };
};
const httpDate = (ms: number) => new Date(ms).toUTCString();
const URL1 = 'https://api.example.com';
const REF = 'https://www.google.com/generate_204';
const ENV: Array<[string, any]> = [];
const clockEnv = (devSkewMs: number, refSkewMs: number, rtt = 0, extra: any = {}) => ({ now: T0, responses: { [URL1]: [{ date: httpDate(T0 + devSkewMs), rtt }], [REF]: [{ date: httpDate(T0 + refSkewMs), rtt }], ...extra } });
for (const dev of [0, 400, 1000, 14_000, 16_000, 30_000, 59_000, 60_000, 61_000, 62_500, 70_000, 200_000, -16_000, -62_000, -200_000]) {
  for (const rtt of [0, 200, 3000]) ENV.push([`skew ${dev} rtt ${rtt}`, clockEnv(dev, 0, rtt)]);
}
ENV.push(['ref-skewed', clockEnv(10_000, 9_000)], ['ref-skewed2', clockEnv(30_000, -30_000)]);
ENV.push(['ref-nodate', { now: T0, responses: { [URL1]: [{ date: httpDate(T0) }], [REF]: [{}] } }]);
ENV.push(['ref-badate', { now: T0, responses: { [URL1]: [{ date: httpDate(T0 + 30_000) }], [REF]: [{ date: 'garbage' }] } }]);
ENV.push(['ref-throws', { now: T0, responses: { [URL1]: [{ date: httpDate(T0 + 30_000) }], [REF]: [{ throw: 'ECONNREFUSED' }] } }]);
ENV.push(['dep-throws', { now: T0, responses: { [URL1]: [{ throw: 'boom' }], [REF]: [{ date: httpDate(T0) }] } }]);
ENV.push(['dep-nodate', { now: T0, responses: { [URL1]: [{}], [REF]: [{ date: httpDate(T0) }] } }]);
ENV.push(['dep-garbage', { now: T0, responses: { [URL1]: [{ date: 'not a date' }], [REF]: [{ date: httpDate(T0) }] } }]);
ENV.push(['dep-iso', { now: T0, responses: { [URL1]: [{ date: new Date(T0 + 5000).toISOString() }], [REF]: [{ date: httpDate(T0) }] } }]);
ENV.push(['dep-wrong-weekday', { now: T0, responses: { [URL1]: [{ date: httpDate(T0 + 5000).replace(/^\w{3}/, 'Xyz') }], [REF]: [{ date: httpDate(T0) }] } }]);
ENV.push(['dep-empty', { now: T0, responses: { [URL1]: [{ date: '' }], [REF]: [{ date: httpDate(T0) }] } }]);
ENV.push(['local', { now: T0, responses: { [URL1]: [{ date: httpDate(T0 + 20_000) }] } }]);
ENV.push(['noroute-ref', { now: T0, responses: { [URL1]: [{ date: httpDate(T0 + 3000) }] } }]);
n = 0;
const cfgs: any[] = [{ url: URL1 }, { url: URL1, clock: { referenceUrl: 'local' } }, { url: URL1, clock: { maxSkewMs: 10_000 } }, { url: URL1, clock: { maxSkewMs: 1500, warnFraction: 0.5 } },
  { url: URL1, clock: { warnFraction: 1 } }, {}, { url: '' }, { url: null }, { url: URL1, clock: { maxSkewMs: 12345.5, referenceUrl: 'local' } }];
for (const [label, env] of ENV) for (const c of cfgs.slice(0, label.startsWith('skew') ? 4 : cfgs.length)) {
  await o.run('checkClock', `${n++} ${label} ${JSON.stringify(c).slice(0, 60)}`, async (...a: any[]) => { const e = mkEnv(a[1]); return D.checkClock(a[0], { fetch: e.fetch, now: e.now }); }, [[c, env]].flat());
}
// readDate directly
for (const [label, env] of ENV.slice(-12)) {
  await o.run('readDate', label, async (...a: any[]) => { const e = mkEnv(a[1]); return D.readDate(URL1, e.fetch, e.now, 1000); }, [null, env]);
}

// ---- proxy probe --------------------------------------------------------------------------------------------------------
const P = 'https://api.example.com/v1/pca/suites';
const probeEnv = (seq: any[]) => ({ now: T0, responses: { [P]: seq } });
const rl = (v: any) => ({ rl: v });
const PS: Array<[string, any[]]> = [
  ['drain-ok', [rl('10'), rl('9'), rl('8'), rl('7')]], ['forged-fresh', [rl('10'), rl('9'), rl('10'), rl('8')]], ['forged-higher', [rl('10'), rl('9'), rl('50'), rl('8')]],
  ['forged-equal-b', [rl('10'), rl('9'), rl('9'), rl('8')]], ['no-header', [{}]], ['one-missing', [rl('5'), rl('4'), {}, rl('3')]], ['nondrain', [rl('5'), rl('5'), rl('5'), rl('5')]],
  ['rollover', [rl('1'), rl('100'), rl('99'), rl('98')]], ['garbage', [rl('abc')]], ['empty-string', [rl('')]], ['hex', [rl('0x10'), rl('0xf'), rl('0xe'), rl('0xd')]], ['exp', [rl('1e1'), rl('9'), rl('8'), rl('7')]],
  ['spaces', [rl(' 10 '), rl(' 9'), rl('8 '), rl('7')]], ['inf', [rl('Infinity')]], ['neg', [rl('-1'), rl('-2'), rl('-3'), rl('-4')]], ['fraction', [rl('10.5'), rl('9.5'), rl('9'), rl('8.5')]],
  ['throws-first', [{ throw: 'down' }]], ['throws-later', [rl('5'), rl('4'), { throw: 'timeout' }]], ['float-str', [rl('1.0'), rl('.5'), rl('0.25'), rl('0.125')]], ['plus', [rl('+10'), rl('9'), rl('8'), rl('7')]],
];
const pcfgs: any[] = [{ url: URL1 }, { url: URL1, proxy: { probe: false } }, { url: URL1, proxy: { probePath: '/other' } }, {}, { url: URL1, proxy: { probePath: 'rel' } }, { url: URL1, clock: { timeoutMs: 5 } }];
n = 0;
for (const [label, seq] of PS) for (const c of pcfgs.slice(0, 2)) {
  await o.run('checkProxyProbe', `${n++} ${label} ${JSON.stringify(c)}`, async (...a: any[]) => { const e = mkEnv(a[1]); return D.checkProxyProbe(a[0], { fetch: e.fetch, rand: rng(7).next }); }, [c, probeEnv(seq)]);
}
await o.run('checkProxyProbe', 'path-other', async (...a: any[]) => { const e = mkEnv(a[1]); return D.checkProxyProbe(a[0], { fetch: e.fetch, rand: rng(7).next }); },
  [pcfgs[2], { now: T0, responses: { 'https://api.example.com/other': [rl('3'), rl('2'), rl('1'), rl('0')] } }]);
await o.run('checkProxyProbe', 'path-rel', async (...a: any[]) => { const e = mkEnv(a[1]); return D.checkProxyProbe(a[0], { fetch: e.fetch, rand: rng(7).next }); },
  [pcfgs[4], { now: T0, responses: { 'https://api.example.com/rel': [rl('3'), rl('2'), rl('1'), rl('0')] } }]);
await o.run('checkProxyProbe', 'no-route', async (...a: any[]) => { const e = mkEnv(a[1]); return D.checkProxyProbe(a[0], { fetch: e.fetch, rand: rng(7).next }); }, [pcfgs[0], { now: T0, responses: {} }]);
await o.run('checkProxyProbe', 'bad-url', async (...a: any[]) => { const e = mkEnv(a[1]); return D.checkProxyProbe(a[0], { fetch: e.fetch, rand: rng(7).next }); }, [{ url: 'not a url' }, { now: T0, responses: {} }]);

// ---- caveats ------------------------------------------------------------------------------------------------------------
const vers = ['0.4.1', '0.4.0', '0.4.2', '0.5.0', '1.0.0', '0.4', '0.4.1-rc.1', '0.4.1+build', '0.10.0', '0.9.9', 'x', '', '..', '1..2', ' 1.2.3', '1.2.3.4', '0x10.0.0', '1e2.0.0', '08.1.1', '-1.0.0', '0.4.01', 'v0.4.1', '0.4.1-0.4.2', '1.2', '1'];
for (const a of vers) for (const b of ['0.4.1', '0.4.0', '1.0.0', '', 'x', '0.4']) await o.run('compareVersion', `${a} vs ${b}`, (x: any, y: any) => D.compareVersion(x, y), [a, b]);
const fakeModule = (behavior: string) => ({
  generateKeyPair: () => ({ publicKey: new Uint8Array(1), secretKey: new Uint8Array(1) }),
  encodeKey: () => 'k',
  mintGrant: () => ({ grant: { caveats: [{ type: 'expires', at: 1 }] } }),
  mintRoot: (a: any) => ({ caveats: a.caveats }),
  delegate: () => ({}),
  DEFAULT_RISK_POLICY: {},
  decide: (a: any) => {
    const amount = a.action.action.params.amount;
    const cav = a.grant.caveats[a.grant.caveats.length - 1];
    if (behavior === 'throws') throw new Error('boom');
    if (behavior === 'allow-all') return { releaseGuardianShare: true, reasons: [] };
    if (behavior === 'deny-all') return { releaseGuardianShare: false, reasons: ['denied', 7] };
    if (behavior === 'nonarray-reasons') return { releaseGuardianShare: false, reasons: 'x' };
    if (cav.type === 'max_spend') {
      if (behavior === 'ignore-max') return { releaseGuardianShare: true, reasons: [] };
      return amount <= cav.usd ? { releaseGuardianShare: true, reasons: [] } : { releaseGuardianShare: false, reasons: ['over max_spend'] };
    }
    if (behavior === 'ignore-unknown') return { releaseGuardianShare: true, reasons: [] };
    return { releaseGuardianShare: false, reasons: ['unknown caveat type'] };
  },
});
const rootRef = (...a: any[]) => {
  const [cfg, spec] = a;
  return D.checkRootCaveats(cfg, { loadPca: () => { if (spec.throws) throw new Error(spec.throws); return { module: fakeModule(spec.behavior), version: spec.version, path: spec.path }; } });
};
n = 0;
for (const behavior of ['enforce', 'ignore-max', 'ignore-unknown', 'deny-all', 'throws', 'nonarray-reasons', 'allow-all']) for (const version of ['0.4.1', '0.4.0', '0.5.2', 'x', '0.4.1-rc.1']) {
  await o.run('checkRootCaveats', `${n++} ${behavior} ${version}`, rootRef, [{}, { behavior, version, path: '/app/node_modules/@atlasauth/pca' }]);
}
await o.run('checkRootCaveats', 'load-throws', rootRef, [{}, { throws: 'cannot find module', behavior: 'enforce', version: '1', path: 'p' }]);
await o.run('checkRootCaveats', 'load-throws-dir', rootRef, [{ verifier: { pcaDir: '/srv/app' } }, { throws: 'not installed', behavior: 'enforce', version: '1', path: 'p' }]);
const encs: any[] = [undefined, {}, { insecureAllowUnenforced: true }, { insecureAllowUnenforced: 'true' }, { require: [] }, { require: D.DEFAULT_REQUIRED }, { require: [...D.DEFAULT_REQUIRED, 'extra'] },
  { require: D.DEFAULT_REQUIRED.slice(1) }, { require: ['replay'] }, { require: null }, { insecureAllowUnenforced: true, require: [] }, { require: ['audience'] }];
n = 0;
for (const v of encs) await o.run('checkEnforcement', `v ${n++}`, (c: any) => D.checkEnforcement(c), [v === undefined ? {} : { verifier: v }]);
await o.run('checkEnforcement', 'verifier-null', (c: any) => D.checkEnforcement(c), [{ verifier: null }]);

// ---- config -------------------------------------------------------------------------------------------------------------
const cps: any[] = [{}, { clock: { maxSkewMs: 0 } }, { clock: { maxSkewMs: -1 } }, { clock: { maxSkewMs: '5' } }, { clock: { maxSkewMs: 5 } }, { clock: { timeoutMs: 0 } },
  { clock: { warnFraction: 0 } }, { clock: { warnFraction: 1 } }, { clock: { warnFraction: 1.5 } }, { clock: { warnFraction: 'x' } }, { clock: { warnFraction: 0.25 } }, { store: { concurrency: 0 } }, { store: { concurrency: 1.5 } },
  { store: { concurrency: 4, rounds: 3 } }, { store: { rounds: -2 } }, { store: { rounds: '3' } }, { proxy: { trustedProxyCount: -1 } }, { proxy: { trustedProxyCount: 1.5 } }, { proxy: { trustedProxyCount: -0 } }, { proxy: { trustedProxyCount: 2, hops: 3 } },
  { proxy: { hops: -1 } }, { proxy: { hops: 'a' } }, { url: 'ftp://x' }, { url: 'https://x' }, { url: 'x' }, { url: '' }, { url: null }, { url: 5 }, { url: 'http://[::1' }, { clock: null }, { clock: 5 }, { store: null },
  { clock: { maxSkewMs: 0 }, store: { rounds: 0 }, proxy: { hops: -5 }, url: 'x' }, { clock: { maxSkewMs: Infinity === 1 ? 1 : 1e308 } }];
n = 0;
for (const c of cps) await o.run('configProblems', `c ${n++}`, (x: any) => D.configProblems(x), [c]);
const mk = (status: string, id = 'x', extra: any = {}) => ({ id, status, detail: `${id} detail`, ...extra });
const resSets: any[] = [[], [mk('skip')], [mk('pass')], [mk('warn')], [mk('fail')], [mk('pass'), mk('warn')], [mk('pass'), mk('skip')], [mk('skip'), mk('skip')], [mk('warn'), mk('fail')], [mk('pass', 'a', { remediation: 'do x' }), mk('warn', 'longer.check.id.here.x', { remediation: 'fix y' })],
  [mk('pass', 'é'), mk('PASS')]];
n = 0;
for (const rs of resSets) for (const strict of [false, true]) {
  await o.run('verdictOf', `r${n} ${strict}`, (a: any, b: any) => D.verdictOf(a, b), [rs, strict]);
  for (const target of [undefined, 'https://t']) await o.run('formatResults', `r${n} ${strict} ${target}`, (a: any, t: any, s: any) => D.formatResults(a, t === null ? undefined : t, s), [rs, target ?? null, strict]);
  n++;
}
await o.run('verdictOf', 'default-strict', (a: any) => D.verdictOf(a), [[mk('warn')]]);
const envs: any[] = [{}, { PCA_DOCTOR_URL: 'https://a' }, { PCA_DOCTOR_REFERENCE_URL: 'local' }, { PCA_DOCTOR_STORE: './s.mjs' }, { TRUSTED_PROXY_COUNT: '2' }, { TRUSTED_PROXY_COUNT: '' }, { TRUSTED_PROXY_COUNT: 'x' }, { TRUSTED_PROXY_COUNT: '-1' },
  { TRUSTED_PROXY_COUNT: '1.5' }, { TRUSTED_PROXY_COUNT: '0x2' }, { TRUSTED_PROXY_COUNT: ' 3 ' }, { TRUSTED_PROXY_COUNT: '1e1' }, { TRUSTED_PROXY_COUNT: '-0' }, { TRUSTED_PROXY_HEADER: 'X-Real-IP' }, { TRUSTED_PROXY_HEADER: 'bogus' }, { TRUSTED_PROXY_HEADER: '' },
  { PCA_TRUSTED_PROXY_HOPS: '2' }, { PCA_TRUSTED_PROXY_HOPS: 'q' }, { PCA_ALLOWED_SUITES: 'ed25519, ml-dsa-65 ,' }, { PCA_ALLOWED_SUITES: '' }, { PCA_ALLOWED_SUITES: ' ,, ' }, { PCA_PQ_PINS: '{"a":"b"}' }, { PCA_PQ_PINS: '{"a":1}' },
  { PCA_PQ_PINS: '[]' }, { PCA_PQ_PINS: 'null' }, { PCA_PQ_PINS: '{bad' }, { PCA_PQ_PINS: '"x"' }, { PCA_PQ_PINS: '{}' }, { PCA_ALLOW_UNBOUND_PQ: 'true' }, { PCA_ALLOW_UNBOUND_PQ: 'YES' }, { PCA_ALLOW_UNBOUND_PQ: '0' }, { PCA_ALLOW_UNBOUND_PQ: '' },
  { PCA_DOCTOR_URL: 'u', TRUSTED_PROXY_COUNT: '1', PCA_ALLOWED_SUITES: 'ed25519', PCA_ALLOW_UNBOUND_PQ: 'on', PCA_TRUSTED_PROXY_HOPS: '1', TRUSTED_PROXY_HEADER: 'forwarded' }, { PCA_DOCTOR_URL: '' }, { OTHER: 'x' }];
n = 0;
for (const e of envs) await o.run('configFromEnv', `e ${n++}`, (x: any) => D.configFromEnv(x), [e]);
const mc: any[][] = [[], [{}], [{ a: 1 }, { b: 2 }], [{ url: 'a' }, { url: 'b' }], [{ clock: { maxSkewMs: 1 } }, { clock: { referenceUrl: 'x' } }], [{ clock: { maxSkewMs: 1 } }, { clock: { maxSkewMs: 2 } }], [{ proxy: { hops: 1 } }, {}, { proxy: { header: 'x-real-ip' } }],
  [{ verifier: { allowedSuites: ['a'] } }, { verifier: { allowedSuites: ['b'] } }], [{ verifier: { allowedSuites: ['a'] } }, { verifier: null }], [{ clock: null }, { clock: { a: 1 } }], [{ clock: { a: 1 } }, { clock: null }], [{ x: [1] }, { x: [2] }],
  [{ x: 'a' }, { x: { b: 1 } }], [{ x: { b: 1 } }, { x: 'a' }], [JSON.parse('{"__proto__": {"x":1}}')], [{ constructor: 1 }], [{ prototype: 1 }], [{ a: 1 }, JSON.parse('{"__proto__": 1}')], [{ store: { adapter: 'a' } }, { store: { options: { k: 'v' } } }, { store: { adapter: 'b' } }]];
n = 0;
for (const a of mc) await o.run('mergeConfig', `m ${n++}`, (...x: any[]) => D.mergeConfig(...x), a);

// ---- cli ----------------------------------------------------------------------------------------------------------------
const argvs: string[][] = [[], ['--help'], ['-h'], ['--url', 'https://x'], ['--url'], ['--config', 'f.json'], ['--store', 'm'], ['--store-option', 'k=v'], ['--store-option', 'k=v', '--store-option', 'a=b=c'], ['--store-option', 'nov'], ['--store-option', '=x'],
  ['--reference', 'local'], ['--max-skew-ms', '5'], ['--max-skew-ms', 'x'], ['--max-skew-ms'], ['--max-skew-ms', ''], ['--max-skew-ms', '1e3'], ['--trusted-proxy-count', '2'], ['--trusted-proxy-count', '-1'], ['--proxy-header', 'X-Real-IP'], ['--proxy-header', 'bad'],
  ['--proxy-header'], ['--proxy-hops', '3'], ['--no-probe'], ['--pca-dir', '/app'], ['--only', 'clock,store'], ['--only', 'nope'], ['--only', ''], ['--only'], ['--skip', 'clock'], ['--skip', 'clock,store,proxy,suites,caveats'], ['--skip', 'bad'], ['--strict'], ['--json'],
  ['--bogus'], ['positional'], ['--only', 'suites', '--skip', 'suites'], ['--url', 'u', '--url', 'v'], ['--store', 'a', '--store-option', 'k=v', '--reference', 'r', '--max-skew-ms', '9'], ['--help', '--bogus'], ['--bogus', '--help'], ['--only', 'clock', '--skip', 'store', '--strict', '--json']];
n = 0;
for (const a of argvs) await o.run('parseDoctorArgs', `a ${n++} ${a.join(' ')}`, (x: any) => D.parseDoctorArgs(x), [a]);
const margs: Array<[string[], Record<string, string>]> = [[['--help'], {}], [['--bogus'], {}], [['--only', 'bad'], {}], [['--max-skew-ms', 'x'], {}], [['--only', 'clock'], {}], [['--only', 'clock', '--json'], {}], [['--only', 'store'], {}],
  [['--only', 'suites'], {}], [['--only', 'suites', '--json'], {}], [['--only', 'suites'], { PCA_ALLOWED_SUITES: 'ed25519' }], [['--only', 'suites', '--strict'], { PCA_ALLOWED_SUITES: 'ed25519,ml-dsa-65' }],
  [['--only', 'suites,proxy', '--json'], { PCA_ALLOWED_SUITES: 'ed25519', TRUSTED_PROXY_COUNT: '1', PCA_TRUSTED_PROXY_HOPS: '1' }], [['--only', 'proxy'], { TRUSTED_PROXY_COUNT: '3', PCA_TRUSTED_PROXY_HOPS: '1' }],
  [['--only', 'suites'], { PCA_PQ_PINS: '{bad' }], [['--only', 'suites'], { TRUSTED_PROXY_HEADER: 'zz' }], [['--only', 'proxy', '--strict'], { TRUSTED_PROXY_COUNT: '1' }], [['--only', 'proxy'], { TRUSTED_PROXY_COUNT: '0' }],
  [['--only', 'proxy'], { TRUSTED_PROXY_COUNT: 'secret=abc' }], [['--max-skew-ms', '0', '--only', 'suites'], {}], [['--only', 'suites', '--trusted-proxy-count', '2', '--proxy-hops', '2'], { PCA_ALLOWED_SUITES: 'nope' }],
  [['--only', 'proxy', '--no-probe', '--trusted-proxy-count', '2', '--proxy-hops', '1', '--proxy-header', 'forwarded'], {}], [['--only', 'suites', '--skip', 'suites'], {}]];
n = 0;
for (const [argv, env] of margs) {
  await o.run('main', `m ${n++} ${argv.join(' ')}`, async (a: any[], e: any) => {
    const out: string[] = [], err: string[] = [];
    const code = await D.main(a, e, (s: string) => out.push(s), (s: string) => err.push(s));
    return { code, out, err };
  }, [argv, env]);
}

// ---- runDoctor ----------------------------------------------------------------------------------------------------------
const rdRef = async (...a: any[]) => {
  const [cfg, only, envSpec, caveat] = a;
  const e = mkEnv(envSpec);
  const deps: any = { fetch: e.fetch, now: e.now, loadPca: () => { if (caveat.throws) throw new Error(caveat.throws); return { module: fakeModule(caveat.behavior), version: caveat.version, path: caveat.path }; } };
  return only === null ? D.runDoctor(cfg, undefined, deps) : D.runDoctor(cfg, only, deps);
};
const okEnv = { now: T0, responses: { [URL1]: [{ date: httpDate(T0 + 1000) }], [REF]: [{ date: httpDate(T0) }], [P]: [rl('10'), rl('9'), rl('8'), rl('7')] } };
const okCav = { behavior: 'enforce', version: '0.5.0', path: '/app/node_modules/@atlasauth/pca' };
const rdCfgs: any[] = [{ url: URL1 }, { url: URL1, proxy: { trustedProxyCount: 1, hops: 1 }, verifier: { allowedSuites: ['ed25519'], trustedRoot: true } }, { url: URL1, proxy: { trustedProxyCount: 3, hops: 1, probe: false } },
  { verifier: { allowedSuites: ['hybrid-ed25519-ml-dsa-65'], allowUnboundPq: true, insecureAllowUnenforced: true } }, { clock: { maxSkewMs: 0 } }, {}, { url: 'ftp://x' }, { url: URL1, clock: { maxSkewMs: 0 }, store: { rounds: 0 } },
  { url: 'https://user:pw@api.example.com', proxy: { probe: false } }, { verifier: { pcaDir: '/srv/app' } }];
n = 0;
for (const c of rdCfgs) for (const only of [null, ['clock'], ['proxy'], ['suites', 'caveats'], ['store'], []]) {
  await o.run('runDoctor', `c${n++} ${JSON.stringify(only)}`, rdRef, [c, only, c.url?.includes('user:') ? { now: T0, responses: { 'https://user:pw@api.example.com': [{ date: httpDate(T0) }] } } : okEnv, okCav]);
}
for (const cav of [{ throws: 'cannot load Bearer abcdefghij', behavior: 'enforce', version: '0', path: 'p' }, { ...okCav, behavior: 'ignore-max' }, { ...okCav, version: '0.3.0' }]) {
  await o.run('runDoctor', `cav ${cav.throws ?? cav.behavior}/${cav.version}`, rdRef, [{ url: URL1 }, ['caveats'], okEnv, cav]);
}
refWrite(o, 'doctor');
