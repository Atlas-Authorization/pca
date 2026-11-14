/**
 * 0.5 hardening (H5, H7, H9, H10, H11, H20): configuration typing is refused at construction instead of silently dropping a
 * gate, and attestation JSON / RIM XML input is bounded before parsing. Every branch and boundary is pinned.
 */
import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { createAmdSnpVerifier } from './attest-amd-snp';
import { createAzureMaaVerifier, parseMaaJwt } from './attest-azure-maa';
import { parseGcpCsJwt } from './attest-gcp-confidential-space';
import { createIntelDcapVerifier } from './attest-intel-dcap';
import { verifySignedJson } from './attest-intel-collateral';
import { nvidiaCollateralHook, verifyNvidiaRim } from './attest-nvidia-rim';
import { createNvidiaSpdmVerifier } from './attest-nvidia-spdm';
import { MAX_ATTEST_JSON_BYTES, assertJsonSize, assertOptionalStringList } from './policy-lists';

const M = 'ab'.repeat(48);
const BAD_LISTS: unknown[] = ['aa', 5, { 0: 'aa' }, true, ['aa', 1], [null], [['aa']], [{}]];

describe('assertOptionalStringList', () => {
  it('absent/null/empty/all-string pass; everything else throws the exact text', () => {
    for (const ok of [undefined, null, [], ['a'], ['a', 'b']]) expect(() => assertOptionalStringList('ctor', 'key', ok)).not.toThrow();
    for (const bad of BAD_LISTS) expect(() => assertOptionalStringList('ctor', 'key', bad), String(bad)).toThrow(new TypeError('ctor: policy.key must be an array of strings'));
  });
  it('assertJsonSize: 16 MiB exactly passes, one more throws', () => {
    expect(MAX_ATTEST_JSON_BYTES).toBe(16_777_216);
    expect(() => assertJsonSize(MAX_ATTEST_JSON_BYTES)).not.toThrow();
    expect(() => assertJsonSize(MAX_ATTEST_JSON_BYTES + 1)).toThrow(new Error('input too large'));
  });
});

describe('H10: optional allowlists must be arrays of strings at construction', () => {
  const amd = (policy: Record<string, unknown>) => () => createAmdSnpVerifier({ family: 'genoa', binding: 'report-data', policy: { measurements: [M], ...policy } } as never);
  const dcap = (policy: Record<string, unknown>) => () => createIntelDcapVerifier({ binding: 'report-data', policy: { mrtds: [M], ...policy } } as never);
  const maa = (policy: Record<string, unknown>) => () =>
    createAzureMaaVerifier({ trustedIssuers: ['https://maa.example'], trustAnchors: { rootSpkiSha256: ['aa'] }, policy: { tdxMrtds: [M], ...policy } } as never);
  const cases: [string, (p: Record<string, unknown>) => () => unknown, string[]][] = [
    ['createAmdSnpVerifier', amd, ['hostData', 'chipIds']],
    ['createIntelDcapVerifier', dcap, ['fmspcs', 'rtmrs']],
    ['createAzureMaaVerifier', maa, ['sevSnpHostData', 'tdxRtmrs', 'tdxAllowedTcbStatuses']],
  ];
  for (const [ctor, mk, keys] of cases) {
    for (const key of keys) {
      it(`${ctor}: policy.${key}`, () => {
        for (const bad of BAD_LISTS) expect(mk({ [key]: bad }), JSON.stringify(bad)).toThrow(new TypeError(`${ctor}: policy.${key} must be an array of strings`));
        for (const ok of [undefined, null, [], ['aa'], ['aa', 'bb']]) expect(mk({ [key]: ok }), JSON.stringify(ok)).not.toThrow();
      });
    }
  }
  it('a string allowlist can no longer act as a substring match for TDX TCB statuses', () => {
    expect(maa({ tdxAllowedTcbStatuses: 'UpToDateAndMore' })).toThrow('policy.tdxAllowedTcbStatuses must be an array of strings');
  });
});

describe('H11: policy.collateral must be an object', () => {
  const mk = (collateral: unknown) => () => createIntelDcapVerifier({ binding: 'report-data', policy: { mrtds: [M], collateral } } as never);
  it('refuses every non-object; accepts absent, null and objects', () => {
    for (const bad of ['x', '', 5, 0, true, false, [], [1]]) expect(mk(bad), JSON.stringify(bad)).toThrow(new TypeError('createIntelDcapVerifier: policy.collateral must be an object'));
    for (const ok of [undefined, null, {}, { minTcbEvaluationDataNumber: 7 }, { acceptStatuses: ['UpToDate'] }]) expect(mk(ok), JSON.stringify(ok)).not.toThrow();
  });
});

describe('H20: a non-finite / non-integer SVN floor is refused at construction (already enforced; pinned)', () => {
  const mk = (floor: unknown) => () =>
    createAzureMaaVerifier({ trustedIssuers: ['https://maa.example'], trustAnchors: { rootSpkiSha256: ['aa'] }, policy: { sevSnpMeasurements: [M], sevSnpMinTcb: { snp: floor } } } as never);
  it('NaN, Infinity, arrays, strings, null, negatives and fractions throw; 0 and integers pass', () => {
    for (const bad of [Number.NaN, Infinity, -Infinity, [5], '5', null, -1, 1.5, {}]) expect(mk(bad), String(bad)).toThrow('policy.sevSnpMinTcb.snp must be a non-negative integer');
    for (const ok of [0, 1, 27, undefined]) expect(mk(ok), String(ok)).not.toThrow();
  });
});

describe('H9: NVIDIA configuration typing', () => {
  const hook = (extra: Record<string, unknown>) => () => nvidiaCollateralHook({ rimRootSpkiSha256: ['aa'], resolve: () => undefined, ...extra } as never);
  const spdm = (policy: Record<string, unknown>) => () => createNvidiaSpdmVerifier({ rootSpkiSha256: ['aa'], policy: { measurements: { 1: 'aa' }, ...policy } } as never);

  it('leafSubjectIncludes: present non-null must be a string', () => {
    for (const bad of [5, true, [], ['GH100'], {}, 0, false]) expect(spdm({ leafSubjectIncludes: bad }), JSON.stringify(bad)).toThrow(new TypeError('createNvidiaSpdmVerifier: policy.leafSubjectIncludes must be a string'));
    for (const ok of [undefined, null, '', 'GH100']) expect(spdm({ leafSubjectIncludes: ok }), JSON.stringify(ok)).not.toThrow();
  });
  it('firmware: absent/null build; a non-object (string, number, boolean, array) is refused, even a falsy one', () => {
    for (const ok of [undefined, null, {}]) expect(hook({ firmware: ok }), JSON.stringify(ok)).not.toThrow();
    for (const bad of ['x', '', 5, 0, true, false, [], ['a']]) expect(hook({ firmware: bad }), JSON.stringify(bad)).toThrow(new TypeError('nvidiaCollateralHook: firmware must be an object'));
  });
  it('minDriverVersion / minVbiosVersion: a truthy non-string is malformed; empty/absent skips; malformed strings still throw', () => {
    for (const k of ['minDriverVersion', 'minVbiosVersion']) {
      for (const bad of [535, true, {}, [], ['1']]) expect(hook({ firmware: { [k]: bad } }), `${k} ${JSON.stringify(bad)}`).toThrow(new TypeError(`nvidiaCollateralHook: malformed ${k} '${String(bad)}'`));
      for (const ok of [undefined, null, '', 0, false]) expect(hook({ firmware: { [k]: ok } }), `${k} ${JSON.stringify(ok)}`).not.toThrow();
      expect(hook({ firmware: { [k]: '1.x' } })).toThrow(`malformed ${k} '1.x'`);
    }
    expect(hook({ firmware: { minDriverVersion: '535.1' } })).not.toThrow();
    expect(hook({ firmware: { minVbiosVersion: '96.00.9f' } })).not.toThrow();
  });
  it('deny lists: a non-array is refused, an array with a non-string entry is refused, absent/null/empty pass', () => {
    for (const [k, label] of [['denyDriverVersions', 'denyDriverVersions entry'], ['denyVbiosVersions', 'denyVbiosVersions entry']] as const) {
      for (const bad of ['535.1', 5, {}, true]) expect(hook({ firmware: { [k]: bad } }), `${k} ${JSON.stringify(bad)}`).toThrow(new TypeError(`nvidiaCollateralHook: malformed ${label} '${String(bad)}'`));
      expect(hook({ firmware: { [k]: ['1.1', 5] } }), k).toThrow(`malformed ${label} '5'`);
      for (const ok of [undefined, null, []]) expect(hook({ firmware: { [k]: ok } }), `${k} ${JSON.stringify(ok)}`).not.toThrow();
    }
    expect(hook({ firmware: { denyDriverVersions: ['535.1', '535.2'] } })).not.toThrow();
    expect(hook({ firmware: { denyVbiosVersions: ['96.00.9f'] } })).not.toThrow();
  });
  it('requireCrlIssuers: must list only strings', () => {
    for (const bad of ['NVIDIA GH100', 5, {}, [1], ['a', null]]) expect(hook({ requireCrlIssuers: bad }), JSON.stringify(bad)).toThrow(new TypeError('nvidiaCollateralHook: requireCrlIssuers must list only strings'));
    for (const ok of [undefined, null, [], ['NVIDIA GH100']]) expect(hook({ requireCrlIssuers: ok }), JSON.stringify(ok)).not.toThrow();
  });
});

describe('H5: RIM XML nesting is refused before parsing', () => {
  const NEST = 'RIM: verification error (fail closed): XML nesting is too deep';
  const rim = async (xml: string) => {
    const r = await verifyNvidiaRim(xml, { rimRootSpkiSha256: ['aa'], nowMs: 0 });
    return r.ok ? 'OK' : r.reason;
  };
  const nest = (n: number, inner = '') => '<a>'.repeat(n) + inner + '</a>'.repeat(n);
  it('64 levels pass the pre-scan, 65 are refused', async () => {
    expect(await rim(nest(65))).toBe(NEST);
    expect(await rim(nest(64))).not.toBe(NEST);
    expect(await rim(nest(1000))).toBe(NEST);
  });
  it('a huge depth is refused fast (linear scan)', async () => {
    const t = Date.now();
    expect(await rim('<a>'.repeat(1_000_000))).toBe(NEST);
    expect(Date.now() - t).toBeLessThan(2000);
  });
  it('closing tags unwind the depth: sequential siblings are not nesting', async () => {
    expect(await rim('<r>' + '<a></a>'.repeat(5000) + '</r>')).not.toBe(NEST);
    expect(await rim(nest(64) + nest(64))).not.toBe(NEST);
  });
  it('self-closing tags, comments, CDATA, processing instructions and DOCTYPE never count', async () => {
    const d64 = (inner: string) => nest(64, inner);
    expect(await rim(d64('<b/>'.repeat(500)))).not.toBe(NEST);
    expect(await rim(d64('<b x="1" />'.repeat(500)))).not.toBe(NEST);
    expect(await rim(d64('<!-- ' + '<c>'.repeat(200) + ' -->'))).not.toBe(NEST);
    expect(await rim(d64('<![CDATA[' + '<c>'.repeat(200) + ']]>'))).not.toBe(NEST);
    expect(await rim(d64('<?pi ' + '<c>'.repeat(200) + ' ?>'))).not.toBe(NEST);
    expect(await rim('<!DOCTYPE a [ <!ENTITY e "<c>"> ]>' + nest(64))).not.toBe(NEST);
  });
  it('a quoted ">" inside an attribute does not end the tag early; a quoted "/" before ">" is not a self-close', async () => {
    expect(await rim('<a x=">">'.repeat(65) + '</a>'.repeat(65))).toBe(NEST);
    expect(await rim('<a x="/">'.repeat(65) + '</a>'.repeat(65))).toBe(NEST);
    expect(await rim("<a x='>'>".repeat(65) + '</a>'.repeat(65))).toBe(NEST);
    expect(await rim('<a x=">"/>'.repeat(500))).not.toBe(NEST);
  });
  it('an unterminated construct or tag ends the scan without a verdict (the parser rejects it)', async () => {
    for (const x of [nest(10) + '<!-- never closed', nest(10) + '<![CDATA[ never', nest(10) + '<?pi never', '<!DOCTYPE never', '<a x="never>']) expect(await rim(x), x).not.toBe(NEST);
  });
});

describe('H7: attestation JSON segments over 16 MiB are refused before parsing', () => {
  const b64u = (b: Buffer) => b.toString('base64url');
  const pad = (n: number) => Buffer.from('{"a":"' + 'x'.repeat(n - 8) + '"}'); // exactly n bytes of valid JSON
  const sig = b64u(Buffer.from([1, 2, 3]));
  const hdr = b64u(Buffer.from('{"alg":"ES256"}'));
  const TOO = (fn: string) => new TypeError(`${fn}: malformed JSON segment: input too large`);
  for (const [fn, parse] of [['parseMaaJwt', parseMaaJwt], ['parseGcpCsJwt', parseGcpCsJwt]] as const) {
    it(`${fn}: payload / header of exactly 16 MiB parse, one byte more is refused`, () => {
      const N = MAX_ATTEST_JSON_BYTES;
      expect(() => parse(`${hdr}.${b64u(pad(N))}.${sig}`)).not.toThrow(/too large/);
      expect(() => parse(`${hdr}.${b64u(pad(N + 1))}.${sig}`)).toThrow(TOO(fn));
      const bigHdr = (n: number) => b64u(Buffer.from('{"alg":"ES256","p":"' + 'x'.repeat(n - 22) + '"}'));
      expect(() => parse(`${bigHdr(N)}.${b64u(Buffer.from('{}'))}.${sig}`)).not.toThrow(/too large/);
      expect(() => parse(`${bigHdr(N + 1)}.${b64u(Buffer.from('{}'))}.${sig}`)).toThrow(TOO(fn));
    });
  }
  it('Intel collateral: a signed document of exactly 16 MiB characters is parsed, one more is refused with its name', () => {
    const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const N = MAX_ATTEST_JSON_BYTES;
    const doc = (n: number) => {
      const head = '{"tcbInfo":{"a":"';
      const tail = '"},"signature":"zz"}';
      return head + 'x'.repeat(n - head.length - tail.length) + tail;
    };
    expect(verifySignedJson(doc(N), 'tcbInfo', publicKey)).toEqual({ error: 'tcbInfo signature missing or malformed' });
    expect(verifySignedJson(doc(N + 1), 'tcbInfo', publicKey)).toEqual({ error: 'tcbInfo: malformed JSON segment: input too large' });
    expect(verifySignedJson(doc(N + 1), 'qeIdentity', publicKey)).toEqual({ error: 'qeIdentity: malformed JSON segment: input too large' });
  });
});
