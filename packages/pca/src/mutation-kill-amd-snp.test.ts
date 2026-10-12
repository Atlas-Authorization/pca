/** Mutation-kill tests for attest-amd-snp.ts with the report verifier mocked, so every branch and forwarded argument is observable. */
import { beforeEach, describe, expect, it, vi } from 'vitest';

const h = vi.hoisted(() => ({ r: vi.fn() }));
vi.mock('./hardware-sevsnp', async (orig) => ({ ...(await orig<typeof import('./hardware-sevsnp')>()), verifyGenuineSevSnpReport: h.r }));

import { createHash } from 'node:crypto';
import { AMD_ARK_SPKI_SHA384, createAmdSnpVerifier, pemToDer } from './attest-amd-snp';
import { attestationBinding } from './attestation';

const EXP = { holderPub: 'h', grantRef: 'g', epoch: 1, nonce: 'n' };
const MEAS = new Uint8Array(48).fill(0xab);
const rdBytes = new TextEncoder().encode(JSON.stringify({ 'user-data': Buffer.from(attestationBinding(EXP)).toString('hex') }));
const rdHash = (() => { const r = new Uint8Array(64); r.set(createHash('sha256').update(rdBytes).digest()); return r; })();
const okR = (over: Record<string, unknown> = {}) => ({ ok: true, report: { report_data: rdHash, measurement: MEAS }, measured: { runtime_measurement: 'm' }, ...over });
const EV = { report: new Uint8Array(4), vcekDer: new Uint8Array(4), askArkPem: 'pem', runtimeData: rdBytes };
const mk = (o: Record<string, unknown> = {}) => createAmdSnpVerifier({ family: 'genoa', binding: 'azure-runtime-data', policy: { measurements: ['aa'] }, resolveEvidence: () => EV, ...o } as never);
const run = (v: ReturnType<typeof mk>, nowMs = 777) => v.verify({ document: {} as never, ctx: {} as never, nowMs, expected: EXP });

beforeEach(() => { h.r.mockReset(); h.r.mockResolvedValue(okR()); });

describe('createAmdSnpVerifier constructor', () => {
  it('exact messages for family / binding / measurements, including undefined options', () => {
    const f = (o: unknown) => () => createAmdSnpVerifier(o as never);
    const FAM = "createAmdSnpVerifier: family must be 'milan' | 'genoa' | 'turin'";
    expect(f(undefined)).toThrow(FAM);
    expect(f({})).toThrow(FAM);
    expect(f({ family: 'rome', binding: 'report-data', policy: { measurements: ['a'] } })).toThrow(FAM);
    expect(f({ family: 'milan' })).toThrow("createAmdSnpVerifier: binding must be 'report-data' or 'azure-runtime-data'");
    expect(f({ family: 'milan', binding: 'x', policy: { measurements: ['a'] } })).toThrow("binding must be 'report-data' or 'azure-runtime-data'");
    const MSG = 'createAmdSnpVerifier: policy.measurements must be a NON-EMPTY allowlist (accept-all is not permitted)';
    expect(f({ family: 'milan', binding: 'report-data' })).toThrow(MSG);
    expect(f({ family: 'milan', binding: 'report-data', policy: { measurements: [] } })).toThrow(MSG);
    expect(f({ family: 'milan', binding: 'report-data', policy: { measurements: 'a' } })).toThrow(MSG);
    expect(f({ family: 'turin', binding: 'azure-runtime-data', policy: { measurements: ['a'] } })).not.toThrow();
  });
});

describe('verify', () => {
  it('forwards the family pin, time, policy, evidence; clockSkewMs only when set (including 0); expected only in direct mode', async () => {
    await run(mk({ binding: 'report-data', clockSkewMs: 0 }));
    let a = h.r.mock.calls[0]![0];
    expect(a).toMatchObject({ report: EV.report, vcekDer: EV.vcekDer, askArkPem: 'pem', trustAnchorArkSpkiSha384: AMD_ARK_SPKI_SHA384.genoa, nowMs: 777, clockSkewMs: 0, expected: EXP });
    expect(a.policy).toEqual({ measurements: ['aa'] });
    await run(mk({ clockSkewMs: 5000 }));
    a = h.r.mock.calls[1]![0];
    expect(a.clockSkewMs).toBe(5000);
    expect('expected' in a).toBe(false);
    await run(mk({ family: 'milan' }));
    a = h.r.mock.calls[2]![0];
    expect('clockSkewMs' in a).toBe(false);
    expect(a.trustAnchorArkSpkiSha384).toBe(AMD_ARK_SPKI_SHA384.milan);
  });
  it('direct mode needs no runtime data; azure mode does, and its binding is checked', async () => {
    const r = await run(mk({ binding: 'report-data', resolveEvidence: () => ({ ...EV, runtimeData: undefined }) }));
    expect(r).toEqual({ ok: true, bound: true, measured: { runtime_measurement: 'm' }, hostAsserted: { attestation_type: 'amd-sev-snp', family: 'genoa', measurement: 'ab'.repeat(48) } });
    expect((await run(mk({ resolveEvidence: () => ({ ...EV, runtimeData: undefined }) }))).reason).toBe('azure-runtime-data binding needs the runtime-data JSON bytes');
    expect((await run(mk())).ok).toBe(true);
    h.r.mockResolvedValueOnce(okR({ report: { report_data: new Uint8Array(64), measurement: MEAS } }));
    expect((await run(mk())).reason).toMatch(/sha256\(runtime data\)/);
  });
  it('report failure: each of ok/report/measured, reason passed through or "unknown"', async () => {
    for (const drop of ['report', 'measured'] as const) {
      h.r.mockResolvedValueOnce(okR({ [drop]: undefined, reason: 'why' }));
      expect(await run(mk())).toEqual({ ok: false, reason: 'SEV-SNP report invalid: why' });
    }
    h.r.mockResolvedValueOnce(okR({ ok: false, reason: 'sig' }));
    expect((await run(mk())).reason).toBe('SEV-SNP report invalid: sig');
    h.r.mockResolvedValueOnce({ ok: false });
    expect((await run(mk())).reason).toBe('SEV-SNP report invalid: unknown');
  });
  it('resolver failure modes with exact reasons', async () => {
    expect(await run(mk({ resolveEvidence: undefined }))).toEqual({ ok: false, reason: 'no AMD SEV-SNP evidence resolver configured (fail closed)' });
    expect(h.r).not.toHaveBeenCalled();
    for (const bad of [undefined, { ...EV, report: [1] }, { ...EV, vcekDer: 'x' }, { ...EV, askArkPem: new Uint8Array(1) }]) {
      expect((await run(mk({ resolveEvidence: () => bad }))).reason).toBe('no AMD SEV-SNP evidence for this action');
    }
    expect((await mk().verify({ document: {} as never, ctx: {} as never, nowMs: 1 } as never)).reason).toBe('no expected attestation binding supplied');
    expect((await run(mk({ resolveEvidence: () => { throw new Error('x'); } }))).reason).toBe('amd-snp verification error (fail closed): x');
    expect((await run(mk({ resolveEvidence: () => { throw 7; } }))).reason).toBe('amd-snp verification error (fail closed): unknown');
  });
});

describe('pemToDer', () => {
  it('decodes one certificate; refuses input with none or an empty body', () => {
    const pem = `-----BEGIN CERTIFICATE-----\n${Buffer.from([1, 2, 3, 4]).toString('base64')}\n-----END CERTIFICATE-----`;
    expect([...pemToDer(pem)]).toEqual([1, 2, 3, 4]);
    expect(() => pemToDer('nothing')).toThrow('pemToDer: no certificate found');
    expect(() => pemToDer('-----BEGIN CERTIFICATE----------END CERTIFICATE-----')).toThrow('pemToDer: no certificate found');
  });
});
