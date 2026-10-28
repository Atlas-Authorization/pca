import { describe, expect, it } from 'vitest';
import type { PCActn, VerifyResult } from '@atlasauth/pca';
import { type SiemSink, consoleSink, exportBatch, exportDecision, formatDecision, httpSink, scrubError, toCef, toEcs, toOcsfEvent } from './index';

const SIG = 'A'.repeat(20) + 'B'.repeat(66);
const NOW = 1_800_000_000_000;
const pcactn = (over: object = {}): PCActn =>
  ({ ver: 2, grant_ref: 'g1', action: { verb: 'stripe.refund', resource: 'pi_1', params_digest: 'pd', reversibility_class: 'reversible' }, plan: { root: 'r', node_id: 'n' }, counter: 1, nonce: 'n1', iat: 1, exp: 2, sig: SIG, cap_chain: [{ issuer: 'P', holder: 'A', caveats: [] }], ...over }) as unknown as PCActn;
const verify = { allow: true, checks: { wire: 'pass', leaf_signature: 'pass' } } as unknown as VerifyResult;
const rec = (over: object = {}) => ({ pcactn: pcactn(over), verify, now: NOW });

describe('the leaf signature in a log line', () => {
  it('is a 16-character prefix by default, in every format', () => {
    const prefix = `${SIG.slice(0, 16)}…`;
    for (const out of [JSON.stringify(toOcsfEvent(rec())), JSON.stringify(toEcs(rec()))]) {
      expect(out).toContain(prefix);
      expect(out).not.toContain(SIG);
    }
    expect(toCef(rec())).not.toContain(SIG.slice(0, 16)); // CEF carries the proof digest, not the signature
  });
  it('can be logged in full or omitted', () => {
    expect(JSON.stringify(toOcsfEvent(rec(), { signature: 'full' }))).toContain(SIG);
    expect(JSON.stringify(toOcsfEvent(rec(), { signature: 'omit' }))).toContain('(omitted)');
    expect(JSON.stringify(toOcsfEvent(rec(), { signature: 'omit' }))).not.toContain(SIG.slice(0, 16));
    expect(formatDecision(rec(), 'ecs', { signature: 'full' }).line).toContain(SIG);
    expect(formatDecision(rec(), 'cef').line).not.toContain(SIG);
  });
  it('a short signature is shown whole', () => {
    expect(JSON.stringify(toOcsfEvent(rec({ sig: 'SIGSIG' })))).toContain('SIGSIG');
  });
});

describe('scrubError', () => {
  it.each([
    ['url userinfo', 'connect https://u:hunter2@splunk.example:8088/x failed', 'connect https://[redacted]@splunk.example:8088/x failed'],
    ['a query token', 'POST https://h/collector?token=abc123def&x=1 -> 500', 'POST https://h/collector?token=[redacted]&x=1 -> 500'],
    ['a splunk header', 'sent Authorization: Splunk 8a3f-1b2c-9d4e', 'sent Authorization: [redacted]'],
    ['a dd key', 'DD-API-KEY=0123456789abcdef0123456789abcdef bad', 'DD-API-KEY=[redacted] bad'],
    ['a bearer', 'got Bearer abc.def.ghi back', 'got Bearer [redacted] back'],
  ])('removes %s', (_n, input, out) => expect(scrubError(input)).toBe(out));
  it('keeps plain messages and cuts long ones', () => {
    expect(scrubError('HTTP 503 Service Unavailable')).toBe('HTTP 503 Service Unavailable');
    expect(scrubError('word '.repeat(100))).toBe(`${'word '.repeat(100).slice(0, 300)}...`);
  });
});

describe('no credential in a returned or reported error', () => {
  const URL_WITH_SECRET = 'https://svc:hunter2@collector.example/services/collector?token=sekret123456';
  it('a fetch error that quotes the url is scrubbed in the result and in onError', async () => {
    const seen: string[] = [];
    const sink = httpSink(URL_WITH_SECRET, { format: 'ocsf', fetch: async (u) => { throw new Error(`connect ECONNREFUSED ${u}`); }, headers: { authorization: 'Splunk header-secret-0123456789abcdef' } });
    const r = await exportDecision(rec(), sink, { onError: (e) => seen.push(e.message) });
    for (const out of [JSON.stringify(r), ...seen]) {
      expect(out).not.toMatch(/hunter2|sekret123456|header-secret/);
    }
    expect(r.ok).toBe(false);
    expect(seen).toHaveLength(1);
  });
  it('the http sink itself scrubs what it returns, before any exporter sees it', async () => {
    const r = await httpSink(URL_WITH_SECRET, { format: 'ocsf', fetch: async (u) => { throw new Error(`connect ECONNREFUSED ${u}`); } }).deliver([{ format: 'ocsf', line: 'x' }]);
    expect(JSON.stringify(r)).not.toMatch(/hunter2|sekret123456/);
  });
  it('a sink that throws or returns an error with a credential is scrubbed too', async () => {
    const thrower: SiemSink = { name: 't', format: 'cef', deliver: () => { throw new Error('bad Authorization: Splunk abcdef123456'); } };
    const returner: SiemSink = { name: 'r', format: 'cef', deliver: () => ({ ok: false, error: 'password=hunter2' }) };
    expect(JSON.stringify(await exportBatch([rec()], thrower))).not.toContain('abcdef123456');
    expect(JSON.stringify(await exportBatch([rec()], returner))).not.toContain('hunter2');
  });
  it('the console sink scrubs a logger failure', () => {
    const r = consoleSink({ logger: () => { throw new Error('token=abcdefg1234'); } }).deliver([{ format: 'ocsf', line: 'x' }]);
    expect(r).toEqual({ ok: false, error: 'token=[redacted]' });
  });
  it('request headers never appear in a result', async () => {
    const r = await httpSink('https://h/x', { format: 'cef', headers: { authorization: 'Splunk top-secret-value-0000' }, fetch: async () => ({ ok: false, status: 401, statusText: 'Unauthorized' }) }).deliver([{ format: 'cef', line: 'a' }]);
    expect(r).toEqual({ ok: false, error: 'HTTP 401 Unauthorized' });
  });
});

describe('a hung collector does not hold the caller', () => {
  it('times out, aborts the request and reports it', async () => {
    let aborted = false;
    const fetch = (_u: string, init: { signal?: AbortSignal }) => new Promise<never>((_res, rej) => init.signal?.addEventListener('abort', () => { aborted = true; rej(new Error('aborted')); }));
    const r = await httpSink('https://h/x', { format: 'ecs', fetch: fetch as never, timeoutMs: 20 }).deliver([{ format: 'ecs', line: 'a' }]);
    expect(r).toEqual({ ok: false, error: 'delivery timed out' });
    expect(aborted).toBe(true);
  });
  it('a non-positive or non-finite timeout falls back to the default instead of firing at once', async () => {
    for (const timeoutMs of [0, -5, Number.NaN]) {
      const r = await httpSink('https://h/x', { format: 'ecs', timeoutMs, fetch: async () => ({ ok: true, status: 200 }) }).deliver([{ format: 'ecs', line: 'a' }]);
      expect(r).toEqual({ ok: true });
    }
  });
});

describe('one bad record does not take the batch with it', () => {
  const sink = (log: string[][]): SiemSink => ({ name: 's', format: 'cef', deliver: (e) => (log.push(e.map((x) => x.line)), { ok: true }) });
  it('the good records are delivered, the bad one is counted and reported', async () => {
    const log: string[][] = [];
    const errs: string[] = [];
    const r = await exportBatch([rec(), null as never, rec({ nonce: 'n2' })], sink(log), { onError: (e) => errs.push(e.message) });
    expect(r).toEqual({ ok: true, delivered: 2, format: 'cef', skipped: 1 });
    expect(log[0]).toHaveLength(2);
    expect(errs).toHaveLength(1);
    expect(errs[0]).toMatch(/^record could not be serialized/);
  });
  it('when nothing can be serialized nothing is delivered and the result says so', async () => {
    const log: string[][] = [];
    const r = await exportBatch([null as never], sink(log));
    expect(r).toEqual({ ok: false, delivered: 0, format: 'cef', error: 'no record could be serialized', skipped: 1 });
    expect(log).toEqual([]);
  });
  it('an empty batch is delivered as an empty batch', async () => {
    const log: string[][] = [];
    expect(await exportBatch([], sink(log))).toEqual({ ok: true, delivered: 0, format: 'cef' });
  });
});

describe('log injection', () => {
  it('a newline or a CEF delimiter in attacker-controlled fields cannot forge a second line or a field', () => {
    const evil = rec({ action: { verb: 'x|9|forged', resource: 'a\nCEF:0|Atlas|PCA|2|pca-authz-allow|forged|1|act=allow', params_digest: 'p=1 outcome=allow', reversibility_class: 'r' } });
    const line = toCef(evil);
    expect(line.split('\n')).toHaveLength(1);
    expect(line.startsWith('CEF:0|Atlas|PCA|2|pca-authz-allow|')).toBe(true);
    expect((line.match(/\|act=allow /g) ?? []).length).toBe(1); // the forged `act=` stayed inside a value, with its `=` escaped
    expect(line).toContain('x\\|9\\|forged on '); // pipes in the header name are escaped
    expect(line).toContain('request=a\\nCEF:0');
    expect(line).not.toMatch(/ outcome=allow outcome=/);
    const nd = formatDecision(evil, 'ocsf').line;
    expect(nd.includes('\n')).toBe(false);
    expect(JSON.parse(nd)).toBeTruthy();
  });
});
